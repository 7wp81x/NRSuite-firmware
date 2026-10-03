#include "mesh.h"

#include <Preferences.h>
#include <esp_wifi.h>
#include <mbedtls/base64.h>
#include <mbedtls/ccm.h>
#include <mbedtls/md.h>
#include <esp_err.h>

namespace {
const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t OFFLINE_ROLE = 0xFF;
}

MeshManager* MeshManager::_instance = nullptr;

// ── Public lifecycle ─────────────────────────────────────────────────────────

void MeshManager::begin(BridgeProtocol& proto, const char* nodeId, const char* chipName) {
    _proto = &proto;
    _instance = this;

    const char* effectiveNodeId = (nodeId && nodeId[0]) ? nodeId : "NR00000000";
    strncpy(_nodeId, effectiveNodeId, sizeof(_nodeId) - 1);
    _nodeId[sizeof(_nodeId) - 1] = '\0';
    _nodeHash = hashNodeId(_nodeId);

    if (chipName && chipName[0]) {
        strncpy(_chipName, chipName, sizeof(_chipName) - 1);
        _chipName[sizeof(_chipName) - 1] = '\0';
    }

    uint32_t boot = esp_random();
    _bootId = boot ? boot : 1;

    loadKeys();

    // Persist the mesh-scoped node id as required by the foundation layout.
    Preferences prefs;
    if (prefs.begin("mesh", false)) {
        if (prefs.getString("mesh_node_id", "") != String(_nodeId)) {
            prefs.putString("mesh_node_id", _nodeId);
        }
        prefs.end();
    }

    // Phase 1.5: an already-provisioned node passively listens for a master
    // after reboot. It never self-elects in this mode; if the USB app sends
    // MESH_ACTIVATE, mesh.stop() + activate() overrides this with the normal
    // candidate election flow.
    if (_initialized && ESP.getFreeHeap() >= MIN_FREE_HEAP_BYTES) {
        if (startRadio()) {
            _role = ROLE_IDLE;
        }
    }
}

void MeshManager::update() {
    if (!_initialized || !_espNowActive) return;

    const uint32_t now = millis();

    if (_role == ROLE_CANDIDATE) {
        if (now - _candidateSinceMs >= ELECTION_WINDOW_MS) {
            becomeMaster();
        }
    }

    if (_role == ROLE_MASTER) {
        if (_lastBroadcastMs == 0 ||
            now - _lastBroadcastMs >= HEARTBEAT_INTERVAL_MS) {
            sendHeartbeat();
        }
        if (_lastPeerSweepMs == 0 ||
            now - _lastPeerSweepMs >= 1000) {
            sweepPeers(now);
            _lastPeerSweepMs = now;
        }
    }

    if (_role == ROLE_CLIENT) {
        if (_lastMasterSeenMs != 0 &&
            now - _lastMasterSeenMs > MASTER_TIMEOUT_MS) {
            _role = ROLE_IDLE;
            _sessionId = 0;
            _lastJoinMs = 0;
            sendStatusEvent("master_timeout");
            return;
        }
        if (_lastJoinMs == 0 || now - _lastJoinMs >= JOIN_INTERVAL_MS) {
            sendJoin();
        }
    }
}

void MeshManager::stop() {
    const bool wasActive = (_role != ROLE_DISABLED);
    stopRadio();
    _role = ROLE_DISABLED;
    _sessionId = 0;
    _counter = 0;
    _lastBroadcastMs = 0;
    _lastJoinMs = 0;
    _lastMasterSeenMs = 0;
    _masterNodeHash = 0;
    _masterBootId = 0;

    if (wasActive) {
        sendStatusEvent("stopped");
    }
}

const char* MeshManager::roleName() const {
    switch (_role) {
        case ROLE_IDLE:      return "idle";
        case ROLE_CANDIDATE: return "candidate";
        case ROLE_MASTER:    return "master";
        case ROLE_CLIENT:    return "client";
        default:             return "disabled";
    }
}

uint32_t MeshManager::peerCount() const {
    uint32_t count = 0;
    const uint32_t now = millis();
    for (size_t i = 0; i < REPLAY_SLOTS; i++) {
        const PeerEntry& peer = _peers[i];
        if (!peer.used) continue;
        if (peer.role == ROLE_CLIENT &&
            now - peer.lastSeenMs <= PEER_TIMEOUT_MS) {
            count++;
        }
    }
    return count;
}

// ── NVS key management ───────────────────────────────────────────────────────

bool MeshManager::loadKeys() {
    Preferences prefs;
    if (!prefs.begin("mesh", true)) return false;

    const bool initialized = prefs.getBool("mesh_init", false);
    const size_t authLen = prefs.getBytesLength("mesh_auth_key");
    const size_t transportLen = prefs.getBytesLength("mesh_trans_key");

    if (initialized && authLen == sizeof(_authKey) && transportLen == sizeof(_transportKey)) {
        prefs.getBytes("mesh_auth_key", _authKey, sizeof(_authKey));
        prefs.getBytes("mesh_trans_key", _transportKey, sizeof(_transportKey));
        String keyId = prefs.getString("mesh_key_id", "");
        strncpy(_keyId, keyId.c_str(), sizeof(_keyId) - 1);
        _keyId[sizeof(_keyId) - 1] = '\0';
        _initialized = true;
    } else {
        _initialized = false;
        memset(_authKey, 0, sizeof(_authKey));
        memset(_transportKey, 0, sizeof(_transportKey));
    }

    prefs.end();
    return _initialized;
}

bool MeshManager::storeKeys() {
    Preferences prefs;
    if (!prefs.begin("mesh", false)) return false;

    bool ok = true;
    ok = ok && prefs.putBytes("mesh_auth_key", _authKey, sizeof(_authKey)) == sizeof(_authKey);
    ok = ok && prefs.putBytes("mesh_trans_key", _transportKey, sizeof(_transportKey)) == sizeof(_transportKey);
    ok = ok && prefs.putBool("mesh_init", true) == 1;
    prefs.putString("mesh_key_id", _keyId);
    prefs.putString("mesh_node_id", _nodeId);
    prefs.end();
    return ok;
}

bool MeshManager::clearKeys() {
    Preferences prefs;
    if (!prefs.begin("mesh", false)) return false;

    prefs.remove("mesh_auth_key");
    prefs.remove("mesh_trans_key");
    prefs.remove("mesh_init");
    prefs.remove("mesh_key_id");
    prefs.remove("mesh_session_id");
    prefs.end();

    memset(_authKey, 0, sizeof(_authKey));
    memset(_transportKey, 0, sizeof(_transportKey));
    _keyId[0] = '\0';
    _initialized = false;
    return true;
}

// ── Radio lifecycle ──────────────────────────────────────────────────────────

bool MeshManager::startRadio() {
    if (_espNowActive) return true;

    esp_wifi_start();
    esp_err_t err = esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) {
        sendError("channel", esp_err_to_name(err));
        return false;
    }

    err = esp_now_init();
    if (err != ESP_OK) {
        sendError("espnow_init", esp_err_to_name(err));
        return false;
    }

    err = esp_now_register_recv_cb(espNowRecvCallback);
    if (err != ESP_OK) {
        esp_now_deinit();
        sendError("espnow_cb", esp_err_to_name(err));
        return false;
    }

    esp_now_peer_info_t peer = {};
    memcpy(peer.peer_addr, BROADCAST_MAC, 6);
    peer.channel = 0;
    peer.ifidx = WIFI_IF_STA;
    peer.encrypt = false;
    err = esp_now_add_peer(&peer);
    if (err != ESP_OK) {
        esp_now_unregister_recv_cb();
        esp_now_deinit();
        sendError("espnow_peer", esp_err_to_name(err));
        return false;
    }

    _espNowActive = true;
    return true;
}

void MeshManager::stopRadio() {
    if (!_espNowActive) return;
    esp_now_del_peer(BROADCAST_MAC);
    esp_now_unregister_recv_cb();
    esp_now_deinit();
    _espNowActive = false;
}

// ── Authentication / activation commands ─────────────────────────────────────

void MeshManager::handleCommand(uint8_t id, JsonDocument& doc) {
    const char* cmd = doc["cmd"] | "";
    JsonVariant args = doc["args"];

    if (strcmp(cmd, "MESH_PROVISION_KEY") == 0) {
        const char* authB64 = args["auth_key"] | "";
        const char* transportB64 = args["transport_key"] | "";
        const char* keyId = args["key_id"] | "";

        uint8_t auth[32];
        uint8_t transport[32];
        size_t authLen = 0;
        size_t transportLen = 0;

        if (!base64Decode(authB64, auth, sizeof(auth), &authLen) ||
            !base64Decode(transportB64, transport, sizeof(transport), &transportLen) ||
            authLen != sizeof(auth) ||
            transportLen != sizeof(transport)) {
            sendResp(id, false, "expected 32-byte base64 auth_key and transport_key");
            return;
        }

        stop();
        memcpy(_authKey, auth, sizeof(_authKey));
        memcpy(_transportKey, transport, sizeof(_transportKey));
        strncpy(_keyId, keyId, sizeof(_keyId) - 1);
        _keyId[sizeof(_keyId) - 1] = '\0';
        _initialized = true;
        _lastAuthMs = 0;

        if (!storeKeys()) {
            _initialized = false;
            sendResp(id, false, "nvs write failed");
            return;
        }

        sendStatusEvent("provisioned");
        sendResp(id, true);
        return;
    }

    if (strcmp(cmd, "MESH_CLEAR_KEY") == 0) {
        stop();
        clearKeys();
        clearPeerTable();
        _lastAuthMs = 0;
        sendStatusEvent("cleared");
        sendResp(id, true);
        return;
    }

    if (strcmp(cmd, "MESH_AUTH_CHALLENGE") == 0) {
        if (!_initialized) {
            sendResp(id, false, "mesh not initialized");
            return;
        }

        const char* nonceB64 = args["nonce"] | "";
        uint8_t nonce[64];
        size_t nonceLen = 0;
        if (!base64Decode(nonceB64, nonce, sizeof(nonce), &nonceLen) || nonceLen == 0) {
            sendResp(id, false, "invalid nonce");
            return;
        }

        uint8_t hmac[32];
        const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        if (!md || mbedtls_md_hmac(md, _authKey, sizeof(_authKey),
                                   nonce, nonceLen, hmac) != 0) {
            sendResp(id, false, "hmac failed");
            return;
        }

        char hmacB64[64];
        if (!base64Encode(hmac, sizeof(hmac), hmacB64, sizeof(hmacB64))) {
            sendResp(id, false, "base64 failed");
            return;
        }

        _lastAuthMs = millis();

        JsonDocument resp;
        resp["ok"] = true;
        resp["node_id"] = _nodeId;
        resp["hmac"] = hmacB64;
        String json;
        serializeJson(resp, json);
        _proto->sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
        return;
    }

    if (strcmp(cmd, "MESH_STATUS") == 0) {
        JsonDocument resp;
        resp["ok"] = true;
        appendStatusJson(resp);
        String json;
        serializeJson(resp, json);
        _proto->sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
        return;
    }

    if (strcmp(cmd, "MESH_ACTIVATE") == 0) {
        if (!_initialized) {
            sendResp(id, false, "mesh not initialized");
            return;
        }
        if (_lastAuthMs == 0 || millis() - _lastAuthMs > AUTH_WINDOW_MS) {
            sendResp(id, false, "authentication required");
            return;
        }

        stop();
        if (!activate()) {
            sendResp(id, false, "could not start esp-now");
            return;
        }

        JsonDocument resp;
        resp["ok"] = true;
        resp["role"] = "candidate";
        String json;
        serializeJson(resp, json);
        _proto->sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
        return;
    }

    if (strcmp(cmd, "MESH_DEACTIVATE") == 0) {
        stop();
        sendResp(id, true);
        return;
    }

    sendResp(id, false, "unknown mesh command");
}

void MeshManager::sendResp(uint8_t id, bool ok, const char* msg) {
    if (_proto) _proto->sendResp(id, ok, msg);
}

// ── Election state machine ───────────────────────────────────────────────────

bool MeshManager::activate() {
    if (!_initialized) return false;
    if (ESP.getFreeHeap() < MIN_FREE_HEAP_BYTES) {
        sendError("heap", "insufficient free heap for mesh radio");
        return false;
    }
    if (!startRadio()) {
        _role = ROLE_DISABLED;
        return false;
    }

    _role = ROLE_CANDIDATE;
    _candidateSinceMs = millis();
    _electionTs = _candidateSinceMs ? _candidateSinceMs : 1;
    _sessionId = 0;
    _counter = 0;
    _seq = 0;
    _lastBroadcastMs = 0;
    _lastJoinMs = 0;
    _lastMasterSeenMs = 0;
    _masterNodeHash = 0;
    _masterBootId = 0;
    sendStatusEvent("candidate");
    return true;
}

void MeshManager::becomeMaster() {
    _role = ROLE_MASTER;
    _sessionId = randomSessionId();
    _counter = 0;
    _seq = 0;
    _lastBroadcastMs = 0;
    _lastPeerSweepMs = 0;
    _masterNodeHash = _nodeHash;
    _masterBootId = _bootId;

    // Preserve replay counters across sessions, but do not count clients from
    // a previous master session as online after this node is elected master.
    for (size_t i = 0; i < REPLAY_SLOTS; i++) {
        if (_peers[i].used && _peers[i].role == ROLE_CLIENT &&
            _peers[i].sessionId != _sessionId) {
            _peers[i].role = OFFLINE_ROLE;
        }
    }

    sendActivationResult(true);
    sendStatusEvent("master");
    sendHeartbeat();
}

void MeshManager::adoptMaster(const PeerEntry& master) {
    const bool wasCandidate = (_role == ROLE_CANDIDATE);
    _role = ROLE_CLIENT;
    _sessionId = master.sessionId;
    _masterNodeHash = master.nodeHash;
    _masterBootId = master.bootId;
    _lastMasterSeenMs = millis();
    _lastJoinMs = 0;

    if (wasCandidate) {
        sendActivationResult(true, "joined existing master");
    }
    sendStatusEvent("client");
}

void MeshManager::demoteToClient(const PeerEntry& master) {
    _role = ROLE_CLIENT;
    _sessionId = master.sessionId;
    _masterNodeHash = master.nodeHash;
    _masterBootId = master.bootId;
    _lastMasterSeenMs = millis();
    _lastJoinMs = 0;
    _electionTs = 0;

    sendActivationResult(false, "another master won election");
    sendStatusEvent("demoted");
    sendHeartbeatEvent(master, master.lastRssi, 0, 0);
}

// ── Packet send/receive ──────────────────────────────────────────────────────

void MeshManager::sendHeartbeat() {
    if (_role != ROLE_MASTER) return;

    _counter++;
    if (_counter == 0) _counter = 1;
    _seq++;

    uint8_t packet[MAX_PACKET_LEN];
    size_t packetLen = 0;
    if (!encryptPacket(PKT_HEARTBEAT, ROLE_MASTER, _sessionId, _counter,
                       millis(), _seq, _electionTs,
                       (const uint8_t*)_chipName, strlen(_chipName),
                       packet, sizeof(packet), &packetLen)) {
        sendError("encrypt", "heartbeat encode failed");
        return;
    }

    esp_err_t err = esp_now_send(BROADCAST_MAC, packet, packetLen);
    if (err != ESP_OK) {
        sendError("send", esp_err_to_name(err));
        return;
    }

    _lastBroadcastMs = millis();

    PeerEntry self = {};
    self.used = true;
    self.nodeHash = _nodeHash;
    self.bootId = _bootId;
    self.sessionId = _sessionId;
    self.lastSeenMs = millis();
    strncpy(self.nodeId, _nodeId, sizeof(self.nodeId) - 1);
    strncpy(self.chip, _chipName, sizeof(self.chip) - 1);
    self.role = ROLE_MASTER;
    sendHeartbeatEvent(self, 0, millis(), _seq);
}

void MeshManager::sendJoin() {
    if (_role != ROLE_CLIENT) return;

    _counter++;
    if (_counter == 0) _counter = 1;
    _seq++;

    uint8_t packet[MAX_PACKET_LEN];
    size_t packetLen = 0;
    if (!encryptPacket(PKT_JOIN, ROLE_CLIENT, _sessionId, _counter,
                       millis(), _seq, 0,
                       (const uint8_t*)_chipName, strlen(_chipName),
                       packet, sizeof(packet), &packetLen)) {
        sendError("encrypt", "join encode failed");
        return;
    }

    esp_now_send(BROADCAST_MAC, packet, packetLen);
    _lastJoinMs = millis();
}

void MeshManager::espNowRecvCallback(const esp_now_recv_info_t* info,
                                     const uint8_t* data, int len) {
    if (!_instance || !info || !info->src_addr || !data || len <= 0) return;
    const int8_t rssi = info->rx_ctrl ? (int8_t)info->rx_ctrl->rssi : 0;
    _instance->handlePacket(info->src_addr, data, len, rssi);
}

void MeshManager::handlePacket(const uint8_t* srcMac, const uint8_t* data, int len, int8_t rssi) {
    (void)srcMac;
    if (len < (int)(HEADER_LEN + BODY_HEADER_LEN + TAG_LEN)) return;

    uint8_t type = 0;
    uint32_t sessionId = 0;
    uint32_t counter = 0;
    uint32_t nodeHash = 0;
    uint32_t bootId = 0;
    uint8_t role = 0;
    uint32_t uptimeMs = 0;
    uint32_t seq = 0;
    uint32_t electionTs = 0;
    char nodeId[11] = {0};
    char chip[16] = {0};
    if (!decodePacket(data, len, &type, &sessionId, &counter, &nodeHash,
                      &bootId, &role, &uptimeMs, &seq, &electionTs,
                      nodeId, chip)) {
        return;
    }

    if (nodeHash == _nodeHash) return;

    if (type == PKT_HEARTBEAT) {
        if (role != ROLE_MASTER) return;

        bool firstSeen = false;
        if (!authenticateAndTrack(nodeHash, bootId, sessionId, counter, nodeId,
                                  chip, role, rssi, &firstSeen)) {
            return;
        }

        PeerEntry* master = findPeer(nodeHash);
        if (!master) return;

        if (_role == ROLE_MASTER) {
            const bool otherWins =
                (electionTs < _electionTs) ||
                (electionTs == _electionTs && nodeHash < _nodeHash);
            if (otherWins) {
                demoteToClient(*master);
            }
            return;
        }

        if (_role == ROLE_CANDIDATE || _role == ROLE_IDLE || _role == ROLE_CLIENT) {
            const bool sessionChanged = (_role != ROLE_CLIENT) || (_sessionId != master->sessionId);
            adoptMaster(*master);
            if (sessionChanged) {
                sendStatusEvent("session_locked");
            }
            sendHeartbeatEvent(*master, rssi, uptimeMs, seq);
        }
        return;
    }

    if (type == PKT_JOIN) {
        if (_role != ROLE_MASTER || sessionId != _sessionId) return;

        bool firstSeen = false;
        if (!authenticateAndTrack(nodeHash, bootId, sessionId, counter, nodeId,
                                  chip, role, rssi, &firstSeen)) {
            return;
        }

        PeerEntry* peer = findPeer(nodeHash);
        if (!peer || peer->role != ROLE_CLIENT) return;

        if (firstSeen) {
            sendNodeJoinedEvent(*peer, rssi);
            sendStatusEvent("node_joined");
        }
        return;
    }

    if (type == PKT_LEAVE) {
        if (_role != ROLE_MASTER || sessionId != _sessionId) return;
        PeerEntry* peer = findPeer(nodeHash);
        if (peer && peer->used) {
            sendNodeLeftEvent(*peer, "left");
            peer->role = OFFLINE_ROLE;
            sendStatusEvent("node_left");
        }
    }
}

bool MeshManager::decodePacket(const uint8_t* data, int len, uint8_t* type,
                               uint32_t* sessionId, uint32_t* counter,
                               uint32_t* nodeHash, uint32_t* bootId,
                               uint8_t* role, uint32_t* uptimeMs, uint32_t* seq,
                               uint32_t* electionTs, char nodeIdOut[11],
                               char chipOut[16]) {
    if (data[0] != MESH_PROTOCOL_VERSION) return false;

    const uint8_t ptype = data[1];
    if (ptype != PKT_HEARTBEAT && ptype != PKT_JOIN && ptype != PKT_LEAVE) return false;

    const uint32_t psession = readU32(data + 4);
    const uint32_t pcounter = readU32(data + 8);
    const uint32_t pnodeHash = readU32(data + 12);
    const uint32_t pbootId = readU32(data + 16);

    const size_t cipherLen = (size_t)len - HEADER_LEN - TAG_LEN;
    if (cipherLen < BODY_HEADER_LEN || cipherLen > BODY_HEADER_LEN + MAX_PAYLOAD_LEN) {
        return false;
    }

    uint8_t aad[HEADER_LEN];
    memcpy(aad, data, sizeof(aad));

    uint8_t nonce[NONCE_LEN];
    writeU32(nonce, psession);
    writeU32(nonce + 4, pcounter);
    writeU32(nonce + 8, pnodeHash ^ pbootId);

    uint8_t plain[BODY_HEADER_LEN + MAX_PAYLOAD_LEN];
    mbedtls_ccm_context ctx;
    mbedtls_ccm_init(&ctx);
    const int rc = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
                                      _transportKey, 256);
    int decryptRc = -1;
    if (rc == 0) {
        decryptRc = mbedtls_ccm_auth_decrypt(
            &ctx,
            cipherLen,
            nonce, sizeof(nonce),
            aad, sizeof(aad),
            data + HEADER_LEN,
            plain,
            data + len - TAG_LEN,
            TAG_LEN
        );
    }
    mbedtls_ccm_free(&ctx);
    if (decryptRc != 0) return false;

    if (plain[0] != MESH_PROTOCOL_VERSION) return false;
    if (plain[1] != ptype) return false;
    const uint8_t prole = plain[2];
    if (prole != ROLE_MASTER && prole != ROLE_CLIENT) return false;
    if (readU32(plain + 4) != psession) return false;
    if (readU32(plain + 8) != pcounter) return false;
    if (readU32(plain + 12) != pnodeHash) return false;
    if (readU32(plain + 16) != pbootId) return false;

    const uint8_t payloadLen = plain[43];
    if ((size_t)payloadLen + BODY_HEADER_LEN != cipherLen) return false;

    char tempNodeId[11];
    memcpy(tempNodeId, plain + 32, 10);
    tempNodeId[10] = '\0';

    char tempChip[16] = {0};
    if (payloadLen > 0) {
        const size_t chipLen = min((size_t)payloadLen, MAX_CHIP_LEN);
        memcpy(tempChip, plain + BODY_HEADER_LEN, chipLen);
        tempChip[chipLen] = '\0';
    }

    *type = ptype;
    *sessionId = psession;
    *counter = pcounter;
    *nodeHash = pnodeHash;
    *bootId = pbootId;
    *role = prole;
    *uptimeMs = readU32(plain + 20);
    *seq = readU32(plain + 24);
    *electionTs = readU32(plain + 28);
    memcpy(nodeIdOut, tempNodeId, 11);
    memcpy(chipOut, tempChip, 16);
    return true;
}

bool MeshManager::encryptPacket(uint8_t type, uint8_t role, uint32_t sessionId,
                                uint32_t counter, uint32_t uptimeMs, uint32_t seq,
                                uint32_t electionTs, const uint8_t* payload,
                                size_t payloadLen, uint8_t* out, size_t outCap,
                                size_t* outLen) {
    if (!out || !outLen || payloadLen > MAX_PAYLOAD_LEN) return false;
    const size_t bodyLen = BODY_HEADER_LEN + payloadLen;
    const size_t totalLen = HEADER_LEN + bodyLen + TAG_LEN;
    if (outCap < totalLen) return false;

    uint8_t header[HEADER_LEN];
    header[0] = MESH_PROTOCOL_VERSION;
    header[1] = type;
    header[2] = 0;
    header[3] = 0;
    writeU32(header + 4, sessionId);
    writeU32(header + 8, counter);
    writeU32(header + 12, _nodeHash);
    writeU32(header + 16, _bootId);

    uint8_t body[BODY_HEADER_LEN + MAX_PAYLOAD_LEN];
    body[0] = MESH_PROTOCOL_VERSION;
    body[1] = type;
    body[2] = role;
    body[3] = 0;
    writeU32(body + 4, sessionId);
    writeU32(body + 8, counter);
    writeU32(body + 12, _nodeHash);
    writeU32(body + 16, _bootId);
    writeU32(body + 20, uptimeMs);
    writeU32(body + 24, seq);
    writeU32(body + 28, electionTs);
    memcpy(body + 32, _nodeId, 10);
    body[42] = 0;
    body[43] = (uint8_t)payloadLen;
    if (payloadLen > 0 && payload) {
        memcpy(body + BODY_HEADER_LEN, payload, payloadLen);
    }

    uint8_t nonce[NONCE_LEN];
    writeU32(nonce, sessionId);
    writeU32(nonce + 4, counter);
    writeU32(nonce + 8, _nodeHash ^ _bootId);

    mbedtls_ccm_context ctx;
    mbedtls_ccm_init(&ctx);
    int rc = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
                                _transportKey, 256);
    if (rc == 0) {
        memcpy(out, header, HEADER_LEN);
        rc = mbedtls_ccm_encrypt_and_tag(
            &ctx,
            bodyLen,
            nonce, sizeof(nonce),
            header, sizeof(header),
            body,
            out + HEADER_LEN,
            out + HEADER_LEN + bodyLen,
            TAG_LEN
        );
    }
    mbedtls_ccm_free(&ctx);
    if (rc != 0) return false;

    *outLen = totalLen;
    return true;
}

// ── Replay/peer table ────────────────────────────────────────────────────────

MeshManager::PeerEntry* MeshManager::findPeer(uint32_t nodeHash) {
    for (size_t i = 0; i < REPLAY_SLOTS; i++) {
        if (_peers[i].used && _peers[i].nodeHash == nodeHash) {
            return &_peers[i];
        }
    }
    return nullptr;
}

MeshManager::PeerEntry* MeshManager::allocPeer() {
    for (size_t i = 0; i < REPLAY_SLOTS; i++) {
        if (!_peers[i].used) return &_peers[i];
    }
    return nullptr;
}

bool MeshManager::authenticateAndTrack(uint32_t nodeHash, uint32_t bootId,
                                       uint32_t sessionId, uint32_t counter,
                                       const char nodeId[11],
                                       const char chip[16],
                                       uint8_t role, int8_t rssi,
                                       bool* firstSeen) {
    PeerEntry* entry = findPeer(nodeHash);
    const bool newPeer = (entry == nullptr) || !entry->used;
    const bool rebooted = (!newPeer && entry->bootId != bootId);
    const bool wasOffline = (!newPeer && entry->role == OFFLINE_ROLE);

    if (newPeer) {
        entry = allocPeer();
        if (!entry) return false;
        entry->used = true;
        entry->nodeHash = nodeHash;
        entry->lastCounter = 0;
        entry->bootId = bootId;
    } else if (rebooted) {
        entry->lastCounter = 0;
        entry->bootId = bootId;
    }

    if (counter <= entry->lastCounter) return false;

    entry->sessionId = sessionId;
    entry->lastCounter = counter;
    entry->lastSeenMs = millis();
    entry->role = role;
    entry->lastRssi = rssi;
    strncpy(entry->nodeId, nodeId, sizeof(entry->nodeId) - 1);
    entry->nodeId[sizeof(entry->nodeId) - 1] = '\0';
    if (chip && chip[0]) {
        strncpy(entry->chip, chip, sizeof(entry->chip) - 1);
        entry->chip[sizeof(entry->chip) - 1] = '\0';
    }

    if (firstSeen) *firstSeen = newPeer || rebooted || wasOffline;
    return true;
}

void MeshManager::sweepPeers(uint32_t now) {
    for (size_t i = 0; i < REPLAY_SLOTS; i++) {
        PeerEntry& peer = _peers[i];
        if (!peer.used) continue;
        if (peer.role == ROLE_CLIENT &&
            now - peer.lastSeenMs > PEER_TIMEOUT_MS) {
            sendNodeLeftEvent(peer, "timeout");
            peer.role = OFFLINE_ROLE;
            sendStatusEvent("node_timeout");
        }
    }
}

void MeshManager::clearPeerTable() {
    memset(_peers, 0, sizeof(_peers));
}

// ── USB event helpers ────────────────────────────────────────────────────────

void MeshManager::sendStatusEvent(const char* reason) {
    if (!_proto) return;
    JsonDocument doc;
    appendStatusJson(doc);
    if (reason) doc["reason"] = reason;
    _proto->sendEvent("mesh_status", doc);
}

void MeshManager::sendActivationResult(bool ok, const char* reason) {
    if (!_proto) return;
    JsonDocument doc;
    doc["ok"] = ok;
    doc["role"] = roleName();
    if (_sessionId != 0) doc["session_id"] = _sessionId;
    if (reason) doc["reason"] = reason;
    _proto->sendEvent("mesh_activation_result", doc);
}

void MeshManager::sendError(const char* code, const char* msg) {
    if (!_proto) return;
    JsonDocument doc;
    doc["code"] = code ? code : "mesh_error";
    doc["msg"] = msg ? msg : "";
    _proto->sendEvent("mesh_error", doc);
}

void MeshManager::sendHeartbeatEvent(const PeerEntry& peer, int8_t rssi,
                                     uint32_t uptimeMs, uint32_t seq) {
    if (!_proto) return;
    const char* peerRole = "unknown";
    if (peer.role == ROLE_MASTER) peerRole = "master";
    else if (peer.role == ROLE_CLIENT) peerRole = "client";

    JsonDocument doc;
    doc["node_id"] = peer.nodeId;
    if (peer.chip[0]) doc["chip"] = peer.chip;
    doc["role"] = peerRole;
    doc["session_id"] = peer.sessionId;
    doc["uptime_ms"] = uptimeMs;
    doc["seq"] = seq;
    doc["rssi"] = rssi;
    _proto->sendEvent("mesh_heartbeat", doc);
}

void MeshManager::sendNodeJoinedEvent(const PeerEntry& peer, int8_t rssi) {
    if (!_proto) return;
    JsonDocument doc;
    doc["node_id"] = peer.nodeId;
    if (peer.chip[0]) doc["chip"] = peer.chip;
    doc["session_id"] = _sessionId;
    doc["rssi"] = rssi;
    _proto->sendEvent("mesh_node_joined", doc);
}

void MeshManager::sendNodeLeftEvent(const PeerEntry& peer, const char* reason) {
    if (!_proto) return;
    JsonDocument doc;
    doc["node_id"] = peer.nodeId;
    doc["session_id"] = _sessionId;
    doc["reason"] = reason ? reason : "timeout";
    _proto->sendEvent("mesh_node_left", doc);
}

void MeshManager::appendStatusJson(JsonDocument& doc) const {
    doc["initialized"] = _initialized;
    doc["role"] = roleName();
    if (_sessionId != 0) doc["session_id"] = _sessionId;
    doc["node_id"] = _nodeId;
    doc["peer_count"] = peerCount();
    doc["active"] = active();

    // Authoritative peer snapshot. The app uses this to rebuild its node list
    // after a clear/refresh, since mesh_node_joined is only emitted once per
    // online transition.
    JsonArray peers = doc["peers"].to<JsonArray>();
    const uint32_t now = millis();
    for (size_t i = 0; i < REPLAY_SLOTS; i++) {
        const PeerEntry& peer = _peers[i];
        if (!peer.used || peer.role == OFFLINE_ROLE) continue;

        JsonObject item = peers.add<JsonObject>();
        item["node_id"] = peer.nodeId;
        if (peer.chip[0]) item["chip"] = peer.chip;
        item["role"] = (peer.role == ROLE_MASTER) ? "master" : "client";
        if (peer.sessionId != 0) item["session_id"] = peer.sessionId;
        const uint32_t timeoutMs = (peer.role == ROLE_MASTER)
            ? MASTER_TIMEOUT_MS
            : PEER_TIMEOUT_MS;
        item["online"] = (now - peer.lastSeenMs) <= timeoutMs;
        item["rssi"] = peer.lastRssi;
        item["last_seen_ms"] = now - peer.lastSeenMs;
    }
}

// ── Utility helpers ──────────────────────────────────────────────────────────

uint32_t MeshManager::randomSessionId() {
    uint32_t value = esp_random() & 0x7FFFFFFF;
    return value ? value : 1;
}

uint32_t MeshManager::hashNodeId(const char* nodeId) {
    uint32_t hash = 2166136261u;
    if (nodeId) {
        while (*nodeId) {
            hash ^= (uint8_t)(*nodeId++);
            hash *= 16777619u;
        }
    }
    return hash ? hash : 1;
}

void MeshManager::writeU32(uint8_t* out, uint32_t value) {
    out[0] = (uint8_t)(value & 0xFF);
    out[1] = (uint8_t)((value >> 8) & 0xFF);
    out[2] = (uint8_t)((value >> 16) & 0xFF);
    out[3] = (uint8_t)((value >> 24) & 0xFF);
}

uint32_t MeshManager::readU32(const uint8_t* in) {
    return (uint32_t)in[0]
         | ((uint32_t)in[1] << 8)
         | ((uint32_t)in[2] << 16)
         | ((uint32_t)in[3] << 24);
}

bool MeshManager::base64Decode(const char* input, uint8_t* out, size_t outCap, size_t* outLen) {
    if (!input || !out || !outLen) return false;
    size_t len = strlen(input);
    int ret = mbedtls_base64_decode(out, outCap, outLen,
                                    (const unsigned char*)input, len);
    return ret == 0;
}

bool MeshManager::base64Encode(const uint8_t* input, size_t inputLen, char* out, size_t outCap) {
    if (!input || !out || outCap == 0) return false;
    size_t written = 0;
    int ret = mbedtls_base64_encode((unsigned char*)out, outCap, &written, input, inputLen);
    if (ret != 0 || written >= outCap) return false;
    out[written] = '\0';
    return true;
}
