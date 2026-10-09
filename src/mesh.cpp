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
    loadChannel();
    _scanChannel = _channel;

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
            _scanChannel = _channel;
            _lastScanHopMs = millis();
            _idleListenUntilMs = millis() + MESH_INITIAL_LISTEN_MS;
        }
    }
}

void MeshManager::update() {
    if (!_initialized || !_espNowActive) return;

    const uint32_t now = millis();

    if (_role == ROLE_MASTER) {
        sweepDetectorControl(now);
    }

    // A client detector window owns the radio. Do not let mesh heartbeats,
    // joins, recovery scans, or channel switches touch the radio while the
    // detector is scanning off the mesh channel.
    if (_detectorWindowActive) return;

    if (_role == ROLE_CANDIDATE) {
        // Before becoming a second master, search the configured channel and
        // then the recovery channel list for an existing master.
        if (_lastScanHopMs == 0 ||
            now - _lastScanHopMs >= MESH_SCAN_DWELL_MS) {
            const uint8_t next = nextRecoveryChannel();
            const esp_err_t err = esp_wifi_set_channel(next, WIFI_SECOND_CHAN_NONE);
            if (err == ESP_OK) {
                _scanChannel = next;
            }
            _lastScanHopMs = now;
        }

        if (now - _candidateSinceMs >= CANDIDATE_DISCOVERY_TIMEOUT_MS) {
            // No master answered during a full discovery pass. Return to the
            // configured channel and start normal master election there.
            setChannel(_channel, false);
            _scanChannel = _channel;
            _lastScanHopMs = 0;
            becomeMaster();
        }
    }

    if (_role == ROLE_IDLE && _initialized && _espNowActive) {
        const bool initialListen = (_idleListenUntilMs != 0 && now < _idleListenUntilMs);
        if (initialListen) {
            // Stay on the last known channel long enough to catch at least one
            // master heartbeat before starting a full recovery sweep.
        } else if (_lastScanHopMs == 0 || now - _lastScanHopMs >= MESH_SCAN_DWELL_MS) {
            _idleListenUntilMs = 0;
            const uint8_t next = nextRecoveryChannel();
            esp_err_t err = esp_wifi_set_channel(next, WIFI_SECOND_CHAN_NONE);
            if (err == ESP_OK) {
                _scanChannel = next;
            }
            _lastScanHopMs = now;
        }
    }

    if (_role == ROLE_MASTER) {
        if (_channelSwitchActive) {
            if (!_channelSwitchCommitSent) {
                if (channelSwitchAllAcked()) {
                    sendChannelSwitchPacket(2);
                    sendChannelSwitchEvent("commit", "all_acked");
                    _channelSwitchCommitSent = true;
                    _switchAtMs = now + CHANNEL_SWITCH_COMMIT_DELAY_MS;
                    _lastChannelSwitchTxMs = now;
                } else if (now >= _channelSwitchDeadlineMs) {
                    sendChannelSwitchPacket(2);
                    sendChannelSwitchEvent("commit", "ack_timeout");
                    _channelSwitchCommitSent = true;
                    _switchAtMs = now + CHANNEL_SWITCH_COMMIT_DELAY_MS;
                    _lastChannelSwitchTxMs = now;
                } else if (_lastChannelSwitchTxMs == 0 ||
                           now - _lastChannelSwitchTxMs >= CHANNEL_SWITCH_REPEAT_MS) {
                    sendChannelSwitchPacket(1);
                    _lastChannelSwitchTxMs = now;
                }
            } else if (now >= _switchAtMs) {
                setChannel(_channelSwitchTarget, true);
                _lastHealthMs = 0;
                _fastHeartbeatUntilMs = now + FAST_HEARTBEAT_WINDOW_MS;
                sendChannelSwitchEvent("committed");
                sendStatusEvent("channel_switched");
                clearChannelSwitchState();
                sendHeartbeat();
            } else if (now - _lastChannelSwitchTxMs >= CHANNEL_SWITCH_COMMIT_REPEAT_MS) {
                sendChannelSwitchPacket(2);
                _lastChannelSwitchTxMs = now;
            }
        }

        const bool fastHeartbeat =
            _fastHeartbeatUntilMs != 0 && now < _fastHeartbeatUntilMs;
        if (_lastBroadcastMs == 0 ||
            now - _lastBroadcastMs >=
                (fastHeartbeat ? FAST_HEARTBEAT_INTERVAL_MS : HEARTBEAT_INTERVAL_MS)) {
            sendHeartbeat();
        }
        if (_fastHeartbeatUntilMs != 0 && now >= _fastHeartbeatUntilMs) {
            _fastHeartbeatUntilMs = 0;
        }
        if (_lastPeerSweepMs == 0 ||
            now - _lastPeerSweepMs >= 1000) {
            sweepPeers(now);
            _lastPeerSweepMs = now;
        }
    }

    if (_role == ROLE_CLIENT) {
        // If the commit packet was missed, fall back to switching after the
        // request ACK timeout. This keeps a client that heard the request from
        // being stranded on the old channel forever.
        if (_pendingChannel == 0 &&
            _clientSwitchRequestTarget != 0 &&
            now >= _clientSwitchRequestDeadlineMs) {
            _pendingChannel = _clientSwitchRequestTarget;
            _switchAtMs = now + CHANNEL_SWITCH_COMMIT_DELAY_MS;
            _clientHoldChannelUntilMs = now + CHANNEL_SWITCH_HOLD_MS;
            _clientSwitchRequestTarget = 0;
            _clientSwitchRequestDeadlineMs = 0;
            sendStatusEvent("channel_switch_fallback");
        }
        if (_pendingChannel != 0 && now >= _switchAtMs) {
            // Do not persist the candidate switch channel yet. It is saved
            // only when a master heartbeat is successfully adopted again.
            setChannel(_pendingChannel, false);
            _pendingChannel = 0;
            _switchAtMs = 0;
            _lastMasterSeenMs = now;
            _lastJoinMs = 0;
            _lastHealthMs = 0;
            _clientHoldChannelUntilMs = now + CHANNEL_SWITCH_HOLD_MS;
            sendStatusEvent("channel_switched");
        }
        if (_lastMasterSeenMs != 0 &&
            now - _lastMasterSeenMs > MASTER_TIMEOUT_MS) {
            if (_clientHoldChannelUntilMs != 0 && now < _clientHoldChannelUntilMs) {
                // Stay on the committed channel for the hold period and keep
                // trying to reach the master. Do not start recovery hopping yet.
            } else {
                _clientHoldChannelUntilMs = 0;
                _role = ROLE_IDLE;
                _sessionId = 0;
                _lastJoinMs = 0;
                _pendingChannel = 0;
                _switchAtMs = 0;
                _clientSwitchRequestTarget = 0;
                _clientSwitchRequestDeadlineMs = 0;
                _scanChannel = _channel;
                _lastScanHopMs = now;
                _idleListenUntilMs = now + MESH_INITIAL_LISTEN_MS;
                sendStatusEvent("master_timeout");
                return;
            }
        }
        if (_lastJoinMs == 0 || now - _lastJoinMs >= JOIN_INTERVAL_MS) {
            sendJoin();
        }
        if (_lastHealthMs == 0 || now - _lastHealthMs >= NODE_HEALTH_INTERVAL_MS) {
            _lastHealthMs = now;
            uint8_t health[MAX_SENSOR_DATA_LEN];
            const size_t healthLen = buildNodeHealthPayload(health, sizeof(health));
            if (healthLen > 0) {
                enqueueSensorReport(REPORT_KIND_NODE_HEALTH, health, healthLen, true);
            }
        }
        if (_lastSensorSendMs == 0 ||
            now - _lastSensorSendMs >= SENSOR_SEND_INTERVAL_MS) {
            sendQueuedSensorReports(now);
        }
    }

    if (_role == ROLE_MASTER) {
        if (_lastHealthMs == 0 || now - _lastHealthMs >= NODE_HEALTH_INTERVAL_MS) {
            _lastHealthMs = now;
            sendNodeHealthReport();
        }
    }
}

void MeshManager::stop() {
    const bool wasActive = (_role != ROLE_DISABLED);
    if (_detectorRadioActive) {
        esp_wifi_set_promiscuous(false);
        _detectorRadioActive = false;
    }
    _detectorWindowActive = false;
    _detectorControlPending = false;
    _detectorControlRetriesLeft = 0;
    _detectorControlNextSendMs = 0;
    stopRadio();
    _role = ROLE_DISABLED;
    _sessionId = 0;
    _counter = 0;
    _lastBroadcastMs = 0;
    _lastJoinMs = 0;
    _lastMasterSeenMs = 0;
    _masterNodeHash = 0;
    _masterBootId = 0;
    _idleListenUntilMs = 0;
    _fastHeartbeatUntilMs = 0;
    _clientSwitchRequestTarget = 0;
    _clientSwitchRequestDeadlineMs = 0;
    clearChannelSwitchState();
    _clientHoldChannelUntilMs = 0;
    clearSensorQueue();
    _lastHealthMs = 0;
    _lastSensorSendMs = 0;

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
    esp_err_t err = esp_wifi_set_channel(_channel, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) {
        // A persisted channel may be regulatory-unavailable on this build
        // (commonly 12-13). Fall back to a safe channel instead of leaving
        // the node permanently disabled.
        sendError("channel", esp_err_to_name(err));
        _channel = 1;
        _scanChannel = 1;
        err = esp_wifi_set_channel(_channel, WIFI_SECOND_CHAN_NONE);
        if (err != ESP_OK) {
            sendError("channel", esp_err_to_name(err));
            return false;
        }
        storeChannel();
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
        const uint8_t requestedChannel = args["channel"] | _channel;

        if (requestedChannel < 1 || requestedChannel > 13) {
            sendResp(id, false, "channel must be 1-13");
            return;
        }

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
        setChannel(requestedChannel, true);
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

    if (strcmp(cmd, "MESH_SET_CHANNEL") == 0) {
        const uint8_t channel = args["channel"] | 0;
        if (channel < 1 || channel > 13) {
            sendResp(id, false, "channel must be 1-13");
            return;
        }

        if (_role == ROLE_MASTER && _espNowActive) {
            startChannelSwitch(channel);
            sendResp(id, true, "channel switch initiated");
        } else {
            setChannel(channel, true);
            sendStatusEvent("channel_saved");
            sendResp(id, true, "channel saved");
        }
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
    _lastScanHopMs = millis();
    _scanChannel = _channel;
    _masterNodeHash = 0;
    _masterBootId = 0;
    clearSensorQueue();
    _lastHealthMs = 0;
    _lastSensorSendMs = 0;
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
    _lastHealthMs = 0;
    _lastSensorSendMs = 0;
    _fastHeartbeatUntilMs = millis() + FAST_HEARTBEAT_WINDOW_MS;
    clearSensorQueue();
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
    const bool sessionChanged = (_role != ROLE_CLIENT) || (_sessionId != master.sessionId);
    _role = ROLE_CLIENT;
    _sessionId = master.sessionId;
    if (_scanChannel >= 1 && _scanChannel <= 13) {
        _channel = _scanChannel;
        storeChannel();
    }
    _pendingChannel = 0;
    _switchAtMs = 0;
    _clientHoldChannelUntilMs = 0;
    _clientSwitchRequestTarget = 0;
    _clientSwitchRequestDeadlineMs = 0;
    _idleListenUntilMs = 0;
    _fastHeartbeatUntilMs = 0;
    _masterNodeHash = master.nodeHash;
    _masterBootId = master.bootId;
    _lastMasterSeenMs = millis();
    _lastJoinMs = 0;

    // A master heartbeat arrives every second. Do not reset report/health
    // state on every heartbeat; only clear it when the session actually
    // changes.
    if (sessionChanged) {
        clearSensorQueue();
        _lastHealthMs = 0;
        _lastSensorSendMs = 0;
    }

    if (wasCandidate) {
        sendActivationResult(true, "joined existing master");
    }
    if (sessionChanged) {
        sendStatusEvent("client");
    }
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
    uint8_t payloadData[MAX_PAYLOAD_LEN] = {0};
    size_t payloadLen = 0;
    if (!decodePacket(data, len, &type, &sessionId, &counter, &nodeHash,
                      &bootId, &role, &uptimeMs, &seq, &electionTs,
                      nodeId, chip, payloadData, sizeof(payloadData), &payloadLen)) {
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

    if (type == PKT_DETECTOR_CONTROL) {
        if (role != ROLE_MASTER || sessionId != _sessionId) return;
        bool firstSeen = false;
        if (!authenticateAndTrack(nodeHash, bootId, sessionId, counter, nodeId,
                                  chip, role, rssi, &firstSeen)) {
            return;
        }
        handleDetectorControl(payloadData, payloadLen);
        return;
    }

    if (type == PKT_SENSOR_REPORT) {
        if (_role != ROLE_MASTER || sessionId != _sessionId) return;
        if (role != ROLE_CLIENT) return;
        if (payloadLen < 1) return;

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

        const uint8_t kind = payloadData[0];
        sendSensorReportEvent(*peer, kind, payloadData + 1, payloadLen - 1, rssi, seq);
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
        return;
    }

    if (type == PKT_CHANNEL_SWITCH) {
        if (role != ROLE_MASTER) return;
        bool firstSeen = false;
        if (!authenticateAndTrack(nodeHash, bootId, sessionId, counter, nodeId,
                                  chip, role, rssi, &firstSeen)) {
            return;
        }
        handleChannelSwitchPacket(payloadData, payloadLen);
        return;
    }

    if (type == PKT_CHANNEL_SWITCH_ACK) {
        if (_role != ROLE_MASTER || sessionId != _sessionId) return;
        if (role != ROLE_CLIENT) return;
        bool firstSeen = false;
        if (!authenticateAndTrack(nodeHash, bootId, sessionId, counter, nodeId,
                                  chip, role, rssi, &firstSeen)) {
            return;
        }
        handleChannelSwitchAckPacket(payloadData, payloadLen, nodeHash);
        return;
    }
}

bool MeshManager::decodePacket(const uint8_t* data, int len, uint8_t* type,
                               uint32_t* sessionId, uint32_t* counter,
                               uint32_t* nodeHash, uint32_t* bootId,
                               uint8_t* role, uint32_t* uptimeMs, uint32_t* seq,
                               uint32_t* electionTs, char nodeIdOut[11],
                               char chipOut[16], uint8_t* payloadOut,
                               size_t payloadCap, size_t* payloadLenOut) {
    if (data[0] != MESH_PROTOCOL_VERSION) return false;

    const uint8_t ptype = data[1];
    if (ptype != PKT_HEARTBEAT && ptype != PKT_JOIN && ptype != PKT_LEAVE &&
        ptype != PKT_CHANNEL_SWITCH && ptype != PKT_SENSOR_REPORT &&
        ptype != PKT_DETECTOR_CONTROL && ptype != PKT_CHANNEL_SWITCH_ACK) return false;

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
    if ((ptype == PKT_HEARTBEAT || ptype == PKT_JOIN) && payloadLen > 0) {
        const size_t chipLen = min((size_t)payloadLen, MAX_CHIP_LEN);
        memcpy(tempChip, plain + BODY_HEADER_LEN, chipLen);
        tempChip[chipLen] = '\0';
    }

    if (payloadLenOut) *payloadLenOut = payloadLen;
    if (payloadOut && payloadCap > 0 && payloadLen > 0) {
        const size_t copyLen = min((size_t)payloadLen, payloadCap);
        memcpy(payloadOut, plain + BODY_HEADER_LEN, copyLen);
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

// ── Phase 3A sensor reports ────────────────────────────────────────────────

void MeshManager::clearSensorQueue() {
    memset(_sensorQueue, 0, sizeof(_sensorQueue));
}

bool MeshManager::enqueueSensorReport(uint8_t kind, const uint8_t* data,
                                       size_t len, bool latestOnly,
                                       uint32_t seq) {
    if (len > MAX_SENSOR_DATA_LEN) return false;
    if (seq == 0) seq = nextSensorSeq();

    if (latestOnly) {
        for (size_t i = 0; i < SENSOR_QUEUE_SLOTS; i++) {
            if (_sensorQueue[i].used && _sensorQueue[i].kind == kind) {
                _sensorQueue[i].used = false;
            }
        }
    }

    SensorReport* slot = nullptr;
    for (size_t i = 0; i < SENSOR_QUEUE_SLOTS; i++) {
        if (!_sensorQueue[i].used) {
            slot = &_sensorQueue[i];
            break;
        }
    }

    if (!slot) {
        // Queue full: replace the oldest entry.
        uint32_t oldest = UINT32_MAX;
        for (size_t i = 0; i < SENSOR_QUEUE_SLOTS; i++) {
            if (_sensorQueue[i].queuedMs < oldest) {
                oldest = _sensorQueue[i].queuedMs;
                slot = &_sensorQueue[i];
            }
        }
    }
    if (!slot) return false;

    slot->used = true;
    slot->kind = kind;
    slot->len = (uint8_t)len;
    slot->sends = 0;
    slot->seq = seq;
    slot->queuedMs = millis();
    if (len > 0 && data) {
        memcpy(slot->data, data, len);
    }
    return true;
}

uint32_t MeshManager::nextSensorSeq() {
    _sensorSeq++;
    if (_sensorSeq == 0) _sensorSeq = 1;
    return _sensorSeq;
}

void MeshManager::sendQueuedSensorReports(uint32_t now) {
    _lastSensorSendMs = now;
    if (!_espNowActive || _role != ROLE_CLIENT || _sessionId == 0) return;

    for (size_t i = 0; i < SENSOR_QUEUE_SLOTS; i++) {
        SensorReport& report = _sensorQueue[i];
        if (!report.used) continue;

        _counter++;
        if (_counter == 0) _counter = 1;

        uint8_t payload[1 + MAX_SENSOR_DATA_LEN];
        payload[0] = report.kind;
        if (report.len > 0) {
            memcpy(payload + 1, report.data, report.len);
        }

        uint8_t packet[MAX_PACKET_LEN];
        size_t packetLen = 0;
        if (!encryptPacket(PKT_SENSOR_REPORT, ROLE_CLIENT, _sessionId, _counter,
                           millis(), report.seq, 0,
                           payload, (size_t)report.len + 1,
                           packet, sizeof(packet), &packetLen)) {
            sendError("encrypt", "sensor report encode failed");
            _lastSensorSendMs = now;
            return;
        }

        const esp_err_t err = esp_now_send(BROADCAST_MAC, packet, packetLen);
        if (err != ESP_OK) {
            sendError("send", esp_err_to_name(err));
            _lastSensorSendMs = now;
            return;
        }

        // Deauth observations are retried with the same stable seq so the
        // Android app can dedupe them. Health reports remain latest-only.
        if (report.kind == REPORT_KIND_DEAUTH) {
            report.sends++;
            if (report.sends < 3) {
                report.queuedMs = now;
            } else {
                report.used = false;
            }
        } else {
            report.used = false;
        }
        _lastSensorSendMs = now;
        return;
    }
}

size_t MeshManager::buildNodeHealthPayload(uint8_t* out, size_t outCap) const {
    if (!out || outCap < 10) return 0;
    writeU32(out, millis());
    writeU32(out + 4, (uint32_t)ESP.getFreeHeap());
    out[8] = _channel;
    out[9] = _role;
    return 10;
}

void MeshManager::sendNodeHealthReport() {
    if (!_proto || _role != ROLE_MASTER || _sessionId == 0) return;

    uint8_t health[10];
    const size_t healthLen = buildNodeHealthPayload(health, sizeof(health));
    if (healthLen == 0) return;

    PeerEntry self = {};
    self.used = true;
    self.nodeHash = _nodeHash;
    self.bootId = _bootId;
    self.sessionId = _sessionId;
    self.lastSeenMs = millis();
    self.role = ROLE_MASTER;
    self.lastRssi = 0;
    strncpy(self.nodeId, _nodeId, sizeof(self.nodeId) - 1);
    strncpy(self.chip, _chipName, sizeof(self.chip) - 1);

    sendSensorReportEvent(self, REPORT_KIND_NODE_HEALTH, health, healthLen, 0, _seq);
}

const char* MeshManager::reportKindName(uint8_t kind) {
    switch (kind) {
        case REPORT_KIND_NODE_HEALTH: return "node_health";
        case REPORT_KIND_DEAUTH:      return "deauth";
        default:                      return "unknown";
    }
}

void MeshManager::sendSensorReportEvent(const PeerEntry& peer, uint8_t kind,
                                        const uint8_t* data, size_t len,
                                        int8_t rssi, uint32_t seq) {
    if (!_proto) return;

    JsonDocument doc;
    doc["node_id"] = peer.nodeId;
    if (peer.chip[0]) doc["chip"] = peer.chip;
    doc["role"] = (peer.role == ROLE_MASTER) ? "master" : "client";
    if (peer.sessionId != 0) doc["session_id"] = peer.sessionId;
    doc["kind"] = reportKindName(kind);
    doc["seq"] = seq;
    doc["rssi"] = rssi;
    doc["channel"] = _channel;

    if (kind == REPORT_KIND_NODE_HEALTH && len >= 10) {
        doc["uptime_ms"] = readU32(data);
        doc["heap"] = readU32(data + 4);
        doc["channel"] = data[8];
        doc["role"] = (data[9] == ROLE_MASTER) ? "master" : "client";
    } else if (kind == REPORT_KIND_DEAUTH && len >= 16) {
        const uint16_t reason = (uint16_t)data[0] | ((uint16_t)data[1] << 8);
        char source[18];
        char target[18];
        snprintf(source, sizeof(source), "%02X:%02X:%02X:%02X:%02X:%02X",
                 data[4], data[5], data[6], data[7], data[8], data[9]);
        snprintf(target, sizeof(target), "%02X:%02X:%02X:%02X:%02X:%02X",
                 data[10], data[11], data[12], data[13], data[14], data[15]);
        doc["reason"] = reason;
        doc["channel"] = data[2];
        doc["rssi"] = (int8_t)data[3];
        doc["source"] = source;
        doc["target"] = target;
    } else if (len > 0 && data) {
        char encoded[192];
        if (base64Encode(data, len, encoded, sizeof(encoded))) {
            doc["data_b64"] = encoded;
            doc["data_len"] = (uint32_t)len;
        }
    }

    _proto->sendEvent("mesh_sensor_report", doc);
}

// ── Phase 3B detector control ──────────────────────────────────────────────

bool MeshManager::enqueueDeauthReport(uint16_t reason, uint8_t channel,
                                      int8_t rssi, const uint8_t* source,
                                      const uint8_t* target) {
    if (!source || !target || !_espNowActive || _sessionId == 0) return false;

    uint8_t payload[16] = {0};
    payload[0] = (uint8_t)(reason & 0xFF);
    payload[1] = (uint8_t)((reason >> 8) & 0xFF);
    payload[2] = channel;
    payload[3] = (uint8_t)rssi;
    memcpy(payload + 4, source, 6);
    memcpy(payload + 10, target, 6);

    if (_role == ROLE_MASTER) {
        PeerEntry self = {};
        self.used = true;
        self.nodeHash = _nodeHash;
        self.bootId = _bootId;
        self.sessionId = _sessionId;
        self.lastSeenMs = millis();
        self.role = ROLE_MASTER;
        self.lastRssi = 0;
        strncpy(self.nodeId, _nodeId, sizeof(self.nodeId) - 1);
        strncpy(self.chip, _chipName, sizeof(self.chip) - 1);
        sendSensorReportEvent(self, REPORT_KIND_DEAUTH, payload, sizeof(payload),
                              0, nextSensorSeq());
        return true;
    }

    if (_role != ROLE_CLIENT) return false;
    return enqueueSensorReport(REPORT_KIND_DEAUTH, payload, sizeof(payload), false);
}

bool MeshManager::enterDetectorWindow(uint8_t channel, bool pauseMesh) {
    if (!_espNowActive) return false;
    if (channel < 1 || channel > 13) return false;

    _detectorWindowActive = pauseMesh;
    _detectorRadioActive = true;
    const esp_err_t err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) {
        _detectorWindowActive = false;
        _detectorRadioActive = false;
        return false;
    }
    esp_wifi_set_promiscuous(true);
    return true;
}

bool MeshManager::setDetectorWindowChannel(uint8_t channel) {
    if (!_espNowActive || !_detectorWindowActive) return false;
    if (channel < 1 || channel > 13) return false;
    return esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE) == ESP_OK;
}

void MeshManager::exitDetectorWindow() {
    _detectorWindowActive = false;
    _detectorRadioActive = false;
    esp_wifi_set_promiscuous(false);
    if (_espNowActive) {
        esp_wifi_set_channel(_channel, WIFI_SECOND_CHAN_NONE);
    }
}

void MeshManager::sendDetectorControl(bool start, uint8_t mode, uint8_t channel,
                                      uint16_t meshWindowMs,
                                      uint16_t detectorWindowMs,
                                      uint16_t hopDwellMs) {
    if (!_espNowActive || _role != ROLE_MASTER || _sessionId == 0) return;

    uint8_t payload[9];
    payload[0] = start ? 1 : 0;
    payload[1] = mode;
    payload[2] = channel;
    payload[3] = (uint8_t)(meshWindowMs & 0xFF);
    payload[4] = (uint8_t)((meshWindowMs >> 8) & 0xFF);
    payload[5] = (uint8_t)(detectorWindowMs & 0xFF);
    payload[6] = (uint8_t)((detectorWindowMs >> 8) & 0xFF);
    payload[7] = (uint8_t)(hopDwellMs & 0xFF);
    payload[8] = (uint8_t)((hopDwellMs >> 8) & 0xFF);

    _counter++;
    if (_counter == 0) _counter = 1;
    _seq++;

    uint8_t packet[MAX_PACKET_LEN];
    size_t packetLen = 0;
    if (!encryptPacket(PKT_DETECTOR_CONTROL, ROLE_MASTER, _sessionId, _counter,
                       millis(), _seq, 0, payload, sizeof(payload),
                       packet, sizeof(packet), &packetLen)) {
        sendError("encrypt", "detector control encode failed");
        return;
    }
    esp_now_send(BROADCAST_MAC, packet, packetLen);
}

bool MeshManager::beginDistributedDetector(bool start, uint8_t mode,
                                           uint8_t channel,
                                           uint16_t meshWindowMs,
                                           uint16_t detectorWindowMs,
                                           uint16_t hopDwellMs) {
    if (!_espNowActive || _role != ROLE_MASTER || _sessionId == 0) return false;

    _detectorControlStart = start;
    _detectorControlMode = mode;
    _detectorControlChannel = channel;
    _detectorControlMeshWindowMs = meshWindowMs;
    _detectorControlDetectorWindowMs = detectorWindowMs;
    _detectorControlHopDwellMs = hopDwellMs;
    _detectorControlRetriesLeft = 5;
    _detectorControlNextSendMs = 0;
    _detectorControlPending = true;

    sendDetectorControl(start, mode, channel, meshWindowMs, detectorWindowMs,
                        hopDwellMs);
    return true;
}

void MeshManager::sweepDetectorControl(uint32_t now) {
    if (!_detectorControlPending) return;
    if (_role != ROLE_MASTER || !_espNowActive || _sessionId == 0) {
        _detectorControlPending = false;
        return;
    }
    if (_detectorControlNextSendMs != 0 && now < _detectorControlNextSendMs) return;

    sendDetectorControl(_detectorControlStart, _detectorControlMode,
                        _detectorControlChannel, _detectorControlMeshWindowMs,
                        _detectorControlDetectorWindowMs,
                        _detectorControlHopDwellMs);
    if (_detectorControlRetriesLeft > 0) _detectorControlRetriesLeft--;
    if (_detectorControlRetriesLeft == 0) {
        _detectorControlPending = false;
        _detectorControlNextSendMs = 0;
    } else {
        _detectorControlNextSendMs = now + 700;
    }
}

void MeshManager::handleDetectorControl(const uint8_t* data, size_t len) {
    if (!data || len < 9) return;
    const bool start = data[0] != 0;
    const uint8_t mode = data[1];
    if (mode > 2) return;
    const uint8_t channel = data[2];
    if (channel < 1 || channel > 13) return;
    const uint16_t meshWindowMs = (uint16_t)data[3] | ((uint16_t)data[4] << 8);
    const uint16_t detectorWindowMs = (uint16_t)data[5] | ((uint16_t)data[6] << 8);
    const uint16_t hopDwellMs = (uint16_t)data[7] | ((uint16_t)data[8] << 8);
    if (detectorWindowMs < 300 || detectorWindowMs > 2500) return;
    if (meshWindowMs < 2000 || meshWindowMs > 10000) return;
    if (hopDwellMs < 200 || hopDwellMs > 1000) return;
    if (_detectorControlCallback) {
        _detectorControlCallback(start, mode, channel, meshWindowMs,
                                 detectorWindowMs, hopDwellMs);
    }
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
    doc["channel"] = _channel;
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
    doc["channel"] = _channel;
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
    doc["channel"] = _channel;
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

// ── Channel management / recovery ────────────────────────────────────────────

bool MeshManager::loadChannel() {
    Preferences prefs;
    if (!prefs.begin("mesh", true)) return false;
    const uint8_t stored = prefs.getUChar("mesh_channel", 1);
    prefs.end();
    _channel = (stored >= 1 && stored <= 13) ? stored : 1;
    _scanChannel = _channel;
    return true;
}

bool MeshManager::storeChannel() {
    Preferences prefs;
    if (!prefs.begin("mesh", false)) return false;
    const size_t written = prefs.putUChar("mesh_channel", _channel);
    prefs.end();
    return written == 1;
}

bool MeshManager::setChannel(uint8_t channel, bool persist) {
    if (channel < 1 || channel > 13) return false;

    const uint8_t previousChannel = _channel;
    if (_espNowActive) {
        const esp_err_t err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        if (err != ESP_OK) {
            sendError("channel", esp_err_to_name(err));
            _channel = previousChannel;
            _scanChannel = previousChannel;
            return false;
        }
    }

    _channel = channel;
    _scanChannel = channel;
    if (persist) {
        storeChannel();
    }
    return true;
}

uint8_t MeshManager::nextRecoveryChannel() {
    if (_scanChannel < 1 || _scanChannel > 13) {
        _scanChannel = 1;
    } else if (_scanChannel >= 13) {
        _scanChannel = 1;
    } else {
        _scanChannel++;
    }
    return _scanChannel;
}

void MeshManager::clearChannelSwitchState() {
    _channelSwitchActive = false;
    _channelSwitchCommitSent = false;
    _channelSwitchTarget = 0;
    _channelSwitchId = 0;
    _channelSwitchDeadlineMs = 0;
    _lastChannelSwitchTxMs = 0;
    _channelSwitchAckCount = 0;
    memset(_channelSwitchAckHashes, 0, sizeof(_channelSwitchAckHashes));
    _pendingChannel = 0;
    _switchAtMs = 0;
    _lastSwitchPacketMs = 0;
}

void MeshManager::startChannelSwitch(uint8_t targetChannel) {
    if (targetChannel < 1 || targetChannel > 13) return;
    if (targetChannel == _channel) return;
    if (_channelSwitchActive) return;

    _channelSwitchActive = true;
    _channelSwitchCommitSent = false;
    _channelSwitchTarget = targetChannel;
    _channelSwitchId = esp_random() ? esp_random() : 1;
    _channelSwitchDeadlineMs = millis() + CHANNEL_SWITCH_ACK_TIMEOUT_MS;
    _lastChannelSwitchTxMs = 0;
    _channelSwitchAckCount = 0;
    memset(_channelSwitchAckHashes, 0, sizeof(_channelSwitchAckHashes));
    _pendingChannel = targetChannel;
    _switchAtMs = 0;
    _lastSwitchPacketMs = 0;

    sendStatusEvent("channel_switch_pending");
    sendChannelSwitchPacket(1);
    sendChannelSwitchEvent("request");
    _lastChannelSwitchTxMs = millis();
}

void MeshManager::sendChannelSwitchPacket(uint8_t phase) {
    if (!_espNowActive || _role != ROLE_MASTER || _sessionId == 0) return;
    if (_channelSwitchTarget < 1 || _channelSwitchTarget > 13) return;

    uint8_t payload[6];
    payload[0] = phase;
    payload[1] = _channelSwitchTarget;
    writeU32(payload + 2, _channelSwitchId);

    _counter++;
    if (_counter == 0) _counter = 1;
    _seq++;

    uint8_t packet[MAX_PACKET_LEN];
    size_t packetLen = 0;
    if (!encryptPacket(PKT_CHANNEL_SWITCH, ROLE_MASTER, _sessionId, _counter,
                       millis(), _seq, 0, payload, sizeof(payload),
                       packet, sizeof(packet), &packetLen)) {
        sendError("encrypt", "channel switch encode failed");
        return;
    }
    esp_now_send(BROADCAST_MAC, packet, packetLen);
}

void MeshManager::sendChannelSwitchAck(uint8_t targetChannel, uint32_t switchId) {
    if (!_espNowActive || _role != ROLE_CLIENT || _sessionId == 0) return;
    if (targetChannel < 1 || targetChannel > 13) return;

    uint8_t payload[5];
    payload[0] = targetChannel;
    writeU32(payload + 1, switchId);

    _counter++;
    if (_counter == 0) _counter = 1;
    _seq++;

    uint8_t packet[MAX_PACKET_LEN];
    size_t packetLen = 0;
    if (!encryptPacket(PKT_CHANNEL_SWITCH_ACK, ROLE_CLIENT, _sessionId, _counter,
                       millis(), _seq, 0, payload, sizeof(payload),
                       packet, sizeof(packet), &packetLen)) {
        sendError("encrypt", "channel switch ack encode failed");
        return;
    }
    esp_now_send(BROADCAST_MAC, packet, packetLen);
}

bool MeshManager::channelSwitchAllAcked() const {
    const uint32_t now = millis();
    for (size_t i = 0; i < REPLAY_SLOTS; i++) {
        const PeerEntry& peer = _peers[i];
        if (!peer.used || peer.role != ROLE_CLIENT) continue;
        if (now - peer.lastSeenMs > PEER_TIMEOUT_MS) continue;
        bool acked = false;
        for (size_t j = 0; j < _channelSwitchAckCount; j++) {
            if (_channelSwitchAckHashes[j] == peer.nodeHash) {
                acked = true;
                break;
            }
        }
        if (!acked) return false;
    }
    return true;
}

void MeshManager::markChannelSwitchAck(uint32_t nodeHash) {
    for (size_t i = 0; i < _channelSwitchAckCount; i++) {
        if (_channelSwitchAckHashes[i] == nodeHash) return;
    }
    if (_channelSwitchAckCount < REPLAY_SLOTS) {
        _channelSwitchAckHashes[_channelSwitchAckCount++] = nodeHash;
    }
    sendChannelSwitchEvent("ack");
}

void MeshManager::handleChannelSwitchPacket(const uint8_t* data, size_t len) {
    if (!data || len < 6) return;
    if (_role != ROLE_CLIENT) return;

    const uint8_t phase = data[0];
    const uint8_t targetChannel = data[1];
    const uint32_t switchId = readU32(data + 2);
    if (targetChannel < 1 || targetChannel > 13) return;

    if (phase == 1) {
        // Master request: acknowledge and wait for the commit. If the commit
        // never arrives, switch after the ACK timeout as a fallback.
        _clientSwitchRequestTarget = targetChannel;
        _clientSwitchRequestDeadlineMs =
            millis() + CHANNEL_SWITCH_ACK_TIMEOUT_MS +
            CHANNEL_SWITCH_COMMIT_DELAY_MS;
        sendChannelSwitchAck(targetChannel, switchId);
        sendStatusEvent("channel_switch_ack_sent");
        return;
    }

    if (phase == 2) {
        // Master commit: switch shortly, then hold on the target channel.
        _channelSwitchId = switchId;
        _pendingChannel = targetChannel;
        _switchAtMs = millis() + CHANNEL_SWITCH_COMMIT_DELAY_MS;
        _clientHoldChannelUntilMs = millis() + CHANNEL_SWITCH_HOLD_MS;
        _clientSwitchRequestTarget = 0;
        _clientSwitchRequestDeadlineMs = 0;
        sendStatusEvent("channel_switch_commit");
    }
}

void MeshManager::handleChannelSwitchAckPacket(const uint8_t* data, size_t len,
                                               uint32_t nodeHash) {
    if (!data || len < 5) return;
    if (!_channelSwitchActive) return;
    const uint8_t targetChannel = data[0];
    const uint32_t switchId = readU32(data + 1);
    if (targetChannel != _channelSwitchTarget || switchId != _channelSwitchId) {
        return;
    }
    markChannelSwitchAck(nodeHash);
}

void MeshManager::sendChannelSwitchEvent(const char* phase, const char* reason) {
    if (!_proto || !phase) return;

    JsonDocument doc;
    doc["phase"] = phase;
    doc["channel"] = _channelSwitchTarget;
    doc["switch_id"] = _channelSwitchId;

    JsonArray acked = doc["acked"].to<JsonArray>();
    JsonArray pending = doc["pending"].to<JsonArray>();
    const uint32_t now = millis();
    for (size_t i = 0; i < REPLAY_SLOTS; i++) {
        const PeerEntry& peer = _peers[i];
        if (!peer.used || peer.role != ROLE_CLIENT) continue;
        if (now - peer.lastSeenMs > PEER_TIMEOUT_MS) continue;

        bool isAcked = false;
        for (size_t j = 0; j < _channelSwitchAckCount; j++) {
            if (_channelSwitchAckHashes[j] == peer.nodeHash) {
                isAcked = true;
                break;
            }
        }
        if (isAcked) {
            acked.add(peer.nodeId);
        } else {
            pending.add(peer.nodeId);
        }
    }

    doc["acked_count"] = (uint32_t)acked.size();
    doc["pending_count"] = (uint32_t)pending.size();
    if (reason) doc["reason"] = reason;
    _proto->sendEvent("mesh_channel_switch", doc);
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
