#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>
#include "BridgeProtocol.h"
#include "esp_now.h"

// NRSuite Mesh Foundation Phase 1.
//
// Responsibilities:
//   - persist app-derived mesh keys in the dedicated "mesh" NVS namespace
//   - answer the USB auth challenge with HMAC-SHA256(auth_key, nonce)
//   - run a simple ESP-NOW master/client election
//   - encrypt/authenticate mesh packets with mbedTLS AES-CCM
//   - reject replayed packets using a small boot-id + monotonic counter table
//
// The raw passphrase never reaches this class. The Android app derives
// auth_key and transport_key with HKDF-SHA256 and provisions only those keys.
class MeshManager {
public:
    void begin(BridgeProtocol& proto, const char* nodeId, const char* chipName);
    void update();
    void stop();

    void handleCommand(uint8_t id, JsonDocument& doc);

    using DetectorControlCallback = void (*)(bool start, uint8_t mode,
                                             uint8_t channel,
                                             uint16_t meshWindowMs,
                                             uint16_t detectorWindowMs,
                                             uint16_t hopDwellMs);

    void setDetectorControlCallback(DetectorControlCallback cb) {
        _detectorControlCallback = cb;
    }

    bool beginDistributedDetector(bool start, uint8_t mode, uint8_t channel,
                                  uint16_t meshWindowMs,
                                  uint16_t detectorWindowMs,
                                  uint16_t hopDwellMs);
    // Detector-window radio ownership. MeshManager owns the radio while the
    // detector window is active; the scheduler calls these hooks rather than
    // touching esp_wifi_set_channel/promiscuous directly.
    bool enterDetectorWindow(uint8_t channel, bool pauseMesh);
    bool setDetectorWindowChannel(uint8_t channel);
    void exitDetectorWindow();
    bool detectorWindowActive() const { return _detectorRadioActive; }
    uint8_t currentChannel() const { return _channel; }
    bool enqueueDeauthReport(uint16_t reason, uint8_t channel, int8_t rssi,
                             const uint8_t* source, const uint8_t* target);

    bool initialized() const { return _initialized; }
    bool active() const { return _role != ROLE_DISABLED; }
    const char* roleName() const;
    uint32_t peerCount() const;

private:
    enum Role : uint8_t {
        ROLE_DISABLED = 0,
        ROLE_IDLE = 1,
        ROLE_CANDIDATE = 2,
        ROLE_MASTER = 3,
        ROLE_CLIENT = 4,
    };

    struct PeerEntry {
        bool     used;
        uint32_t nodeHash;
        uint32_t bootId;
        uint32_t sessionId;
        uint32_t lastCounter;
        uint32_t lastSeenMs;
        char     nodeId[11];
        char     chip[16];
        uint8_t  role;
        int8_t   lastRssi;
    };

    static const uint8_t  MESH_PROTOCOL_VERSION = 1;
    static const uint8_t  PKT_HEARTBEAT = 1;
    static const uint8_t  PKT_JOIN      = 2;
    static const uint8_t  PKT_LEAVE     = 3;
    static const uint8_t  PKT_CHANNEL_SWITCH = 4;
    static const uint8_t  PKT_SENSOR_REPORT  = 5;
    static const uint8_t  PKT_DETECTOR_CONTROL = 6;
    static const uint8_t  PKT_CHANNEL_SWITCH_ACK = 7;

    static const uint8_t  REPORT_KIND_NODE_HEALTH = 1;
    static const uint8_t  REPORT_KIND_DEAUTH      = 2;

    static const size_t   HEADER_LEN    = 20;  // version,type,rsvd,session,counter,nodeHash,bootId
    static const size_t   TAG_LEN       = 16;  // AES-CCM tag
    static const size_t   NONCE_LEN     = 12;  // session || counter || nodeHash
    static const size_t   BODY_HEADER_LEN = 44; // includes node id + payload-length byte
    static const size_t   MAX_PAYLOAD_LEN = 96;
    static const size_t   MAX_CHIP_LEN    = 15;
    static const size_t   MAX_PACKET_LEN = HEADER_LEN + BODY_HEADER_LEN + MAX_PAYLOAD_LEN + TAG_LEN;
    static const size_t   REPLAY_SLOTS  = 12;

    static const size_t   SENSOR_QUEUE_SLOTS = 6;
    static const size_t   MAX_SENSOR_DATA_LEN = 64;

    struct SensorReport {
        bool     used;
        uint8_t  kind;
        uint8_t  len;
        uint8_t  sends;
        uint8_t  data[MAX_SENSOR_DATA_LEN];
        uint32_t seq;
        uint32_t queuedMs;
    };

    static const uint32_t ELECTION_WINDOW_MS   = 1200;
    static const uint32_t CANDIDATE_DISCOVERY_TIMEOUT_MS = 7000;
    static const uint32_t HEARTBEAT_INTERVAL_MS = 1000;
    static const uint32_t MASTER_TIMEOUT_MS    = 5000;
    static const uint32_t JOIN_INTERVAL_MS     = 2000;
    static const uint32_t PEER_TIMEOUT_MS      = 8000;
    static const uint32_t AUTH_WINDOW_MS       = 30000;
    static const uint32_t MIN_FREE_HEAP_BYTES  = 40000;
    static const uint32_t MESH_SCAN_DWELL_MS   = 500;
    static const uint32_t CHANNEL_SWITCH_DELAY_MS = 3000;
    static const uint32_t CHANNEL_SWITCH_ACK_TIMEOUT_MS = 3000;
    static const uint32_t CHANNEL_SWITCH_COMMIT_DELAY_MS = 500;
    static const uint32_t CHANNEL_SWITCH_HOLD_MS = 60000;
    static const uint16_t CHANNEL_SWITCH_REPEAT_MS = 500;
    static const uint16_t CHANNEL_SWITCH_COMMIT_REPEAT_MS = 400;
    static const uint32_t NODE_HEALTH_INTERVAL_MS = 5000;
    static const uint32_t SENSOR_SEND_INTERVAL_MS = 1000;

    BridgeProtocol* _proto = nullptr;
    static MeshManager* _instance;

    char     _nodeId[11] = {0};
    char     _chipName[16] = {0};
    uint32_t _nodeHash = 0;
    uint32_t _bootId = 0;

    bool     _initialized = false;
    uint8_t  _authKey[32] = {0};
    uint8_t  _transportKey[32] = {0};
    char     _keyId[33] = {0};

    Role     _role = ROLE_DISABLED;
    bool     _espNowActive = false;
    uint32_t _sessionId = 0;
    uint32_t _counter = 0;
    uint32_t _seq = 0;
    uint32_t _electionTs = 0;
    uint32_t _candidateSinceMs = 0;
    uint32_t _lastBroadcastMs = 0;
    uint32_t _lastJoinMs = 0;
    uint32_t _lastMasterSeenMs = 0;
    uint32_t _lastAuthMs = 0;
    uint32_t _masterNodeHash = 0;
    uint32_t _masterBootId = 0;
    uint32_t _lastPeerSweepMs = 0;

    uint8_t  _channel = 1;
    uint8_t  _scanChannel = 1;
    uint8_t  _pendingChannel = 0;
    uint32_t _lastScanHopMs = 0;
    uint32_t _switchAtMs = 0;
    uint32_t _lastSwitchPacketMs = 0;
    bool     _channelSwitchActive = false;
    bool     _channelSwitchCommitSent = false;
    uint8_t  _channelSwitchTarget = 0;
    uint32_t _channelSwitchId = 0;
    uint32_t _channelSwitchDeadlineMs = 0;
    uint32_t _lastChannelSwitchTxMs = 0;
    uint32_t _channelSwitchAckHashes[REPLAY_SLOTS] = {};
    uint8_t  _channelSwitchAckCount = 0;
    uint32_t _clientHoldChannelUntilMs = 0;

    PeerEntry _peers[REPLAY_SLOTS] = {};

    SensorReport _sensorQueue[SENSOR_QUEUE_SLOTS] = {};
    uint32_t _lastHealthMs = 0;
    uint32_t _lastSensorSendMs = 0;
    uint32_t _sensorSeq = 0;
    DetectorControlCallback _detectorControlCallback = nullptr;
    bool     _detectorWindowActive = false;   // true while mesh updates are paused
    bool     _detectorRadioActive = false;    // true whenever promiscuous RX is on
    bool     _detectorControlPending = false;
    bool     _detectorControlStart = false;
    uint8_t  _detectorControlMode = 1;  // 0=same_channel, 1=fixed, 2=hop
    uint8_t  _detectorControlChannel = 1;
    uint16_t _detectorControlMeshWindowMs = 4500;
    uint16_t _detectorControlDetectorWindowMs = 1500;
    uint16_t _detectorControlHopDwellMs = 350;
    uint8_t  _detectorControlRetriesLeft = 0;
    uint32_t _detectorControlNextSendMs = 0;

    bool loadKeys();
    bool storeKeys();
    bool loadChannel();
    bool storeChannel();
    bool setChannel(uint8_t channel, bool persist);
    uint8_t nextRecoveryChannel();
    void startChannelSwitch(uint8_t targetChannel);
    void clearChannelSwitchState();
    void sendChannelSwitchPacket(uint8_t phase);
    void sendChannelSwitchAck(uint8_t targetChannel, uint32_t switchId);
    bool channelSwitchAllAcked() const;
    void markChannelSwitchAck(uint32_t nodeHash);
    void handleChannelSwitchPacket(const uint8_t* data, size_t len);
    void handleChannelSwitchAckPacket(const uint8_t* data, size_t len,
                                      uint32_t nodeHash);
    void sendChannelSwitchEvent(const char* phase, const char* reason = nullptr);
    bool clearKeys();
    bool startRadio();
    void stopRadio();

    bool activate();
    void becomeMaster();
    void adoptMaster(const PeerEntry& master);
    void demoteToClient(const PeerEntry& master);
    void sendHeartbeat();
    void sendJoin();

    void handlePacket(const uint8_t* srcMac, const uint8_t* data, int len, int8_t rssi);
    bool decodePacket(const uint8_t* data, int len, uint8_t* type,
                      uint32_t* sessionId, uint32_t* counter, uint32_t* nodeHash,
                      uint32_t* bootId, uint8_t* role, uint32_t* uptimeMs,
                      uint32_t* seq, uint32_t* electionTs,
                      char nodeIdOut[11], char chipOut[16],
                      uint8_t* payloadOut, size_t payloadCap, size_t* payloadLenOut);
    bool encryptPacket(uint8_t type, uint8_t role, uint32_t sessionId,
                       uint32_t counter, uint32_t uptimeMs, uint32_t seq,
                       uint32_t electionTs, const uint8_t* payload,
                       size_t payloadLen, uint8_t* out, size_t outCap,
                       size_t* outLen);
    bool authenticateAndTrack(uint32_t nodeHash, uint32_t bootId, uint32_t sessionId,
                              uint32_t counter, const char nodeId[11],
                              const char chip[16], uint8_t role, int8_t rssi,
                              bool* firstSeen);
    PeerEntry* findPeer(uint32_t nodeHash);
    PeerEntry* allocPeer();
    void sweepPeers(uint32_t now);
    void clearPeerTable();

    bool enqueueSensorReport(uint8_t kind, const uint8_t* data, size_t len,
                             bool latestOnly, uint32_t seq = 0);
    void sendQueuedSensorReports(uint32_t now);
    void sendNodeHealthReport();
    void clearSensorQueue();
    void sendSensorReportEvent(const PeerEntry& peer, uint8_t kind,
                               const uint8_t* data, size_t len,
                               int8_t rssi, uint32_t seq);
    size_t buildNodeHealthPayload(uint8_t* out, size_t outCap) const;
    static const char* reportKindName(uint8_t kind);
    uint32_t nextSensorSeq();
    void sendDetectorControl(bool start, uint8_t mode, uint8_t channel,
                             uint16_t meshWindowMs, uint16_t detectorWindowMs,
                             uint16_t hopDwellMs);
    void handleDetectorControl(const uint8_t* data, size_t len);
    void sweepDetectorControl(uint32_t now);

    void sendResp(uint8_t id, bool ok, const char* msg = nullptr);
    void sendStatusEvent(const char* reason = nullptr);
    void sendActivationResult(bool ok, const char* reason = nullptr);
    void sendError(const char* code, const char* msg);
    void sendHeartbeatEvent(const PeerEntry& peer, int8_t rssi, uint32_t uptimeMs = 0, uint32_t seq = 0);
    void sendNodeJoinedEvent(const PeerEntry& peer, int8_t rssi);
    void sendNodeLeftEvent(const PeerEntry& peer, const char* reason);
    void appendStatusJson(JsonDocument& doc) const;

    uint32_t randomSessionId();
    static uint32_t hashNodeId(const char* nodeId);
    static void writeU32(uint8_t* out, uint32_t value);
    static uint32_t readU32(const uint8_t* in);
    static bool base64Decode(const char* input, uint8_t* out, size_t outCap, size_t* outLen);
    static bool base64Encode(const uint8_t* input, size_t inputLen, char* out, size_t outCap);

    static void espNowRecvCallback(const esp_now_recv_info_t* info, const uint8_t* data, int len);
};
