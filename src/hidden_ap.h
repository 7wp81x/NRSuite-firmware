#pragma once

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include "BridgeProtocol.h"

#define HIDDEN_AP_QUEUE_DEPTH 32
#define HIDDEN_AP_CACHE_SIZE 32

struct HiddenApConfig {
    bool     hop = false;
    uint8_t  channel = 1;
    uint16_t intervalMs = 300;
};

struct HiddenApStats {
    uint32_t hiddenSeen = 0;
    uint32_t candidates = 0;
    uint32_t resolved = 0;
    uint32_t sent = 0;
    uint32_t dropped = 0;
};

class HiddenApDetector {
public:
    void begin(BridgeProtocol& proto);
    static HiddenApDetector* instance() { return _instance; }

    bool start(const HiddenApConfig& config);
    void stop();
    void update();

    bool              active()  const { return _active; }
    bool              hopping() const { return _hopMode; }
    uint8_t           channel() const { return _channel; }
    HiddenApStats     stats()   const { return _stats; }

private:
    enum class EventType : uint8_t {
        HIDDEN_AP = 1,
        CANDIDATE = 2,
        RESOLVED = 3,
    };

    struct Event {
        EventType type;
        uint8_t   bssid[6];
        bool      hasBssid;
        uint8_t   client[6];
        bool      hasClient;
        char      ssid[33];
        uint8_t   channel;
        int8_t    rssi;
        uint8_t   subtype;
        uint32_t  uptimeMs;
    };

    BridgeProtocol* _proto = nullptr;
    QueueHandle_t   _queue = nullptr;

    volatile bool   _active = false;
    bool            _hopMode = false;
    uint8_t         _channel = 1;
    uint16_t        _hopIntervalMs = 300;
    uint32_t        _lastHopMs = 0;

    struct HiddenBssidEntry {
        bool     used;
        uint8_t  bssid[6];
        uint32_t lastSeenMs;
    };

    HiddenApConfig    _config;
    HiddenApStats     _stats;
    HiddenBssidEntry  _hiddenCache[HIDDEN_AP_CACHE_SIZE] = {};

    static HiddenApDetector* _instance;
    static void promiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type);
    void handlePacket(wifi_promiscuous_pkt_t* pkt);
    bool emitFromFrame(wifi_promiscuous_pkt_t* pkt, uint8_t subtype);
    void rememberHiddenBssid(const uint8_t* bssid);
    bool isHiddenBssid(const uint8_t* bssid) const;
    static void macToString(const uint8_t* mac, char* out);
};
