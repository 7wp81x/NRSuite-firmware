#pragma once

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include "BridgeProtocol.h"

#define DEAUTH_DETECT_QUEUE_DEPTH 24

struct DeauthDetectConfig {
    bool     hop = false;
    uint8_t  channel = 1;
    uint16_t intervalMs = 300;
    bool     hasBssid = false;
    uint8_t  bssid[6] = {0};
    bool     hasClient = false;
    uint8_t  client[6] = {0};
    int8_t   rssiMin = -127;
};

struct DeauthDetectStats {
    uint32_t detected = 0;
    uint32_t sent = 0;
    uint32_t dropped = 0;
};

class DeauthDetector {
public:
    void begin(BridgeProtocol& proto);
    static DeauthDetector* instance() { return _instance; }

    bool start(const DeauthDetectConfig& config);
    void stop();
    void update();

    bool                active()  const { return _active; }
    bool                hopping() const { return _hopMode; }
    uint8_t             channel() const { return _channel; }
    DeauthDetectStats   stats()   const { return _stats; }

private:
    struct Alert {
        uint8_t  subtype;
        uint8_t  channel;
        int8_t   rssi;
        uint16_t reason;
        uint32_t uptimeMs;
        uint8_t  client[6];
        uint8_t  source[6];
        uint8_t  bssid[6];
    };

    BridgeProtocol* _proto = nullptr;
    QueueHandle_t   _queue = nullptr;

    volatile bool   _active = false;
    bool            _hopMode = false;
    uint8_t         _channel = 1;
    uint16_t        _hopIntervalMs = 300;
    uint32_t        _lastHopMs = 0;

    DeauthDetectConfig _config;
    DeauthDetectStats  _stats;

    static DeauthDetector* _instance;
    static void promiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type);
    void handlePacket(wifi_promiscuous_pkt_t* pkt);
    bool matchesFilters(const uint8_t* dst, const uint8_t* src, const uint8_t* bssid) const;
    static void macToString(const uint8_t* mac, char* out);
};
