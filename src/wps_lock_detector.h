#pragma once

#include <Arduino.h>
#include <esp_wifi.h>
#include "BridgeProtocol.h"

class WpsLockDetector {
public:
    void begin(BridgeProtocol& proto);
    int scan(bool include5ghz, uint16_t dwellMs);

private:
    struct ApRecord {
        bool used = false;
        char ssid[33] = {};
        uint8_t bssid[6] = {};
        uint8_t channel = 0;
        int8_t rssi = -127;
        char security[12] = "OPEN";
        bool wpsParsed = false;
        bool lockReported = false;
        bool locked = false;
        uint8_t wpsVersion = 0;
        uint16_t configMethods = 0;
        bool selectedRegistrar = false;
        uint32_t lastSeenMs = 0;
    };

    static WpsLockDetector* instance_;
    static void promiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type);

    BridgeProtocol* proto_ = nullptr;
    ApRecord records_[64];
    size_t recordCount_ = 0;
    uint8_t currentChannel_ = 0;

    void handlePacket(const wifi_promiscuous_pkt_t* pkt);
    void upsert(const ApRecord& record);
};
