#pragma once

#include <Arduino.h>
#include <esp_wifi.h>
#include "BridgeProtocol.h"

class WpsAttemptDetector {
public:
    void begin(BridgeProtocol& proto);
    bool start(
        const uint8_t* channels,
        size_t channelCount,
        const uint8_t* targetBssids,
        size_t targetCount,
        uint16_t hopIntervalMs,
        bool include5ghz
    );
    void stop();
    void update();

    bool active() const { return active_; }
    bool hopping() const { return hopping_; }
    uint8_t channel() const { return channel_; }
    uint16_t sessionCount() const { return sessionCount_; }
    uint32_t frameCount() const { return frameCount_; }

private:
    struct Session {
        bool used = false;
        uint32_t id = 0;
        uint8_t bssid[6] = {};
        uint8_t client[6] = {};
        char ssid[33] = {};
        uint8_t channel = 0;
        int8_t rssi = -127;
        uint8_t lastStage = 0;
        char lastStageName[12] = {};
        uint32_t firstSeenMs = 0;
        uint32_t lastSeenMs = 0;
        uint16_t frames = 0;
    };

    struct ApName {
        bool used = false;
        uint8_t bssid[6] = {};
        char ssid[33] = {};
        bool wpsLockInitialized = false;
        uint8_t wpsLockCode = 0; // 1=locked, 2=likely unlocked, 3=unknown
    };

    struct LockEvent {
        uint8_t bssid[6] = {};
        char ssid[33] = {};
        uint8_t channel = 0;
        int8_t rssi = -127;
        bool wpsParsed = false;
        bool lockReported = false;
        bool locked = false;
        uint32_t seenMs = 0;
    };

    struct AttemptEvent {
        uint8_t bssid[6] = {};
        uint8_t client[6] = {};
        char ssid[33] = {};
        uint8_t channel = 0;
        int8_t rssi = -127;
        uint8_t stage = 0;
        char stageName[12] = {};
        uint32_t seenMs = 0;
    };

    static WpsAttemptDetector* instance_;
    static void promiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type);

    BridgeProtocol* proto_ = nullptr;
    QueueHandle_t eventQueue_ = nullptr;
    QueueHandle_t lockEventQueue_ = nullptr;
    bool active_ = false;
    bool hopping_ = false;
    bool include5ghz_ = false;
    uint8_t channel_ = 1;
    uint16_t hopIntervalMs_ = 300;
    uint32_t lastHopMs_ = 0;
    uint8_t hopIndex_ = 0;
    uint8_t hopChannels_[64] = {};
    size_t hopChannelCount_ = 0;
    uint8_t targetBssids_[32][6] = {};
    size_t targetCount_ = 0;
    uint16_t sessionCount_ = 0;
    uint32_t frameCount_ = 0;
    uint32_t nextSessionId_ = 1;
    Session sessions_[32] = {};
    ApName apNames_[64] = {};

    void handlePacket(const wifi_promiscuous_pkt_t* pkt);
    void rememberApName(
        const uint8_t bssid[6],
        const char* ssid,
        uint8_t channel,
        int8_t rssi,
        bool hasWpsIe,
        bool wpsParsed,
        bool lockReported,
        bool locked
    );
    void enqueueLockEvent(const ApName& apName);
    void enqueueAttempt(
        const uint8_t bssid[6],
        const uint8_t client[6],
        uint8_t channel,
        int8_t rssi,
        uint8_t stage,
        const char* stageName
    );
    void processEvent(const AttemptEvent& event);
    void hop();
    bool matchesTarget(const uint8_t bssid[6]) const;
};
