#pragma once

#include <Arduino.h>
#include "BridgeProtocol.h"

#ifdef ENABLE_BLE_HID
#include <NimBLEAdvertisedDevice.h>
#include <NimBLEDevice.h>
#include <NimBLEScan.h>

#define BLE_SCAN_QUEUE_DEPTH 16
#define BLE_SCAN_RECENT_CACHE 64
#define BLE_SCAN_MAX_SERVICES 8

class BleScanner {
public:
    void begin(BridgeProtocol& proto);
    static BleScanner* instance() { return _instance; }

    bool start(bool active, uint16_t intervalMs, uint16_t windowMs, uint32_t minEmitMs);
    void stop();
    void update();

    bool active() const { return _active; }
    bool scanning() const;

    void onAdvertised(const NimBLEAdvertisedDevice* device);

private:
    struct Event {
        char     address[18];
        char     name[33];
        uint8_t  addressType;
        int8_t   rssi;
        bool     connectable;
        int8_t   txPower;
        uint16_t appearance;
        uint8_t  manufacturer[32];
        uint8_t  manufacturerLength;
        uint8_t  serviceCount;
        char     services[BLE_SCAN_MAX_SERVICES][37];
        uint32_t uptimeMs;
    };

    struct RecentEntry {
        bool     used;
        char     address[18];
        uint32_t lastMs;
    };

    BridgeProtocol* _proto = nullptr;
    QueueHandle_t   _queue = nullptr;

    volatile bool _active = false;
    uint32_t      _minEmitMs = 1000;
    uint32_t      _startedMs = 0;
    NimBLEScan*   _scan = nullptr;

    RecentEntry   _recent[BLE_SCAN_RECENT_CACHE] = {};

    static BleScanner* _instance;
    bool shouldEmit(const char* address);
    static void macToHexString(const uint8_t* data, size_t len, char* out, size_t outSize);
};

#endif // ENABLE_BLE_HID
