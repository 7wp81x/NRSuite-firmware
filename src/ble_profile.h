#pragma once

#include <Arduino.h>
#include "BridgeProtocol.h"

#ifdef ENABLE_BLE_HID
#include <NimBLEDevice.h>

#define BLE_PROFILE_QUEUE_DEPTH 32

class BleProfile {
public:
    void begin(BridgeProtocol& proto);
    static BleProfile* instance() { return _instance; }

    bool start(const char* address, uint8_t addressType);
    void stop();
    void update();

    bool active() const { return _active; }

private:
    enum class EventType : uint8_t {
        PROFILE = 1,
        SERVICE = 2,
        CHARACTERISTIC = 3,
        DONE = 4,
        FAILED = 5,
    };

    struct Event {
        EventType type;
        char      address[18];
        char      serviceUuid[40];
        char      characteristicUuid[40];
        char      message[64];
        uint8_t   properties;
        int       reason;
    };

    BridgeProtocol* _proto = nullptr;
    QueueHandle_t   _queue = nullptr;
    TaskHandle_t    _task = nullptr;

    volatile bool _active = false;
    volatile bool _abort = false;

    char     _address[18] = {0};
    uint8_t  _addressType = 0;

    static BleProfile* _instance;
    static void taskEntry(void* arg);
    void taskLoop();
    void queueEvent(const Event& event);
};

#endif // ENABLE_BLE_HID
