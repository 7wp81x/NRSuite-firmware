#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>

class BridgeProtocol;
class Adafruit_PN532;

class Pn532Nfc {
public:
    void begin(BridgeProtocol& proto);
    void update();

    bool setConfig(const char* interfaceName, int sdaGpio, int sclGpio, String& error);
    bool ensureConnected(String& error);
    bool startScan(String& error);
    void stopScan();

    void appendStatus(JsonDocument& doc) const;
    void appendGpioOptions(JsonDocument& doc) const;

    bool connected() const { return _connected; }
    bool scanning() const { return _scanning; }
    bool configured() const { return _sdaGpio >= 0 && _sclGpio >= 0; }
    int sdaGpio() const { return _sdaGpio; }
    int sclGpio() const { return _sclGpio; }

private:
    bool isSafePin(int gpio) const;
    bool initializeReader(String& error);
    void releaseReader();
    void loadConfig();
    void saveConfig();
    void emitStatusEvent();
    void emitErrorEvent(const char* kind, const String& message);
    const char* classifyTag(uint16_t atqa, uint8_t sak) const;

    BridgeProtocol* _proto = nullptr;
    Adafruit_PN532* _reader = nullptr;
    int _sdaGpio = -1;
    int _sclGpio = -1;
    bool _connected = false;
    bool _scanning = false;
    uint32_t _firmwareVersion = 0;
    char _firmwareVersionText[16] = {0};
    uint32_t _lastPollMs = 0;
    uint32_t _lastTagEventMs = 0;
    uint32_t _lastErrorEventMs = 0;
    String _lastUid;
};
