#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>
#include "BridgeProtocol.h"

#ifdef ENABLE_BLE_HID

enum class BlePinBruteforceState : uint8_t {
    IDLE = 0,
    ADVERTISING,
    READY,
    RUNNING,
    PAUSED,
    DONE,
    ERROR_STATE,
};

enum class BlePinBruteforceSource : uint8_t {
    RANGE = 0,
    WORDLIST,
};

class BlePinBruteforce {
public:
    void begin(BridgeProtocol& proto);
    void update();

    bool advertiseStart(JsonObject args, String& error);
    bool advertiseStop(String& error);
    bool start(JsonObject args, String& error);
    bool pause(String& error);
    bool resume(String& error);
    bool stop(String& error);
    bool nextAttempt(String& error);
    bool previousAttempt(String& error);
    bool clear(bool clearWordlist, String& error);
    bool forgetBond(String& error);
    bool disconnectPeer(String& error);
    void onBleEnded();

    void status(JsonDocument& doc);
    bool active() const;
    bool ownsBle() const { return _ownsBle; }

private:
    static constexpr const char* NVS_NAMESPACE = "blepin";
    static constexpr const char* WORDLIST_PATH = "/pin_wordlist.txt";
    static constexpr size_t MAX_WORDLIST_BYTES = 16 * 1024;
    static constexpr size_t MAX_WORDLIST_LINES = 1000;

    BridgeProtocol* _proto = nullptr;

    BlePinBruteforceState _state = BlePinBruteforceState::IDLE;
    BlePinBruteforceSource _source = BlePinBruteforceSource::RANGE;
    bool _configured = false;
    bool _ownsBle = false;

    String _deviceName = "NRSuite PIN Keyboard";
    bool _autoReconnect = true;
    bool _autoStartOnConnect = false;
    bool _pauseOnDisconnect = true;

    uint8_t _pinLength = 4;
    String _start;
    String _end;
    String _charset = "0123456789";
    uint32_t _timeoutMs = 1000;
    uint16_t _attemptsBeforeTimeout = 0;
    uint32_t _cooldownMs = 30000;
    uint32_t _interAttemptMs = 400;
    uint16_t _typingDelayMs = 20;
    uint16_t _startDelayMs = 500;
    uint32_t _maxAttempts = 10000;
    uint16_t _persistEvery = 1;
    bool _autoResume = true;
    String _sessionKey = "default";
    String _wordlistFile = WORDLIST_PATH;

    uint64_t _startIndex = 0;
    uint64_t _endIndex = 0;
    uint32_t _attemptsTotal = 0;
    uint32_t _attemptsInCycle = 0;
    uint64_t _estimatedTotal = 0;
    String _stopReason;
    String _lastPin;
    String _lastError;
    uint32_t _startedAt = 0;
    uint32_t _updatedAt = 0;
    uint32_t _nextAttemptAtMs = 0;
    uint32_t _cooldownUntilMs = 0;

    bool _lastBleConnected = false;
    bool _lastBleAdvertising = false;
    bool _lastBonded = false;
    String _lastPeer = "";

    String _wordlist;

    bool parseConfig(JsonObject args, String& error);
    bool validateConfig(String& error);
    bool loadWordlist(String& error);
    bool buildWordlistLines(String& error);
    bool readWordlistFile(String& out);
    bool readLineFromWordlist(uint32_t index, String& out) const;
    bool nextRangePinAt(uint64_t value, String& out) const;
    bool wordlistFileExists();
    void removeWordlistFile();

    bool pinAtAttemptIndex(uint32_t attemptIndex, String& out) const;
    uint32_t effectiveTotal() const;
    void setLastPinFromAttemptCount();
    void startRunning(const char* reason);
    void pauseInternal(const char* reason);
    void finish(const char* reason);

    void updateBleState();
    void emitStatus(const char* reason = nullptr);
    void emitAttempt(bool skipped = false);
    void emitDone();
    void emitError(const char* code, const char* message);
    void emitConnection();

    void persistSession();
    void persistProgress();
    void loadPersistedSession();
    void clearPersistedSession();

    const char* stateName() const;
    const char* sourceName() const;
};

extern BlePinBruteforce blePinBruteforce;

#endif // ENABLE_BLE_HID
