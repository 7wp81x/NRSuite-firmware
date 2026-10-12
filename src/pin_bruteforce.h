#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>
#include "BridgeProtocol.h"

enum class PinBruteforceState : uint8_t {
    IDLE = 0,
    ARMED,
    RUNNING,
    PAUSED,
    DONE,
    ERROR_STATE,
};

enum class PinBruteforceMode : uint8_t {
    STANDALONE_NATIVE_HID = 0,
    EXTERNAL_CH9329_REALTIME,
};

enum class PinBruteforceSource : uint8_t {
    RANGE = 0,
    WORDLIST,
};

class PinBruteforce {
public:
    void begin(BridgeProtocol& proto);
    void update();

    bool start(JsonObject args, String& error);
    bool resume(String& error);
    bool stop();
    bool clear(bool clearWordlist, String& error);
    void status(JsonDocument& doc) const;

    // Standalone native-HID path: called once from setup() before the normal
    // USB CDC bridge begins. Returns true if a persisted session was executed.
    bool runIfArmed();

    // Wordlist upload support. Data is decoded by the command handler.
    bool beginWordlistUpload(String& error);
    bool addWordlistChunk(const uint8_t* data, size_t len, bool last, String& error);
    void resetWordlistUpload();

    bool active() const { return _state == PinBruteforceState::RUNNING || _state == PinBruteforceState::ARMED; }

private:
    static constexpr const char* NVS_NAMESPACE = "pinbrute";
    static constexpr const char* WORDLIST_PATH = "/pin_wordlist.txt";
    static constexpr size_t MAX_WORDLIST_BYTES = 16 * 1024;
    static constexpr size_t MAX_WORDLIST_LINES = 1000;
    static constexpr uint32_t PERSIST_EVERY_N = 10;

    BridgeProtocol* _proto = nullptr;

    PinBruteforceState _state = PinBruteforceState::IDLE;
    PinBruteforceMode _mode = PinBruteforceMode::STANDALONE_NATIVE_HID;
    PinBruteforceSource _source = PinBruteforceSource::RANGE;

    bool _standalone = false;
    uint8_t _pinLength = 4;
    String _start;
    String _end;
    String _charset;
    String _prefix;
    String _suffix;
    uint32_t _timeoutMs = 1000;
    uint16_t _attemptsBeforeTimeout = 0;
    uint32_t _interAttemptMs = 400;
    bool _autoResume = true;
    String _sessionKey = "default";
    String _wordlistFile = WORDLIST_PATH;

    uint32_t _uartBaud = 115200;
    int8_t _uartRxPin = -1;
    int8_t _uartTxPin = -1;

    uint64_t _startIndex = 0;
    uint64_t _currentIndex = 0;
    uint64_t _endIndex = 0;
    uint32_t _attemptsTotal = 0;
    uint32_t _attemptsInCycle = 0;
    String _lastPin;
    String _lastError;
    uint32_t _startedAt = 0;
    uint32_t _updatedAt = 0;

    uint32_t _nextAttemptAtMs = 0;
    bool _nvsDirty = false;
    bool _hidReady = false;

    String _wordlist;
    String _uploadBuffer;
    bool _uploadActive = false;

    bool parseConfig(JsonObject args, String& error);
    bool validateConfig(String& error);
    bool loadWordlist(String& error);
    bool buildWordlistLines(String& error);
    bool nextPin(String& out);
    void sendCurrentPin();
    void emitStatus(const char* reason = nullptr);
    void emitAttempt();
    void emitDone();
    void emitError(const char* code, const char* message);
    void persistSession();
    void loadPersistedSession();
    void clearPersistedSession();
    const char* stateName() const;
    const char* modeName() const;
    const char* sourceName() const;
    bool readLineFromWordlist(uint32_t index, String& out) const;
    bool writeWordlistFile(const String& content);
    bool readWordlistFile(String& out);
    bool wordlistFileExists();
    void removeWordlistFile();
    bool initHid(String& error);
    void stopHid();
    bool initCh9329(String& error);
    void ch9329SendKey(uint8_t keycode, uint8_t modifiers);
    bool ch9329Char(char c);
    void ch9329ReleaseAll();
    bool nextRangePin(String& out);
};

extern PinBruteforce pinBruteforce;
