#include "pin_bruteforce.h"

#include <Preferences.h>
#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
#include <FFat.h>
#include "UsbHID.h"
#else
#include <SPIFFS.h>
#endif

PinBruteforce pinBruteforce;

namespace {
constexpr const char* PIN_WORDLIST_PATH = "/pin_wordlist.txt";

bool pinFsBegin(bool format) {
#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
    return FFat.begin(format, "/ffat", 10, "msc_ffat");
#else
    return SPIFFS.begin(format);
#endif
}

void pinFsEnd() {
#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
    FFat.end();
#else
    SPIFFS.end();
#endif
}

#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
#define PIN_FS_OPEN(path, mode) FFat.open((path), (mode))
#else
#define PIN_FS_OPEN(path, mode) SPIFFS.open((path), (mode))
#endif

char pinFsSeparator() {
    return '/';
}

int charIndex(const String& chars, char c) {
    for (size_t i = 0; i < chars.length(); i++) {
        if (chars[i] == c) return (int)i;
    }
    return -1;
}

uint64_t saturatingPow(uint32_t base, uint8_t exponent) {
    uint64_t value = 1;
    for (uint8_t i = 0; i < exponent; i++) {
        if (value > (UINT64_MAX / base)) return UINT64_MAX;
        value *= base;
    }
    return value;
}
}

void PinBruteforce::begin(BridgeProtocol& proto) {
    _proto = &proto;
    loadPersistedSession();
}

const char* PinBruteforce::stateName() const {
    switch (_state) {
        case PinBruteforceState::IDLE: return "idle";
        case PinBruteforceState::ARMED: return "armed";
        case PinBruteforceState::RUNNING: return "running";
        case PinBruteforceState::PAUSED: return "paused";
        case PinBruteforceState::DONE: return "done";
        case PinBruteforceState::ERROR_STATE: return "error";
    }
    return "idle";
}

const char* PinBruteforce::modeName() const {
    return _mode == PinBruteforceMode::STANDALONE_NATIVE_HID
        ? "standalone_native_hid"
        : "external_ch9329_realtime";
}

const char* PinBruteforce::sourceName() const {
    return _source == PinBruteforceSource::RANGE ? "range" : "wordlist";
}

bool PinBruteforce::parseConfig(JsonObject args, String& error) {
    const char* modeArg = args["mode"] | "standalone_native_hid";
    if (strcmp(modeArg, "standalone_native_hid") == 0) {
        _mode = PinBruteforceMode::STANDALONE_NATIVE_HID;
    } else if (strcmp(modeArg, "external_ch9329_realtime") == 0) {
        _mode = PinBruteforceMode::EXTERNAL_CH9329_REALTIME;
    } else {
        error = "invalid mode";
        return false;
    }

    const char* sourceArg = args["source"] | "range";
    if (strcmp(sourceArg, "range") == 0) {
        _source = PinBruteforceSource::RANGE;
    } else if (strcmp(sourceArg, "wordlist") == 0) {
        _source = PinBruteforceSource::WORDLIST;
    } else {
        error = "invalid source";
        return false;
    }

    _pinLength = (uint8_t)(args["pin_length"] | 4);
    _start = String((const char*)(args["start"] | ""));
    _end = String((const char*)(args["end"] | ""));
    const char* charsetArg = args["charset"] | "digits";
    if (strcmp(charsetArg, "digits") == 0) {
        _charset = "0123456789";
    } else if (strcmp(charsetArg, "custom") == 0) {
        _charset = String((const char*)(args["custom_chars"] | "0123456789"));
    } else {
        _charset = String(charsetArg);
    }
    _prefix = String((const char*)(args["prefix"] | ""));
    _suffix = String((const char*)(args["suffix"] | ""));
    _timeoutMs = (uint32_t)(args["timeout_ms"] | 1000);
    _attemptsBeforeTimeout = (uint16_t)(args["attempts_before_timeout"] | 0);
    _interAttemptMs = (uint32_t)(args["inter_attempt_ms"] | 400);
    _autoResume = args["auto_resume"] | true;
    _sessionKey = String((const char*)(args["session_key"] | "default"));
    _wordlistFile = String((const char*)(args["wordlist_file"] | PIN_WORDLIST_PATH));
    _uartBaud = (uint32_t)(args["uart_baud"] | 115200);
    _uartRxPin = (int8_t)(args["uart_rx"] | -1);
    _uartTxPin = (int8_t)(args["uart_tx"] | -1);

    if (_wordlistFile.length() == 0) _wordlistFile = PIN_WORDLIST_PATH;
    if (_charset.length() < 2) {
        error = "charset must contain at least 2 characters";
        return false;
    }
    if (_pinLength < 4 || _pinLength > 12) {
        error = "pin_length must be 4..12";
        return false;
    }
    if (_sessionKey.length() == 0) _sessionKey = "default";
    if (_timeoutMs < 50) _timeoutMs = 50;
    if (_timeoutMs > 60000) _timeoutMs = 60000;
    if (_interAttemptMs > 60000) _interAttemptMs = 60000;
    if (_attemptsBeforeTimeout > 1000) _attemptsBeforeTimeout = 1000;
    return true;
}

bool PinBruteforce::validateConfig(String& error) {
    if (_source == PinBruteforceSource::WORDLIST) {
        if (!wordlistFileExists()) {
            error = "wordlist file not found";
            return false;
        }
        if (!loadWordlist(error)) return false;
        _currentIndex = 0;
        _endIndex = 0;
        return true;
    }

    if (_start.length() == 0) {
        _start = "";
        for (uint8_t i = 0; i < _pinLength; i++) _start += _charset[0];
    } else if (_start.length() < _pinLength) {
        while (_start.length() < _pinLength) _start = String(_charset[0]) + _start;
    } else if (_start.length() > _pinLength) {
        error = "start is longer than pin_length";
        return false;
    }

    if (_end.length() == 0) {
        _end = "";
        for (uint8_t i = 0; i < _pinLength; i++) _end += _charset[_charset.length() - 1];
    } else if (_end.length() < _pinLength) {
        while (_end.length() < _pinLength) _end = String(_charset[0]) + _end;
    } else if (_end.length() > _pinLength) {
        error = "end is longer than pin_length";
        return false;
    }

    uint64_t startIndex = 0;
    uint64_t endIndex = 0;
    for (size_t i = 0; i < _start.length(); i++) {
        int idx = charIndex(_charset, _start[i]);
        if (idx < 0) { error = "start contains a character outside charset"; return false; }
        startIndex = (startIndex * _charset.length()) + idx;
    }
    for (size_t i = 0; i < _end.length(); i++) {
        int idx = charIndex(_charset, _end[i]);
        if (idx < 0) { error = "end contains a character outside charset"; return false; }
        endIndex = (endIndex * _charset.length()) + idx;
    }

    if (endIndex < startIndex) {
        error = "end is before start";
        return false;
    }
    _currentIndex = startIndex;
    _endIndex = endIndex;
    return true;
}

bool PinBruteforce::loadWordlist(String& error) {
    error = "";
    _wordlist = "";
    if (!buildWordlistLines(error)) return false;
    return true;
}

bool PinBruteforce::buildWordlistLines(String& error) {
    String content;
    if (!readWordlistFile(content)) {
        error = "could not read wordlist file";
        return false;
    }
    content.replace("\r", "");
    content.replace("\n", "\n");

    uint32_t lines = 0;
    String normalized;
    normalized.reserve(content.length());
    int start = 0;
    while (start <= (int)content.length()) {
        int nl = content.indexOf('\n', start);
        String line = (nl < 0) ? content.substring(start) : content.substring(start, nl);
        line.trim();
        if (line.length() > 0) {
            if (line.length() > 64) {
                error = "wordlist line exceeds 64 characters";
                return false;
            }
            lines++;
            if (lines > MAX_WORDLIST_LINES) {
                error = "wordlist exceeds 1000 lines";
                return false;
            }
            normalized += line;
            normalized += '\n';
        }
        if (nl < 0) break;
        start = nl + 1;
    }
    if (lines == 0) {
        error = "wordlist is empty";
        return false;
    }
    if (normalized.length() > MAX_WORDLIST_BYTES) {
        error = "wordlist exceeds 16 KB";
        return false;
    }
    _wordlist = normalized;
    return true;
}

bool PinBruteforce::readLineFromWordlist(uint32_t index, String& out) const {
    uint32_t line = 0;
    int start = 0;
    while (start <= (int)_wordlist.length()) {
        int nl = _wordlist.indexOf('\n', start);
        String current = (nl < 0) ? _wordlist.substring(start) : _wordlist.substring(start, nl);
        if (line == index) {
            out = current;
            return true;
        }
        if (nl < 0) break;
        line++;
        start = nl + 1;
    }
    return false;
}

bool PinBruteforce::nextPin(String& out) {
    if (_source == PinBruteforceSource::WORDLIST) {
        if (!readLineFromWordlist((uint32_t)_currentIndex, out)) return false;
        _currentIndex++;
    } else {
        if (_currentIndex > _endIndex) return false;
        if (!nextRangePin(out)) return false;
        _currentIndex++;
    }
    out = _prefix + out + _suffix;
    return true;
}

bool PinBruteforce::nextRangePin(String& out) {
    char buffer[13] = {0};
    uint64_t value = _currentIndex;
    const uint32_t base = _charset.length();
    for (int i = _pinLength - 1; i >= 0; i--) {
        buffer[i] = _charset[value % base];
        value /= base;
    }
    out = String(buffer);
    return true;
}

bool PinBruteforce::initHid(String& error) {
    if (_mode == PinBruteforceMode::STANDALONE_NATIVE_HID) {
#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
        if (!UsbHID::available()) {
            error = "native HID unavailable";
            return false;
        }
        _hidReady = true;
        return true;
#else
        error = "standalone_native_hid requires ESP32-S2/S3";
        return false;
#endif
    }

    if (!initCh9329(error)) return false;
    _hidReady = true;
    return true;
}

void PinBruteforce::stopHid() {
    if (!_hidReady) return;
    if (_mode == PinBruteforceMode::STANDALONE_NATIVE_HID) {
#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
        UsbHID::releaseAll();
#endif
    } else {
        ch9329ReleaseAll();
    }
    _hidReady = false;
}

bool PinBruteforce::initCh9329(String& error) {
    Serial1.begin(_uartBaud, SERIAL_8N1, _uartRxPin, _uartTxPin);
    delay(50);
    ch9329ReleaseAll();
    return true;
}

void PinBruteforce::ch9329SendKey(uint8_t keycode, uint8_t modifiers) {
    uint8_t frame[14] = {0x57, 0xAB, 0x00, 0x02, 0x08,
                         modifiers, 0x00, keycode, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t sum = 0;
    for (int i = 0; i < 13; i++) sum = (uint8_t)(sum + frame[i]);
    frame[13] = sum;
    Serial1.write(frame, sizeof(frame));
    Serial1.flush();
}

bool PinBruteforce::ch9329Char(char c) {
    uint8_t modifier = 0;
    uint8_t keycode = 0;

    if (c >= 'a' && c <= 'z') keycode = 0x04 + (c - 'a');
    else if (c >= 'A' && c <= 'Z') { keycode = 0x04 + (c - 'A'); modifier = 0x02; }
    else if (c >= '1' && c <= '9') keycode = 0x1E + (c - '1');
    else if (c == '0') keycode = 0x27;
    else if (c == ' ') keycode = 0x2C;
    else if (c == '-') keycode = 0x2D;
    else if (c == '_') { keycode = 0x2D; modifier = 0x02; }
    else if (c == '=') keycode = 0x2E;
    else if (c == '+') { keycode = 0x2E; modifier = 0x02; }
    else if (c == '[') keycode = 0x2F;
    else if (c == '{') { keycode = 0x2F; modifier = 0x02; }
    else if (c == ']') keycode = 0x30;
    else if (c == '}') { keycode = 0x30; modifier = 0x02; }
    else if (c == '\\') keycode = 0x31;
    else if (c == '|') { keycode = 0x31; modifier = 0x02; }
    else if (c == ';') keycode = 0x33;
    else if (c == ':') { keycode = 0x33; modifier = 0x02; }
    else if (c == '\'') keycode = 0x34;
    else if (c == '"') { keycode = 0x34; modifier = 0x02; }
    else if (c == '`') keycode = 0x35;
    else if (c == '~') { keycode = 0x35; modifier = 0x02; }
    else if (c == ',') keycode = 0x36;
    else if (c == '<') { keycode = 0x36; modifier = 0x02; }
    else if (c == '.') keycode = 0x37;
    else if (c == '>') { keycode = 0x37; modifier = 0x02; }
    else if (c == '/') keycode = 0x38;
    else if (c == '?') { keycode = 0x38; modifier = 0x02; }
    else if (c == '!') { keycode = 0x1E; modifier = 0x02; }
    else if (c == '@') { keycode = 0x1F; modifier = 0x02; }
    else if (c == '#') { keycode = 0x20; modifier = 0x02; }
    else if (c == '$') { keycode = 0x21; modifier = 0x02; }
    else if (c == '%') { keycode = 0x22; modifier = 0x02; }
    else if (c == '^') { keycode = 0x23; modifier = 0x02; }
    else if (c == '&') { keycode = 0x24; modifier = 0x02; }
    else if (c == '*') { keycode = 0x25; modifier = 0x02; }
    else if (c == '(') { keycode = 0x26; modifier = 0x02; }
    else if (c == ')') { keycode = 0x27; modifier = 0x02; }
    else return false;

    ch9329SendKey(keycode, modifier);
    delay(6);
    ch9329SendKey(0, 0);
    delay(6);
    return true;
}

void PinBruteforce::ch9329ReleaseAll() {
    ch9329SendKey(0, 0);
}

void PinBruteforce::sendCurrentPin() {
    if (_mode == PinBruteforceMode::STANDALONE_NATIVE_HID) {
#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
        UsbHID::sendText(_lastPin);
        UsbHID::pressEnter();
#endif
        return;
    }

    for (size_t i = 0; i < _lastPin.length(); i++) {
        if (!ch9329Char(_lastPin[i])) {
            _lastError = "unsupported wordlist character";
            emitError("hid_encode", _lastError.c_str());
            break;
        }
    }
    ch9329SendKey(0x28, 0);
    delay(6);
    ch9329SendKey(0, 0);
}

bool PinBruteforce::start(JsonObject args, String& error) {
    stop();
    resetWordlistUpload();
    if (!parseConfig(args, error)) return false;
    if (!validateConfig(error)) return false;

    _standalone = (_mode == PinBruteforceMode::STANDALONE_NATIVE_HID);
    _attemptsTotal = 0;
    _attemptsInCycle = 0;
    _lastPin = "";
    _lastError = "";
    _startedAt = millis();
    _updatedAt = _startedAt;
    _nextAttemptAtMs = 0;

    if (_standalone) {
#if !defined(CONFIG_IDF_TARGET_ESP32S2) && !defined(CONFIG_IDF_TARGET_ESP32S3)
        error = "standalone_native_hid requires ESP32-S2/S3";
        _state = PinBruteforceState::ERROR_STATE;
        return false;
#else
        _state = PinBruteforceState::ARMED;
        persistSession();
        emitStatus("armed");
        return true;
#endif
    }

    if (!initHid(error)) {
        _state = PinBruteforceState::ERROR_STATE;
        _lastError = error;
        emitError("hid_init", error.c_str());
        return false;
    }
    _state = PinBruteforceState::RUNNING;
    _nextAttemptAtMs = millis();
    persistSession();
    emitStatus("started");
    return true;
}

bool PinBruteforce::resume(String& error) {
    Preferences prefs;
    if (!prefs.begin(NVS_NAMESPACE, true)) {
        error = "NVS unavailable";
        return false;
    }
    bool hasSession = prefs.isKey("state");
    prefs.end();
    if (!hasSession) {
        error = "no persisted session";
        return false;
    }

    loadPersistedSession();
    if (_state == PinBruteforceState::IDLE || _state == PinBruteforceState::DONE) {
        error = "persisted session is already finished";
        return false;
    }
    if (_source == PinBruteforceSource::WORDLIST && !loadWordlist(error)) {
        return false;
    }
    if (!initHid(error)) {
        _state = PinBruteforceState::ERROR_STATE;
        emitError("hid_init", error.c_str());
        return false;
    }
    _standalone = false;
    _state = PinBruteforceState::RUNNING;
    _nextAttemptAtMs = millis();
    emitStatus("resumed");
    return true;
}

bool PinBruteforce::stop() {
    if (_state == PinBruteforceState::RUNNING || _state == PinBruteforceState::ARMED) {
        _state = PinBruteforceState::PAUSED;
        _updatedAt = millis();
        stopHid();
        persistSession();
        emitStatus("paused");
        return true;
    }
    if (_state == PinBruteforceState::PAUSED) {
        stopHid();
        return true;
    }
    stopHid();
    return false;
}

bool PinBruteforce::clear(bool clearWordlist, String& error) {
    (void)error;
    stop();
    _state = PinBruteforceState::IDLE;
    _attemptsTotal = 0;
    _attemptsInCycle = 0;
    _currentIndex = 0;
    _endIndex = 0;
    _lastPin = "";
    _lastError = "";
    _startedAt = 0;
    _updatedAt = 0;
    _wordlist = "";
    clearPersistedSession();
    if (clearWordlist) removeWordlistFile();
    emitStatus("cleared");
    return true;
}

void PinBruteforce::update() {
    if (_state == PinBruteforceState::ARMED &&
        _mode == PinBruteforceMode::STANDALONE_NATIVE_HID &&
        _autoResume) {
        String error;
        if (initHid(error)) {
            _state = PinBruteforceState::RUNNING;
            _nextAttemptAtMs = millis();
            emitStatus("auto_resume");
        }
    }
    if (_state != PinBruteforceState::RUNNING) return;
    const uint32_t now = millis();
    if (_nextAttemptAtMs != 0 && now < _nextAttemptAtMs) return;

    String pin;
    if (!nextPin(pin)) {
        _state = PinBruteforceState::DONE;
        _updatedAt = now;
        stopHid();
        persistSession();
        emitDone();
        return;
    }

    _lastPin = pin;
    _attemptsTotal++;
    _attemptsInCycle++;
    _updatedAt = now;
    sendCurrentPin();
    emitAttempt();

    bool cooldown = false;
    if (_attemptsBeforeTimeout > 0 && _attemptsInCycle >= _attemptsBeforeTimeout) {
        _attemptsInCycle = 0;
        cooldown = true;
    }
    _nextAttemptAtMs = now + _timeoutMs + (cooldown ? _timeoutMs : 0) + _interAttemptMs;

    if ((_attemptsTotal % PERSIST_EVERY_N) == 0 || cooldown) persistSession();
    if (_state == PinBruteforceState::ERROR_STATE) {
        stopHid();
    }
}

bool PinBruteforce::runIfArmed() {
#if !defined(CONFIG_IDF_TARGET_ESP32S2) && !defined(CONFIG_IDF_TARGET_ESP32S3)
    return false;
#else
    loadPersistedSession();
    if (!_autoResume) return false;
    if (_mode != PinBruteforceMode::STANDALONE_NATIVE_HID) return false;
    if (_state != PinBruteforceState::ARMED && _state != PinBruteforceState::RUNNING) return false;

    String error;
    if (_source == PinBruteforceSource::WORDLIST && !loadWordlist(error)) {
        _lastError = error;
        _state = PinBruteforceState::ERROR_STATE;
        emitError("wordlist", error.c_str());
        return true;
    }
    if (!initHid(error)) {
        _lastError = error;
        _state = PinBruteforceState::ERROR_STATE;
        emitError("hid_init", error.c_str());
        return true;
    }

    _standalone = true;
    _state = PinBruteforceState::RUNNING;
    _attemptsTotal = 0;
    _nextAttemptAtMs = 0;
    if (_startedAt == 0) _startedAt = millis();
    emitStatus("standalone_running");

    while (_state == PinBruteforceState::RUNNING) {
        String pin;
        if (!nextPin(pin)) {
            _state = PinBruteforceState::DONE;
            _updatedAt = millis();
            persistSession();
            emitDone();
            break;
        }
        _lastPin = pin;
        _attemptsTotal++;
        _attemptsInCycle++;
        _updatedAt = millis();
        sendCurrentPin();
        emitAttempt();

        bool cooldown = false;
        if (_attemptsBeforeTimeout > 0 && _attemptsInCycle >= _attemptsBeforeTimeout) {
            _attemptsInCycle = 0;
            cooldown = true;
        }
        delay(_timeoutMs);
        if (cooldown) delay(_timeoutMs);
        if (_interAttemptMs > 0) delay(_interAttemptMs);
        if ((_attemptsTotal % PERSIST_EVERY_N) == 0 || cooldown) persistSession();
    }

    stopHid();
    return true;
#endif
}

void PinBruteforce::emitStatus(const char* reason) {
    if (!_proto) return;
    JsonDocument doc;
    status(doc);
    if (reason) doc["reason"] = reason;
    _proto->sendEvent("pin_session_status", doc);
}

void PinBruteforce::emitAttempt() {
    if (!_proto) return;
    JsonDocument doc;
    doc["mode"] = modeName();
    doc["source"] = sourceName();
    doc["pin"] = _lastPin;
    doc["current_sequence"] = _currentIndex;
    doc["attempts_total"] = _attemptsTotal;
    doc["attempts_in_cycle"] = _attemptsInCycle;
    doc["started_at"] = _startedAt;
    doc["updated_at"] = _updatedAt;
    _proto->sendEvent("pin_attempt", doc);
}

void PinBruteforce::emitDone() {
    if (!_proto) return;
    JsonDocument doc;
    doc["mode"] = modeName();
    doc["source"] = sourceName();
    doc["attempts_total"] = _attemptsTotal;
    doc["last_pin"] = _lastPin;
    doc["started_at"] = _startedAt;
    doc["updated_at"] = _updatedAt;
    _proto->sendEvent("pin_range_done", doc);
    emitStatus("done");
}

void PinBruteforce::emitError(const char* code, const char* message) {
    if (!_proto) return;
    JsonDocument doc;
    doc["code"] = code ? code : "error";
    doc["msg"] = message ? message : "";
    _proto->sendEvent("pin_range_error", doc);
    emitStatus("error");
}

void PinBruteforce::status(JsonDocument& doc) const {
    doc["state"] = stateName();
    doc["mode"] = modeName();
    doc["source"] = sourceName();
    doc["standalone"] = _standalone;
    doc["active"] = active();
    doc["pin_length"] = _pinLength;
    doc["charset"] = _charset;
    doc["prefix"] = _prefix;
    doc["suffix"] = _suffix;
    doc["timeout_ms"] = _timeoutMs;
    doc["attempts_before_timeout"] = _attemptsBeforeTimeout;
    doc["inter_attempt_ms"] = _interAttemptMs;
    doc["auto_resume"] = _autoResume;
    doc["session_key"] = _sessionKey;
    doc["current_index"] = (uint32_t)_currentIndex;
    doc["end_index"] = (uint32_t)_endIndex;
    doc["current_sequence"] = (uint32_t)_currentIndex;
    doc["attempts_total"] = _attemptsTotal;
    doc["attempts_in_cycle"] = _attemptsInCycle;
    doc["last_pin"] = _lastPin;
    doc["last_error"] = _lastError;
    doc["started_at"] = _startedAt;
    doc["updated_at"] = _updatedAt;
    doc["wordlist_lines"] = 0;
    if (_source == PinBruteforceSource::WORDLIST && _wordlist.length() > 0) {
        uint32_t lines = 0;
        for (size_t i = 0; i < _wordlist.length(); i++) if (_wordlist[i] == '\n') lines++;
        doc["wordlist_lines"] = lines;
    }
    doc["wordlist_bytes"] = _wordlist.length();

    Preferences prefs;
    if (prefs.begin(NVS_NAMESPACE, true)) {
        doc["persisted_in_nvs"] = prefs.isKey("state");
        prefs.end();
    } else {
        doc["persisted_in_nvs"] = false;
    }
}

void PinBruteforce::persistSession() {
    Preferences prefs;
    if (!prefs.begin(NVS_NAMESPACE, false)) return;
    prefs.putString("session_key", _sessionKey);
    prefs.putUChar("mode", (uint8_t)_mode);
    prefs.putUChar("source", (uint8_t)_source);
    prefs.putUChar("state", (uint8_t)_state);
    prefs.putUChar("pin_len", _pinLength);
    prefs.putString("start", _start);
    prefs.putString("end", _end);
    prefs.putString("charset", _charset);
    prefs.putString("prefix", _prefix);
    prefs.putString("suffix", _suffix);
    prefs.putUInt("timeout", _timeoutMs);
    prefs.putUShort("att_before", _attemptsBeforeTimeout);
    prefs.putUInt("inter", _interAttemptMs);
    prefs.putBool("auto_resume", _autoResume);
    prefs.putString("wordlist_file", _wordlistFile);
    prefs.putULong64("current_index", _currentIndex);
    prefs.putULong64("end_index", _endIndex);
    prefs.putUInt("attempts_total", _attemptsTotal);
    prefs.putUInt("attempts_cycle", _attemptsInCycle);
    prefs.putString("last_pin", _lastPin);
    prefs.putString("last_error", _lastError);
    prefs.putUInt("started_at", _startedAt);
    prefs.putUInt("updated_at", _updatedAt);
    prefs.end();
    _nvsDirty = false;
}

void PinBruteforce::loadPersistedSession() {
    Preferences prefs;
    if (!prefs.begin(NVS_NAMESPACE, true)) return;
    if (!prefs.isKey("state")) {
        prefs.end();
        return;
    }
    _mode = (PinBruteforceMode)prefs.getUChar("mode", (uint8_t)PinBruteforceMode::STANDALONE_NATIVE_HID);
    _source = (PinBruteforceSource)prefs.getUChar("source", (uint8_t)PinBruteforceSource::RANGE);
    _state = (PinBruteforceState)prefs.getUChar("state", (uint8_t)PinBruteforceState::IDLE);
    _pinLength = prefs.getUChar("pin_len", 4);
    _start = prefs.getString("start", "");
    _end = prefs.getString("end", "");
    _charset = prefs.getString("charset", "0123456789");
    _prefix = prefs.getString("prefix", "");
    _suffix = prefs.getString("suffix", "");
    _timeoutMs = prefs.getUInt("timeout", 1000);
    _attemptsBeforeTimeout = prefs.getUShort("att_before", 0);
    _interAttemptMs = prefs.getUInt("inter", 400);
    _autoResume = prefs.getBool("auto_resume", true);
    _sessionKey = prefs.getString("session_key", "default");
    _wordlistFile = prefs.getString("wordlist_file", PIN_WORDLIST_PATH);
    _currentIndex = prefs.getULong64("current_index", 0);
    _endIndex = prefs.getULong64("end_index", 0);
    _attemptsTotal = prefs.getUInt("attempts_total", 0);
    _attemptsInCycle = prefs.getUInt("attempts_cycle", 0);
    _lastPin = prefs.getString("last_pin", "");
    _lastError = prefs.getString("last_error", "");
    _startedAt = prefs.getUInt("started_at", 0);
    _updatedAt = prefs.getUInt("updated_at", 0);
    prefs.end();
}

void PinBruteforce::clearPersistedSession() {
    Preferences prefs;
    if (prefs.begin(NVS_NAMESPACE, false)) {
        prefs.clear();
        prefs.end();
    }
}

bool PinBruteforce::beginWordlistUpload(String& error) {
    (void)error;
    _uploadBuffer = "";
    _uploadBuffer.reserve(MAX_WORDLIST_BYTES);
    _uploadActive = true;
    return true;
}

bool PinBruteforce::addWordlistChunk(const uint8_t* data, size_t len, bool last, String& error) {
    if (!_uploadActive) {
        error = "wordlist upload not started";
        return false;
    }
    if (data && len > 0) {
        if (_uploadBuffer.length() + len > MAX_WORDLIST_BYTES) {
            error = "wordlist exceeds 16 KB";
            return false;
        }
        _uploadBuffer.concat((const char*)data, len);
    }
    if (!last) return true;

    _uploadBuffer.replace("\r", "");
    uint32_t lines = 0;
    int start = 0;
    while (start <= (int)_uploadBuffer.length()) {
        int nl = _uploadBuffer.indexOf('\n', start);
        String line = (nl < 0) ? _uploadBuffer.substring(start) : _uploadBuffer.substring(start, nl);
        line.trim();
        if (line.length() > 0) {
            if (line.length() > 64) {
                error = "wordlist line exceeds 64 characters";
                return false;
            }
            lines++;
            if (lines > MAX_WORDLIST_LINES) {
                error = "wordlist exceeds 1000 lines";
                return false;
            }
        }
        if (nl < 0) break;
        start = nl + 1;
    }
    if (lines == 0) {
        error = "wordlist is empty";
        return false;
    }
    if (!writeWordlistFile(_uploadBuffer)) {
        error = "could not save wordlist";
        return false;
    }
    _uploadActive = false;
    return true;
}

void PinBruteforce::resetWordlistUpload() {
    _uploadBuffer = "";
    _uploadActive = false;
}

bool PinBruteforce::readWordlistFile(String& out) {
    if (!pinFsBegin(false)) return false;
    File file = PIN_FS_OPEN(_wordlistFile.c_str(), FILE_READ);
    if (!file) {
        pinFsEnd();
        return false;
    }
    out = "";
    out.reserve(file.size());
    while (file.available()) out += (char)file.read();
    file.close();
    pinFsEnd();
    return true;
}

bool PinBruteforce::writeWordlistFile(const String& content) {
    if (!pinFsBegin(true)) return false;
    File file = PIN_FS_OPEN(_wordlistFile.c_str(), FILE_WRITE);
    if (!file) {
        pinFsEnd();
        return false;
    }
    size_t written = file.print(content);
    file.close();
    pinFsEnd();
    return written == content.length();
}

bool PinBruteforce::wordlistFileExists() {
    if (!pinFsBegin(false)) return false;
    bool exists = false;
#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
    exists = FFat.exists(_wordlistFile.c_str());
#else
    exists = SPIFFS.exists(_wordlistFile.c_str());
#endif
    pinFsEnd();
    return exists;
}

void PinBruteforce::removeWordlistFile() {
    if (!pinFsBegin(false)) return;
#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
    FFat.remove(_wordlistFile.c_str());
#else
    SPIFFS.remove(_wordlistFile.c_str());
#endif
    pinFsEnd();
}
