#include "ld2450.h"

void Ld2450::begin(HardwareSerial& serial, uint32_t baud, int8_t rxPin, int8_t txPin) {
    _serial = &serial;
    _serial->begin(baud, SERIAL_8N1, rxPin, txPin);
    resetParser();
    _active = true;
    _lastNoTargetPrintMs = millis();
    _lastStatsPrintMs = millis();

    Serial.printf("[LD2450] UART2 started: baud=%lu rx=%d tx=%d\n",
                  (unsigned long)baud, rxPin, txPin);
}

void Ld2450::resetParser() {
    _state = ParserState::HEADER_0;
    _payloadPos = 0;
    memset(_payload, 0, sizeof(_payload));
    for (auto& target : _targets) target = Target{};
}

void Ld2450::stop() {
    _active = false;
    Serial.println("[LD2450] stopped");
}

void Ld2450::update() {
    if (!_active || !_serial) return;
    while (_serial->available() > 0) {
        handleByte((uint8_t)_serial->read());
    }
}

void Ld2450::handleByte(uint8_t value) {
    switch (_state) {
        case ParserState::HEADER_0:
            if (value == 0xAA) _state = ParserState::HEADER_1;
            else _droppedBytes++;
            break;
        case ParserState::HEADER_1:
            _state = (value == 0xFF) ? ParserState::HEADER_2 : ParserState::HEADER_0;
            if (value != 0xFF) _droppedBytes++;
            break;
        case ParserState::HEADER_2:
            _state = (value == 0x03) ? ParserState::HEADER_3 : ParserState::HEADER_0;
            if (value != 0x03) _droppedBytes++;
            break;
        case ParserState::HEADER_3:
            _state = (value == 0x00) ? ParserState::TARGETS : ParserState::HEADER_0;
            if (value != 0x00) _droppedBytes++;
            else _payloadPos = 0;
            break;
        case ParserState::TARGETS:
            _payload[_payloadPos++] = value;
            if (_payloadPos >= sizeof(_payload)) {
                _state = ParserState::FOOTER_0;
            }
            break;
        case ParserState::FOOTER_0:
            _state = (value == 0x55) ? ParserState::FOOTER_1 : ParserState::HEADER_0;
            if (value != 0x55) {
                _invalidFrames++;
                resetParser();
            }
            break;
        case ParserState::FOOTER_1:
            if (value == 0xCC) {
                handleFrame();
            } else {
                _invalidFrames++;
                resetParser();
            }
            break;
    }
}

void Ld2450::handleFrame() {
    _validFrames++;
    uint8_t validCount = 0;
    for (uint8_t i = 0; i < 3; i++) {
        const uint8_t* base = _payload + (i * 8);
        Target& target = _targets[i];
        target.xMm = readI16(base + 0);
        target.yMm = readI16(base + 2);
        target.speedCmS = readI16(base + 4);
        target.resolutionMm = readU16(base + 6);
        target.valid = !(target.xMm == 0 && target.yMm == 0 &&
                         target.speedCmS == 0 && target.resolutionMm == 0);
        if (target.valid) validCount++;
    }

    if (_debugPrint) printFrame(validCount);
    resetParser();
}

void Ld2450::printFrame(uint8_t validCount) {
    const uint32_t now = millis();

    if (validCount > 0) {
        Serial.printf("[LD2450] %lu ms targets=%u\n", (unsigned long)now, validCount);
        for (uint8_t i = 0; i < 3; i++) {
            const Target& target = _targets[i];
            if (!target.valid) continue;
            Serial.printf(
                "  T%u x=%d mm (%d cm) y=%d mm (%d cm) speed=%+d cm/s (%s) res=%u mm\n",
                i + 1,
                target.xMm, target.xMm / 10,
                target.yMm, target.yMm / 10,
                target.speedCmS, motionLabel(target.speedCmS),
                target.resolutionMm);
        }
        _lastNoTargetPrintMs = now;
    } else if (now - _lastNoTargetPrintMs >= 1000) {
        Serial.printf("[LD2450] %lu ms targets=0\n", (unsigned long)now);
        _lastNoTargetPrintMs = now;
    }

    if (now - _lastStatsPrintMs >= 5000) {
        Serial.printf("[LD2450] stats valid=%lu invalid=%lu dropped=%lu heap=%u\n",
                      (unsigned long)_validFrames,
                      (unsigned long)_invalidFrames,
                      (unsigned long)_droppedBytes,
                      (unsigned)ESP.getFreeHeap());
        _lastStatsPrintMs = now;
    }
}

int16_t Ld2450::readI16(const uint8_t* data) {
    return (int16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
}

uint16_t Ld2450::readU16(const uint8_t* data) {
    return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
}

const char* Ld2450::motionLabel(int16_t speedCmS) {
    if (speedCmS > 10) return "approaching";
    if (speedCmS < -10) return "receding";
    return "stationary";
}
