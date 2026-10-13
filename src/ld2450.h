#pragma once

#include <Arduino.h>

/**
 * HLK-LD2450 24 GHz mmWave radar UART driver.
 *
 * Parses the standard 30-byte target frame:
 *
 *   AA FF 03 00
 *   target 1: X i16, Y i16, speed i16, resolution u16
 *   target 2: X i16, Y i16, speed i16, resolution u16
 *   target 3: X i16, Y i16, speed i16, resolution u16
 *   55 CC
 *
 * X/Y are millimetres, speed is cm/s, and resolution is millimetres.
 * X/Y/speed use sign bit + 15-bit magnitude (not two's-complement):
 *   bit 15 = 1 -> positive, bit 15 = 0 -> negative.
 */
class Ld2450 {
public:
    struct Target {
        bool valid = false;
        int16_t xMm = 0;
        int16_t yMm = 0;
        int16_t speedCmS = 0;
        uint16_t resolutionMm = 0;
    };

    bool begin(HardwareSerial& serial, uint32_t baud, int8_t rxPin, int8_t txPin,
               bool debugPrint = false);
    void update();
    void stop();
    void setDebugPrint(bool enabled) { _debugPrint = enabled; }

    bool active() const { return _active; }
    bool debugPrint() const { return _debugPrint; }
    bool hasData() const { return _validFrames > 0; }
    uint32_t validFrames() const { return _validFrames; }
    uint32_t invalidFrames() const { return _invalidFrames; }
    uint32_t droppedBytes() const { return _droppedBytes; }
    uint32_t lastFrameMs() const { return _lastFrameMs; }
    uint8_t targetCount() const { return _targetCount; }
    const Target* targets() const { return _targets; }

private:
    enum class ParserState : uint8_t {
        HEADER_0,
        HEADER_1,
        HEADER_2,
        HEADER_3,
        TARGETS,
        FOOTER_0,
        FOOTER_1,
    };

    HardwareSerial* _serial = nullptr;
    bool _active = false;
    bool _debugPrint = false;

    ParserState _state = ParserState::HEADER_0;
    uint8_t _payload[24] = {0};
    uint8_t _payloadPos = 0;
    uint32_t _validFrames = 0;
    uint32_t _invalidFrames = 0;
    uint32_t _droppedBytes = 0;
    uint32_t _lastFrameMs = 0;
    uint32_t _lastNoTargetPrintMs = 0;
    uint32_t _lastStatsPrintMs = 0;
    uint32_t _rawPrintCounter = 0;
    uint8_t _targetCount = 0;

    Target _targets[3];

    void resetParser();
    void resetTargets();
    void handleByte(uint8_t value);
    void handleFrame();
    void printFrame(uint8_t validCount);
    void printRawFrame();
    static int16_t readI16(const uint8_t* data);
    static uint16_t readU16(const uint8_t* data);
    static const char* motionLabel(int16_t speedCmS);
};
