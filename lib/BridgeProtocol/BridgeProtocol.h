#pragma once
#include <Arduino.h>
#include <ArduinoJson.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include "ProtocolSpec.h"

#define PROTO_RX_BUF_SIZE   (PROTO_MAX_CHUNK + PROTO_HEADER_SZ + 64)
#define PROTO_MAX_TRANSPORTS 2

// ── Parsed frame ─────────────────────────────────────────────────────────────
struct ProtoFrame {
    uint8_t  type;
    uint8_t  id;
    uint32_t length;
    uint8_t* payload;   // points into internal buffer — copy if you need it later
    bool     valid;
};

// ── Callbacks ─────────────────────────────────────────────────────────────────
using CmdCallback   = void (*)(uint8_t id, JsonDocument& doc);
using AckCallback   = void (*)(uint32_t chunk_index);
using HtmlCallback = void (*)(const uint8_t* data, size_t len);


// ── BridgeProtocol ────────────────────────────────────────────────────────────
class BridgeProtocol {
public:
    BridgeProtocol(Stream& stream, const char* transportName = "uart0") {
        addTransport(stream, transportName);
    }

    // Register an additional physical transport. At most two are supported:
    // one native USB CDC/JTAG stream and one UART stream.
    void addTransport(Stream& stream, const char* transportName);

    // Initialise transport-level state (TX mutex). Call once from setup().
    void begin();

    // Register handlers
    void onCmd(CmdCallback cb)  { _onCmd = cb; }
    void onAck(AckCallback cb)  { _onAck = cb; }

    // Call from loop() — processes all available incoming bytes
    void update();

    // Send helpers. Responses and asynchronous events go to the currently
    // active transport, selected by the most recent valid incoming frame.
    void sendResp(uint8_t id, bool ok, const char* msg = nullptr);
    void sendEvent(const char* type, JsonDocument& doc);
    void sendPcapChunk(uint8_t chunk_idx, const uint8_t* data, uint32_t len);
    void sendRaw(uint8_t type, uint8_t id, const uint8_t* payload, uint32_t len);
    // Wait for the active transport's transmit buffer to drain. Used before an
    // explicit reboot so the acknowledgement reaches the host first.
    void flushActive();
    uint32_t oversizedFrameCount() const { return _oversizedFrames; }
    void onHtml(HtmlCallback cb) { _onHtml = cb; }
    const char* activeTransportName() const;

private:
    struct Transport {
        Stream* stream = nullptr;
        const char* name = "unknown";
        uint8_t buf[PROTO_RX_BUF_SIZE] = {};
        uint32_t bufLen = 0;
    };

    Transport _transports[PROTO_MAX_TRANSPORTS];
    uint8_t _transportCount = 0;
    uint8_t _activeTransport = 0;

    CmdCallback _onCmd = nullptr;
    AckCallback _onAck = nullptr;
    SemaphoreHandle_t _txMutex = nullptr;

    bool     _tryParse(Transport& transport);
    void     _dispatch(ProtoFrame& f, Transport& transport);
    void     _resync(Transport& transport);
    uint32_t _oversizedFrames = 0;
    HtmlCallback _onHtml = nullptr;
};
