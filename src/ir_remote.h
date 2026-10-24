#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>
#include <driver/gpio.h>
#include <driver/rmt_types.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#ifndef IR_RX_MAX_SYMBOLS
#define IR_RX_MAX_SYMBOLS 48
#endif

class BridgeProtocol;

class IrRemote {
public:
    void begin(BridgeProtocol& proto);
    void update();

    bool setPins(int txGpio, int rxGpio, String& error);
    bool startRx(String& error);
    void stopRx();
    bool transmitRaw(
        uint32_t frequencyHz,
        int repeat,
        JsonArrayConst timings,
        String& error,
        size_t& timingCount
    );
    void stopTx();

    void appendStatus(JsonDocument& doc) const;
    void appendPinOptions(JsonDocument& doc) const;
    bool rxActive() const { return _rxActive; }
    int txGpio() const { return _txGpio; }
    int rxGpio() const { return _rxGpio; }

private:
    static bool onRxDone(
        rmt_channel_handle_t channel,
        const rmt_rx_done_event_data_t* event,
        void* userCtx
    );
    bool ensureRxChannel(String& error);
    bool ensureTxChannel(String& error);
    bool beginReceive(String& error);
    void destroyChannels();
    bool isSafePin(int gpio) const;
    void loadConfig();
    void saveConfig();
    void setTxPinIdle();

    BridgeProtocol* _proto = nullptr;
    rmt_channel_handle_t _rxChannel = nullptr;
    rmt_channel_handle_t _txChannel = nullptr;
    rmt_encoder_handle_t _copyEncoder = nullptr;
    SemaphoreHandle_t _txMutex = nullptr;
    int _txGpio = -1;
    int _rxGpio = -1;
    bool _rxActive = false;
    volatile bool _rxDone = false;
    volatile bool _rxOverflow = false;
    volatile size_t _rxSymbolCount = 0;
    alignas(4) rmt_symbol_word_t _rxSymbols[IR_RX_MAX_SYMBOLS];
};
