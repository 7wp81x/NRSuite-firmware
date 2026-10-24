#include "ir_remote.h"

#include <driver/rmt_common.h>
#include <driver/rmt_encoder.h>
#include <driver/rmt_rx.h>
#include <driver/rmt_tx.h>
#include <esp_err.h>
#include <esp_log.h>
#include <Preferences.h>
#include <new>

#include "BridgeProtocol.h"

namespace {
constexpr const char* TAG = "IrRemote";
constexpr uint32_t RMT_RESOLUTION_HZ = 1'000'000;
constexpr size_t IR_TX_MAX_TIMINGS = 1024;
constexpr int IR_TX_REPEAT_MAX = 10;
constexpr uint32_t IR_RX_IDLE_TIMEOUT_NS = 12'000'000;

#if defined(CONFIG_IDF_TARGET_ESP32C3)
static const int SAFE_IR_GPIOS[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
#elif defined(CONFIG_IDF_TARGET_ESP32C5)
// GPIO 11/12 are UART0, 13/14 are native USB, and 15-21 are flash/SPI.
static const int SAFE_IR_GPIOS[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 22, 23, 24, 25, 26, 27, 28,
};
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
// GPIO 19/20 are native USB, 26-37 are flash/PSRAM, and 43/44 are UART0.
static const int SAFE_IR_GPIOS[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    21, 38, 39, 40, 41, 42, 45, 46, 47, 48,
};
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
// GPIO 19/20 are native USB, 26-32 are flash, and 43/44 are UART0.
static const int SAFE_IR_GPIOS[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    21, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 45,
};
#else
// Classic ESP32: avoid boot strapping, flash, UART0, PSRAM, and input-only pins.
static const int SAFE_IR_GPIOS[] = {
    4, 5, 12, 13, 14, 15, 18, 19, 21, 22, 23, 25, 26, 27, 32, 33,
};
#endif
constexpr size_t SAFE_IR_GPIO_COUNT = sizeof(SAFE_IR_GPIOS) / sizeof(SAFE_IR_GPIOS[0]);
}  // namespace

void IrRemote::begin(BridgeProtocol& proto) {
    _proto = &proto;
    if (_txMutex == nullptr) {
        _txMutex = xSemaphoreCreateMutex();
    }
    loadConfig();
}

void IrRemote::update() {
    if (!_rxDone || !_rxActive) return;

    _rxDone = false;
    const bool overflow = _rxOverflow;
    const size_t symbolCount = _rxSymbolCount;
    if (symbolCount > 0) {
        JsonDocument event;
        event["frequency_hz"] = 38000;
        event["protocol"] = "RAW";
        event["gpio"] = _rxGpio;
        event["overflow"] = overflow;
        JsonArray timings = event["timings_us"].to<JsonArray>();
        for (size_t i = 0; i < symbolCount; i++) {
            const rmt_symbol_word_t symbol = _rxSymbols[i];
            if (symbol.duration0 > 0) timings.add(symbol.duration0);
            if (symbol.duration1 > 0) timings.add(symbol.duration1);
        }
        event["count"] = timings.size();
        if (_proto != nullptr) _proto->sendEvent("ir_rx", event);
    } else if (_proto != nullptr) {
        JsonDocument event;
        event["frequency_hz"] = 38000;
        event["protocol"] = "RAW";
        event["gpio"] = _rxGpio;
        event["overflow"] = overflow;
        event["count"] = 0;
        _proto->sendEvent("ir_rx", event);
    }

    if (_rxActive) {
        String error;
        if (!beginReceive(error)) {
            _rxActive = false;
            if (_proto != nullptr) {
                JsonDocument event;
                event["msg"] = error;
                _proto->sendEvent("ir_error", event);
            }
        }
    }
}

bool IrRemote::isSafePin(int gpio) const {
    for (size_t i = 0; i < SAFE_IR_GPIO_COUNT; i++) {
        if (SAFE_IR_GPIOS[i] == gpio) return true;
    }
    return false;
}

void IrRemote::loadConfig() {
    Preferences prefs;
    if (!prefs.begin("nrsuite", true)) return;
    _txGpio = prefs.getInt("ir_tx_gpio", -1);
    _rxGpio = prefs.getInt("ir_rx_gpio", -1);
    prefs.end();
    if (_txGpio >= 0 && !isSafePin(_txGpio)) _txGpio = -1;
    if (_rxGpio >= 0 && !isSafePin(_rxGpio)) _rxGpio = -1;
    setTxPinIdle();
}

void IrRemote::saveConfig() {
    Preferences prefs;
    if (!prefs.begin("nrsuite", false)) return;
    prefs.putInt("ir_tx_gpio", _txGpio);
    prefs.putInt("ir_rx_gpio", _rxGpio);
    prefs.end();
}

bool IrRemote::setPins(int txGpio, int rxGpio, String& error) {
    if (txGpio == rxGpio && txGpio >= 0) {
        error = "IR TX and RX GPIOs must be different";
        return false;
    }
    if (txGpio >= 0 && !isSafePin(txGpio)) {
        error = "Unsupported or unsafe IR TX GPIO";
        return false;
    }
    if (rxGpio >= 0 && !isSafePin(rxGpio)) {
        error = "Unsupported or unsafe IR RX GPIO";
        return false;
    }

    stopRx();
    stopTx();
    destroyChannels();
    _txGpio = txGpio;
    _rxGpio = rxGpio;
    saveConfig();
    setTxPinIdle();
    return true;
}

void IrRemote::setTxPinIdle() {
    if (_txGpio < 0) return;
    const gpio_num_t pin = static_cast<gpio_num_t>(_txGpio);
    gpio_reset_pin(pin);
    gpio_set_direction(pin, GPIO_MODE_OUTPUT);
    gpio_set_level(pin, 0);
}

bool IrRemote::ensureTxChannel(String& error) {
    if (_txGpio < 0) {
        error = "IR TX GPIO is not configured";
        return false;
    }
    if (_txChannel != nullptr && _copyEncoder != nullptr) return true;

    rmt_tx_channel_config_t config = {};
    config.gpio_num = static_cast<gpio_num_t>(_txGpio);
    config.clk_src = RMT_CLK_SRC_DEFAULT;
    config.resolution_hz = RMT_RESOLUTION_HZ;
    config.mem_block_symbols = 48;
    config.trans_queue_depth = 1;
    config.intr_priority = 0;
    config.flags.invert_out = false;
    config.flags.with_dma = false;
    config.flags.io_loop_back = false;
    config.flags.io_od_mode = false;
    config.flags.init_level = 0;

    esp_err_t err = rmt_new_tx_channel(&config, &_txChannel);
    if (err != ESP_OK) {
        error = String("rmt_new_tx_channel failed: ") + esp_err_to_name(err);
        _txChannel = nullptr;
        return false;
    }
    rmt_copy_encoder_config_t encoderConfig = {};
    err = rmt_new_copy_encoder(&encoderConfig, &_copyEncoder);
    if (err != ESP_OK) {
        error = String("rmt_new_copy_encoder failed: ") + esp_err_to_name(err);
        destroyChannels();
        return false;
    }
    err = rmt_enable(_txChannel);
    if (err != ESP_OK) {
        error = String("rmt_enable TX failed: ") + esp_err_to_name(err);
        destroyChannels();
        return false;
    }
    return true;
}

bool IrRemote::ensureRxChannel(String& error) {
    if (_rxGpio < 0) {
        error = "IR RX GPIO is not configured";
        return false;
    }
    if (_rxChannel != nullptr) return true;

    rmt_rx_channel_config_t config = {};
    config.gpio_num = static_cast<gpio_num_t>(_rxGpio);
    config.clk_src = RMT_CLK_SRC_DEFAULT;
    config.resolution_hz = RMT_RESOLUTION_HZ;
    // C3/C5 expose 48 RMT words per channel. Keep RX to one RMT memory
    // block so creating the receiver cannot exhaust the shared TX/RX pool.
    // 48 symbols is enough for NEC (34 symbols) and typical consumer remotes.
    config.mem_block_symbols = IR_RX_MAX_SYMBOLS;
    config.intr_priority = 0;
    config.flags.invert_in = true;
    config.flags.with_dma = false;
    config.flags.io_loop_back = false;

    esp_err_t err = rmt_new_rx_channel(&config, &_rxChannel);
    if (err != ESP_OK) {
        error = String("rmt_new_rx_channel failed: ") + esp_err_to_name(err);
        _rxChannel = nullptr;
        return false;
    }
    rmt_rx_event_callbacks_t callbacks = {};
    callbacks.on_recv_done = &IrRemote::onRxDone;
    err = rmt_rx_register_event_callbacks(_rxChannel, &callbacks, this);
    if (err != ESP_OK) {
        error = String("rmt_rx_register_event_callbacks failed: ") + esp_err_to_name(err);
        destroyChannels();
        return false;
    }
    err = rmt_enable(_rxChannel);
    if (err != ESP_OK) {
        error = String("rmt_enable RX failed: ") + esp_err_to_name(err);
        destroyChannels();
        return false;
    }
    return true;
}

bool IrRemote::beginReceive(String& error) {
    if (!ensureRxChannel(error)) return false;
    rmt_receive_config_t config = {};
    // Use the same conservative receive window as the ESP-IDF RMT examples.
    // The RMT idle threshold is expressed in channel ticks and must stay
    // below the hardware maximum (32767 ticks at 1 MHz). Disabling the glitch
    // filter avoids target-specific filter-clock validation issues.
    config.signal_range_min_ns = 0;
    config.signal_range_max_ns = IR_RX_IDLE_TIMEOUT_NS;
    config.flags.en_partial_rx = false;
    _rxDone = false;
    _rxOverflow = false;
    esp_err_t err = rmt_receive(_rxChannel, _rxSymbols, sizeof(_rxSymbols), &config);
    if (err != ESP_OK) {
        error = String("rmt_receive failed: ") + esp_err_to_name(err);
        return false;
    }
    return true;
}

bool IrRemote::startRx(String& error) {
    if (_rxGpio < 0) {
        error = "IR RX GPIO is not configured";
        return false;
    }
    if (_rxActive) return true;
    if (!beginReceive(error)) return false;
    _rxActive = true;
    return true;
}

void IrRemote::stopRx() {
    _rxActive = false;
    _rxDone = false;
    if (_rxChannel != nullptr) {
        rmt_disable(_rxChannel);
        rmt_enable(_rxChannel);
    }
}

void IrRemote::stopTx() {
    if (_txChannel != nullptr) {
        rmt_disable(_txChannel);
        rmt_apply_carrier(_txChannel, nullptr);
        rmt_enable(_txChannel);
    }
}

bool IrRemote::transmitRaw(
    uint32_t frequencyHz,
    int repeat,
    JsonArrayConst timings,
    String& error,
    size_t& timingCount
) {
    timingCount = timings.size();
    if (timingCount == 0) {
        error = "timings_us is empty";
        return false;
    }
    if (timingCount > IR_TX_MAX_TIMINGS) {
        error = "timings_us exceeds firmware limit";
        return false;
    }
    if (repeat < 1) repeat = 1;
    if (repeat > IR_TX_REPEAT_MAX) repeat = IR_TX_REPEAT_MAX;
    if (frequencyHz < 20000 || frequencyHz > 60000) frequencyHz = 38000;
    if (!ensureTxChannel(error)) return false;

    const size_t symbolCount = (timingCount + 1) / 2;
    auto* symbols = new (std::nothrow) rmt_symbol_word_t[symbolCount];
    if (symbols == nullptr) {
        error = "Not enough memory for IR timings";
        return false;
    }
    size_t timingIndex = 0;
    for (size_t i = 0; i < symbolCount; i++) {
        const uint32_t duration0 = static_cast<uint32_t>(timings[timingIndex++].as<long>());
        const uint32_t duration1 = timingIndex < timingCount
            ? static_cast<uint32_t>(timings[timingIndex++].as<long>())
            : 0;
        symbols[i].duration0 = min(duration0, 32767UL);
        symbols[i].level0 = 1;
        symbols[i].duration1 = min(duration1, 32767UL);
        symbols[i].level1 = 0;
    }

    if (_txMutex != nullptr) xSemaphoreTake(_txMutex, portMAX_DELAY);
    rmt_carrier_config_t carrier = {};
    carrier.frequency_hz = frequencyHz;
    carrier.duty_cycle = 0.33f;
    carrier.flags.polarity_active_low = 0;
    carrier.flags.always_on = 0;
    esp_err_t err = rmt_apply_carrier(_txChannel, &carrier);

    rmt_transmit_config_t txConfig = {};
    txConfig.loop_count = 0;
    txConfig.flags.eot_level = 0;
    txConfig.flags.queue_nonblocking = 0;
    for (int i = 0; i < repeat && err == ESP_OK; i++) {
        err = rmt_transmit(
            _txChannel,
            _copyEncoder,
            symbols,
            symbolCount * sizeof(rmt_symbol_word_t),
            &txConfig
        );
        if (err == ESP_OK) {
            err = rmt_tx_wait_all_done(_txChannel, 5000);
        }
    }
    if (_txMutex != nullptr) xSemaphoreGive(_txMutex);
    delete[] symbols;

    // Keep the RMT GPIO routing intact, but disable carrier modulation after
    // the transaction. The transaction's eot_level is already low, so the
    // external transistor/LED driver is returned to its idle-off state.
    if (_txChannel != nullptr) {
        rmt_apply_carrier(_txChannel, nullptr);
    }

    if (err != ESP_OK) {
        error = String("IR transmit failed: ") + esp_err_to_name(err);
        return false;
    }

    if (_proto != nullptr) {
        JsonDocument event;
        event["gpio"] = _txGpio;
        event["frequency_hz"] = frequencyHz;
        event["repeat"] = repeat;
        event["timings"] = timingCount;
        _proto->sendEvent("ir_tx_done", event);
    }
    return true;
}

void IrRemote::appendStatus(JsonDocument& doc) const {
    doc["ir_tx_gpio"] = _txGpio;
    doc["ir_rx_gpio"] = _rxGpio;
    doc["ir_rx_active"] = _rxActive;
    doc["ir_tx_active"] = false;
    doc["ir_rx_max_symbols"] = IR_RX_MAX_SYMBOLS;
    doc["ir_tx_max_timings"] = IR_TX_MAX_TIMINGS;
}

void IrRemote::appendPinOptions(JsonDocument& doc) const {
    JsonArray txPins = doc["ir_tx_gpios"].to<JsonArray>();
    JsonArray rxPins = doc["ir_rx_gpios"].to<JsonArray>();
    for (size_t i = 0; i < SAFE_IR_GPIO_COUNT; i++) {
        txPins.add(SAFE_IR_GPIOS[i]);
        rxPins.add(SAFE_IR_GPIOS[i]);
    }
}

void IrRemote::destroyChannels() {
    _rxActive = false;
    _rxDone = false;
    if (_rxChannel != nullptr) {
        rmt_disable(_rxChannel);
        rmt_del_channel(_rxChannel);
        _rxChannel = nullptr;
    }
    if (_txChannel != nullptr) {
        rmt_disable(_txChannel);
        rmt_del_channel(_txChannel);
        _txChannel = nullptr;
    }
    if (_copyEncoder != nullptr) {
        rmt_del_encoder(_copyEncoder);
        _copyEncoder = nullptr;
    }
    setTxPinIdle();
}

bool IrRemote::onRxDone(
    rmt_channel_handle_t channel,
    const rmt_rx_done_event_data_t* event,
    void* userCtx
) {
    (void)channel;
    auto* self = static_cast<IrRemote*>(userCtx);
    if (self == nullptr || event == nullptr) return false;
    self->_rxSymbolCount = min<size_t>(event->num_symbols, IR_RX_MAX_SYMBOLS);
    self->_rxOverflow = !event->flags.is_last || event->num_symbols >= IR_RX_MAX_SYMBOLS;
    self->_rxDone = true;
    return false;
}
