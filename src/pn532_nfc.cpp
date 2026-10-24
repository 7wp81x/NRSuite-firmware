#include "pn532_nfc.h"

#include <Adafruit_PN532.h>
#include <Preferences.h>
#include <Wire.h>

#include "BridgeProtocol.h"

// The Adafruit PN532 library keeps the full InListPassiveTarget response in
// this global buffer. readPassiveTargetID() only copies the UID, so we read
// the adjacent SENS_RES (ATQA) and SEL_RES (SAK) fields from the same frame.
extern byte pn532_packetbuffer[64];

namespace {
constexpr uint32_t PN532_I2C_CLOCK_HZ = 100000;
constexpr uint32_t PN532_POLL_INTERVAL_MS = 120;
constexpr uint32_t PN532_TAG_REPEAT_MS = 2500;
constexpr uint32_t PN532_ERROR_EVENT_INTERVAL_MS = 5000;
constexpr uint16_t PN532_POLL_TIMEOUT_MS = 120;

#if defined(CONFIG_IDF_TARGET_ESP32C3)
// GPIO 12-17 are flash, 18/19 are native USB, and 20/21 are UART0.
static const int SAFE_PN532_GPIOS[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
#elif defined(CONFIG_IDF_TARGET_ESP32C5)
// GPIO 11/12 are UART0, 13/14 are native USB, and 15-21 are flash/SPI.
static const int SAFE_PN532_GPIOS[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 22, 23, 24, 25, 26, 27, 28,
};
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
// GPIO 19/20 are native USB, 26-37 are flash/PSRAM, and 43/44 are UART0.
static const int SAFE_PN532_GPIOS[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    21, 38, 39, 40, 41, 42, 45, 46, 47, 48,
};
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
// GPIO 19/20 are native USB, 26-32 are flash, and 43/44 are UART0.
static const int SAFE_PN532_GPIOS[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    21, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 45,
};
#else
// Classic ESP32: avoid boot strapping, flash, UART0, PSRAM, and input-only pins.
static const int SAFE_PN532_GPIOS[] = {
    4, 5, 12, 13, 14, 15, 18, 19, 21, 22, 23, 25, 26, 27, 32, 33,
};
#endif
constexpr size_t SAFE_PN532_GPIO_COUNT =
    sizeof(SAFE_PN532_GPIOS) / sizeof(SAFE_PN532_GPIOS[0]);

String uidToHex(const uint8_t* uid, uint8_t uidLength) {
    static const char HEX_CHARS[] = "0123456789ABCDEF";
    String out;
    out.reserve(uidLength * 2);
    for (uint8_t i = 0; i < uidLength; i++) {
        out += HEX_CHARS[(uid[i] >> 4) & 0x0F];
        out += HEX_CHARS[uid[i] & 0x0F];
    }
    return out;
}
}  // namespace

void Pn532Nfc::begin(BridgeProtocol& proto) {
    _proto = &proto;
    loadConfig();
}

void Pn532Nfc::loadConfig() {
    Preferences prefs;
    if (!prefs.begin("nrsuite", true)) return;
    _sdaGpio = prefs.getInt("rfid_sda_gpio", -1);
    _sclGpio = prefs.getInt("rfid_scl_gpio", -1);
    prefs.end();

    if (_sdaGpio >= 0 && !isSafePin(_sdaGpio)) _sdaGpio = -1;
    if (_sclGpio >= 0 && !isSafePin(_sclGpio)) _sclGpio = -1;
    if (_sdaGpio == _sclGpio) {
        _sdaGpio = -1;
        _sclGpio = -1;
    }
}

void Pn532Nfc::saveConfig() {
    Preferences prefs;
    if (!prefs.begin("nrsuite", false)) return;
    prefs.putInt("rfid_sda_gpio", _sdaGpio);
    prefs.putInt("rfid_scl_gpio", _sclGpio);
    prefs.end();
}

bool Pn532Nfc::isSafePin(int gpio) const {
    for (size_t i = 0; i < SAFE_PN532_GPIO_COUNT; i++) {
        if (SAFE_PN532_GPIOS[i] == gpio) return true;
    }
    return false;
}

void Pn532Nfc::appendGpioOptions(JsonDocument& doc) const {
    JsonArray pins = doc["rfid_gpios"].to<JsonArray>();
    for (size_t i = 0; i < SAFE_PN532_GPIO_COUNT; i++) {
        pins.add(SAFE_PN532_GPIOS[i]);
    }
}

void Pn532Nfc::appendStatus(JsonDocument& doc) const {
    doc["connected"] = _connected;
    doc["configured"] = configured();
    doc["interface"] = "i2c";
    doc["sda_gpio"] = _sdaGpio;
    doc["scl_gpio"] = _sclGpio;
    doc["firmware_version"] = _firmwareVersionText[0] == '\0'
        ? String("")
        : String(_firmwareVersionText);
    doc["firmware_version_raw"] = _firmwareVersion;
    doc["scanning"] = _scanning;
    doc["tag_read_only"] = true;
    appendGpioOptions(doc);
}

void Pn532Nfc::releaseReader() {
    _connected = false;
    _firmwareVersion = 0;
    _firmwareVersionText[0] = '\0';
    if (_reader != nullptr) {
        delete _reader;
        _reader = nullptr;
    }
    Wire.end();
}

bool Pn532Nfc::initializeReader(String& error) {
    if (!configured()) {
        error = "Configure PN532 I2C SDA and SCL GPIOs first";
        return false;
    }

    _scanning = false;
    releaseReader();

    Wire.begin(_sdaGpio, _sclGpio, PN532_I2C_CLOCK_HZ);
    Wire.setClock(PN532_I2C_CLOCK_HZ);
    Wire.setTimeOut(50);
    delay(80);

    // First verify that something ACKs at the PN532's fixed 7-bit address.
    // This distinguishes a wiring/power/interface-mode problem from a PN532
    // protocol problem and produces a useful app-side error.
    uint8_t probeError = 0xFF;
    for (uint8_t attempt = 0; attempt < 3; attempt++) {
        Wire.beginTransmission(PN532_I2C_ADDRESS);
        probeError = Wire.endTransmission();
        if (probeError == 0) break;
        delay(50);
    }
    if (probeError != 0) {
        error = "No I2C ACK at 0x24 (error ";
        error += String(probeError);
        error += "). Check PN532 power, common ground, SDA/SCL wiring, I2C mode switch, and pull-ups.";
        releaseReader();
        return false;
    }

    // The no-IRQ/no-reset constructor uses -1 sentinel pins. Adafruit's
    // begin() reuses the already-configured Wire pins and performs the
    // wakeup/SAM-configuration sequence; do not remove this or some modules
    // will ACK their address but never answer GetFirmwareVersion.
    _reader = new Adafruit_PN532(
        static_cast<uint8_t>(-1),
        static_cast<uint8_t>(-1),
        &Wire
    );
    if (_reader == nullptr) {
        error = "Not enough memory to initialize PN532";
        Wire.end();
        return false;
    }
    _reader->begin();
    delay(10);

    uint32_t version = 0;
    for (uint8_t attempt = 0; attempt < 5 && version == 0; attempt++) {
        version = _reader->getFirmwareVersion();
        if (version == 0) delay(50);
    }
    if (version == 0) {
        error = "I2C device ACKed at 0x24 but PN532 firmware version did not respond. Check that the interface switch is set to I2C and that SDA/SCL are not swapped.";
        releaseReader();
        return false;
    }

    if (!_reader->SAMConfig()) {
        error = "PN532 detected but SAM configuration failed";
        releaseReader();
        return false;
    }

    _firmwareVersion = version;
    snprintf(
        _firmwareVersionText,
        sizeof(_firmwareVersionText),
        "%u.%u",
        static_cast<unsigned>((version >> 16) & 0xFF),
        static_cast<unsigned>((version >> 8) & 0xFF)
    );
    _connected = true;
    _lastPollMs = 0;
    _lastTagEventMs = 0;
    _lastUid = "";
    return true;
}

bool Pn532Nfc::ensureConnected(String& error) {
    if (_connected && _reader != nullptr) return true;
    return initializeReader(error);
}

bool Pn532Nfc::setConfig(
    const char* interfaceName,
    int sdaGpio,
    int sclGpio,
    String& error
) {
    if (interfaceName == nullptr || strcmp(interfaceName, "i2c") != 0) {
        error = "Only the i2c interface is supported";
        return false;
    }
    if (sdaGpio == sclGpio) {
        error = "PN532 SDA and SCL GPIOs must be different";
        return false;
    }
    if (!isSafePin(sdaGpio)) {
        error = "Unsupported or unsafe PN532 SDA GPIO";
        return false;
    }
    if (!isSafePin(sclGpio)) {
        error = "Unsupported or unsafe PN532 SCL GPIO";
        return false;
    }

    stopScan();
    releaseReader();
    _sdaGpio = sdaGpio;
    _sclGpio = sclGpio;
    saveConfig();

    if (!initializeReader(error)) {
        // The GPIO configuration is valid and has been persisted. Detection is
        // reported separately in the response/status so the user can correct
        // wiring and retry without having to re-enter the pins.
        emitErrorEvent("config", error);
        emitStatusEvent();
        return true;
    }
    emitStatusEvent();
    return true;
}

bool Pn532Nfc::startScan(String& error) {
    if (_scanning) return true;
    if (!ensureConnected(error)) {
        emitErrorEvent("start", error);
        return false;
    }
    _scanning = true;
    _lastPollMs = 0;
    _lastUid = "";
    emitStatusEvent();
    return true;
}

void Pn532Nfc::stopScan() {
    if (!_scanning) return;
    _scanning = false;
    emitStatusEvent();
}

const char* Pn532Nfc::classifyTag(uint16_t atqa, uint8_t sak) const {
    if (sak == 0x08) return "MIFARE Classic 1K";
    if (sak == 0x18) return "MIFARE Classic 4K";
    if (sak == 0x09) return "MIFARE Classic Mini";
    if (sak == 0x00) {
        if (atqa == 0x0044) return "NTAG / MIFARE Ultralight";
        return "MIFARE Ultralight / NTAG";
    }
    if ((sak & 0x20) != 0) return "ISO14443-4";
    if (sak == 0x28) return "SmartMX / ISO14443-4";
    return "ISO14443A";
}

void Pn532Nfc::update() {
    if (!_scanning || !_connected || _reader == nullptr) return;

    const uint32_t now = millis();
    if (_lastPollMs != 0 && now - _lastPollMs < PN532_POLL_INTERVAL_MS) return;
    _lastPollMs = now;

    uint8_t uid[10] = {0};
    uint8_t uidLength = 0;
    if (!_reader->readPassiveTargetID(
            PN532_MIFARE_ISO14443A,
            uid,
            &uidLength,
            PN532_POLL_TIMEOUT_MS
        )) {
        return;
    }
    if (uidLength == 0 || uidLength > sizeof(uid)) return;

    // InListPassiveTarget response:
    //   [9..10] SENS_RES (ATQA), [11] SEL_RES (SAK), [12] UID length,
    //   [13..] UID. The Adafruit helper copies the UID but leaves this frame.
    const uint8_t atqa0 = pn532_packetbuffer[9];
    const uint8_t atqa1 = pn532_packetbuffer[10];
    const uint8_t sak = pn532_packetbuffer[11];
    const uint16_t atqa = (static_cast<uint16_t>(atqa0) << 8) | atqa1;

    const String uidHex = uidToHex(uid, uidLength);
    if (uidHex == _lastUid && now - _lastTagEventMs < PN532_TAG_REPEAT_MS) {
        return;
    }
    _lastUid = uidHex;

    JsonDocument event;
    event["uid"] = uidHex;
    char atqaText[5];
    snprintf(atqaText, sizeof(atqaText), "%04X", atqa);
    event["atqa"] = atqaText;
    char sakText[3];
    snprintf(sakText, sizeof(sakText), "%02X", sak);
    event["sak"] = sakText;
    event["type"] = classifyTag(atqa, sak);
    event["timestamp_ms"] = now;
    event["read_only"] = true;
    _lastTagEventMs = now;
    if (_proto != nullptr) _proto->sendEvent("rfid_tag", event);
}

void Pn532Nfc::emitStatusEvent() {
    if (_proto == nullptr) return;
    JsonDocument event;
    appendStatus(event);
    _proto->sendEvent("rfid_status", event);
}

void Pn532Nfc::emitErrorEvent(const char* kind, const String& message) {
    if (_proto == nullptr) return;
    const uint32_t now = millis();
    if (_lastErrorEventMs != 0 &&
        now - _lastErrorEventMs < PN532_ERROR_EVENT_INTERVAL_MS) {
        return;
    }
    _lastErrorEventMs = now;
    JsonDocument event;
    event["kind"] = kind != nullptr ? kind : "error";
    event["msg"] = message;
    event["connected"] = _connected;
    event["scanning"] = _scanning;
    _proto->sendEvent("rfid_error", event);
}
