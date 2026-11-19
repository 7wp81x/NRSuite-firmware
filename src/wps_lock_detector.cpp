#include "wps_lock_detector.h"
#include "wps_parser.h"

#include <cstring>

namespace {
constexpr uint8_t WIFI_2G_CHANNELS[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
constexpr uint8_t WIFI_5G_CHANNELS[] = {
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165, 169, 173, 177,
};
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

WpsLockDetector* WpsLockDetector::instance_ = nullptr;

void WpsLockDetector::begin(BridgeProtocol& proto) {
    proto_ = &proto;
    instance_ = this;
}

static void copySsid(char out[33], const uint8_t* data, size_t length) {
    if (length > 32) length = 32;
    if (data != nullptr && length > 0) {
        memcpy(out, data, length);
    }
    out[length] = '\0';
}

void WpsLockDetector::promiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (instance_ == nullptr || type != WIFI_PKT_MGMT || buf == nullptr) return;
    instance_->handlePacket(static_cast<const wifi_promiscuous_pkt_t*>(buf));
}

void WpsLockDetector::handlePacket(const wifi_promiscuous_pkt_t* pkt) {
    const uint8_t* frame = pkt->payload;
    const size_t length = pkt->rx_ctrl.sig_len;
    if (frame == nullptr || length < 36) return;

    const uint8_t frameControl = frame[0];
    const uint8_t type = (frameControl >> 2) & 0x03;
    const uint8_t subtype = (frameControl >> 4) & 0x0f;
    if (type != 0 || (subtype != 8 && subtype != 5)) return; // beacon or probe response

    ApRecord record;
    memcpy(record.bssid, frame + 16, 6);
    record.channel = pkt->rx_ctrl.channel != 0 ? pkt->rx_ctrl.channel : currentChannel_;
    record.rssi = pkt->rx_ctrl.rssi;
    record.lastSeenMs = millis();

    const uint16_t capability = static_cast<uint16_t>(frame[34]) |
        (static_cast<uint16_t>(frame[35]) << 8);
    const bool privacy = (capability & 0x0010) != 0;
    bool hasRsn = false;
    bool hasWpa = false;
    bool hasWps = false;
    uint8_t dsChannel = 0;

    size_t offset = 36;
    while (offset + 2 <= length) {
        const uint8_t elementId = frame[offset];
        const uint8_t elementLength = frame[offset + 1];
        offset += 2;
        if (elementLength > length - offset) break;
        const uint8_t* value = frame + offset;

        if (elementId == 0) {
            copySsid(record.ssid, value, elementLength);
        } else if (elementId == 3 && elementLength >= 1) {
            dsChannel = value[0];
        } else if (elementId == 48) {
            hasRsn = true;
        } else if (elementId == 221 && elementLength >= 4) {
            const bool wfaOui = value[0] == 0x00 && value[1] == 0x50 && value[2] == 0xf2;
            if (wfaOui && value[3] == 0x01) {
                hasWpa = true;
            } else if (wfaOui && value[3] == 0x04) {
                hasWps = true;
                wps::WpsAttributes attributes;
                if (attributes.parse(value + 4, elementLength - 4)) {
                    record.wpsParsed = true;
                    const wps::WpsAttribute* version = attributes.find(wps::ATTR_VERSION);
                    if (version != nullptr && version->length >= 1) {
                        record.wpsVersion = version->value[0];
                    }
                    const wps::WpsAttribute* config = attributes.find(wps::ATTR_CONFIG_METHODS);
                    if (config != nullptr && config->length >= 2) {
                        record.configMethods = wps::readBe16(config->value);
                    }
                    const wps::WpsAttribute* selected =
                        attributes.find(wps::ATTR_SELECTED_REGISTRAR);
                    if (selected != nullptr && selected->length >= 1) {
                        record.selectedRegistrar = selected->value[0] != 0;
                    }
                    const wps::WpsAttribute* locked =
                        attributes.find(wps::ATTR_AP_SETUP_LOCKED);
                    if (locked != nullptr && locked->length >= 1) {
                        record.lockReported = true;
                        record.apSetupLocked = locked->value[0] != 0;
                    }
                }
            }
        }
        offset += elementLength;
    }

    if (dsChannel != 0) record.channel = dsChannel;
    if (record.channel == 0) return;
    if (hasRsn) {
        strncpy(record.security, "WPA2/3", sizeof(record.security) - 1);
    } else if (hasWpa) {
        strncpy(record.security, "WPA", sizeof(record.security) - 1);
    } else if (privacy) {
        strncpy(record.security, "PRIVATE", sizeof(record.security) - 1);
    } else {
        strncpy(record.security, "OPEN", sizeof(record.security) - 1);
    }

    // The lock detector only reports WPS-enabled APs.
    if (!hasWps) return;
    record.wps = true;
    record.activeScan = false;
    upsert(record);
}

void WpsLockDetector::upsert(const ApRecord& record) {
    wpsScanMergeRecord(
        records_,
        recordCount_,
        sizeof(records_) / sizeof(records_[0]),
        record
    );
}

void WpsLockDetector::discoverActiveWpsCandidates(bool include5ghz, bool includeNonWps) {
    wifi_scan_config_t scanConfig = {};
    scanConfig.show_hidden = true;
    scanConfig.scan_type = WIFI_SCAN_TYPE_ACTIVE;
    scanConfig.scan_time.active.min = 100;
#if defined(CONFIG_IDF_TARGET_ESP32)
    // Match the classic ESP32 SCAN_WIFI default: short active scans are
    // noticeably less reliable on this target.
    scanConfig.scan_time.active.max = 500;
#else
    scanConfig.scan_time.active.max = 300;
#endif

    if (esp_wifi_scan_start(&scanConfig, true) != ESP_OK) {
        return;
    }

    uint16_t apCount = 0;
    if (esp_wifi_scan_get_ap_num(&apCount) == ESP_OK && apCount > 0) {
        wifi_ap_record_t* records = (wifi_ap_record_t*)malloc(
            apCount * sizeof(wifi_ap_record_t)
        );
        if (records != nullptr) {
            uint16_t fetched = apCount;
            if (esp_wifi_scan_get_ap_records(&fetched, records) == ESP_OK) {
                for (uint16_t index = 0; index < fetched; ++index) {
                    if (!includeNonWps && !records[index].wps) continue;
                    if (!include5ghz && records[index].primary >= 36) continue;

                    ApRecord candidate;
                    candidate.activeScan = true;
                    candidate.wps = records[index].wps;
                    candidate.channel = records[index].primary;
                    candidate.rssi = records[index].rssi;
                    candidate.lastSeenMs = millis();
                    memcpy(candidate.ssid, records[index].ssid, sizeof(candidate.ssid));
                    candidate.ssid[sizeof(candidate.ssid) - 1] = '\0';
                    memcpy(candidate.bssid, records[index].bssid, sizeof(candidate.bssid));
                    wpsScanCopyText(
                        candidate.security,
                        sizeof(candidate.security),
                        authModeStr(records[index].authmode)
                    );
                    upsert(candidate);
                }
            }
            free(records);
        }
    }
    esp_wifi_scan_stop();
}

int WpsLockDetector::scan(
    bool include5ghz,
    uint16_t dwellMs,
    bool emitEvents,
    bool includeNonWps
) {
    recordCount_ = 0;
    memset(records_, 0, sizeof(records_));
    if (dwellMs < 60) dwellMs = 60;
    if (dwellMs > 1000) dwellMs = 1000;

    // Active discovery first: this is the same discovery capability used by
    // SCAN_WIFI and is authoritative for the candidate set and radio fields.
    // The passive pass below only enriches WPS IE metadata.
    discoverActiveWpsCandidates(include5ghz, includeNonWps);

    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&WpsLockDetector::promiscuousCb);
    esp_wifi_set_promiscuous(true);

    for (uint8_t channel : WIFI_2G_CHANNELS) {
        currentChannel_ = channel;
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        delay(dwellMs);
    }
    if (include5ghz) {
        for (uint8_t channel : WIFI_5G_CHANNELS) {
            currentChannel_ = channel;
            esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
            delay(dwellMs);
        }
    }

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    currentChannel_ = 0;

    if (proto_ == nullptr || !emitEvents) return (int)recordCount_;
    int emitted = 0;
    for (size_t index = 0; index < recordCount_; ++index) {
        const ApRecord& record = records_[index];
        char bssid[18];
        snprintf(
            bssid,
            sizeof(bssid),
            "%02X:%02X:%02X:%02X:%02X:%02X",
            record.bssid[0], record.bssid[1], record.bssid[2],
            record.bssid[3], record.bssid[4], record.bssid[5]
        );

        JsonDocument event;
        event["ssid"] = record.ssid;
        event["bssid"] = bssid;
        event["channel"] = record.channel;
        event["rssi"] = record.rssi;
        event["security"] = record.security;
        event["wps"] = record.wps;
        if (record.wps) {
            event["wps_parsed"] = record.wpsParsed;
            event["lock_reported"] = record.lockReported;
            event["ap_setup_locked"] = record.apSetupLocked;
            event["wps_version"] = record.wpsVersion;
            event["config_methods"] = record.configMethods;
            event["selected_registrar"] = record.selectedRegistrar;
            event["last_seen_ms"] = record.lastSeenMs;
            proto_->sendEvent("wps_lock_ap", event);
        } else {
            event["band"] = record.channel >= 36 ? "5g" : "2g";
            proto_->sendEvent("scan_ap", event);
        }
        // Match the scan-event pacing used by SCAN_WIFI. WPS AP events are
        // larger, so sending several back-to-back can overrun UART bridges.
        proto_->flushActive();
        delay(2);
        emitted++;
    }
    return emitted;
}

void WpsLockDetector::appendResults(ScanResultStore& store) const {
    for (size_t index = 0; index < recordCount_; ++index) {
        const ApRecord& source = records_[index];
        ScanResultStore::Record record;
        memcpy(record.ssid, source.ssid, sizeof(record.ssid));
        memcpy(record.bssid, source.bssid, sizeof(record.bssid));
        record.channel = source.channel;
        record.rssi = source.rssi;
        strncpy(record.security, source.security, sizeof(record.security) - 1);
        record.security[sizeof(record.security) - 1] = '\0';
        record.wps = source.wps;
        record.band = source.channel >= 36 ? 1 : 0;
        record.wpsParsed = source.wpsParsed;
        record.lockReported = source.lockReported;
        record.apSetupLocked = source.apSetupLocked;
        record.wpsVersion = source.wpsVersion;
        record.configMethods = source.configMethods;
        record.selectedRegistrar = source.selectedRegistrar;
        record.lastSeenMs = source.lastSeenMs;
        store.add(record);
    }
}
