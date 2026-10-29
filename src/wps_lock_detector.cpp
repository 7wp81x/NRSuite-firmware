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
                        record.locked = locked->value[0] != 0;
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
    upsert(record);
}

void WpsLockDetector::upsert(const ApRecord& record) {
    for (size_t index = 0; index < recordCount_; ++index) {
        if (memcmp(records_[index].bssid, record.bssid, 6) == 0) {
            records_[index] = record;
            return;
        }
    }
    if (recordCount_ < sizeof(records_) / sizeof(records_[0])) {
        records_[recordCount_++] = record;
    }
}

int WpsLockDetector::scan(bool include5ghz, uint16_t dwellMs) {
    recordCount_ = 0;
    memset(records_, 0, sizeof(records_));
    if (dwellMs < 60) dwellMs = 60;
    if (dwellMs > 1000) dwellMs = 1000;

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

    if (proto_ == nullptr) return 0;
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
        event["type"] = "wps_lock_ap";
        event["ssid"] = record.ssid;
        event["bssid"] = bssid;
        event["channel"] = record.channel;
        event["rssi"] = record.rssi;
        event["security"] = record.security;
        event["wps"] = true;
        event["wps_parsed"] = record.wpsParsed;
        event["lock_reported"] = record.lockReported;
        event["ap_setup_locked"] = record.locked;
        event["wps_version"] = record.wpsVersion;
        event["config_methods"] = record.configMethods;
        event["selected_registrar"] = record.selectedRegistrar;
        event["last_seen_ms"] = record.lastSeenMs;
        proto_->sendEvent("wps_lock_ap", event);
        emitted++;
    }
    return emitted;
}
