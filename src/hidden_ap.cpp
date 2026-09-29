#include "hidden_ap.h"

HiddenApDetector* HiddenApDetector::_instance = nullptr;

static bool findSsidIe(
    const uint8_t* p,
    size_t len,
    size_t offset,
    char* out,
    size_t outSize,
    bool* present
) {
    if (present) *present = false;
    if (!p || !out || outSize == 0) return false;
    out[0] = '\0';

    while (offset + 2 <= len) {
        uint8_t id = p[offset];
        uint8_t ieLen = p[offset + 1];
        if (offset + 2 + ieLen > len) break;

        if (id == 0) {
            if (present) *present = true;
            size_t copyLen = ieLen < (outSize - 1) ? ieLen : (outSize - 1);
            if (copyLen > 0) memcpy(out, p + offset + 2, copyLen);
            out[copyLen] = '\0';
            return copyLen > 0;
        }
        offset += 2 + ieLen;
    }
    return false;
}

void HiddenApDetector::begin(BridgeProtocol& proto) {
    _proto = &proto;
    _instance = this;
    if (!_queue) {
        _queue = xQueueCreate(HIDDEN_AP_QUEUE_DEPTH, sizeof(Event));
    }
    esp_wifi_set_promiscuous(false);
}

bool HiddenApDetector::start(const HiddenApConfig& config) {
    if (_active) stop();

    if (config.hop) {
        _hopMode = true;
        _hopIntervalMs = constrain(config.intervalMs, 50, 5000);
        _channel = 1;
    } else {
        if (config.channel < 1 || config.channel > 14) return false;
        _hopMode = false;
        _hopIntervalMs = 300;
        _channel = config.channel;
    }

    _config = config;
    _config.intervalMs = constrain(_config.intervalMs, 50, 5000);
    memset(_hiddenCache, 0, sizeof(_hiddenCache));
    if (_queue) xQueueReset(_queue);
    _stats = HiddenApStats{};
    _lastHopMs = millis();

    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&HiddenApDetector::promiscuousCb);
    esp_wifi_set_channel(_channel, WIFI_SECOND_CHAN_NONE);
    _active = true;
    esp_wifi_set_promiscuous(true);
    return true;
}

void HiddenApDetector::stop() {
    if (_active) {
        esp_wifi_set_promiscuous(false);
    }
    _active = false;
    _hopMode = false;
}

void HiddenApDetector::update() {
    if (!_proto) return;

    if (_active && _hopMode && millis() - _lastHopMs >= _hopIntervalMs) {
        _lastHopMs = millis();
        _channel = (_channel % 13) + 1;
        esp_wifi_set_channel(_channel, WIFI_SECOND_CHAN_NONE);

        JsonDocument ev;
        ev["channel"] = _channel;
        _proto->sendEvent("hidden_ap_hop", ev);
    }

    Event event;
    while (_queue && xQueueReceive(_queue, &event, 0) == pdTRUE) {
        JsonDocument ev;
        if (event.hasBssid) {
            char bssid[18];
            macToString(event.bssid, bssid);
            ev["bssid"] = bssid;
        }
        if (event.hasClient) {
            char client[18];
            macToString(event.client, client);
            ev["client"] = client;
        }
        if (event.ssid[0] != '\0') ev["ssid"] = event.ssid;
        ev["channel"] = event.channel;
        ev["rssi"] = event.rssi;
        ev["uptime_ms"] = event.uptimeMs;
        if (event.subtype != 0) ev["subtype"] = event.subtype;

        const char* name = "hidden_ap";
        if (event.type == EventType::CANDIDATE) name = "hidden_ssid_candidate";
        else if (event.type == EventType::RESOLVED) name = "hidden_ssid_resolved";

        _proto->sendEvent(name, ev);
        _stats.sent++;
    }
}

void HiddenApDetector::promiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type) {
    (void)type;
    if (_instance) _instance->handlePacket((wifi_promiscuous_pkt_t*)buf);
}

bool HiddenApDetector::emitFromFrame(wifi_promiscuous_pkt_t* pkt, uint8_t subtype) {
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 24) return false;

    const uint8_t* p = pkt->payload;
    uint8_t channel = pkt->rx_ctrl.channel != 0 ? pkt->rx_ctrl.channel : _channel;
    int8_t rssi = pkt->rx_ctrl.rssi;

    Event event{};
    event.channel = channel;
    event.rssi = rssi;
    event.subtype = subtype;
    event.uptimeMs = millis();

    if (subtype == 0x08 || subtype == 0x05) {  // beacon / probe response
        if (len < 38) return false;
        bool present = false;
        char ssid[33] = {0};
        bool hasSsid = findSsidIe(p, len, 36, ssid, sizeof(ssid), &present);

        // A zero-length or missing SSID IE is considered hidden.
        if (hasSsid) return false;
        (void)present;
        event.type = EventType::HIDDEN_AP;
        memcpy(event.bssid, p + 16, 6);
        event.hasBssid = true;
        rememberHiddenBssid(event.bssid);
        _stats.hiddenSeen++;
    } else if (subtype == 0x04) {  // probe request
        bool present = false;
        char ssid[33] = {0};
        bool hasSsid = findSsidIe(p, len, 24, ssid, sizeof(ssid), &present);
        if (!hasSsid || !present) return false;

        event.type = EventType::CANDIDATE;
        memcpy(event.client, p + 10, 6);
        event.hasClient = true;
        strncpy(event.ssid, ssid, sizeof(event.ssid) - 1);
        event.ssid[sizeof(event.ssid) - 1] = '\0';
        _stats.candidates++;
    } else if (subtype == 0x00 || subtype == 0x02) {  // assoc / reassoc request
        size_t offset = subtype == 0x00 ? 28 : 34;
        bool present = false;
        char ssid[33] = {0};
        bool hasSsid = findSsidIe(p, len, offset, ssid, sizeof(ssid), &present);
        if (!hasSsid || !present) return false;

        if (!isHiddenBssid(p + 16)) return false;

        event.type = EventType::RESOLVED;
        memcpy(event.bssid, p + 16, 6);
        event.hasBssid = true;
        memcpy(event.client, p + 10, 6);
        event.hasClient = true;
        strncpy(event.ssid, ssid, sizeof(event.ssid) - 1);
        event.ssid[sizeof(event.ssid) - 1] = '\0';
        _stats.resolved++;
    } else {
        return false;
    }

    if (!_queue || xQueueSend(_queue, &event, 0) != pdTRUE) {
        _stats.dropped++;
        return false;
    }
    return true;
}

void HiddenApDetector::handlePacket(wifi_promiscuous_pkt_t* pkt) {
    if (!_active || !pkt) return;

    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 24) return;

    const uint8_t* p = pkt->payload;
    uint8_t fc0 = p[0];
    if (((fc0 >> 2) & 0x3) != 0) return;  // management only

    uint8_t subtype = (fc0 >> 4) & 0xF;
    if (subtype != 0x08 && subtype != 0x05 &&
        subtype != 0x04 && subtype != 0x00 &&
        subtype != 0x02) {
        return;
    }

    emitFromFrame(pkt, subtype);
}

void HiddenApDetector::rememberHiddenBssid(const uint8_t* bssid) {
    if (!bssid) return;

    int emptyIndex = -1;
    int oldestIndex = 0;
    uint32_t oldestMs = 0xFFFFFFFF;
    uint32_t now = millis();

    for (int i = 0; i < HIDDEN_AP_CACHE_SIZE; i++) {
        HiddenBssidEntry& entry = _hiddenCache[i];
        if (entry.used && memcmp(entry.bssid, bssid, 6) == 0) {
            entry.lastSeenMs = now;
            return;
        }
        if (!entry.used && emptyIndex < 0) emptyIndex = i;
        if (entry.used && entry.lastSeenMs < oldestMs) {
            oldestMs = entry.lastSeenMs;
            oldestIndex = i;
        }
    }

    int index = emptyIndex >= 0 ? emptyIndex : oldestIndex;
    HiddenBssidEntry& entry = _hiddenCache[index];
    memcpy(entry.bssid, bssid, 6);
    entry.lastSeenMs = now;
    entry.used = true;
}

bool HiddenApDetector::isHiddenBssid(const uint8_t* bssid) const {
    if (!bssid) return false;
    for (int i = 0; i < HIDDEN_AP_CACHE_SIZE; i++) {
        const HiddenBssidEntry& entry = _hiddenCache[i];
        if (entry.used && memcmp(entry.bssid, bssid, 6) == 0) {
            return true;
        }
    }
    return false;
}

void HiddenApDetector::macToString(const uint8_t* mac, char* out) {
    snprintf(
        out,
        18,
        "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
}
