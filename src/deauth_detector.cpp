#include "deauth_detector.h"

DeauthDetector* DeauthDetector::_instance = nullptr;

void DeauthDetector::begin(BridgeProtocol& proto) {
    _proto = &proto;
    _instance = this;
    if (!_queue) {
        _queue = xQueueCreate(DEAUTH_DETECT_QUEUE_DEPTH, sizeof(Alert));
    }
    memset(_ssidCache, 0, sizeof(_ssidCache));
    esp_wifi_set_promiscuous(false);
}

bool DeauthDetector::start(const DeauthDetectConfig& config) {
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
    memset(_ssidCache, 0, sizeof(_ssidCache));
    if (_queue) xQueueReset(_queue);
    _stats = DeauthDetectStats{};
    _lastHopMs = millis();

    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&DeauthDetector::promiscuousCb);
    esp_wifi_set_channel(_channel, WIFI_SECOND_CHAN_NONE);
    _active = true;
    esp_wifi_set_promiscuous(true);
    return true;
}

void DeauthDetector::stop() {
    if (_active) {
        esp_wifi_set_promiscuous(false);
    }
    _active = false;
    _hopMode = false;
}

void DeauthDetector::promiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type) {
    (void)type;
    if (_instance) _instance->handlePacket((wifi_promiscuous_pkt_t*)buf);
}

bool DeauthDetector::matchesFilters(const uint8_t* dst, const uint8_t* src, const uint8_t* bssid) const {
    if (_config.hasBssid &&
        memcmp(src, _config.bssid, 6) != 0 &&
        memcmp(bssid, _config.bssid, 6) != 0) {
        return false;
    }
    if (_config.hasClient && memcmp(dst, _config.client, 6) != 0) {
        return false;
    }
    return true;
}

void DeauthDetector::handlePacket(wifi_promiscuous_pkt_t* pkt) {
    if (!_active || !pkt) return;

    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 24) return;

    const uint8_t* p = pkt->payload;
    uint8_t fc0 = p[0];

    // Management frames only.
    if (((fc0 >> 2) & 0x3) != 0) return;

    uint8_t subtype = (fc0 >> 4) & 0xF;
    if (subtype == 0x08 || subtype == 0x05) {  // beacon / probe response
        rememberBeaconSsid(pkt);
        return;
    }
    if (subtype != 0x0C && subtype != 0x0A) return;  // deauth / disassoc

    int8_t rssi = pkt->rx_ctrl.rssi;
    if (rssi < _config.rssiMin) return;

    const uint8_t* dst   = p + 4;   // Addr1: client / destination
    const uint8_t* src   = p + 10;  // Addr2: source / transmitter
    const uint8_t* bssid = p + 16;  // Addr3: BSSID

    if (!matchesFilters(dst, src, bssid)) return;

    Alert alert;
    alert.subtype  = subtype;
    alert.channel  = pkt->rx_ctrl.channel != 0 ? pkt->rx_ctrl.channel : _channel;
    alert.rssi     = rssi;
    alert.reason   = len >= 26
        ? (uint16_t)(p[24] | ((uint16_t)p[25] << 8))
        : 0;
    alert.uptimeMs = millis();
    memcpy(alert.client, dst, 6);
    memcpy(alert.source, src, 6);
    memcpy(alert.bssid, bssid, 6);
    alert.ssid[0] = '\0';
    const char* cached = findSsid(bssid);
    if (cached) {
        strncpy(alert.ssid, cached, sizeof(alert.ssid) - 1);
        alert.ssid[sizeof(alert.ssid) - 1] = '\0';
    }

    _stats.detected++;
    if (!_queue || xQueueSend(_queue, &alert, 0) != pdTRUE) {
        _stats.dropped++;
    }
}

void DeauthDetector::update() {
    if (!_active || !_proto) return;

    if (_hopMode && millis() - _lastHopMs >= _hopIntervalMs) {
        _lastHopMs = millis();
        _channel = (_channel % 13) + 1;
        esp_wifi_set_channel(_channel, WIFI_SECOND_CHAN_NONE);

        JsonDocument ev;
        ev["channel"] = _channel;
        _proto->sendEvent("deauth_detector_hop", ev);
    }

    Alert alert;
    while (_queue && xQueueReceive(_queue, &alert, 0) == pdTRUE) {
        char bssid[18];
        char source[18];
        char client[18];
        macToString(alert.bssid, bssid);
        macToString(alert.source, source);
        macToString(alert.client, client);

        JsonDocument ev;
        ev["subtype"]      = alert.subtype == 0x0C ? "deauth" : "disassoc";
        ev["subtype_code"] = alert.subtype;
        ev["bssid"]        = bssid;
        ev["source"]       = source;
        ev["client"]       = client;
        ev["destination"]  = client;
        ev["channel"]      = alert.channel;
        ev["rssi"]         = alert.rssi;
        ev["reason"]       = alert.reason;
        ev["uptime_ms"]    = alert.uptimeMs;
        if (alert.ssid[0] != '\0') {
            ev["ssid"] = alert.ssid;
        }

        _proto->sendEvent("deauth_detected", ev);
        _stats.sent++;
    }
}

void DeauthDetector::rememberBeaconSsid(wifi_promiscuous_pkt_t* pkt) {
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 38) return;

    const uint8_t* p = pkt->payload;
    const uint8_t* bssid = p + 16;
    size_t offset = 24 + 12;  // mgmt header + beacon/probe-response fixed body

    while (offset + 2 <= len) {
        uint8_t id = p[offset];
        uint8_t ieLen = p[offset + 1];
        if (offset + 2 + ieLen > len) break;

        if (id == 0) {  // SSID element
            if (ieLen > 0 && ieLen <= 32) {
                updateSsidCache(bssid, (const char*)(p + offset + 2), ieLen);
            }
            return;
        }
        offset += 2 + ieLen;
    }
}

void DeauthDetector::updateSsidCache(const uint8_t* bssid, const char* ssid, size_t len) {
    if (!bssid || !ssid || len == 0) return;
    if (len > 32) len = 32;

    int emptyIndex = -1;
    int oldestIndex = 0;
    uint32_t oldestMs = 0xFFFFFFFF;

    for (int i = 0; i < DEAUTH_SSID_CACHE_SIZE; i++) {
        SsidCacheEntry& entry = _ssidCache[i];
        if (entry.used && memcmp(entry.bssid, bssid, 6) == 0) {
            memcpy(entry.ssid, ssid, len);
            entry.ssid[len] = '\0';
            entry.lastSeenMs = millis();
            return;
        }
        if (!entry.used && emptyIndex < 0) {
            emptyIndex = i;
        }
        if (entry.used && entry.lastSeenMs < oldestMs) {
            oldestMs = entry.lastSeenMs;
            oldestIndex = i;
        }
    }

    int index = emptyIndex >= 0 ? emptyIndex : oldestIndex;
    SsidCacheEntry& entry = _ssidCache[index];
    memcpy(entry.bssid, bssid, 6);
    memcpy(entry.ssid, ssid, len);
    entry.ssid[len] = '\0';
    entry.lastSeenMs = millis();
    entry.used = true;
}

const char* DeauthDetector::findSsid(const uint8_t* bssid) const {
    if (!bssid) return nullptr;
    for (int i = 0; i < DEAUTH_SSID_CACHE_SIZE; i++) {
        const SsidCacheEntry& entry = _ssidCache[i];
        if (entry.used &&
            entry.ssid[0] != '\0' &&
            memcmp(entry.bssid, bssid, 6) == 0) {
            return entry.ssid;
        }
    }
    return nullptr;
}

void DeauthDetector::macToString(const uint8_t* mac, char* out) {
    snprintf(
        out,
        18,
        "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
}
