#include "sniffer.h"

#include <esp_heap_caps.h>

Sniffer* Sniffer::_instance = nullptr;

#pragma pack(push, 1)
struct RadiotapHeader {
    uint8_t  version;
    uint8_t  pad;
    uint16_t len;
    uint32_t present;
    uint16_t chan_freq;
    uint16_t chan_flags;
    int8_t   dbm_signal;
};
#pragma pack(pop)

static const uint8_t WIFI_2G_CHANNELS[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
static const uint8_t WIFI_5G_CHANNELS[] = {
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165, 169, 173, 177,
};
static const uint8_t WIFI_AUTO_CHANNELS[] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165, 169, 173, 177,
};

static uint16_t channelToFreqMHz(uint8_t ch) {
    if (ch >= 1 && ch <= 13) return 2407 + ch * 5;
    if (ch == 14) return 2484;
    if (ch >= 36) return 5000 + ch * 5;
    return 2412;
}

static uint16_t readBe16(const uint8_t* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void writeBe16(uint8_t* p, uint16_t value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void writeBe32(uint8_t* p, uint32_t value) {
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static constexpr uint32_t DNS_HIJACK_EVENT_INTERVAL_MS = 5000;

static uint16_t ipv4HeaderChecksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += (uint16_t)((data[i] << 8) | data[i + 1]);
    }
    if (len & 1) sum += (uint16_t)data[len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

// ── begin ─────────────────────────────────────────────────────────────────
void Sniffer::begin(BridgeProtocol& proto) {
    _proto = &proto;
    _instance = this;
    // Queues are allocated on first use so S2-class boards keep their heap
    // available for USB command/response handling at boot.

    WiFi.disconnect();
    esp_wifi_set_promiscuous(false);
}

// ── buildRadiotap ────────────────────────────────────────────────────────
size_t Sniffer::buildRadiotap(uint8_t* out, uint8_t channel, int8_t rssi) {
    RadiotapHeader* rt = (RadiotapHeader*)out;
    rt->version = 0;
    rt->pad = 0;
    rt->len = sizeof(RadiotapHeader);
    rt->present = (1u << 3) | (1u << 5);
    rt->chan_freq = channelToFreqMHz(channel);
    rt->chan_flags = 0x00A0;
    rt->dbm_signal = rssi;
    return sizeof(RadiotapHeader);
}

// ── startFixed / startHop / stop / setChannel ─────────────────────────────
bool Sniffer::startFixed(uint8_t channel, bool include5ghz) {
    return startFixedInternal(channel, false, include5ghz);
}

bool Sniffer::startHop(uint16_t intervalMs, bool include5ghz) {
    return startHopInternal(intervalMs, false, include5ghz);
}

bool Sniffer::startClientFixed(uint8_t channel, bool include5ghz) {
    return startFixedInternal(channel, true, include5ghz);
}

bool Sniffer::startClientHop(uint16_t intervalMs, bool include5ghz) {
    return startHopInternal(intervalMs, true, include5ghz);
}

bool Sniffer::startDnsHijack(uint8_t channel) {
    if (!isValidChannel(channel, false)) return false;

    // This mode exists only to answer plaintext DNS queries sent to a custom
    // resolver. Do not allocate the PCAP/client queues: they are unnecessary
    // here and cost several KiB of heap on the S2/C3-class targets.
    _clientOnly = false;
    _dnsOnly = true;
    _include5ghz = false;
    _hopMode = false;

    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&Sniffer::promiscuousCb);
    if (esp_wifi_set_promiscuous(true) != ESP_OK) {
        _dnsOnly = false;
        _active = false;
        return false;
    }
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

    // Drain stale frames from any previous PCAP session if those queues were
    // already allocated earlier; do not allocate new ones for this mode.
    if (_queue) xQueueReset(_queue);
    if (_clientQueue) xQueueReset(_clientQueue);

    _channel = channel;
    _active = true;
    _stats = SniffStats{};
    return true;
}

void Sniffer::setDnsHijack(bool enabled, IPAddress portalIp) {
    _dnsHijackEnabled = enabled;
    _dnsHijackPortalIp = portalIp;
    if (enabled) {
        _dnsHijackCount = 0;
        _lastDnsHijackEventMs = 0;
    }
    _dnsOnly = enabled ? _dnsOnly : false;
}

bool Sniffer::isValidChannel(uint8_t channel, bool include5ghz) const {
    for (uint8_t ch : WIFI_2G_CHANNELS) {
        if (ch == channel) return true;
    }
    if (!include5ghz) return false;
    for (uint8_t ch : WIFI_5G_CHANNELS) {
        if (ch == channel) return true;
    }
    return false;
}

bool Sniffer::ensureCaptureQueues() {
    if (!_queue) {
        // Prefer PSRAM for the bulk frame storage when available. Queue
        // control structures stay in internal RAM. This keeps roughly 11 KiB
        // of per-sniff-session buffers out of internal SRAM on S3 PSRAM boards.
        const size_t queueBytes = SNIFF_QUEUE_DEPTH * sizeof(CapturedFrame);
        _queueStorage = (uint8_t*)heap_caps_malloc(
            queueBytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (_queueStorage) {
            _queue = xQueueCreateStatic(
                SNIFF_QUEUE_DEPTH, sizeof(CapturedFrame),
                _queueStorage, &_queueControl);
            if (!_queue) {
                heap_caps_free(_queueStorage);
                _queueStorage = nullptr;
            }
        }
        if (!_queue) {
            _queue = xQueueCreate(SNIFF_QUEUE_DEPTH, sizeof(CapturedFrame));
        }
    }

    if (!_clientQueue) {
        const size_t clientQueueBytes =
            CLIENT_EVENT_QUEUE_DEPTH * sizeof(ClientEvent);
        _clientQueueStorage = (uint8_t*)heap_caps_malloc(
            clientQueueBytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (_clientQueueStorage) {
            _clientQueue = xQueueCreateStatic(
                CLIENT_EVENT_QUEUE_DEPTH, sizeof(ClientEvent),
                _clientQueueStorage, &_clientQueueControl);
            if (!_clientQueue) {
                heap_caps_free(_clientQueueStorage);
                _clientQueueStorage = nullptr;
            }
        }
        if (!_clientQueue) {
            _clientQueue = xQueueCreate(
                CLIENT_EVENT_QUEUE_DEPTH, sizeof(ClientEvent));
        }
    }

    return _queue != nullptr && _clientQueue != nullptr;
}

bool Sniffer::startFixedInternal(uint8_t channel, bool clientOnly, bool include5ghz) {
    if (!isValidChannel(channel, include5ghz)) return false;
    _dnsOnly = false;
    if (!ensureCaptureQueues()) return false;
    _clientOnly = clientOnly;
    _include5ghz = include5ghz;

    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&Sniffer::promiscuousCb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

    // Reset flow-control and queued frames so a new sniff session cannot be
    // starved by unacknowledged frames left over from a previous session.
    _inFlight = 0;
    _chunkCtr = 0;
    if (_queue) xQueueReset(_queue);
    if (_clientQueue) xQueueReset(_clientQueue);

    _channel = channel;
    _hopMode = false;
    _active = true;
    _stats = SniffStats{};
    return true;
}

bool Sniffer::startHopInternal(uint16_t intervalMs, bool clientOnly, bool include5ghz) {
    _hopChannels = include5ghz ? WIFI_AUTO_CHANNELS : WIFI_2G_CHANNELS;
    _hopCount = include5ghz
        ? (uint8_t)(sizeof(WIFI_AUTO_CHANNELS) / sizeof(WIFI_AUTO_CHANNELS[0]))
        : (uint8_t)(sizeof(WIFI_2G_CHANNELS) / sizeof(WIFI_2G_CHANNELS[0]));
    _hopIndex = 0;
    if (!startFixedInternal(_hopChannels[0], clientOnly, include5ghz)) return false;
    _hopMode = true;
    _hopIntervalMs = intervalMs;
    _lastHopMs = millis();
    return true;
}

void Sniffer::stop() {
    esp_wifi_set_promiscuous(false);
    // Drain any client events that were queued between loop iterations.
    processClientEvents();
    _active = false;
    _hopMode = false;
    _clientOnly = false;
    _dnsOnly = false;
    _dnsHijackEnabled = false;
}

bool Sniffer::setChannel(uint8_t channel) {
    if (!isValidChannel(channel, _include5ghz)) return false;
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    _channel = channel;
    return true;
}

void Sniffer::handleHop() {
    if (!_active || !_hopMode) return;
    if (millis() - _lastHopMs < _hopIntervalMs) return;
    if (!_hopChannels || _hopCount == 0) return;
    _lastHopMs = millis();
    _hopIndex = (uint8_t)((_hopIndex + 1) % _hopCount);
    _channel = _hopChannels[_hopIndex];
    esp_wifi_set_channel(_channel, WIFI_SECOND_CHAN_NONE);
}

// ── Filter ────────────────────────────────────────────────────────────────
void Sniffer::setEapolFilter(bool enable, const uint8_t bssid[6], bool allBeacons) {
    _eapolOnly = enable;
    _captureAllBeacons = allBeacons;
    _hasTargetBssid = (bssid != nullptr && enable);
    if (_hasTargetBssid) memcpy(_targetBssid, bssid, 6);
    _beaconCaptured = false;
    _beaconBssidCount = 0;
    memset(_beaconBssids, 0, sizeof(_beaconBssids));
}

bool Sniffer::isEapolFrame(const wifi_promiscuous_pkt_t* pkt) const {
    uint16_t len = pkt->rx_ctrl.sig_len;
    const uint8_t* p = pkt->payload;
    if (len < 40) return false;

    uint8_t fc0 = p[0];
    if (((fc0 >> 2) & 0x3) != 2) return false; // Data only

    size_t offset = 24;
    if (((fc0 >> 4) & 0xF) & 0x08) offset += 2; // QoS

    for (size_t i = offset; i < len - 8; ++i) {
        if (p[i] == 0xAA && p[i+1] == 0xAA && p[i+2] == 0x03 &&
            p[i+6] == 0x88 && p[i+7] == 0x8E) {
            return true;
        }
    }
    return false;
}

bool Sniffer::isBeaconFrame(const wifi_promiscuous_pkt_t* pkt) const {
    if (!pkt || pkt->rx_ctrl.sig_len < 38) return false;
    const uint8_t* p = pkt->payload;
    uint8_t fc0 = p[0];
    return ((fc0 >> 2) & 0x3) == 0 && ((fc0 >> 4) & 0xF) == 8;
}

bool Sniffer::matchesTargetBssid(const wifi_promiscuous_pkt_t* pkt) const {
    if (pkt->rx_ctrl.sig_len < 22) return false;
    const uint8_t* p = pkt->payload;
    const uint8_t* addr1 = p + 4;
    const uint8_t* addr2 = p + 10;
    const uint8_t* addr3 = p + 16;
    return memcmp(addr1, _targetBssid, 6) == 0 ||
           memcmp(addr2, _targetBssid, 6) == 0 ||
           memcmp(addr3, _targetBssid, 6) == 0;
}

// ── Callback & Packet Handler ─────────────────────────────────────────────
void Sniffer::promiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (_instance) _instance->handlePacket((wifi_promiscuous_pkt_t*)buf);
}

bool Sniffer::isAssociationRequest(const wifi_promiscuous_pkt_t* pkt) const {
    if (!pkt) return false;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 24) return false;
    const uint8_t* p = pkt->payload;
    uint8_t fc0 = p[0];
    uint8_t ftype = (fc0 >> 2) & 0x3;
    uint8_t subtype = (fc0 >> 4) & 0xF;
    return (ftype == 0) && (subtype == 0);  // Management + Assoc Request
}

static bool parseSsidIe(
    const uint8_t* p,
    size_t len,
    size_t offset,
    char* out,
    size_t outSize
) {
    while (offset + 2 <= len) {
        uint8_t id = p[offset];
        uint8_t ieLen = p[offset + 1];
        if (offset + 2 + ieLen > len) break;
        if (id == 0) {
            size_t copyLen = ieLen < (outSize - 1) ? ieLen : (outSize - 1);
            memcpy(out, p + offset + 2, copyLen);
            out[copyLen] = '\0';
            return copyLen > 0;
        }
        offset += 2 + ieLen;
    }
    return false;
}

bool Sniffer::enqueueClientEvent(wifi_promiscuous_pkt_t* pkt) {
    if (!_clientQueue || !pkt) return false;

    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 24) return false;

    const uint8_t* p = pkt->payload;
    uint8_t fc0 = p[0];
    if (((fc0 >> 2) & 0x3) != 0) return false;  // management only

    uint8_t subtype = (fc0 >> 4) & 0xF;
    if (subtype != 0x00 && subtype != 0x02 &&
        subtype != 0x04 && subtype != 0x0B) {
        return false;
    }

    ClientEvent ev{};
    memcpy(ev.client, p + 10, 6);  // addr2 / transmitter
    memcpy(ev.bssid, p + 16, 6);   // addr3 / BSSID
    ev.subtype = subtype;
    ev.rssi = pkt->rx_ctrl.rssi;
    ev.channel = pkt->rx_ctrl.channel != 0 ? pkt->rx_ctrl.channel : _channel;

    ev.hasBssid = true;
    for (int i = 0; i < 6; i++) {
        if (ev.bssid[i] != 0xFF) break;
        if (i == 5) ev.hasBssid = false;
    }

    if (subtype == 0x04) {
        parseSsidIe(p, len, 24, ev.ssid, sizeof(ev.ssid));
    } else if (subtype == 0x00) {
        parseSsidIe(p, len, 28, ev.ssid, sizeof(ev.ssid));
    } else if (subtype == 0x02) {
        parseSsidIe(p, len, 34, ev.ssid, sizeof(ev.ssid));
    }

    if (xQueueSend(_clientQueue, &ev, 0) != pdTRUE) {
        _stats.dropped++;
        return false;
    }

    _stats.captured++;
    return true;
}

void Sniffer::processClientEvents() {
    if (!_proto || !_clientQueue) return;

    ClientEvent ev;
    while (xQueueReceive(_clientQueue, &ev, 0) == pdTRUE) {
        char clientStr[18];
        char bssidStr[18];
        snprintf(clientStr, sizeof(clientStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                 ev.client[0], ev.client[1], ev.client[2],
                 ev.client[3], ev.client[4], ev.client[5]);
        snprintf(bssidStr, sizeof(bssidStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                 ev.bssid[0], ev.bssid[1], ev.bssid[2],
                 ev.bssid[3], ev.bssid[4], ev.bssid[5]);

        JsonDocument doc;
        doc["client"] = clientStr;
        if (ev.hasBssid) doc["bssid"] = bssidStr;
        if (ev.ssid[0] != '\0') doc["ssid"] = ev.ssid;
        doc["subtype"] =
            ev.subtype == 0x04 ? "probe_request" :
            ev.subtype == 0x00 ? "association_request" :
            ev.subtype == 0x02 ? "reassociation_request" :
                                 "auth";
        doc["rssi"] = ev.rssi;
        doc["channel"] = ev.channel;

        _proto->sendEvent("client_detected", doc);
        _stats.sent++;
    }
}

void Sniffer::handlePacket(wifi_promiscuous_pkt_t* pkt) {
    if (!_active) return;

    if (_dnsHijackEnabled) {
        handleDnsHijack(pkt);
    }
    if (_clientOnly) {
        enqueueClientEvent(pkt);
        return;
    }
    if (_dnsOnly) return;

    bool shouldCapture = false;

    if (_eapolOnly) {
        if (!_hasTargetBssid || matchesTargetBssid(pkt)) {
            if (isEapolFrame(pkt)) {
                shouldCapture = true;
            } else if (isBeaconFrame(pkt)) {
                const uint8_t* beaconBssid = pkt->payload + 16;
                bool alreadyCaptured = false;
                for (uint8_t i = 0; i < _beaconBssidCount; i++) {
                    if (memcmp(_beaconBssids[i], beaconBssid, 6) == 0) {
                        alreadyCaptured = true;
                        break;
                    }
                }
                if (_captureAllBeacons) {
                    if (!alreadyCaptured && _beaconBssidCount < MAX_BEACON_BSSIDS) {
                        shouldCapture = true;
                        memcpy(_beaconBssids[_beaconBssidCount++], beaconBssid, 6);
                    }
                } else if (!_beaconCaptured) {
                    shouldCapture = true;
                    _beaconCaptured = true;
                }
            }
        }
    } else {
        shouldCapture = true;
    }

    if (!shouldCapture) return;

    _stats.captured++;

    CapturedFrame f;
    uint16_t onAirLen = pkt->rx_ctrl.sig_len;
    f.orig_len = onAirLen;
    f.cap_len = (onAirLen < SNIFF_SNAPLEN) ? onAirLen : SNIFF_SNAPLEN;
    f.channel = pkt->rx_ctrl.channel;
    f.rssi = pkt->rx_ctrl.rssi;
    memcpy(f.data, pkt->payload, f.cap_len);

    if (xQueueSend(_queue, &f, 0) != pdTRUE) {
        _stats.dropped++;
    }

    // Association events
    if (isAssociationRequest(pkt)) {
        const uint8_t* addr2 = pkt->payload + 10; // Client MAC (TA)
        const uint8_t* addr3 = pkt->payload + 16; // BSSID

        if (!_eapolOnly || !_hasTargetBssid || memcmp(addr3, _targetBssid, 6) == 0) {
            char client_mac[18], bssid_str[18];
            snprintf(client_mac, sizeof(client_mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                     addr2[0], addr2[1], addr2[2], addr2[3], addr2[4], addr2[5]);
            snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                     addr3[0], addr3[1], addr3[2], addr3[3], addr3[4], addr3[5]);

            JsonDocument ev;
            ev["type"] = "client_associated";
            ev["client"] = client_mac;
            ev["bssid"] = bssid_str;
            ev["rssi"] = pkt->rx_ctrl.rssi;
            _proto->sendEvent("client_associated", ev);
        }
    }
}

void Sniffer::emitDnsHijackEvent(const IPAddress& clientIp,
                                  const IPAddress& destination) {
    if (!_proto) return;
    const uint32_t now = millis();
    if (_lastDnsHijackEventMs != 0 &&
        now - _lastDnsHijackEventMs < DNS_HIJACK_EVENT_INTERVAL_MS) {
        return;
    }
    _lastDnsHijackEventMs = now;

    JsonDocument event;
    event["type"] = "portal_dns_hijack";
    event["client_ip"] = clientIp.toString();
    event["destination"] = destination.toString();
    event["count"] = _dnsHijackCount;
    event["free_heap"] = ESP.getFreeHeap();
    event["heap_min_free"] = ESP.getMinFreeHeap();
    event["heap_max_alloc"] = ESP.getMaxAllocHeap();
    _proto->sendEvent("portal_dns_hijack", event);
}

void Sniffer::handleDnsHijack(const wifi_promiscuous_pkt_t* pkt) {
    if (!pkt) return;
    const uint16_t onAirLen = pkt->rx_ctrl.sig_len;
    const uint8_t* frame = pkt->payload;
    if (!frame || onAirLen < 24 + 8 + 20 + 8 + 12) return;

    const uint8_t fc0 = frame[0];
    const uint8_t fc1 = frame[1];
    // Client-to-AP data only. Responses sent by this hook are FromDS and are
    // therefore ignored if the promiscuous callback sees them again.
    if (((fc0 >> 2) & 0x3) != 2) return;
    if ((fc1 & 0x03) != 0x01) return;

    size_t headerLen = 24;
    if ((fc0 & 0x80) != 0) headerLen += 2;  // QoS data
    if (headerLen + 8 + 20 + 8 + 12 > onAirLen) return;

    const uint8_t* llc = frame + headerLen;
    if (!(llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
          llc[6] == 0x08 && llc[7] == 0x00)) {
        return;
    }

    const uint8_t* ip = llc + 8;
    if ((ip[0] >> 4) != 4) return;
    const size_t ipHeaderLen = (size_t)(ip[0] & 0x0F) * 4;
    if (ipHeaderLen < 20 || headerLen + 8 + ipHeaderLen + 8 + 12 > onAirLen) {
        return;
    }
    if (ip[9] != 17) return;  // UDP
    if (readBe16(ip + 6) & 0x3FFF) return;  // fragments unsupported

    const uint8_t* udp = ip + ipHeaderLen;
    const uint16_t sourcePort = readBe16(udp);
    const uint16_t destinationPort = readBe16(udp + 2);
    if (destinationPort != 53 || sourcePort == 0) return;
    const uint16_t udpLen = readBe16(udp + 4);
    if (udpLen < 8 + 12 ||
        headerLen + 8 + ipHeaderLen + udpLen > onAirLen) {
        return;
    }

    const IPAddress clientIp(ip[12], ip[13], ip[14], ip[15]);
    const IPAddress destination(ip[16], ip[17], ip[18], ip[19]);
    // Queries addressed to the AP are answered by lwIP's DNSServer. Only
    // intercept queries that a client sent to a custom external resolver.
    if (destination == _dnsHijackPortalIp || destination == IPAddress(0, 0, 0, 0)) {
        return;
    }

    const uint8_t* dns = udp + 8;
    const uint16_t dnsLen = udpLen - 8;
    if (dnsLen < 12) return;
    const uint16_t dnsFlags = readBe16(dns + 2);
    if ((dnsFlags & 0x8000) != 0) return;  // already a response
    if (readBe16(dns + 4) != 1) return;    // one question only

    size_t questionEnd = 12;
    bool nameComplete = false;
    while (questionEnd < dnsLen) {
        const uint8_t labelLen = dns[questionEnd];
        if (labelLen == 0) {
            questionEnd++;
            nameComplete = true;
            break;
        }
        if ((labelLen & 0xC0) != 0 || labelLen > 63 ||
            questionEnd + 1 + labelLen > dnsLen) {
            return;
        }
        questionEnd += 1 + labelLen;
    }
    if (!nameComplete || questionEnd + 4 > dnsLen) return;

    const uint16_t queryType = readBe16(dns + questionEnd);
    const uint16_t queryClass = readBe16(dns + questionEnd + 2);
    if (!((queryType == 1 || queryType == 255) &&
          (queryClass == 1 || queryClass == 255))) {
        return;
    }

    const size_t questionLen = questionEnd + 4 - 12;
    const size_t replyDnsLen = 12 + questionLen + 16;
    const size_t replyIpLen = 20 + 8 + replyDnsLen;
    if (replyDnsLen > 400 || replyIpLen > 512) return;

    uint8_t reply[512];
    memset(reply, 0, sizeof(reply));

    // 802.11 data frame from the AP to the requesting station.
    reply[0] = 0x08;
    reply[1] = 0x02;  // FromDS
    memcpy(reply + 4, frame + 10, 6);   // destination station
    memcpy(reply + 10, frame + 4, 6);   // AP BSSID
    memcpy(reply + 16, frame + 4, 6);   // source BSSID

    size_t offset = 24;
    static const uint8_t llcSnap[8] = {
        0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00,
    };
    memcpy(reply + offset, llcSnap, sizeof(llcSnap));
    offset += sizeof(llcSnap);

    const size_t ipOffset = offset;
    reply[ipOffset] = 0x45;
    writeBe16(reply + ipOffset + 2, (uint16_t)replyIpLen);
    writeBe16(reply + ipOffset + 4, (uint16_t)(esp_random() & 0xFFFF));
    writeBe16(reply + ipOffset + 6, 0x4000);
    reply[ipOffset + 8] = 64;
    reply[ipOffset + 9] = 17;
    memcpy(reply + ipOffset + 12, ip + 16, 4);  // source = requested resolver
    memcpy(reply + ipOffset + 16, ip + 12, 4);  // destination = client
    writeBe16(
        reply + ipOffset + 10,
        ipv4HeaderChecksum(reply + ipOffset, 20));
    offset += 20;

    const size_t udpOffset = offset;
    writeBe16(reply + udpOffset, 53);
    writeBe16(reply + udpOffset + 2, sourcePort);
    writeBe16(reply + udpOffset + 4, (uint16_t)(8 + replyDnsLen));
    writeBe16(reply + udpOffset + 6, 0);  // IPv4 UDP checksum optional
    offset += 8;

    const size_t dnsOffset = offset;
    reply[dnsOffset] = dns[0];  // transaction ID
    reply[dnsOffset + 1] = dns[1];
    const uint16_t responseFlags =
        (uint16_t)(0x8000 | 0x0400 | (dnsFlags & 0x0100) | 0x0080);
    writeBe16(reply + dnsOffset + 2, responseFlags);
    writeBe16(reply + dnsOffset + 4, 1);
    writeBe16(reply + dnsOffset + 6, 1);
    writeBe16(reply + dnsOffset + 8, 0);
    writeBe16(reply + dnsOffset + 10, 0);
    memcpy(reply + dnsOffset + 12, dns + 12, questionLen);
    offset = dnsOffset + 12 + questionLen;

    reply[offset++] = 0xC0;  // pointer to question name
    reply[offset++] = 0x0C;
    writeBe16(reply + offset, 1);  // A
    offset += 2;
    writeBe16(reply + offset, 1);  // IN
    offset += 2;
    writeBe32(reply + offset, 1);  // TTL
    offset += 4;
    writeBe16(reply + offset, 4);  // RDLENGTH
    offset += 2;
    reply[offset++] = 192;
    reply[offset++] = 168;
    reply[offset++] = 4;
    reply[offset++] = 1;

    if (offset > sizeof(reply)) return;
    if (esp_wifi_80211_tx(WIFI_IF_AP, reply, (int)offset, false) == ESP_OK) {
        _dnsHijackCount++;
        emitDnsHijackEvent(clientIp, destination);
    }
}

// ── processQueue — call from loop() ──────────────────────────────────────
void Sniffer::processQueue() {
    if (_dnsOnly || !_proto || !_queue) return;

    processClientEvents();

    CapturedFrame f;
    while (_inFlight < SNIFF_MAX_INFLIGHT && xQueueReceive(_queue, &f, 0) == pdTRUE) {
        uint8_t out[sizeof(RadiotapHeader) + SNIFF_SNAPLEN];
        size_t  rtLen = buildRadiotap(out, f.channel, f.rssi);
        memcpy(out + rtLen, f.data, f.cap_len);

        _proto->sendPcapChunk(_chunkCtr++, out, rtLen + f.cap_len);
        _inFlight++;
        _stats.sent++;
    }
    // If _inFlight is maxed, captured frames simply pile up in _queue
    // (and eventually get dropped there) until ACKs free up credit.
}

// ── onAck — wire to BridgeProtocol::onAck ───────────────────────────────────
void Sniffer::onAck(uint32_t chunkIndex) {
    (void)chunkIndex;
    if (_inFlight > 0) _inFlight--;
}