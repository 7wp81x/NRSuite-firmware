#include "scan_results.h"

#include <cstring>
#include <cstdio>

namespace {

uint32_t crc32Ieee(const uint8_t* data, size_t length) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < length; ++i) {
        crc ^= data[i];
        for (uint8_t bit = 0; bit < 8; ++bit) {
            const uint32_t mask = (crc & 1u) ? 0xFFFFFFFFu : 0u;
            crc = (crc >> 1u) ^ (0xEDB88320u & mask);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

void formatBssid(const uint8_t bssid[6], char out[18]) {
    snprintf(
        out,
        18,
        "%02X:%02X:%02X:%02X:%02X:%02X",
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]
    );
}

void appendSizedField(String& out, const char* value) {
    const size_t length = value ? strlen(value) : 0;
    out += String((unsigned long)length);
    out += ':';
    if (length > 0) out.concat(value, length);
    out += '|';
}

void appendBool(String& out, bool value) {
    out += value ? '1' : '0';
    out += '|';
}

}  // namespace

void ScanResultStore::begin(Kind kind, uint32_t scanId) {
    kind_ = kind;
    scanId_ = scanId;
    count_ = 0;
    active_ = true;
}

void ScanResultStore::clear() {
    count_ = 0;
    scanId_ = 0;
    active_ = false;
}

bool ScanResultStore::add(const Record& record) {
    if (!active_ || count_ >= kMaxResults) return false;
    records_[count_++] = record;
    return true;
}

bool ScanResultStore::matches(uint32_t scanId) const {
    return active_ && scanId_ == scanId;
}

const char* ScanResultStore::kindName() const {
    return kind_ == Kind::Wps ? "wps" : "wifi";
}

size_t ScanResultStore::appendResults(
    JsonArray& out,
    size_t offset,
    size_t limit,
    size_t& nextOffset
) const {
    if (offset > count_) {
        nextOffset = count_;
        return 0;
    }
    if (limit == 0) limit = kDefaultChunkLimit;
    if (limit > kMaxChunkLimit) limit = kMaxChunkLimit;
    const size_t end = min(count_, offset + limit);

    for (size_t index = offset; index < end; ++index) {
        const Record& record = records_[index];
        char bssid[18];
        formatBssid(record.bssid, bssid);

        JsonObject item = out.add<JsonObject>();
        item["type"] = kind_ == Kind::Wps ? "wps_lock_ap" : "scan_ap";
        item["ssid"] = record.ssid;
        item["bssid"] = bssid;
        item["channel"] = record.channel;
        item["rssi"] = record.rssi;
        item["security"] = record.security;
        item["wps"] = record.wps;
        if (kind_ == Kind::Wifi) {
            item["band"] = record.band == 1 ? "5g" : "2g";
        } else {
            item["wps_parsed"] = record.wpsParsed;
            item["lock_reported"] = record.lockReported;
            item["ap_setup_locked"] = record.apSetupLocked;
            item["wps_version"] = record.wpsVersion;
            item["config_methods"] = record.configMethods;
            item["selected_registrar"] = record.selectedRegistrar;
            item["last_seen_ms"] = record.lastSeenMs;
        }
    }

    nextOffset = end;
    return end - offset;
}

void ScanResultStore::appendCanonical(
    String& out,
    size_t offset,
    size_t limit
) const {
    if (offset > count_) return;
    if (limit == 0) limit = kDefaultChunkLimit;
    if (limit > kMaxChunkLimit) limit = kMaxChunkLimit;
    const size_t end = min(count_, offset + limit);

    for (size_t index = offset; index < end; ++index) {
        const Record& record = records_[index];
        char bssid[18];
        formatBssid(record.bssid, bssid);

        out += kind_ == Kind::Wps ? "wps|" : "wifi|";
        appendSizedField(out, record.ssid);
        out += bssid;
        out += '|';
        out += String((unsigned)record.channel);
        out += '|';
        out += String((int)record.rssi);
        out += '|';
        appendSizedField(out, record.security);
        appendBool(out, record.wps);
        if (kind_ == Kind::Wifi) {
            out += record.band == 1 ? "5g" : "2g";
            out += '\n';
        } else {
            appendBool(out, record.wpsParsed);
            appendBool(out, record.lockReported);
            appendBool(out, record.apSetupLocked);
            out += String((unsigned)record.wpsVersion);
            out += '|';
            out += String((unsigned)record.configMethods);
            out += '|';
            appendBool(out, record.selectedRegistrar);
            out += String((unsigned long)record.lastSeenMs);
            out += '\n';
        }
    }
}

uint32_t ScanResultStore::crc32ForRange(size_t offset, size_t limit) const {
    String canonical;
    canonical.reserve(1024);
    appendCanonical(canonical, offset, limit);
    return crc32Ieee(
        reinterpret_cast<const uint8_t*>(canonical.c_str()),
        canonical.length()
    );
}
