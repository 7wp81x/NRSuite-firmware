#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * Discovery record used by the hybrid WPS scan.
 *
 * Active scan is authoritative for SSID/channel/security/RSSI. The passive
 * promiscuous pass only enriches WPS IE metadata such as AP Setup Locked,
 * WPS version, and configuration methods.
 */
struct WpsScanRecord {
    char ssid[33] = {};
    uint8_t bssid[6] = {};
    uint8_t channel = 0;
    int8_t rssi = -127;
    char security[20] = "OPEN";
    bool wps = false;
    bool activeScan = false;
    bool wpsParsed = false;
    bool lockReported = false;
    bool apSetupLocked = false;
    uint8_t wpsVersion = 0;
    uint16_t configMethods = 0;
    bool selectedRegistrar = false;
    uint32_t lastSeenMs = 0;
};

inline bool wpsScanSameBssid(const uint8_t left[6], const uint8_t right[6]) {
    return memcmp(left, right, 6) == 0;
}

inline void wpsScanCopyText(char* destination, size_t capacity, const char* source) {
    if (destination == nullptr || capacity == 0 || source == nullptr || source[0] == '\0') {
        return;
    }
    strncpy(destination, source, capacity - 1);
    destination[capacity - 1] = '\0';
}

inline void wpsScanMergeMetadata(WpsScanRecord& target, const WpsScanRecord& source) {
    target.wps = target.wps || source.wps;
    if (source.wpsParsed) {
        target.wpsParsed = true;
        if (target.wpsVersion == 0) target.wpsVersion = source.wpsVersion;
        if (target.configMethods == 0) target.configMethods = source.configMethods;
        target.selectedRegistrar = target.selectedRegistrar || source.selectedRegistrar;
    }
    if (source.lockReported) {
        target.lockReported = true;
        target.apSetupLocked = source.apSetupLocked;
    }
    if (source.lastSeenMs > target.lastSeenMs) {
        target.lastSeenMs = source.lastSeenMs;
    }
}

/**
 * Upsert with a clear precedence rule:
 *  - preserve active-scan discovery fields over passive-scan fields;
 *  - merge WPS IE metadata from either pass;
 *  - keep a passive-only WPS candidate if the active scan missed it.
 */
inline void wpsScanMergeRecord(
    WpsScanRecord* records,
    size_t& count,
    size_t capacity,
    const WpsScanRecord& incoming
) {
    for (size_t index = 0; index < count; ++index) {
        WpsScanRecord& existing = records[index];
        if (!wpsScanSameBssid(existing.bssid, incoming.bssid)) continue;

        WpsScanRecord merged = incoming;
        if (existing.activeScan && !incoming.activeScan) {
            // Keep the more reliable active-scan discovery values.
            merged = existing;
        } else if (!existing.activeScan && incoming.activeScan) {
            // Active discovery wins over a passive-only observation.
            merged = incoming;
        }

        if (merged.ssid[0] == '\0') {
            wpsScanCopyText(merged.ssid, sizeof(merged.ssid), existing.ssid);
        }
        if (merged.ssid[0] == '\0') {
            wpsScanCopyText(merged.ssid, sizeof(merged.ssid), incoming.ssid);
        }
        if (merged.channel == 0) merged.channel = existing.channel;
        if (merged.rssi == -127) merged.rssi = existing.rssi;
        if (merged.security[0] == '\0') {
            wpsScanCopyText(merged.security, sizeof(merged.security), existing.security);
        }

        wpsScanMergeMetadata(merged, existing);
        wpsScanMergeMetadata(merged, incoming);
        existing = merged;
        return;
    }

    if (count < capacity) {
        records[count++] = incoming;
    }
}
