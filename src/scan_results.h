#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>

/**
 * Bounded, pull-based scan result snapshot.
 *
 * Firmware stores the most recent SCAN_WIFI or WPS_LOCK_SCAN result set so the
 * app can retrieve it in small, independently verifiable chunks. This avoids
 * relying on a burst of fire-and-forget event frames over lossy UART bridges.
 */
class ScanResultStore {
public:
    static constexpr size_t kMaxResults = 32;
    static constexpr uint8_t kDefaultChunkLimit = 4;
    static constexpr uint8_t kMaxChunkLimit = 8;

    enum class Kind : uint8_t {
        Wifi,
        Wps,
    };

    struct Record {
        char ssid[33] = {};
        uint8_t bssid[6] = {};
        uint8_t channel = 0;
        int8_t rssi = -127;
        char security[16] = "UNKNOWN";
        bool wps = false;
        uint8_t band = 0;  // 0 = 2.4 GHz, 1 = 5 GHz
        bool wpsParsed = false;
        bool lockReported = false;
        bool apSetupLocked = false;
        uint8_t wpsVersion = 0;
        uint16_t configMethods = 0;
        bool selectedRegistrar = false;
        uint32_t lastSeenMs = 0;
    };

    void begin(Kind kind, uint32_t scanId);
    void clear();

    bool add(const Record& record);
    bool matches(uint32_t scanId) const;
    bool active() const { return active_; }
    Kind kind() const { return kind_; }
    const char* kindName() const;
    uint32_t scanId() const { return scanId_; }
    size_t count() const { return count_; }

    size_t appendResults(
        JsonArray& out,
        size_t offset,
        size_t limit,
        size_t& nextOffset
    ) const;

    // CRC32 (IEEE 802.3 / zlib polynomial) over the deterministic canonical
    // representation of the selected records. The Android app computes the
    // same representation from the results array before accepting a chunk.
    uint32_t crc32ForRange(size_t offset, size_t limit) const;

private:
    Record records_[kMaxResults] = {};
    size_t count_ = 0;
    uint32_t scanId_ = 0;
    Kind kind_ = Kind::Wifi;
    bool active_ = false;

    void appendCanonical(String& out, size_t offset, size_t limit) const;
};
