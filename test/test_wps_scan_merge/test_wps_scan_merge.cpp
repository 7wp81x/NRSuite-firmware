#include <unity.h>

#include "wps_scan_merge.h"

namespace {

WpsScanRecord activeCandidate(uint8_t bssidLast, const char* ssid, int8_t rssi) {
    WpsScanRecord record;
    record.activeScan = true;
    record.wps = true;
    record.bssid[5] = bssidLast;
    record.rssi = rssi;
    record.channel = 6;
    record.lastSeenMs = 100;
    wpsScanCopyText(record.ssid, sizeof(record.ssid), ssid);
    wpsScanCopyText(record.security, sizeof(record.security), "WPA2-PSK");
    return record;
}

WpsScanRecord passiveCandidate(uint8_t bssidLast, int8_t rssi, bool parsed, bool locked) {
    WpsScanRecord record;
    record.activeScan = false;
    record.wps = true;
    record.bssid[5] = bssidLast;
    record.rssi = rssi;
    record.channel = 6;
    record.lastSeenMs = 200;
    record.wpsParsed = parsed;
    record.lockReported = parsed;
    record.apSetupLocked = locked;
    record.wpsVersion = 0x10;
    record.configMethods = 0x000C;
    record.selectedRegistrar = true;
    wpsScanCopyText(record.ssid, sizeof(record.ssid), "Passive SSID");
    wpsScanCopyText(record.security, sizeof(record.security), "OPEN");
    return record;
}

void test_active_wps_candidates_survive_when_passive_pass_misses_them() {
    WpsScanRecord records[8] = {};
    size_t count = 0;

    WpsScanRecord a = activeCandidate(0x01, "Alpha", -42);
    WpsScanRecord b = activeCandidate(0x02, "Bravo", -61);
    WpsScanRecord c = activeCandidate(0x03, "Charlie", -73);
    wpsScanMergeRecord(records, count, 8, a);
    wpsScanMergeRecord(records, count, 8, b);
    wpsScanMergeRecord(records, count, 8, c);

    // Passive pass only enriches Alpha.
    WpsScanRecord alphaPassive = passiveCandidate(0x01, -88, true, false);
    wpsScanMergeRecord(records, count, 8, alphaPassive);

    TEST_ASSERT_EQUAL_UINT32(3, count);
    TEST_ASSERT_EQUAL_STRING("Alpha", records[0].ssid);
    TEST_ASSERT_EQUAL(-42, records[0].rssi);
    TEST_ASSERT_TRUE(records[0].wpsParsed);
    TEST_ASSERT_EQUAL_UINT8(0x10, records[0].wpsVersion);
    TEST_ASSERT_EQUAL_STRING("Bravo", records[1].ssid);
    TEST_ASSERT_EQUAL(-61, records[1].rssi);
    TEST_ASSERT_FALSE(records[1].wpsParsed);
    TEST_ASSERT_EQUAL_STRING("Charlie", records[2].ssid);
}

void test_active_discovery_fields_win_over_passive_rssi_and_security() {
    WpsScanRecord records[4] = {};
    size_t count = 0;
    WpsScanRecord active = activeCandidate(0x10, "Stable", -50);
    wpsScanMergeRecord(records, count, 4, active);

    WpsScanRecord passive = passiveCandidate(0x10, -91, true, false);
    wpsScanMergeRecord(records, count, 4, passive);

    TEST_ASSERT_EQUAL_UINT32(1, count);
    TEST_ASSERT_EQUAL_STRING("Stable", records[0].ssid);
    TEST_ASSERT_EQUAL_STRING("WPA2-PSK", records[0].security);
    TEST_ASSERT_EQUAL(-50, records[0].rssi);
    TEST_ASSERT_TRUE(records[0].wpsParsed);
}

void test_passive_only_wps_candidate_is_retained() {
    WpsScanRecord records[4] = {};
    size_t count = 0;
    WpsScanRecord passiveOnly = passiveCandidate(0x20, -77, true, true);
    wpsScanMergeRecord(records, count, 4, passiveOnly);

    TEST_ASSERT_EQUAL_UINT32(1, count);
    TEST_ASSERT_EQUAL_STRING("Passive SSID", records[0].ssid);
    TEST_ASSERT_TRUE(records[0].lockReported);
    TEST_ASSERT_TRUE(records[0].apSetupLocked);
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_active_wps_candidates_survive_when_passive_pass_misses_them);
    RUN_TEST(test_active_discovery_fields_win_over_passive_rssi_and_security);
    RUN_TEST(test_passive_only_wps_candidate_is_retained);
    return UNITY_END();
}
