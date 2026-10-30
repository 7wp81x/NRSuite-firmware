#include <unity.h>

#include "DeauthMultiRules.h"

void setUp(void) {}
void tearDown(void) {}

void test_target_capacity_limit() {
    TEST_ASSERT_EQUAL_UINT32(32, deauth_multi::kMaxTargets);
}

void test_frame_count_clamping() {
    TEST_ASSERT_EQUAL_UINT32(1, deauth_multi::clampFrameCount(0));
    TEST_ASSERT_EQUAL_UINT32(20, deauth_multi::clampFrameCount(20));
    TEST_ASSERT_EQUAL_UINT32(2000, deauth_multi::clampFrameCount(99999));
}

void test_interval_clamping() {
    TEST_ASSERT_EQUAL_UINT16(10, deauth_multi::clampIntervalMs(1));
    TEST_ASSERT_EQUAL_UINT16(100, deauth_multi::clampIntervalMs(100));
    TEST_ASSERT_EQUAL_UINT16(10000, deauth_multi::clampIntervalMs(60000));
}

void test_duration_clamping() {
    TEST_ASSERT_EQUAL_UINT32(0, deauth_multi::clampDurationSec(0));
    TEST_ASSERT_EQUAL_UINT32(3600, deauth_multi::clampDurationSec(99999));
}

void test_burst_requested_frame_total() {
    TEST_ASSERT_EQUAL_UINT32(40, deauth_multi::burstRequestedFrames(2, 20));
    TEST_ASSERT_EQUAL_UINT32(4000, deauth_multi::burstRequestedFrames(2, 99999));
}

int main(int argc, char** argv) {
    UNITY_BEGIN();
    RUN_TEST(test_target_capacity_limit);
    RUN_TEST(test_frame_count_clamping);
    RUN_TEST(test_interval_clamping);
    RUN_TEST(test_duration_clamping);
    RUN_TEST(test_burst_requested_frame_total);
    return UNITY_END();
}
