#include <unity.h>

#include "DeauthRules.h"

void setUp(void) {}
void tearDown(void) {}

void test_explicit_zero_duration_is_until_stopped() {
    TEST_ASSERT_EQUAL_UINT32(0, deauth_rules::resolveDurationSec(true, 0));
}

void test_missing_duration_uses_default() {
    TEST_ASSERT_EQUAL_UINT32(
        deauth_rules::kDefaultDurationSec,
        deauth_rules::resolveDurationSec(false, 0));
}

void test_explicit_duration_is_preserved_and_clamped() {
    TEST_ASSERT_EQUAL_UINT32(120, deauth_rules::resolveDurationSec(true, 120));
    TEST_ASSERT_EQUAL_UINT32(
        deauth_rules::kMaxDurationSec,
        deauth_rules::clampDurationSec(99999));
}

int main(int argc, char** argv) {
    UNITY_BEGIN();
    RUN_TEST(test_explicit_zero_duration_is_until_stopped);
    RUN_TEST(test_missing_duration_uses_default);
    RUN_TEST(test_explicit_duration_is_preserved_and_clamped);
    return UNITY_END();
}
