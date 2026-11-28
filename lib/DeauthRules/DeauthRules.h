#pragma once

#include <stdint.h>

namespace deauth_rules {

constexpr uint32_t kDefaultDurationSec = 30;
constexpr uint32_t kMaxDurationSec = 3600;

// Distinguish an omitted duration from an explicit zero. Zero is a valid
// duration meaning "run until stopped"; only a missing field gets the default.
static inline uint32_t resolveDurationSec(bool provided, uint32_t durationSec) {
    return provided ? durationSec : kDefaultDurationSec;
}

static inline uint32_t clampDurationSec(uint32_t durationSec) {
    return durationSec > kMaxDurationSec ? kMaxDurationSec : durationSec;
}

}  // namespace deauth_rules
