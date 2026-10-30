#pragma once

#include <stddef.h>
#include <stdint.h>

namespace deauth_multi {

constexpr size_t kMaxTargets = 32;
constexpr uint32_t kMaxFramesPerTarget = 2000;
constexpr uint32_t kMaxDurationSec = 3600;
constexpr uint16_t kMinIntervalMs = 10;
constexpr uint16_t kMaxIntervalMs = 10000;
constexpr uint16_t kDefaultIntervalMs = 100;

static inline uint32_t clampFrameCount(uint32_t count) {
    if (count < 1) return 1;
    return count > kMaxFramesPerTarget ? kMaxFramesPerTarget : count;
}

static inline uint32_t clampDurationSec(uint32_t durationSec) {
    return durationSec > kMaxDurationSec ? kMaxDurationSec : durationSec;
}

static inline uint16_t clampIntervalMs(uint16_t intervalMs) {
    if (intervalMs < kMinIntervalMs) return kMinIntervalMs;
    return intervalMs > kMaxIntervalMs ? kMaxIntervalMs : intervalMs;
}

static inline uint32_t burstRequestedFrames(size_t targetCount, uint32_t countPerTarget) {
    return static_cast<uint32_t>(targetCount) * clampFrameCount(countPerTarget);
}

}  // namespace deauth_multi
