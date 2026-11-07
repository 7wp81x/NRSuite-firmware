#pragma once

#include <Arduino.h>

// Raw Serial debug output is disabled by default. On UART-only boards Serial
// is the NRSuite protocol transport, so any print corrupts frame boundaries and
// can drop asynchronous events. Enable only when a dedicated debug transport is
// available and the protocol stream is not using Serial.
#ifndef NRSUITE_DEBUG_SERIAL
#define NRSUITE_DEBUG_SERIAL 0
#endif

#if NRSUITE_DEBUG_SERIAL
#define NRSUITE_DEBUG_PRINT(...) Serial.print(__VA_ARGS__)
#define NRSUITE_DEBUG_PRINTLN(...) Serial.println(__VA_ARGS__)
#define NRSUITE_DEBUG_PRINTF(...) Serial.printf(__VA_ARGS__)
#else
#define NRSUITE_DEBUG_PRINT(...) do {} while (0)
#define NRSUITE_DEBUG_PRINTLN(...) do {} while (0)
#define NRSUITE_DEBUG_PRINTF(...) do {} while (0)
#endif
