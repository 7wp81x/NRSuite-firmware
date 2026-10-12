#pragma once
#include <Arduino.h>

#if CONFIG_IDF_TARGET_ESP32S2 || CONFIG_IDF_TARGET_ESP32S3

#include <USBHIDKeyboard.h>

#ifdef String
#undef String
#endif

extern USBHIDKeyboard Keyboard;

class UsbHID {
public:
    static bool armScript(const String& filename, bool mscMode);
    static bool disarm();
    static bool runIfArmed();

    // Realtime helpers used by the PIN bruteforce module and future HID tools.
    static bool available();
    static void sendText(const String& text);
    static void pressEnter();
    static void releaseAll();

    // DuckyScript fallback store used when the FAT/MSC partition is missing
    // or cannot be written. Keeps BadUSB usable on minimal/flash-recovered
    // builds without changing the Android upload protocol.
    static bool saveScript(const String& content);
    static bool loadScript(String& out);
    static void clearScript();

private:
    static void runScript(const String& scriptContent);
};

#endif // CONFIG_IDF_TARGET_ESP32S2 || CONFIG_IDF_TARGET_ESP32S3