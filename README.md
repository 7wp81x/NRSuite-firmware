# NRSuite Firmware

**ESP32 firmware for the NRSuite security research toolkit.**

This firmware runs on the ESP32 and communicates with the [NRSuite Android app](https://github.com/7wp81x/nrsuite-android) over USB serial. It handles all radio-level operations: Wi-Fi scanning, monitor-mode packet capture, deauthentication, beacon injection, captive portal, BLE HID, BadUSB, and mass storage -- with more modules planned.

> **Authorized use only.** This firmware is for security research and testing on networks and devices you own or are explicitly authorized to test. See [LEGAL.md](./LEGAL.md).

---

## Supported Boards

| Board | MCU | Native USB | BLE | BadUSB / MSC | Environment |
|---|---|---|---|---|---|
| ESP32-C3 DevKitM-1 | ESP32-C3 | Yes (CDC) | Yes | No | `esp32-c3` |
| ESP32-S3 DevKitC-1 | ESP32-S3 | Yes (TinyUSB) | Yes | Yes | `esp32-s3` |
| ESP32-S2 Saola-1 | ESP32-S2 | Yes (TinyUSB) | No | Yes | `esp32-s2` |
| ESP32 DevKit | ESP32 | No (needs CP2102/CH340) | Yes | No | `esp32-devkit` |

**Recommended board for getting started:** ESP32-C3 DevKitM-1. It has native USB CDC (no external USB-UART chip), BLE, and is the default build target.

---

## Features

### Current (v1.0.0-beta.1)

| Module | Supported Boards | Description |
|---|---|---|
| Wi-Fi Scan | All | Active AP scan with SSID, BSSID, channel, RSSI, security type |
| Packet Sniffer | All | Monitor-mode pcap capture, fixed channel or channel hopping, optional EAPOL-only filter |
| Deauthentication | All | Raw 802.11 deauth frame injection, broadcast or targeted |
| Deauth + Capture | All | Deauth followed by immediate EAPOL capture for WPA handshake collection |
| Beacon Spam | All | Inject fake beacon frames, random BSSID, hidden SSID support |
| Captive Portal | All | SoftAP evil twin with async HTTP server, custom HTML upload |
| BLE HID | C3, S3, DevKit | Bluetooth keyboard and mouse emulation, Ducky Script execution |
| BadUSB | S2, S3 | USB HID keyboard injection via TinyUSB, Ducky Script from storage |
| Mass Storage | S2, S3 | USB MSC mode, FAT filesystem, file read/write/delete over USB |
| Heartbeat | All | Periodic uptime and free heap event to the app |

### Planned (see [FEATURES.md](./FEATURES.md))
- Defense modules: deauth detector, rogue AP detector, AirTag/tracker detector
- ESP-NOW mesh: multi-node activation, distributed sensing, triangulation
- Mesh chat
- Remote camera support (ESP32-CAM node)
- Sub-GHz, nRF24, RFID/NFC, IR peripheral modules
- LoRa long-range relay node

---

## Requirements

### Hardware
- One of the supported ESP32 boards listed above
- USB cable (USB-C for most modern devkits)
- For the classic ESP32 DevKit: a CP2102 or CH340 USB-UART bridge is built into most devkit boards

### Software
- [PlatformIO](https://platformio.org/) (CLI or VS Code extension)
- Python 3.x (used by PlatformIO and the merge script)

---

## Building

### Install PlatformIO

```bash
pip install platformio
```

Or install the [PlatformIO VS Code extension](https://platformio.org/install/ide?install=vscode).

### Clone and build

```bash
git clone https://github.com/7wp81x/nrsuite-firmware.git
cd nrsuite-firmware
```

Build the default target (ESP32-C3):

```bash
pio run
```

Build a specific board:

```bash
pio run -e esp32-c3
pio run -e esp32-s3
pio run -e esp32-s2
pio run -e esp32-devkit
```

Build all targets:

```bash
pio run -e esp32-c3 -e esp32-s3 -e esp32-s2 -e esp32-devkit
```

---

## Flashing

### Option A: Flash from the NRSuite Android app (recommended)

The Android app has a built-in ESP32 flasher. Connect your board via USB-OTG and use the flasher screen to upload the latest firmware binary from the [Releases](../../releases) page.

### Option B: Flash via PlatformIO

```bash
pio run -e esp32-c3 --target upload
```

Replace `esp32-c3` with your target environment.

### Option C: Flash via esptool manually

Download the merged binary from [Releases](../../releases) and flash it:

```bash
esptool.py --port /dev/ttyUSB0 --baud 921600 write_flash 0x0 nrsuite-firmware-esp32c3-v1.0.0-beta.1.bin
```

> The release binary is a merged flash image (bootloader + partition table + app) produced by `merge_script.py` at build time. Use offset `0x0` when flashing the merged binary.

---

## Running Tests

Unit tests run natively on your machine without any hardware:

```bash
pio test -e native
```

This runs the protocol spec tests under `test/test_protocol_spec/`.

---

## Project Structure

```
src/
  main.cpp          # Entry point, command handler, setup/loop
  sniffer.cpp/h     # Monitor-mode packet capture and pcap streaming
  beacon.cpp/h      # Beacon frame injection
  portal.cpp/h      # Captive portal (SoftAP + async HTTP server)
  ble_hid.cpp/h     # BLE keyboard/mouse HID (C3, S3, DevKit)
  UsbHID.cpp/h      # USB HID BadUSB via TinyUSB (S2, S3)
  mass_storage.cpp/h  # USB MSC + FAT filesystem (S2, S3)
  FileUpload.cpp/h  # Chunked file upload to mass storage
  override_sanity.cpp  # ieee80211 raw frame sanity check override (required for frame injection)

lib/
  BridgeProtocol/   # USB serial framing protocol (shared with nrsuite-android)
    BridgeProtocol.cpp/h
    ProtocolSpec.h
  HijelHID_BLEKeyboard/  # BLE HID keyboard library

test/
  test_protocol_spec/  # Native unit tests for the bridge protocol

default_4MB.csv          # Default 4MB partition table
esp32c3_partitions.csv   # C3-specific partition layout (LittleFS)
esp32s2_msc_partitions.csv  # S2 partition layout with FAT for MSC
esp32s3_msc_partitions.csv  # S3 partition layout with FAT for MSC
merge_script.py          # Post-build script that merges bootloader + partitions + app into one flashable binary
platformio.ini           # PlatformIO build configuration
```

---

## Wire Protocol

The firmware communicates with the Android app using the NRSuite bridge protocol implemented in `lib/BridgeProtocol/`. The protocol spec is versioned separately in [nrsuite-protocol](https://github.com/7wp81x/nrsuite-protocol).

**Current protocol version: `1.0`**

If your contribution changes any command, response field, or frame type, update the protocol spec first and reference the spec version in your PR.

---

## Feature Flags

Features are conditionally compiled based on the target board. Key flags set in `platformio.ini`:

| Flag | Boards | Description |
|---|---|---|
| `ENABLE_BLE_HID` | C3, S3, DevKit | Enables BLE keyboard and mouse HID |
| `MSC_SUPPORTED` | S2, S3 | Enables USB mass storage |
| `HID_SUPPORTED` | S2, S3 | Enables USB HID BadUSB |
| `ARDUINO_USB_CDC_ON_BOOT` | C3, S2, S3 | Native USB CDC without external UART |
| `CONFIG_ESP_WIFI_ENABLE_SNIFFER` | All | Enables promiscuous mode for packet capture |

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the full guide: branching model, PR process, testing expectations, and scope boundaries.

Short version:
- Open an issue before starting any nontrivial feature
- Branch from `develop`, not `main`
- Test on real hardware before submitting (CI only does a compile check)
- Run `pio test -e native` before submitting protocol-related changes
- Jamming features (RF/Wi-Fi/BLE denial-of-service transmission) will not be merged, see CONTRIBUTING.md

---

## Related Repos

| Repo | Contents |
|---|---|
| [nrsuite-android](https://github.com/7wp81x/nrsuite-android) | Android companion app (Kotlin/Jetpack Compose) |
| [nrsuite-protocol](https://github.com/7wp81x/nrsuite-protocol) | Wire protocol specification |

---

## Versioning and Compatibility

| Firmware version | App version | Protocol spec |
|---|---|---|
| v1.0.0-beta.1 | v1.0.0-beta.1 | v1.0 |

---

## Security

If you find a vulnerability in the firmware itself (for example, a flaw in the bridge protocol auth, the portal HTML injection handling, or the deauth frame construction), please report it privately. See [SECURITY.md](./SECURITY.md).

---

## License

[MIT](./LICENSE)

This license covers redistribution of the code. It does not authorize use of the firmware against systems you do not own or lack permission to test. See [LEGAL.md](./LEGAL.md).