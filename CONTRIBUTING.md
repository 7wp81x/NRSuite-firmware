# Contributing to NRSuite Firmware

Thanks for considering contributing. The firmware spans multiple ESP32 chip targets, a custom USB serial protocol, and radio-level Wi-Fi/BLE operations -- so there is a lot of ground to cover. This guide helps you get set up and submit good PRs.

## Before You Start

1. **Check [FEATURES.md](./FEATURES.md)** for the roadmap and current status of each module.
2. **Search existing issues** before opening a new one to avoid duplicate work.
3. **Open an issue first** before writing code for anything nontrivial. Describe what you want to build and why. This avoids wasted effort on PRs that conflict with work already in progress or do not fit the roadmap.
4. Read the [Legal/Ethical boundaries](#legalethical-boundaries) section below before starting.

## Repos

| Repo | Stack | What lives here |
|---|---|---|
| `nrsuite-firmware` | C/C++, Arduino framework, PlatformIO | ESP32 firmware: all radio modules, protocol implementation, peripheral drivers |
| `nrsuite-android` | Kotlin, Jetpack Compose | Android companion app |
| `nrsuite-protocol` | Markdown spec | Shared frame and packet format between app and firmware |

If your change touches any command, response field, or frame type, update `nrsuite-protocol` first and reference the spec version in your PR description.

---

## Development Setup

### Requirements

- [PlatformIO Core](https://docs.platformio.org/en/latest/core/installation/index.html) (CLI) or the [PlatformIO VS Code extension](https://platformio.org/install/ide?install=vscode)
- Python 3.x
- A supported ESP32 board for hardware testing (see README for the board list)
- USB cable

### Install PlatformIO CLI

```bash
pip install platformio
```

### Clone the repo

```bash
git clone https://github.com/7wp81x/nrsuite-firmware.git
cd nrsuite-firmware
```

### Build

```bash
# Default target (ESP32-C3)
pio run

# Specific target
pio run -e esp32-c3
pio run -e esp32-s3
pio run -e esp32-s2
pio run -e esp32-devkit

# All targets
pio run -e esp32-c3 -e esp32-s3 -e esp32-s2 -e esp32-devkit
```

### Run unit tests (no hardware needed)

```bash
pio test -e native
```

The native environment runs protocol spec tests on your machine without any ESP32 connected. Run this before submitting any change that touches `lib/BridgeProtocol/`.

### Flash to hardware

```bash
pio run -e esp32-c3 --target upload
```

Replace `esp32-c3` with your target. Make sure the board is connected and the correct port is detected by PlatformIO.

### Monitor serial output

```bash
pio device monitor --baud 115200
```

---

## Branching Model

- `main` -- always stable and flashable. Protected, no direct pushes.
- `develop` -- integration branch for the next release. Target your PRs here.
- `feature/<short-name>` -- one feature or fix per branch, branched from `develop`
- `hotfix/<short-name>` -- urgent fixes branched from `main`, merged to both `main` and `develop`

Naming examples: `feature/deauth-detector`, `feature/espnow-mesh-activation`, `hotfix/sniffer-channel-crash`.

---

## Pull Request Process

1. Branch from `develop` (or `main` for hotfixes).
2. Keep PRs scoped to one feature or fix. Large multi-feature PRs will likely be asked to split.
3. Fill out the PR template: what changed, why, which boards were tested, any protocol or partition changes.
4. Ensure CI passes (compile check across all targets).
5. Run `pio test -e native` if your change touches the bridge protocol.
6. At least one maintainer approval required before merge.
7. Squash-merge preferred to keep history readable.

---

## Testing Expectations

Hardware testing is expected for firmware PRs. The CI only does a compile check -- it cannot test radio behavior, USB serial communication, or pcap output on a real device.

| Change type | Testing required |
|---|---|
| Wi-Fi scan, sniffer, deauth, beacon, portal | Test on real hardware, at least one board |
| BLE HID, BadUSB, MSC | Test on a board that supports the feature (S2/S3 for MSC/HID, C3/S3 for BLE) |
| Bridge protocol changes | Run `pio test -e native` plus hardware test with the Android app |
| New board support | Test compile and basic `PING`/`STATUS` response on that board |
| Partition table changes | Flash and verify the board boots and all features function |
| Defense modules (new) | Test detection accuracy on a controlled setup you own |

When submitting, mention in the PR:
- Which board(s) you tested on
- Firmware version flashed
- App version used to verify (if testing with the Android app)

---

## Code Style

- Match the existing structure: offense modules in `src/`, defense modules will go in `src/defense/` (pending), mesh in `src/mesh/` (pending), peripheral drivers in `src/peripherals/` (pending)
- Keep radio-specific code isolated per peripheral -- do not couple sub-GHz or nRF24 logic into the Wi-Fi/BLE path
- Use `#ifdef` guards for features that are not available on all chips (follow the existing `ENABLE_BLE_HID`, `MSC_SUPPORTED`, `HID_SUPPORTED` pattern)
- Comment the "why" for protocol-level and radio-level code, not just the "what" -- raw 802.11 frame construction and ESP-IDF quirks especially benefit from inline rationale
- Keep `main.cpp` as a thin command dispatcher. Business logic belongs in the relevant module files

---

## Commit Style

Conventional-commit-style prefixes appreciated:

```
feat: add deauth detector module
fix: correct channel sync before frame injection
board: add ESP32-C6 environment
docs: update protocol version in README
refactor: extract EAPOL filter into sniffer helper
test: add native test for frame decoder edge case
```

---

## Adding a New Board

1. Add a new `[env:your-board]` section in `platformio.ini` following the existing patterns
2. Set the correct `board`, `board_build.mcu`, feature flags, and partition table
3. If the board needs a new partition layout, add a `your-board_partitions.csv` file
4. Test compile: `pio run -e your-board`
5. Test on real hardware: flash and verify `PING`/`STATUS` response in the Android app
6. Update the board table in `README.md`
7. Note any feature limitations (e.g. no BLE, no native USB) in the board table

---

## Legal/Ethical Boundaries

Some contribution categories will not be accepted:

- **RF/Wi-Fi/BLE jamming** (transmission-based denial of service against a radio spectrum) -- illegal in most jurisdictions regardless of intent. PRs implementing jamming (as opposed to jam detection) will be closed. See [FEATURES.md](./FEATURES.md#explicitly-out-of-scope).
- Features whose only plausible use is targeting systems without authorization will be evaluated case by case and may be declined.

When in doubt, open an issue before building.

---

## Reporting Security Issues

If you find a vulnerability in the firmware itself (for example, a flaw in the bridge protocol, the HTML chunk handling in the portal module, or the raw frame injection path), please report privately rather than opening a public issue. See [SECURITY.md](./SECURITY.md).

---

## Code of Conduct

Be respectful, assume good faith, keep discussion focused on technical merits. Requests for help targeting specific real-world unauthorized systems will result in a ban from the project.