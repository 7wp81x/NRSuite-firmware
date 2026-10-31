# NRSuite — Features & Roadmap

This document lists all current and planned features across the NRSuite ecosystem (Android app + ESP32 firmware + mesh network). Status legend:

- ✅ Implemented
- 🚧 In progress
- 📋 Planned
- 🧪 Experimental / not release-ready
- ⏸️ Parked / disabled pending hardware validation
- ❌ Out of scope

---

## 1. Offense Modules (Wi-Fi / BLE)

| Feature | Status | Notes |
|---|---|---|
| Firmware Release Assets | ✅ | Release CI builds merged images for ESP32-C5, C3, S3, S2, and classic ESP32; C5 merged image uses the correct `0x2000` bootloader layout |
| Wi-Fi Scan | ✅ | Active AP/channel discovery; band-aware `SCAN_WIFI`/`scan_ap`, AUTO 2.4+5 GHz on C5, 2.4 GHz fallback elsewhere; regulatory country/channel mask exposed via `STATUS` |
| Beacon Injection | ✅ | Beacon frame injection/spoofing |
| Deauthentication | ✅ | Deauth frame injection; finite burst or stoppable duration-based loop mode using `DEAUTH_STOP`; firmware-native up-to-32-target `DEAUTH_MULTI` with per-target channel schedules and counters |
| Evil Twin | ✅ | Rogue AP with captive portal |
| Captive Portal | ✅ | Credential harvesting UI |
| Packet Sniffer | ✅ | Monitor-mode capture, pcap export; AUTO/2.4/5 GHz hop selection on C5, target-channel-aware fixed capture, and capture-preserving deauth retries |
| WPA Handshake Capture/Crack | ✅ | Offline WPA2 M1/M2 dictionary cracking support and capture-assist flows; app-side PCAP → `.22000` conversion is planned |
| Nrugochi channel capture support | ✅ | Advertises `nrugochi`; `DEAUTH_CHANNEL_CAPTURE` supports multi-AP deauth plus all-EAPOL/all-beacon capture and reports requested/sent/failed frame counts |
| WPS Pixie Dust | S3, C5 | Raw WPS registrar M1-M8 flow, AP-lock preflight, hidden randomized WPA2 helper SoftAP, M3-only Pixie capture, same-session recovered-PIN continuation, and WSC completion. Advertises `wps_pixie`. |
| WPS Lock Detector | All | Passive beacon/probe-response scan that parses WPS IEs and reports AP Setup Locked state, WPS version, configuration methods, and selected-registrar metadata. Advertises `wps_lock_detect`. |
| WPS Attempt Detector | All | Passive EAP-WSC monitor tracks Identity/M1-M8/M2D/NACK sessions by BSSID and source client MAC, preserves per-session evidence flags, and emits live WPS lock-state changes. Advertises `wps_attempt_detect`. |
| Half Handshake capture | 🧪 Experimental | Active probe-response/SoftAP experiment intended to elicit WPA2 M1+M2 from an authorized auto-connecting client. Not implemented; requires explicit authorization, WPA2/RSN compatibility, temporary-AP cleanup, and hardware validation. |
| BLE HID | ✅ | Bluetooth LE keyboard/mouse HID and DuckyScript payloads |
| BLE Scanner | ✅ | Advertisement scan with names, RSSI, manufacturer data, service UUIDs, and raw payload |
| BLE GATT Profile | ✅ | Read-only service/characteristic enumeration over a BLE connection |
| FastPair Model ID | 📋 | Map FastPair model IDs to known device names/types |
| BadUSB | ✅ | HID injection via USB; DuckyScript NVS fallback when FAT is unavailable |
| PIN Bruteforce | ✅ | Native-HID range/wordlist tester; one-shot boot-arm like BadUSB; configurable typing/start delays; session persistence; CH9329 abandoned |
| BLE HID PIN Bruteforce | ✅ | Hidden/experimental: live CDC-controlled BLE HID PIN tester retained for future unlocked-host and mesh HID reuse; lock-screen use unsupported |
| Credential Manager | ✅ | Local storage of harvested creds |

## 2. Defense Modules

| Feature | Status | Notes |
|---|---|---|
| Rogue AP Detector | ✅ | Baseline SSID→BSSID/channel/security; flags mismatches, downgrades, duplicate SSIDs, KARMA-style probe-response behavior |
| Deauth Detector | ✅ | Passive deauth/disassoc monitoring with BSSID/client/RSSI/reason filters, async alerts, and live logs |
| Deauth Locator | 📋 | RSSI-based direction/distance estimate; multi-node triangulation |
| Tracker Detector | ✅ | Android-side Find My-style detection using BLE Scanner raw payloads, repeated sightings, and alerts |
| Client Detector | ✅ | Passive probe/assoc/reassoc/auth monitoring plus active deauth-trigger mode |
| Hidden AP Revealer | ✅ | Hidden AP detection, probe-request candidates, association-based SSID resolution, and optional deauth reconnect trigger |
| Unauthorized RFID Reader Detector | 📋 | Detect unattended/skimmer-style RF field polling nearby |
| Jam Detector (Sub-GHz / 2.4GHz) | 📋 | Wideband noise-floor anomaly detection (detection only — see Legal notes) |

## 3. Mesh Network (ESP-NOW)

| Feature | Status | Notes |
|---|---|---|
| Shared Group Key Provisioning | ✅ | HKDF-SHA256-derived auth/transport keys provisioned over USB and stored in NVS |
| Dynamic Master Election | ✅ | USB-authenticated candidate election; existing master forces self-demotion |
| Client Idle/Standby Mode | ✅ | Provisioned nodes passively listen after reboot and auto-join a valid master |
| Encrypted ESP-NOW Transport | ✅ | AES-CCM transport encryption with replay protection |
| Activation Handshake | ✅ | Decrypt, auth, replay-counter, and 30 s USB auth window |
| Session Locking | ✅ | Fresh master session ID; clients lock to it and recover after master reboot |
| Heartbeat/Auto-Timeout | ✅ | 1 s master heartbeat, 5 s master timeout, 8 s peer timeout |
| Distributed Sensor Reporting | 🟡 | Phase 3A `node_health` transport hardware-validated on S3 + S2; detector reports pending |
| Triangulation Engine (app-side) | 📋 | Log-distance path-loss + trilateration from 3+ node RSSI reports |

## 4. Mesh Chat

| Feature | Status | Notes |
|---|---|---|
| ESP-NOW Chat Transport | 📋 | Reuses mesh group-key infra |
| Multi-hop Relay | 📋 | Flood-fill with message-ID dedup |
| Store-and-Forward | 📋 | Hold messages for out-of-range recipients |
| Message Fragmentation | 📋 | Handles ESP-NOW's ~250 byte payload cap |
| Sender Aliases | 📋 | Human-readable operator names instead of raw MAC |
| Quick/Canned Messages | 📋 | Preset messages for fast field use |
| Chat/Sensor Traffic Prioritization | 📋 | Alerts pre-empt chat traffic on shared channel |

## 5. Remote Camera Node (ESP32-CAM)

| Feature | Status | Notes |
|---|---|---|
| Live Feed Streaming | 📋 | Separate Wi-Fi link (not over ESP-NOW — bandwidth) |
| Snapshot-on-Trigger | 📋 | Captures still on detection events from other modules |
| Motion Detection | 📋 | Frame-diff trigger, reduces idle streaming |
| Deep-sleep/Low-power Mode | 📋 | Timer or PIR-interrupt wake |
| SD Card Buffering | 📋 | Local storage if master link is down |
| Mesh Manager Integration | 📋 | Camera nodes shown alongside sensor/chat nodes |

## 6. Long-Range Relay (LoRa)

| Feature | Status | Notes |
|---|---|---|
| LoRa Node-to-Node Link | 📋 | SX1276/78, kilometers of range, requires soldering |
| LoRa Chat Bridge | 📋 | Bridges distant node clusters into mesh chat |
| Low-bandwidth Telemetry | 📋 | Alerts, GPS, heartbeats — not video |
| Long-baseline Locator Beacon | 📋 | Improves triangulation geometry via wider node spacing |
| Multi-hop Routing | 📋 | Beyond simple flood-relay, given larger distances/node counts |

## 7. Peripheral Radios (planned expansion modules)

| Feature | Status | Notes |
|---|---|---|
| **IR** — Capture/Replay | ✅ | RMT raw IR TX/RX with dynamic GPIO configuration, NVS persistence, `.ir` import/library, received-capture workflow, and Phone/ESP32 backends. Broader protocol/board validation remains pending. |
| **IR** — Universal Remote DB | ✅ | Flipper-IRDB download/update/ZIP import and local remote library |
| **IR** — TV-off Brute-force | ❌ | Out of scope; IR Finder covers the supported workflow |
| **Sub-GHz (CC1101)** — Scanner | 📋 | 315/433/868/915MHz sweep |
| **Sub-GHz** — Capture/Replay | 📋 | Fixed-code devices; rolling-code explicitly not supported/replayable |
| **Sub-GHz** — Protocol Decoder | 📋 | Identifies fixed vs. rolling code |
| **nRF24** — RC/Device Scanner | 📋 | Detect nearby nRF24-based peripherals |
| **nRF24** — MouseJack-style Analysis | 📋 | Detection/analysis of known-vulnerable wireless HID dongles |
| **nRF24** — Packet Sniffer | 📋 | Promiscuous capture for research |
| **LD2450** — mmWave Radar | 🟡 | UART 256000 target parser, corrected sign-magnitude decode, `LD2450_START/STOP/STATUS`, targets/presence/error events; Android plot and target list implemented |
| **RFID/NFC** — PN532 I2C read | ⏸️ | Firmware/Android scaffolding exists but capability is disabled until reliable hardware validation |
| **RFID/NFC** — Read (125kHz + 13.56MHz) | 📋 | RC522 + LF reader modules |
| **RFID/NFC** — Emulate | 📋 | Replay previously-read tag |
| **RFID/NFC** — Write/Clone | 📋 | To blank/magic tags |
| **RFID/NFC** — Access Control Analyzer | 📋 | Identify tag type + known weaknesses (e.g., MIFARE Classic) |

## Explicitly Out of Scope

- **RF/Wi-Fi/BLE Jamming (transmission-based denial)** — illegal in most jurisdictions regardless of stated intent (US 47 U.S.C. §333 and equivalents). NRSuite implements **jam detection**, not jamming. This is a firm project boundary, not just a "not yet built" item.

---

## Roadmap Phasing

### v1 — Near-term
Builds on existing offense infrastructure (sniff/pcap/frame codec).
- Rogue AP Detector
- Deauth Detector
- AirTag/Tracker Detector
- Mesh Chat (single-hop, basic)

### v2 — Mesh & Camera
- Mesh master/client election + activation handshake
- Distributed sensor reporting + triangulation
- Deauth Locator
- ESP32-CAM node integration

### v3 — Peripheral & Long-range Expansion
- Sub-GHz, nRF24, and RFID/NFC expansion modules
- LoRa long-range relay node
- Multi-hop mesh routing

Contributions toward any phase are welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md). If you want to pick up a 📋 item, open an issue first so work isn't duplicated.
