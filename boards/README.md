# Firmware board profiles

`platformio.ini` contains only shared build configuration and the
`extra_configs` list. Every build environment is defined here.

## Layout

```text
boards/
  targets.json                     Machine-readable target registry
  common/esp32-s3-common.ini       Shared ESP32-S3 build configuration
  esp32-c3.ini
  esp32-c5.ini                     C5 universal + experimental N8R4/N16R4
  esp32-devkit.ini
  esp32-s2.ini
  esp32-s3.ini                     Universal safe fallback
  esp32-s3-n4r2.ini                Also exposes esp32-s3-psram compatibility alias
  esp32-s3-n4r8.ini
  esp32-s3-n8r8.ini
  esp32-s3-n16.ini
  esp32-s3-n16r8.ini
  native.ini
partitions/
  esp32c3_4mb.csv
  esp32c5_4mb.csv
  esp32c5_8mb.csv                  Experimental C5 N8R4
  esp32c5_16mb.csv                 Experimental C5 N16R4
  esp32dev_4mb.csv
  esp32s2_4mb_msc.csv
  esp32s3_4mb_msc.csv
  esp32s3_n8r8_msc.csv
  esp32s3_n16_msc.csv
  esp32s3_n16r8_msc.csv
```

## Registry contract

`targets.json` is the single source of truth for:

- PlatformIO environment and compatibility aliases
- chip family passed to esptool
- flash and PSRAM sizes
- partition table path
- bootloader and application offsets
- canonical release asset name
- supported / experimental / test-only status

`merge_script.py` resolves the application offset from this registry and
verifies it against the `app0` offset in the partition table. Do not hardcode
`0x10000` in release tooling.

Run the registry and layout checks with:

```bash
python3 scripts/validate_targets.py
```

After a build, verify that every merged image has the bootloader, partition
table, and application at the expected offsets:

```bash
python3 scripts/verify_merged_images.py --version 1.0.0-rc.2
```

## Partition rules

- NVS stays at `0x9000` with a size of `0x5000` (20 KB).
- `app0` stays at `0x10000`.
- Do not move `app0` to `0x86000` and do not grow NVS to 500 KB.
- S3 N4 layouts: `0x300000` application + `0xF0000` FAT.
- S3 N8R8: `0x400000` application + `0x3F0000` FAT.
- S3 N16/N16R8: `0x600000` application + `0x9F0000` FAT.
- C5 N8R4/N16R4 are experimental. C5 has no MSC support, so their additional
  flash is assigned to the LittleFS data partition.

## Adding a target

1. Add a `boards/<target>.ini` environment that extends the appropriate shared
   configuration.
2. Add or reuse a partition table under `partitions/`.
3. Add exactly one registry entry in `boards/targets.json`, including any
   compatibility aliases and the canonical stable asset name.
4. Add the environment and asset matcher to the Android release tests when it
   is intended for app-driven flashing.
5. Run `python3 scripts/validate_targets.py` and build the environment.

Do not add ESP32-S3 N32R8 or ESP32-C5 N16R8 profiles.
