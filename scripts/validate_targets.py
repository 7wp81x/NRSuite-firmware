#!/usr/bin/env python3
"""Validate the firmware target registry and partition layouts."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from target_registry import (
    REGISTRY_RELATIVE_PATH,
    TargetRegistryError,
    load_registry,
    parse_partition_table,
    resolve_app_offset,
    target_for_environment,
    targets_by_environment,
)


EXPECTED_S3_LAYOUTS = {
    "esp32-s3": ("0x300000", "0xF0000", 4 * 1024 * 1024),
    "esp32-s3-n4r2": ("0x300000", "0xF0000", 4 * 1024 * 1024),
    "esp32-s3-n4r8": ("0x300000", "0xF0000", 4 * 1024 * 1024),
    "esp32-s3-n8r8": ("0x400000", "0x3F0000", 8 * 1024 * 1024),
    "esp32-s3-n16": ("0x600000", "0x9F0000", 16 * 1024 * 1024),
    "esp32-s3-n16r8": ("0x600000", "0x9F0000", 16 * 1024 * 1024),
}
FORBIDDEN_ENVIRONMENTS = {"esp32-s3-n32r8", "esp32-c5-n16r8"}
KNOWN_CHIP_FAMILIES = {"esp32", "esp32s2", "esp32s3", "esp32c3", "esp32c5"}


def fail(message: str) -> None:
    raise TargetRegistryError(message)


def validate(project_dir: Path) -> list[str]:
    registry = load_registry(project_dir)
    mapping = targets_by_environment(registry)
    targets = registry["targets"]
    seen_assets: dict[str, str] = {}
    lines: list[str] = []

    platformio = (project_dir / "platformio.ini").read_text(encoding="utf-8")
    if "[env:" in platformio:
        fail("platformio.ini must not define per-board [env:*] sections")

    ini_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((project_dir / "boards").rglob("*.ini"))
    )

    for target in targets:
        environment = target["environment"]
        if environment in FORBIDDEN_ENVIRONMENTS:
            fail(f"forbidden target present: {environment}")
        if f"[env:{environment}]" not in ini_text:
            fail(f"{environment}: no matching [env:{environment}] in boards/*.ini")

        chip_family = target.get("chip_family")
        if chip_family not in KNOWN_CHIP_FAMILIES:
            fail(f"{environment}: unsupported chip_family {chip_family!r}")

        partition_table = target.get("partition_table")
        if not partition_table:
            fail(f"{environment}: missing partition_table")
        partition_path = project_dir / partition_table
        if not partition_path.is_file():
            fail(f"{environment}: partition table missing: {partition_table}")

        entries = parse_partition_table(partition_path)
        names = {entry["name"] for entry in entries}
        for required in ("nvs", "app0"):
            if required not in names:
                fail(f"{environment}: {partition_table} missing {required}")
        nvs = next(entry for entry in entries if entry["name"] == "nvs")
        if nvs["offset"] != 0x9000 or nvs["size"] != 0x5000:
            fail(
                f"{environment}: NVS must stay at 0x9000/0x5000, got "
                f"{nvs['offset']:#x}/{nvs['size']:#x}"
            )

        resolved_app_offset = resolve_app_offset(
            project_dir, registry, environment, partition_table
        )
        if resolved_app_offset != 0x10000:
            fail(
                f"{environment}: app0 must stay at 0x10000, got "
                f"{resolved_app_offset:#x}"
            )

        flash_bytes = target.get("flash_bytes")
        if not isinstance(flash_bytes, int) or flash_bytes <= 0:
            fail(f"{environment}: invalid flash_bytes")
        for entry in entries:
            end = entry["offset"] + entry["size"]
            if end > flash_bytes:
                fail(
                    f"{environment}: partition {entry['name']} ends at {end:#x}, "
                    f"beyond flash size {flash_bytes:#x}"
                )

        asset_name = target.get("asset_name")
        if not asset_name or not asset_name.endswith(".bin"):
            fail(f"{environment}: invalid release asset_name {asset_name!r}")
        previous = seen_assets.get(asset_name)
        if previous is not None:
            fail(f"duplicate asset_name {asset_name!r}: {previous} and {environment}")
        seen_assets[asset_name] = environment

        for channel in ("stable", "beta", "rc"):
            prefix = registry["release_asset_prefixes"][channel]
            expected_prefix = "" if channel == "stable" else f"{channel}-"
            if prefix != expected_prefix:
                fail(f"unexpected {channel} asset prefix {prefix!r}")

        lines.append(
            f"{environment:28s} {target['flash_size']:>4s} "
            f"psram={target['psram']:<8s} app@{resolved_app_offset:#x} "
            f"{target['release_status']}"
        )

    for environment, (app_size, fat_size, flash_bytes) in EXPECTED_S3_LAYOUTS.items():
        target = target_for_environment(registry, environment)
        if target is None:
            fail(f"missing required S3 profile: {environment}")
        entries = parse_partition_table(project_dir / target["partition_table"])
        by_name = {entry["name"]: entry for entry in entries}
        if by_name["app0"]["size"] != int(app_size, 0):
            fail(f"{environment}: unexpected app0 size {by_name['app0']['size']:#x}")
        if "msc_ffat" not in by_name:
            fail(f"{environment}: partition table has no msc_ffat")
        if by_name["msc_ffat"]["size"] != int(fat_size, 0):
            fail(
                f"{environment}: unexpected msc_ffat size "
                f"{by_name['msc_ffat']['size']:#x}"
            )
        if target["flash_bytes"] != flash_bytes:
            fail(f"{environment}: unexpected flash size {target['flash_bytes']:#x}")
        if target["release_status"] != "supported":
            fail(f"{environment}: S3 profile must be marked supported")

    for environment in ("esp32-c5-n8r4", "esp32-c5-n16r4"):
        target = target_for_environment(registry, environment)
        if target is None:
            fail(f"missing experimental profile: {environment}")
        if target["release_status"] != "experimental":
            fail(f"{environment}: must remain experimental")

    if target_for_environment(registry, "esp32-s3-psram") is None:
        fail("esp32-s3-psram compatibility alias is missing")

    return lines


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "project_dir",
        nargs="?",
        default=str(Path(__file__).resolve().parents[1]),
        help="Firmware project root (defaults to the repository root)",
    )
    args = parser.parse_args()
    project_dir = Path(args.project_dir).resolve()
    try:
        lines = validate(project_dir)
    except TargetRegistryError as exc:
        print(f"[targets] ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"[targets] validated {len(lines)} targets from {REGISTRY_RELATIVE_PATH}")
    for line in lines:
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
