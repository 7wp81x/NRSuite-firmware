#!/usr/bin/env python3
"""Verify merged release images use the registry's boot/app offsets."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from target_registry import (
    TargetRegistryError,
    load_registry,
    target_for_environment,
    targets_by_environment,
)


PARTITION_TABLE_OFFSET = 0x8000
ESP_IMAGE_MAGIC = b"\xe9"
PARTITION_TABLE_MAGIC = b"\xaa\x50"


def verify_target(project_dir: Path, target: dict, expected_version: str | None) -> str:
    asset_path = project_dir / "release" / target["asset_name"]
    if not asset_path.is_file():
        raise TargetRegistryError(f"missing merged image: {asset_path}")

    data = asset_path.read_bytes()
    boot_offset = int(str(target["bootloader_offset"]), 0)
    app_offset = int(str(target["app_offset"]), 0)
    if data[boot_offset : boot_offset + 1] != ESP_IMAGE_MAGIC:
        raise TargetRegistryError(
            f"{asset_path}: bootloader magic missing at {boot_offset:#x}"
        )
    if data[PARTITION_TABLE_OFFSET : PARTITION_TABLE_OFFSET + 2] != PARTITION_TABLE_MAGIC:
        raise TargetRegistryError(
            f"{asset_path}: partition table magic missing at {PARTITION_TABLE_OFFSET:#x}"
        )
    if data[app_offset : app_offset + 1] != ESP_IMAGE_MAGIC:
        raise TargetRegistryError(f"{asset_path}: app magic missing at {app_offset:#x}")
    if len(data) > int(target["flash_bytes"]):
        raise TargetRegistryError(
            f"{asset_path}: image is larger than {target['flash_size']} flash"
        )
    if expected_version is not None and expected_version.encode() not in data:
        raise TargetRegistryError(
            f"{asset_path}: firmware version {expected_version!r} not embedded"
        )
    return (
        f"{target['environment']:20s} {asset_path.name:38s} "
        f"boot@{boot_offset:#x} app@{app_offset:#x} size={len(data)}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "project_dir",
        nargs="?",
        default=str(Path(__file__).resolve().parents[1]),
    )
    parser.add_argument(
        "--environment",
        action="append",
        default=None,
        help="Verify only this environment (may be repeated). Default: all release targets.",
    )
    parser.add_argument(
        "--version",
        default=None,
        help="Require this firmware version string in the merged image.",
    )
    args = parser.parse_args()
    project_dir = Path(args.project_dir).resolve()
    try:
        registry = load_registry(project_dir)
        if args.environment:
            targets = []
            for environment in args.environment:
                target = target_for_environment(registry, environment)
                if target is None:
                    raise TargetRegistryError(
                        f"environment {environment!r} is not registered"
                    )
                targets.append(target)
        else:
            targets = [
                target
                for target in targets_by_environment(registry).values()
                if target.get("release_available")
            ]
            # Alias lookup returns the same dict for multiple keys; de-duplicate.
            targets = list({id(target): target for target in targets}.values())

        lines = [
            verify_target(project_dir, target, args.version)
            for target in targets
        ]
    except TargetRegistryError as exc:
        print(f"[images] ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"[images] verified {len(lines)} merged release image(s)")
    for line in lines:
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
