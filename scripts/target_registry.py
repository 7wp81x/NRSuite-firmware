"""Shared target-registry and partition-table helpers.

This module is deliberately dependency-free so it can be imported by
merge_script.py under PlatformIO/SCons and by standalone validation scripts.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


REGISTRY_RELATIVE_PATH = Path("boards") / "targets.json"


class TargetRegistryError(ValueError):
    """Raised when a target registry or partition table is invalid."""


def load_registry(project_dir: str | Path) -> dict[str, Any]:
    registry_path = Path(project_dir) / REGISTRY_RELATIVE_PATH
    try:
        with registry_path.open("r", encoding="utf-8") as handle:
            registry = json.load(handle)
    except FileNotFoundError as exc:
        raise TargetRegistryError(f"target registry not found: {registry_path}") from exc
    except json.JSONDecodeError as exc:
        raise TargetRegistryError(f"invalid target registry JSON: {exc}") from exc

    if registry.get("schema_version") != 1:
        raise TargetRegistryError(
            f"unsupported target registry schema: {registry.get('schema_version')!r}"
        )
    if not isinstance(registry.get("targets"), list):
        raise TargetRegistryError("target registry must contain a targets list")
    return registry


def targets_by_environment(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    mapping: dict[str, dict[str, Any]] = {}
    for target in registry["targets"]:
        environment = target.get("environment")
        if not environment:
            raise TargetRegistryError("target entry is missing environment")
        if environment in mapping:
            raise TargetRegistryError(f"duplicate environment: {environment}")
        mapping[environment] = target
        for alias in target.get("aliases", []):
            if alias in mapping:
                raise TargetRegistryError(f"duplicate environment alias: {alias}")
            mapping[alias] = target
    return mapping


def target_for_environment(
    registry: dict[str, Any], environment: str
) -> dict[str, Any] | None:
    return targets_by_environment(registry).get(environment)


def parse_partition_table(path: str | Path) -> list[dict[str, Any]]:
    """Parse an ESP-IDF partition CSV into normalised entries."""
    partition_path = Path(path)
    try:
        with partition_path.open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.reader(handle))
    except FileNotFoundError as exc:
        raise TargetRegistryError(f"partition table not found: {partition_path}") from exc

    entries: list[dict[str, Any]] = []
    for line_number, row in enumerate(rows, start=1):
        if not row:
            continue
        cells = [cell.strip() for cell in row]
        if not cells or not cells[0] or cells[0].startswith("#"):
            continue
        # ESP-IDF CSVs may have a trailing empty cell, so accept the first six
        # values and ignore optional empty fields after them.
        while len(cells) < 6:
            cells.append("")
        name, partition_type, subtype, offset, size, flags = cells[:6]
        try:
            offset_value = int(offset, 0)
        except ValueError as exc:
            raise TargetRegistryError(
                f"{partition_path}:{line_number}: invalid offset {offset!r}"
            ) from exc
        try:
            size_value = int(size, 0)
        except ValueError as exc:
            raise TargetRegistryError(
                f"{partition_path}:{line_number}: invalid size {size!r}"
            ) from exc
        entries.append(
            {
                "name": name,
                "type": partition_type,
                "subtype": subtype,
                "offset": offset_value,
                "size": size_value,
                "flags": flags,
                "line": line_number,
            }
        )
    if not entries:
        raise TargetRegistryError(f"partition table is empty: {partition_path}")
    return entries


def partition_entry(path: str | Path, name: str = "app0") -> dict[str, Any]:
    entries = parse_partition_table(path)
    for entry in entries:
        if entry["name"] == name:
            return entry
    raise TargetRegistryError(f"{path}: missing {name!r} partition")


def resolve_app_offset(
    project_dir: str | Path,
    registry: dict[str, Any],
    environment: str,
    partition_table: str | Path | None = None,
) -> int:
    """Resolve app0's flash offset from the registry and partition table.

    The registry value and partition table must agree. This prevents a stale
    merge script from hardcoding 0x10000 when a future layout moves app0.
    """
    project_path = Path(project_dir)
    target = target_for_environment(registry, environment)
    if target is None:
        raise TargetRegistryError(
            f"environment {environment!r} is not present in {REGISTRY_RELATIVE_PATH}"
        )

    relative_partition = partition_table or target.get("partition_table")
    if not relative_partition:
        raise TargetRegistryError(
            f"environment {environment!r} has no partition table in the registry"
        )
    partition_path = project_path / str(relative_partition)
    app = partition_entry(partition_path, "app0")
    table_offset = app["offset"]

    raw_registry_offset = target.get("app_offset")
    if raw_registry_offset in (None, ""):
        return table_offset
    try:
        registry_offset = int(str(raw_registry_offset), 0)
    except ValueError as exc:
        raise TargetRegistryError(
            f"environment {environment!r}: invalid app_offset "
            f"{raw_registry_offset!r}"
        ) from exc
    if registry_offset != table_offset:
        raise TargetRegistryError(
            f"environment {environment!r}: app_offset {registry_offset:#x} does not "
            f"match {relative_partition} app0 offset {table_offset:#x}"
        )
    return registry_offset


def release_asset_name(registry: dict[str, Any], target: dict[str, Any], channel: str) -> str:
    prefixes = registry.get("release_asset_prefixes")
    if not isinstance(prefixes, dict) or channel not in prefixes:
        raise TargetRegistryError(f"unknown release channel: {channel!r}")
    asset_name = target.get("asset_name")
    if not asset_name:
        raise TargetRegistryError(
            f"environment {target.get('environment')!r} has no asset_name"
        )
    return f"{prefixes[channel]}{asset_name}"
