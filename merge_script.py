Import("env")

import os
import shutil
import sys

PROJECT_DIR = env.subst("$PROJECT_DIR")
SCRIPTS_DIR = os.path.join(PROJECT_DIR, "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from target_registry import (  # noqa: E402
    TargetRegistryError,
    load_registry,
    release_asset_name,
    resolve_app_offset,
    target_for_environment,
)

PARTITION_TABLE_OFFSET = 0x8000
RELEASE_CHANNELS = (
    ("stable", "release"),
    ("beta", "beta-release"),
    ("rc", "rc-release"),
)


def merge_bin_action(source, target, env):
    pioenv = env["PIOENV"]
    build_dir = env.subst("$BUILD_DIR")
    project_dir = env.subst("$PROJECT_DIR")

    bootloader = os.path.join(build_dir, "bootloader.bin")
    partitions = os.path.join(build_dir, "partitions.bin")
    firmware = os.path.join(build_dir, "firmware.bin")

    try:
        registry = load_registry(project_dir)
        target_entry = target_for_environment(registry, pioenv)
        if target_entry is None:
            raise TargetRegistryError(
                f"environment {pioenv!r} is not registered in boards/targets.json"
            )
        app_offset = resolve_app_offset(
            project_dir,
            registry,
            pioenv,
            target_entry["partition_table"],
        )
        bootloader_offset = int(str(target_entry["bootloader_offset"]), 0)
        flash_size = str(target_entry["flash_size"]).upper()
        mcu = str(target_entry["chip_family"])
    except (TargetRegistryError, KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(f"[merge_script] {exc}") from exc

    for input_path in (bootloader, partitions, firmware):
        if not os.path.isfile(input_path):
            raise RuntimeError(
                f"[merge_script] required build artifact missing: {input_path}"
            )

    output_dirs = {directory for _, directory in RELEASE_CHANNELS}
    for directory in output_dirs:
        os.makedirs(os.path.join(project_dir, directory), exist_ok=True)

    stable_name = release_asset_name(registry, target_entry, "stable")
    merged = os.path.join(project_dir, "release", stable_name)

    cmd = (
        f'"{env.subst("$PYTHONEXE")}" -m esptool '
        f'--chip {mcu} merge_bin -o "{merged}" '
        f'--flash_size {flash_size} '
        f'{bootloader_offset:#x} "{bootloader}" '
        f'{PARTITION_TABLE_OFFSET:#x} "{partitions}" '
        f'{app_offset:#x} "{firmware}"'
    )
    print(
        f"[merge_script] Merging -> {merged} "
        f"(mcu={mcu}, boot_offset={bootloader_offset:#x}, app_offset={app_offset:#x})"
    )
    result = env.Execute(cmd)
    if result != 0:
        raise RuntimeError(
            f"[merge_script] merge_bin failed for {pioenv} (exit {result})"
        )

    for channel, directory in RELEASE_CHANNELS:
        channel_name = release_asset_name(registry, target_entry, channel)
        channel_path = os.path.join(project_dir, directory, channel_name)
        try:
            if os.path.abspath(channel_path) != os.path.abspath(merged):
                shutil.copyfile(merged, channel_path)
            print(f"[merge_script] Wrote   -> {channel_path}")
        except OSError as exc:
            raise RuntimeError(
                f"[merge_script] failed to write {channel} binary "
                f"for {pioenv}: {exc}"
            ) from exc


env.AddPostAction("$BUILD_DIR/${PROGNAME}.bin", merge_bin_action)
