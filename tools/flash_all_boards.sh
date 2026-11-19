#!/usr/bin/env bash
#
# Flash every detected ESP32 board connected through a USB hub.
# Ports that do not identify as an esptool-compatible ESP32 are skipped.
#
# Usage:
#   ./tools/flash_all_boards.sh
#   ./tools/flash_all_boards.sh /dev/ttyUSB0 /dev/ttyACM0
#
# Optional env:
#   PIO=/path/to/pio
#   ESPTOOL_PYTHON=/path/to/python
#
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PIO="${PIO:-$ROOT/.pio/penv/bin/pio}"
ESPTOOL_PYTHON="${ESPTOOL_PYTHON:-$ROOT/.pio/penv/bin/python}"
export PLATFORMIO_CORE_DIR="${PLATFORMIO_CORE_DIR:-$ROOT/.pio}"
export UV_CACHE_DIR="${UV_CACHE_DIR:-$ROOT/.pio/uv-cache}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$ROOT/.pio/xdg-cache}"

if [[ $# -gt 0 ]]; then
    PORTS=("$@")
else
    mapfile -t PORTS < <("$PIO" device list --json-output | jq -r '.[].port')
fi

if [[ ${#PORTS[@]} -eq 0 ]]; then
    echo "No serial ports detected."
    exit 0
fi

failed=0
flashed=0

for port in "${PORTS[@]}"; do
    [[ -n "$port" ]] || continue
    echo
    echo "=== Probing $port ==="

    chip_output="$("$ESPTOOL_PYTHON" -m esptool --port "$port" chip-id 2>&1)"
    if [[ $? -ne 0 ]]; then
        echo "Skipping $port: no ESP32 response."
        continue
    fi

    chip="$(grep -Eo 'ESP32(-[A-Z0-9]+)?' <<<"$chip_output" | head -n1)"
    case "$chip" in
        ESP32-S3*) env="esp32-s3" ;;
        ESP32-S2*) env="esp32-s2" ;;
        ESP32-C5*) env="esp32-c5" ;;
        ESP32-C3*) env="esp32-c3" ;;
        ESP32-C6*) echo "Skipping $port: ESP32-C6 has no PlatformIO environment in this repo."; continue ;;
        ESP32*)    env="esp32-devkit" ;;
        *)         echo "Skipping $port: could not identify chip (${chip:-unknown})."; continue ;;
    esac

    echo "Detected $chip on $port -> $env"
    if "$PIO" run -e "$env" -t upload --upload-port "$port"; then
        echo "Upload complete: $env -> $port"
        flashed=$((flashed + 1))
    else
        echo "Upload FAILED: $env -> $port"
        failed=$((failed + 1))
    fi
done

echo
echo "=== Summary ==="
echo "Flashed: $flashed"
echo "Failed:  $failed"
exit "$((failed > 0 ? 1 : 0))"
