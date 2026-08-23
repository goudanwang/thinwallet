#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
adb="${ADB:-/mnt/e/thinwallet/.tools/android/platform-tools/adb.exe}"
output="${1:-$repo_root/results/android_s23/device_metadata.json}"

mapfile -t devices < <("$adb" devices | tr -d '\r' | awk 'NR > 1 && $2 == "device" { print $1 }')
if [ "${#devices[@]}" -ne 1 ]; then
  echo "expected exactly one authorized Android device; found ${#devices[@]}" >&2
  "$adb" devices -l >&2 || true
  exit 2
fi
serial="${devices[0]}"
serial_sha256="$(printf '%s' "$serial" | sha256sum | awk '{print $1}')"

shell() {
  "$adb" -s "$serial" shell "$@" | tr -d '\r'
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$(dirname "$output")"

manufacturer="$(shell getprop ro.product.manufacturer)"
model="$(shell getprop ro.product.model)"
product="$(shell getprop ro.product.name)"
soc="$(shell getprop ro.soc.model)"
android_version="$(shell getprop ro.build.version.release)"
fingerprint_sha256="$(shell getprop ro.build.fingerprint | sha256sum | awk '{print $1}')"
kernel="$(shell uname -a)"
filesystem_type="$(shell stat -f -c %T /data/local/tmp)"

shell cat /proc/meminfo >"$tmp/meminfo.txt"
shell df -k /data/local/tmp >"$tmp/storage.txt"
shell dumpsys battery >"$tmp/battery.txt"
shell 'dumpsys thermalservice 2>/dev/null || true' >"$tmp/thermal.txt"
shell 'cat /sys/devices/system/cpu/online 2>/dev/null || true' >"$tmp/cpu_online.txt"
shell 'for p in /sys/devices/system/cpu/cpufreq/policy*; do [ -d "$p" ] || continue; echo "policy=$(basename "$p")"; for f in scaling_min_freq scaling_max_freq scaling_cur_freq cpuinfo_min_freq cpuinfo_max_freq; do [ -r "$p/$f" ] && echo "$f=$(cat "$p/$f")"; done; done' >"$tmp/cpu_frequency.txt"
shell 'for f in /sys/block/zram*/disksize /sys/block/zram*/comp_algorithm /sys/block/zram*/mm_stat; do [ -r "$f" ] && { echo "[$f]"; cat "$f"; }; done' >"$tmp/zram.txt"
shell 'ulimit -a 2>/dev/null || true' >"$tmp/process_limits.txt"
shell 'getprop | grep -Ei "lmk|lowmemorykiller" || true' >"$tmp/lmkd_properties.txt"
shell 'for f in /sys/class/thermal/thermal_zone*/type /sys/class/thermal/thermal_zone*/temp; do [ -r "$f" ] && printf "%s=" "$f" && cat "$f"; done' >"$tmp/thermal_zones.txt"

export THINWALLET_METADATA_SERIAL_SHA256="$serial_sha256"
export THINWALLET_METADATA_MANUFACTURER="$manufacturer"
export THINWALLET_METADATA_MODEL="$model"
export THINWALLET_METADATA_PRODUCT="$product"
export THINWALLET_METADATA_SOC="$soc"
export THINWALLET_METADATA_ANDROID_VERSION="$android_version"
export THINWALLET_METADATA_FINGERPRINT_SHA256="$fingerprint_sha256"
export THINWALLET_METADATA_KERNEL="$kernel"
export THINWALLET_METADATA_FILESYSTEM_TYPE="$filesystem_type"
export THINWALLET_METADATA_TMP="$tmp"
export THINWALLET_METADATA_OUTPUT="$output"

python3 - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

tmp = Path(os.environ["THINWALLET_METADATA_TMP"])

def text(name):
    return (tmp / name).read_text(encoding="utf-8", errors="replace").strip()

def meminfo():
    parsed = {}
    for line in text("meminfo.txt").splitlines():
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        parts = rest.split()
        if not parts:
            continue
        value = int(parts[0])
        parsed[key] = value * 1024 if len(parts) > 1 and parts[1] == "kB" else value
    return parsed

def battery():
    parsed = {}
    for line in text("battery.txt").splitlines():
        if ":" in line:
            key, value = line.strip().split(":", 1)
            normalized = key.strip().lower().replace(" ", "_")
            parsed[normalized] = value.strip()
    for key in ("level", "temperature"):
        if key in parsed:
            try:
                parsed[key] = int(parsed[key])
            except ValueError:
                pass
    return parsed

memory = meminfo()
record = {
    "schema_version": "thinwallet-android-phase4b1-device-v1",
    "collected_at_utc": datetime.now(timezone.utc).isoformat(),
    "adb_serial_sha256": os.environ["THINWALLET_METADATA_SERIAL_SHA256"],
    "manufacturer": os.environ["THINWALLET_METADATA_MANUFACTURER"],
    "model": os.environ["THINWALLET_METADATA_MODEL"],
    "product": os.environ["THINWALLET_METADATA_PRODUCT"],
    "soc": os.environ["THINWALLET_METADATA_SOC"] or None,
    "android_version": os.environ["THINWALLET_METADATA_ANDROID_VERSION"],
    "build_fingerprint_sha256": os.environ["THINWALLET_METADATA_FINGERPRINT_SHA256"],
    "kernel_version": os.environ["THINWALLET_METADATA_KERNEL"],
    "total_physical_ram_bytes": memory.get("MemTotal"),
    "memory": {
        key: memory.get(key)
        for key in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree")
    },
    "zram": text("zram.txt") or None,
    "experiment_temp_root": "/data/local/tmp/thinwallet-phase4b1",
    "experiment_temp_filesystem_type": os.environ["THINWALLET_METADATA_FILESYSTEM_TYPE"],
    "free_storage": text("storage.txt"),
    "battery": battery(),
    "thermal_service": text("thermal.txt") or None,
    "thermal_zones": text("thermal_zones.txt") or None,
    "cpu_online": text("cpu_online.txt") or None,
    "cpu_frequency": text("cpu_frequency.txt") or None,
    "process_memory_limits": text("process_limits.txt") or None,
    "lmkd_properties": text("lmkd_properties.txt") or None,
    "privacy": {
        "adb_serial_plaintext_recorded": False,
        "build_fingerprint_plaintext_recorded": False,
    },
}
Path(os.environ["THINWALLET_METADATA_OUTPUT"]).write_text(
    json.dumps(record, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

echo "$output"
