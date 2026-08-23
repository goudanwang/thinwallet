#!/usr/bin/env bash
set -euo pipefail

repo="${THINWALLET_REPO_ROOT:-/mnt/e/thinwallet}"
adb="${ADB:-$repo/.tools/android/platform-tools/adb.exe}"
ndk="${ANDROID_NDK:-$HOME/.local/android/android-ndk-r27c}"
clang="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android23-clang"
results="$repo/results/android_s23"
raw="$results/client_metric_capability_raw"
remote=/data/local/tmp/thinwallet-phase5-metric-probe
mkdir -p "$raw"

mapfile -t devices < <("$adb" devices | tr -d '\r' | awk 'NR > 1 && $2 == "device" {print $1}')
if [[ "${#devices[@]}" -ne 1 ]]; then
  printf 'expected exactly one authorized device, found %s\n' "${#devices[@]}" >&2
  exit 2
fi
serial="${devices[0]}"
serial_sha256="$(printf '%s' "$serial" | sha256sum | awk '{print $1}')"

test -x "$clang"
"$clang" -O2 -Wall -Wextra -Werror \
  "$repo/src/android_metrics/android_metric_probe.c" \
  -o "$raw/android_metric_probe"
probe_host_path="$(wslpath -w "$raw/android_metric_probe")"
"$adb" -s "$serial" push "$probe_host_path" "$remote" >"$raw/adb_push.txt" 2>&1
"$adb" -s "$serial" shell "chmod 700 $remote && $remote" \
  | tr -d '\r' >"$raw/native_probe.json"

adb_shell() {
  "$adb" -s "$serial" shell "$@"
}

adb_shell 'simpleperf stat -e task-clock,cpu-cycles,instructions,cache-references,cache-misses,branch-instructions,branch-misses,context-switches,page-faults -- sleep 0.1' \
  >"$raw/simpleperf.txt" 2>&1 || true
adb_shell '
  echo __SELF_SCHED__; cat /proc/self/sched
  echo __SELF_SCHEDSTAT__; cat /proc/self/schedstat
  echo __TASK_STAT__; for f in /proc/self/task/*/stat; do head -c 1024 "$f"; echo; done
  echo __TASK_SCHEDSTAT__; for f in /proc/self/task/*/schedstat; do cat "$f"; done
' >"$raw/scheduler.txt" 2>&1 || true
adb_shell '
  echo __ONLINE__; cat /sys/devices/system/cpu/online
  for p in /sys/devices/system/cpu/cpufreq/policy*; do
    echo "__POLICY__=$p"
    for f in scaling_cur_freq scaling_min_freq scaling_max_freq cpuinfo_min_freq cpuinfo_max_freq; do
      [ -r "$p/$f" ] && { printf "%s=" "$f"; cat "$p/$f"; }
    done
    if [ -r "$p/stats/time_in_state" ]; then
      echo __TIME_IN_STATE__
      cat "$p/stats/time_in_state"
    fi
  done
' >"$raw/cpu_residency.txt" 2>&1 || true
adb_shell '
  echo __BATTERY__; dumpsys battery
  echo __BATTERY_PROPERTIES__; dumpsys batteryproperties 2>&1
  echo __BATTERYSTATS__; dumpsys batterystats --checkin 2>&1 | head -400
  echo __POWERSTATS__; dumpsys powerstats 2>&1 | head -400
' >"$raw/energy.txt" 2>&1 || true
adb_shell '
  echo __THERMAL__; dumpsys thermalservice
  echo __ZONES__; for f in /sys/class/thermal/thermal_zone*/type /sys/class/thermal/thermal_zone*/temp; do
    [ -r "$f" ] && printf "%s=" "$f" && cat "$f"
  done
' >"$raw/thermal.txt" 2>&1 || true
adb_shell 'cat /proc/self/io' >"$raw/proc_io.txt" 2>&1 || true
adb_shell 'ping -c 3 -W 2 192.168.31.226' >"$raw/server_rtt.txt" 2>&1 || true

export THINWALLET_METRIC_REPO="$repo"
export THINWALLET_METRIC_SERIAL_HASH="$serial_sha256"
python3 - <<'PY'
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

repo = Path(os.environ["THINWALLET_METRIC_REPO"])
raw = repo / "results/android_s23/client_metric_capability_raw"

def text(name):
    return (raw / name).read_text(encoding="utf-8", errors="replace")

native = json.loads(text("native_probe.json"))
simpleperf = text("simpleperf.txt")
scheduler = text("scheduler.txt")
cpu = text("cpu_residency.txt")
energy = text("energy.txt")
thermal = text("thermal.txt")
io = text("proc_io.txt")
rtt = text("server_rtt.txt")

perf_available = any(
    item["available"] for item in native["perf_event_open"].values()
)
if not perf_available:
    perf_classification = "PERF_COUNTERS_UNAVAILABLE"
else:
    perf_classification = "PERF_COUNTERS_PARTIAL"

def battery_number(name):
    match = re.search(rf"(?mi)^\s*{re.escape(name)}:\s*(-?\d+)", energy)
    return int(match.group(1)) if match else None

charge = battery_number("charge counter")
current = battery_number("current now")
voltage = battery_number("voltage")
if re.search(r"(?i)energy.counter\s*[:=]\s*[1-9]\d*", energy):
    energy_class = "DIRECT_ENERGY_COUNTER"
elif charge is not None and charge >= 0 and voltage is not None:
    energy_class = "CHARGE_COUNTER_WITH_VOLTAGE"
elif current is not None and voltage is not None:
    energy_class = "CURRENT_INTEGRATION_PROXY"
else:
    energy_class = "NO_RELIABLE_ENERGY_MEASUREMENT"

value = {
    "schema_version": "thinwallet-android-phase5-client-metrics-v1",
    "captured_at_utc": datetime.now(timezone.utc).isoformat(),
    "adb_serial_sha256": os.environ["THINWALLET_METRIC_SERIAL_HASH"],
    "cpu_time": {
        "clock_process_cputime_id": native["clock_process_cputime_id"],
        "clock_thread_cputime_id": native["clock_thread_cputime_id"],
        "getrusage_self": native["getrusage_self"],
        "getrusage_thread": native["getrusage_thread"],
        "proc_self_stat": native["proc_self_stat_readable"],
        "proc_self_task_stat": "__TASK_STAT__" in scheduler,
    },
    "performance_counters": {
        "classification": perf_classification,
        "perf_event_open": native["perf_event_open"],
        "simpleperf_present": "simpleperf" not in simpleperf.lower() or "not found" not in simpleperf.lower(),
        "simpleperf_raw_result": "client_metric_capability_raw/simpleperf.txt",
    },
    "scheduler": {
        "proc_self_sched": native["proc_self_sched_readable"],
        "proc_self_schedstat": native["proc_self_schedstat_readable"],
        "proc_task_schedstat": "__TASK_SCHEDSTAT__" in scheduler,
        "cpu_online": "__ONLINE__" in cpu,
        "cpufreq": "__POLICY__=" in cpu,
        "time_in_state": "__TIME_IN_STATE__" in cpu,
    },
    "energy": {
        "classification": energy_class,
        "direct_energy_joules_available": energy_class == "DIRECT_ENERGY_COUNTER",
        "charge_counter_available": charge is not None,
        "current_now_available": current is not None,
        "voltage_available": voltage is not None,
        "charge_counter_resolution_and_semantics": "Android dumpsys value; report raw deltas, not precise joules",
    },
    "thermal": {
        "thermalservice": "Thermal Status:" in thermal,
        "battery_temperature": battery_number("temperature") is not None,
        "thermal_zones": "__ZONES__" in thermal,
    },
    "io": {
        name: bool(re.search(rf"(?m)^{name}:", io))
        for name in (
            "rchar",
            "wchar",
            "syscr",
            "syscw",
            "read_bytes",
            "write_bytes",
            "cancelled_write_bytes",
        )
    },
    "network": {
        "client_protocol_timestamps": True,
        "server_protocol_timestamps": True,
        "ping_rtt_probe": "time=" in rtt,
    },
    "raw_directory": "results/android_s23/client_metric_capability_raw",
    "notes": [
        "The helper is a standalone capability probe and is not linked into the frozen prover.",
        "Unavailable hardware counters remain null in attribution results.",
        "Charge/current measurements are not reported as precise joules.",
    ],
}
(repo / "results/android_s23/client_metric_capabilities.json").write_text(
    json.dumps(value, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
print(json.dumps(value, indent=2, sort_keys=True))
PY

"$adb" -s "$serial" shell "rm -f $remote" >/dev/null 2>&1 || true
