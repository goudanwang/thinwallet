#!/usr/bin/env bash
set -euo pipefail

repo="${THINWALLET_REPO_ROOT:-/mnt/e/thinwallet}"
adb="${ADB:-$repo/.tools/android/platform-tools/adb.exe}"
results="$repo/results/android_s23"
raw="$results/memory_control_raw"
mkdir -p "$raw"

if [[ ! -x "$adb" ]]; then
  printf 'ADB not executable: %s\n' "$adb" >&2
  exit 2
fi

mapfile -t devices < <("$adb" devices | tr -d '\r' | awk 'NR > 1 && $2 == "device" {print $1}')
if [[ "${#devices[@]}" -ne 1 ]]; then
  printf 'expected exactly one authorized device, found %s\n' "${#devices[@]}" >&2
  exit 2
fi
serial="${devices[0]}"
serial_sha256="$(printf '%s' "$serial" | sha256sum | awk '{print $1}')"

adb_shell() {
  "$adb" -s "$serial" shell "$@"
}

adb_shell 'mount' >"$raw/mount.txt" 2>&1 || true
adb_shell 'cat /proc/cgroups' >"$raw/proc_cgroups.txt" 2>&1 || true
adb_shell 'cat /proc/self/cgroup' >"$raw/proc_self_cgroup.txt" 2>&1 || true
adb_shell 'find /sys/fs/cgroup -maxdepth 5 -type d -o -type f 2>/dev/null | head -4000' \
  >"$raw/cgroup_tree.txt" 2>&1 || true
adb_shell '
  echo "__ID__"; id
  echo "__SELINUX__"; getenforce
  echo "__ROOT_CONTROLLERS__"; cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
  echo "__ROOT_SUBTREE_CONTROL__"; cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
  echo "__SELF__"; cat /proc/self/cgroup
  cg=$(awk -F: '"'"'$1=="0" {print $3}'"'"' /proc/self/cgroup)
  path=/sys/fs/cgroup$cg
  echo "__SELF_PATH__=$path"
  for base in /sys/fs/cgroup "$path"; do
    echo "__PATH__=$base"
    ls -ld "$base" 2>&1
    for f in cgroup.procs cgroup.subtree_control memory.max memory.high \
      memory.swap.max memory.current memory.peak memory.events memory.stat; do
      target="$base/$f"
      if [ -e "$target" ]; then
        ls -l "$target"
        [ -r "$target" ] && { echo "__VALUE__$f"; head -80 "$target"; }
        [ -w "$target" ] && echo "__WRITABLE__$f=true" || echo "__WRITABLE__$f=false"
      else
        echo "__MISSING__$f"
      fi
    done
  done
' >"$raw/permissions.txt" 2>&1 || true
adb_shell 'getprop | grep -Ei "lmk|task.profile|cgroup|memcg"; dumpsys activity settings 2>/dev/null | grep -i task | head -100' \
  >"$raw/task_profiles.txt" 2>&1 || true
adb_shell 'ulimit -a; (ulimit -v 1048576; echo __RLIMIT_SET_STATUS__=$?; echo __RLIMIT_VALUE_KIB__; ulimit -v) 2>&1' \
  >"$raw/ulimit.txt" 2>&1 || true
adb_shell 'su -c id' >"$raw/su.txt" 2>&1 || true
"$adb" -s "$serial" root >"$raw/adb_root.txt" 2>&1 || true

export THINWALLET_PROBE_REPO="$repo"
export THINWALLET_PROBE_SERIAL_HASH="$serial_sha256"
python3 - <<'PY'
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

repo = Path(os.environ["THINWALLET_PROBE_REPO"])
raw = repo / "results/android_s23/memory_control_raw"
out = repo / "results/android_s23/memory_control_capabilities.json"

def text(name):
    path = raw / name
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""

mount = text("mount.txt")
permissions = text("permissions.txt")
ulimit = text("ulimit.txt")
adb_root = text("adb_root.txt")
su = text("su.txt")
proc_self = text("proc_self_cgroup.txt")

cgroup_v2 = "type cgroup2" in mount
memory_controller_available = bool(
    re.search(r"__ROOT_CONTROLLERS__\s*(?:\r?\n)?[^\n]*\bmemory\b", permissions)
)
memory_max_present = "__MISSING__memory.max" not in permissions
memory_max_writable = "__WRITABLE__memory.max=true" in permissions
memory_high_writable = "__WRITABLE__memory.high=true" in permissions
memory_swap_max_writable = "__WRITABLE__memory.swap.max=true" in permissions
memory_current_readable = "__VALUE__memory.current" in permissions
memory_peak_readable = "__VALUE__memory.peak" in permissions
memory_events_readable = "__VALUE__memory.events" in permissions
memory_stat_readable = "__VALUE__memory.stat" in permissions
cgroup_procs_writable = "__WRITABLE__cgroup.procs=true" in permissions
rlimit_as_settable = "__RLIMIT_SET_STATUS__=0" in ulimit
adb_root_available = "adbd is already running as root" in adb_root.lower()
su_available = "uid=0" in su

if (
    cgroup_v2
    and memory_max_writable
    and memory_current_readable
    and memory_peak_readable
    and memory_events_readable
    and cgroup_procs_writable
):
    capability = "MEMCG_WRITABLE"
elif memory_controller_available and (
    memory_max_present or memory_current_readable or memory_events_readable
):
    capability = "MEMCG_READ_ONLY"
elif rlimit_as_settable:
    capability = "RLIMIT_AS_ONLY"
else:
    capability = "NO_RELIABLE_CONTROL"

value = {
    "schema_version": "thinwallet-android-phase4b2-memory-control-v1",
    "captured_at_utc": datetime.now(timezone.utc).isoformat(),
    "adb_serial_sha256": os.environ["THINWALLET_PROBE_SERIAL_HASH"],
    "capability": capability,
    "cgroup_version": 2 if cgroup_v2 else None,
    "self_cgroup": proc_self.strip(),
    "memory_controller_available": memory_controller_available,
    "memory_max_present": memory_max_present,
    "memory_max_writable": memory_max_writable,
    "memory_high_writable": memory_high_writable,
    "memory_swap_max_writable": memory_swap_max_writable,
    "memory_current_readable": memory_current_readable,
    "memory_peak_readable": memory_peak_readable,
    "memory_events_readable": memory_events_readable,
    "memory_stat_readable": memory_stat_readable,
    "cgroup_procs_writable": cgroup_procs_writable,
    "adb_root_available": adb_root_available,
    "su_root_available": su_available,
    "selinux_mode": "Enforcing" if "Enforcing" in permissions else None,
    "rlimit_as_settable": rlimit_as_settable,
    "main_controlled_memcg_sweep_permitted": capability == "MEMCG_WRITABLE",
    "rlimit_as_is_physical_memory_budget": False,
    "raw_directory": "results/android_s23/memory_control_raw",
    "notes": [
        "The probe did not change persistent system configuration.",
        "RLIMIT_AS, when available, is only a virtual-address-space diagnostic.",
    ],
}
out.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(value, indent=2, sort_keys=True))
PY
