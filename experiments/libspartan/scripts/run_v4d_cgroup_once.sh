#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.."

workload="${1:?expected Profile-S workload}"
log_size="${2:?expected log size}"
cap_mib="${3:?expected cgroup memory cap in MiB}"
repetition="${4:?expected repetition}"

safe_workload="${workload//-/_}"
unit="thinwallet-v4d-${safe_workload,,}-${cap_mib}-${repetition}-$$"
prefix="$PWD/../credential_workloads/results/v4d/runs/${safe_workload}_E4_${cap_mib}_r${repetition}"
mkdir -p "$(dirname "$prefix")"

set +e
systemd-run \
  --quiet \
  --unit "$unit" \
  --property "MemoryMax=${cap_mib}M" \
  --property "MemorySwapMax=0" \
  --property "User=ubuntu" \
  --setenv=HOME=/home/ubuntu \
  /usr/bin/env V4D_CGROUP_ENFORCED=1 V4D_DEFER_EXTERNAL_VERIFY=1 \
  "$PWD/scripts/run_v4d_once.sh" "$workload" E4 "$log_size" "$cap_mib" "$repetition"
launch_status=$?
set +e

control_group=""
for _ in $(seq 1 100); do
  control_group=$(systemctl show "$unit.service" --property ControlGroup --value 2>/dev/null || true)
  [[ -n "$control_group" ]] && break
  sleep 0.01
done
cgroup_root="/sys/fs/cgroup${control_group}"
read_value() {
  local path="$1"
  if [[ -r "$path" ]]; then cat "$path"; else printf 'null\n'; fi
}

memory_peak=null
memory_current=null
memory_swap_current=null
memory_events=""
max_process_rss_kib=0
max_process_hwm_kib=0
max_process_anon_kib=0
max_process_file_kib=0
max_process_pss_kib=0
max_cgroup_anon_bytes=0
max_cgroup_file_bytes=0
max_temporary_state_bytes=0
sample_index=0
while [[ -n "$control_group" && -d "$cgroup_root" ]]; do
  memory_peak=$(read_value "$cgroup_root/memory.peak")
  memory_current=$(read_value "$cgroup_root/memory.current")
  memory_swap_current=$(read_value "$cgroup_root/memory.swap.current")
  memory_events=$(if [[ -r "$cgroup_root/memory.events" ]]; then cat "$cgroup_root/memory.events"; fi)
  if [[ -r "$cgroup_root/memory.stat" ]]; then
    current_anon=$(awk '$1 == "anon" {print $2}' "$cgroup_root/memory.stat" 2>/dev/null || echo 0)
    current_file=$(awk '$1 == "file" {print $2}' "$cgroup_root/memory.stat" 2>/dev/null || echo 0)
    (( current_anon > max_cgroup_anon_bytes )) && max_cgroup_anon_bytes=$current_anon
    (( current_file > max_cgroup_file_bytes )) && max_cgroup_file_bytes=$current_file
  fi
  if [[ -r "$cgroup_root/cgroup.procs" ]]; then
    while read -r pid; do
      [[ -r "/proc/$pid/cmdline" ]] || continue
      command_line=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' || true)
      [[ "$command_line" == *phase_v2_pbmo*malicious* ]] || continue
      status_path="/proc/$pid/status"
      rss=$(awk '$1 == "VmRSS:" {print $2}' "$status_path" 2>/dev/null || echo 0)
      hwm=$(awk '$1 == "VmHWM:" {print $2}' "$status_path" 2>/dev/null || echo 0)
      anon=$(awk '$1 == "RssAnon:" {print $2}' "$status_path" 2>/dev/null || echo 0)
      file=$(awk '$1 == "RssFile:" {print $2}' "$status_path" 2>/dev/null || echo 0)
      pss=$(awk '$1 == "Pss:" {print $2}' "/proc/$pid/smaps_rollup" 2>/dev/null || echo 0)
      (( rss > max_process_rss_kib )) && max_process_rss_kib=$rss
      (( hwm > max_process_hwm_kib )) && max_process_hwm_kib=$hwm
      (( anon > max_process_anon_kib )) && max_process_anon_kib=$anon
      (( file > max_process_file_kib )) && max_process_file_kib=$file
      (( pss > max_process_pss_kib )) && max_process_pss_kib=$pss
    done <"$cgroup_root/cgroup.procs"
  fi
  if (( sample_index % 5 == 0 )); then
    current_temporary_state_bytes=$(find /tmp -maxdepth 1 -type d \
      -name "thinwallet-v4d-${safe_workload}-E4-${cap_mib}-${repetition}-*" \
      -exec du -sb {} + 2>/dev/null | awk '{total += $1} END {print total + 0}')
    (( current_temporary_state_bytes > max_temporary_state_bytes )) && \
      max_temporary_state_bytes=$current_temporary_state_bytes
  fi
  sample_index=$((sample_index + 1))
  systemctl is-active --quiet "$unit.service" || break
  sleep 0.05
done
unit_status=$(systemctl show "$unit.service" --property ExecMainStatus --value 2>/dev/null || echo "$launch_status")

verify_status=null
if [[ -s "${prefix}.proof.bin" && "$unit_status" -eq 0 ]]; then
  set +e
  runuser -u ubuntu -- env THINWALLET_CREDENTIAL_WORKLOAD="$workload" \
    "$PWD/target/release/phase_v2_pbmo" verify-proof "${prefix}.proof.bin" "$log_size" \
    >"${prefix}.verify.json" 2>"${prefix}.verify.stderr"
  verify_status=$?
  set -e
  python3 - "$prefix.json" "$verify_status" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
status = int(sys.argv[2])
if path.exists():
    payload = json.loads(path.read_text())
    verify_path = Path(str(path).removesuffix(".json") + ".verify.json")
    payload["external_upstream_verifier_exit_status"] = status
    payload["external_upstream_verifier"] = (
        json.loads(verify_path.read_text())
        if verify_path.exists() and verify_path.stat().st_size
        else None
    )
    path.write_text(json.dumps(payload, indent=2) + "\n")
PY
fi

python3 - "$prefix.cgroup.json" "$unit" "$unit_status" "$cap_mib" \
  "$control_group" "$memory_peak" "$memory_current" "$memory_swap_current" "$memory_events" \
  "$max_process_rss_kib" "$max_process_hwm_kib" "$max_process_anon_kib" \
  "$max_process_file_kib" "$max_process_pss_kib" "$max_cgroup_anon_bytes" \
  "$max_cgroup_file_bytes" "$max_temporary_state_bytes" "$verify_status" <<'PY'
import json
import sys
from pathlib import Path

(
    path, unit, status, cap, control, peak, current, swap, events,
    process_rss, process_hwm, process_anon, process_file, process_pss,
    cgroup_anon, cgroup_file, temporary_state, verify_status,
) = sys.argv[1:]
def integer(value):
    try:
        return int(value)
    except ValueError:
        return None

parsed_events = {}
for line in events.splitlines():
    fields = line.split()
    if len(fields) == 2:
        parsed_events[fields[0]] = int(fields[1])

payload = {
    "unit": unit,
    "unit_exit_status": int(status),
    "control_group": control or None,
    "memory_max_bytes": int(cap) * 1024 * 1024,
    "memory_peak_bytes": integer(peak),
    "memory_current_bytes_after_run": integer(current),
    "memory_swap_current_bytes": integer(swap),
    "memory_events": parsed_events,
    "sampled_process_peak_rss_kib": integer(process_rss),
    "sampled_process_vm_hwm_kib": integer(process_hwm),
    "sampled_process_peak_rss_anon_kib": integer(process_anon),
    "sampled_process_peak_rss_file_kib": integer(process_file),
    "sampled_process_peak_pss_kib": integer(process_pss),
    "sampled_cgroup_peak_anon_bytes": integer(cgroup_anon),
    "sampled_cgroup_peak_file_bytes": integer(cgroup_file),
    "sampled_temporary_state_peak_bytes": integer(temporary_state),
    "external_upstream_verifier_exit_status": integer(verify_status),
}
Path(path).write_text(json.dumps(payload, indent=2) + "\n")
PY

systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
exit 0
