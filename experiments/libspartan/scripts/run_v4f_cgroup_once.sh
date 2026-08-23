#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.."

monotonic_ns() {
  python3 -c 'import time; print(time.monotonic_ns())'
}
workload="${1:?expected canonical S-WK workload}"
mode="${2:?expected M0 through M4}"
log_size="${3:?expected log size}"
cap_mib="${4:?expected memory cap MiB}"
repetition="${5:?expected repetition}"
tag="${6:-headline}"

safe_workload="${workload//-/_}"
unit="thinwallet-v4f-${mode,,}-${cap_mib}-${repetition}-$$"
out_dir="${THINWALLET_RESULTS_ROOT:-$PWD/../../results/v4f/raw/runs}"
prefix="$out_dir/${tag}_${safe_workload}_${mode}_${cap_mib}_r${repetition}"
source_path="$PWD/../credential_workloads/results/v4e/sources/${safe_workload}.twcs"
mkdir -p "$(dirname "$prefix")"

if [[ ( "$mode" == M3 || "$mode" == M4 ) && "${THINWALLET_SKIP_PREFLIGHT:-0}" != 1 ]]; then
  set +e
  if [[ "${THINWALLET_V4G_PREFLIGHT:-0}" == 1 ]]; then
    python3 "$PWD/scripts/v4g_planner_preflight.py" "$prefix" "$workload" "$mode" "$log_size" "$cap_mib" "$repetition"
  else
    python3 "$PWD/scripts/v4f_planner_preflight.py" "$prefix" "$workload" "$mode" "$log_size" "$cap_mib" "$repetition"
  fi
  preflight_status=$?
  set -e
  [[ $preflight_status -eq 42 ]] && exit 0
  [[ $preflight_status -eq 0 ]] || exit $preflight_status
fi

set +e
systemd-run --quiet --unit "$unit" \
  --property "MemoryMax=${cap_mib}M" --property "MemorySwapMax=0" \
  --property "User=ubuntu" --setenv=HOME=/home/ubuntu \
  --setenv=THINWALLET_RESULTS_ROOT="$out_dir" \
  /usr/bin/env V4F_CGROUP_ENFORCED=1 V4F_DEFER_EXTERNAL_VERIFY=1 V4F_DEFER_COLLECT=1 \
  V4F_TRACE_TRANSCRIPT="${V4F_TRACE_TRANSCRIPT:-0}" \
  "$PWD/scripts/run_v4f_once.sh" "$workload" "$mode" "$log_size" "$cap_mib" "$repetition" "$tag"
launch_status=$?

control_group=""
for _ in $(seq 1 200); do
  control_group=$(systemctl show "$unit.service" --property ControlGroup --value 2>/dev/null || true)
  [[ -n "$control_group" ]] && break
  sleep 0.01
done
cgroup_root="/sys/fs/cgroup${control_group}"
read_value() { [[ -r "$1" ]] && cat "$1" 2>/dev/null || printf 'null\n'; }

memory_peak=null; memory_current=null; memory_swap_current=null; memory_events=""
max_process_rss_kib=0; max_process_hwm_kib=0; max_process_anon_kib=0
max_process_file_kib=0; max_process_pss_kib=0; max_cgroup_anon_bytes=0
max_cgroup_file_bytes=0; max_cgroup_inactive_file_bytes=0; max_cgroup_active_file_bytes=0
max_cgroup_shmem_bytes=0; max_temporary_state_bytes=0; sample_index=0
while [[ -n "$control_group" && -d "$cgroup_root" ]]; do
  sampled_peak=$(read_value "$cgroup_root/memory.peak")
  sampled_current=$(read_value "$cgroup_root/memory.current")
  sampled_swap=$(read_value "$cgroup_root/memory.swap.current")
  [[ "$sampled_peak" != null ]] && memory_peak=$sampled_peak
  [[ "$sampled_current" != null ]] && memory_current=$sampled_current
  [[ "$sampled_swap" != null ]] && memory_swap_current=$sampled_swap
  sampled_events=$(if [[ -r "$cgroup_root/memory.events" ]]; then cat "$cgroup_root/memory.events" 2>/dev/null || true; fi)
  [[ -n "$sampled_events" ]] && memory_events=$sampled_events
  if [[ -r "$cgroup_root/memory.stat" ]]; then
    current_anon=$(awk '$1 == "anon" {print $2}' "$cgroup_root/memory.stat" 2>/dev/null || echo 0)
    current_file=$(awk '$1 == "file" {print $2}' "$cgroup_root/memory.stat" 2>/dev/null || echo 0)
    current_inactive_file=$(awk '$1 == "inactive_file" {print $2}' "$cgroup_root/memory.stat" 2>/dev/null || echo 0)
    current_active_file=$(awk '$1 == "active_file" {print $2}' "$cgroup_root/memory.stat" 2>/dev/null || echo 0)
    current_shmem=$(awk '$1 == "shmem" {print $2}' "$cgroup_root/memory.stat" 2>/dev/null || echo 0)
    (( current_anon > max_cgroup_anon_bytes )) && max_cgroup_anon_bytes=$current_anon
    (( current_file > max_cgroup_file_bytes )) && max_cgroup_file_bytes=$current_file
    (( current_inactive_file > max_cgroup_inactive_file_bytes )) && max_cgroup_inactive_file_bytes=$current_inactive_file
    (( current_active_file > max_cgroup_active_file_bytes )) && max_cgroup_active_file_bytes=$current_active_file
    (( current_shmem > max_cgroup_shmem_bytes )) && max_cgroup_shmem_bytes=$current_shmem
  fi
  if [[ -r "$cgroup_root/cgroup.procs" ]]; then
    proc_snapshot=$(cat "$cgroup_root/cgroup.procs" 2>/dev/null || true)
    while read -r pid; do
      [[ -n "$pid" ]] || continue
      [[ -r "/proc/$pid/cmdline" ]] || continue
      command_line=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' || true)
      [[ "$command_line" == *phase_v2_pbmo* ]] || continue
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
    done <<<"$proc_snapshot"
  fi
  if (( sample_index % 5 == 0 )); then
    temporary=$(find /tmp -maxdepth 1 -type d -name "thinwallet-v4f-${safe_workload}-${mode}-${cap_mib}-${repetition}-*" -exec du -sb {} + 2>/dev/null | awk '{t += $1} END {print t + 0}')
    (( temporary > max_temporary_state_bytes )) && max_temporary_state_bytes=$temporary
  fi
  sample_index=$((sample_index + 1))
  systemctl is-active --quiet "$unit.service" || break
  sleep 0.05
done

for _ in $(seq 1 500); do
  [[ -s "${prefix}.exit_status" ]] && break
  sleep 0.01
done
backend_status=$(cat "${prefix}.exit_status" 2>/dev/null || echo "$launch_status")
wall_ms=$(cat "${prefix}.wall_ms" 2>/dev/null || echo 0)
external_status=$(cat "${prefix}.external_auth_status" 2>/dev/null || echo null)
external_ms=$(cat "${prefix}.external_auth_ms" 2>/dev/null || echo null)

verify_status=null; verify_ms=null
if [[ "$backend_status" -eq 0 && -s "${prefix}.proof.bin" ]]; then
  proof_session_id=$(python3 - "$workload" <<'PY'
import hashlib, sys
w=sys.argv[1].replace("sparse-merkle","sparse_merkle").replace("expiry-only","expiry_only").encode(); g=(1).to_bytes(8,"big"); h=hashlib.sha256(b"thinwallet/proof-session/v1")
for v in (w,g): h.update(len(v).to_bytes(8,"big")); h.update(v)
print(h.hexdigest())
PY
)
  verify_start=$(monotonic_ns)
  runuser -u ubuntu -- env THINWALLET_CREDENTIAL_WORKLOAD="$workload" \
    THINWALLET_CREDENTIAL_SOURCE_PATH="$source_path" THINWALLET_PROOF_SESSION_ID="$proof_session_id" \
    "$PWD/target/release/phase_v2_pbmo" verify-proof "${prefix}.proof.bin" "$log_size" \
    >"${prefix}.verify.json" 2>"${prefix}.verify.stderr"
  verify_status=$?
  verify_end=$(monotonic_ns)
  verify_ms=$(python3 -c "print(($verify_end-$verify_start)/1e6)")
fi

python3 - "$prefix.cgroup.json" "$unit" "$cap_mib" "$control_group" "$memory_peak" "$memory_current" "$memory_swap_current" "$memory_events" "$max_process_rss_kib" "$max_process_hwm_kib" "$max_process_anon_kib" "$max_process_file_kib" "$max_process_pss_kib" "$max_cgroup_anon_bytes" "$max_cgroup_file_bytes" "$max_cgroup_inactive_file_bytes" "$max_cgroup_active_file_bytes" "$max_cgroup_shmem_bytes" "$max_temporary_state_bytes" <<'PY'
import json, sys
from pathlib import Path
(path,unit,cap,control,peak,current,swap,events,rss,hwm,anon,file,pss,cga,cgf,inactive_file,active_file,shmem,temp)=sys.argv[1:]
def number(v):
    try: return int(v)
    except ValueError: return None
event_map={}
for line in events.splitlines():
    fields=line.split()
    if len(fields)==2: event_map[fields[0]]=int(fields[1])
Path(path).write_text(json.dumps({
  "unit":unit,"control_group":control or None,"memory_max_bytes":int(cap)*1024*1024,
  "memory_peak_bytes":number(peak),"memory_current_bytes_after_run":number(current),
  "memory_swap_current_bytes":number(swap),"memory_events":event_map,
  "sampled_process_peak_rss_kib":number(rss),"sampled_process_vm_hwm_kib":number(hwm),
  "sampled_process_peak_rss_anon_kib":number(anon),"sampled_process_peak_rss_file_kib":number(file),
  "sampled_process_peak_pss_kib":number(pss),"sampled_cgroup_peak_anon_bytes":number(cga),
  "sampled_cgroup_peak_file_bytes":number(cgf),
  "sampled_cgroup_peak_inactive_file_bytes":number(inactive_file),
  "sampled_cgroup_peak_active_file_bytes":number(active_file),
  "sampled_cgroup_peak_shmem_bytes":number(shmem),
  "sampled_temporary_state_peak_bytes":number(temp)
},indent=2)+"\n")
PY

python3 "$PWD/scripts/collect_v4f_run.py" "$prefix" "$workload" "$mode" "$log_size" "$cap_mib" "$repetition" "$backend_status" "$wall_ms" "$external_status" "$external_ms" "$verify_status" "$verify_ms"
systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
exit 0
