#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 || $# -gt 6 ]]; then
  echo "usage: $0 <run-id> <memory-budget-mib> <port> <trim-after-phase:0|1> [workload] [defer-upstream-verify:0|1]" >&2
  exit 2
fi

run_id=$1
memory_budget_mib=$2
port=$3
trim_after_phase=$4
workload=${5:-H2}
defer_upstream_verify=${6:-0}

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
result_root="$repo_root/results/memory-reconciliation"
server_root="$result_root/server-$run_id"
key_path="/tmp/thinwallet-memory-reconciliation-$port.key"
temp_dir="/tmp/thinwallet-memory-reconciliation-$run_id"
canonical_workload=$(
  "$repo_root/experiments/libspartan/target/release/thinwallet_android_bench" \
    describe-workload "$workload" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["canonical_name"])'
)
run_dir="$result_root/raw/local-wsl-memory-reconciliation/$canonical_workload/full/$run_id"

mkdir -p "$server_root"
printf 'thinwallet/phase2/controlled-test-key' |
  openssl dgst -sha256 -binary >"$key_path"

THINWALLET_PBMO_LISTEN="127.0.0.1:$port" \
THINWALLET_PBMO_PSK_FILE="$key_path" \
THINWALLET_PBMO_SERVER_METRICS="$server_root/connections.jsonl" \
THINWALLET_PBMO_MAX_CONNECTIONS=1000 \
  "$repo_root/experiments/libspartan/target/release/pbmo_tcp_server" \
  >"$server_root/stdout.log" 2>"$server_root/stderr.log" &
server_pid=$!

cleanup() {
  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
  rm -f "$key_path"
}
trap cleanup EXIT
sleep 1

THINWALLET_MEMORY_RECONCILIATION=1 \
THINWALLET_MALLOC_TRIM_AFTER_PHASE="$trim_after_phase" \
THINWALLET_DEFER_UPSTREAM_VERIFY="$defer_upstream_verify" \
THINWALLET_MEMORY_MAPS_PATH="$run_dir/memory_maps.jsonl" \
  python3 "$repo_root/scripts/thinwallet_bench.py" run \
  --workload "$workload" \
  --device-id local-wsl-memory-reconciliation \
  --prover-seed 978453202 \
  --thread-count 1 \
  --memory-budget-mib "$memory_budget_mib" \
  --timeout-s 600 \
  --metrics-sample-ms 100 \
  --repo-root "$repo_root" \
  --binary "$repo_root/experiments/libspartan/target/release/thinwallet_android_bench" \
  --server-binary "$repo_root/experiments/libspartan/target/release/pbmo_tcp_server" \
  --result-root "$result_root/raw" \
  --summary-root "$result_root/summary" \
  --experiment-mode full \
  --run-id "$run_id" \
  --workload-seed 0 \
  --pbmo-endpoint "127.0.0.1:$port" \
  --pbmo-psk-file "$key_path" \
  --experiment-temp-dir "$temp_dir" \
  --instrumentation \
  --instrumentation-profile perf
