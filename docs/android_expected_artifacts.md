# Expected Android Artifacts

Every physical run directory must contain `device.json`, `environment.txt`,
`command.txt`, `stdout`, `stderr`, `exit_status`, `resource_samples.jsonl`,
`resource_summary.json`, `proof.bin`, `proof.json`, `verify.json`, and
`SHA256SUMS`. Network runs additionally contain request/response byte counts and
transport timing. Security runs contain mutation identity and expected/actual
result.

The final device archive must include build/toolchain hashes, frozen workload
and source-fixture hashes, raw runs, statistical summaries, cap decisions,
thermal/energy metadata, crash/token-state artifacts, and an explicit list of
unsupported (`null`) counters. No Android artifacts exist in Phase V4F.
