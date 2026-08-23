# Physical Android Benchmark Plan

Status: `NOT_EXECUTED`. This is the Phase V5A handoff, not Android evidence.

Use the frozen V4F H0/H1/H2 fixtures and M4 semantics on one authorized ARM64
device. Begin with an uncapped correctness smoke, then discover supported OS
memory controls before selecting cap cells. Record cold and warm runs, five
repetitions at the final stable cap and adjacent controlled boundary, and keep
single-worker execution with no competing app workload.

For each run collect `/proc/<pid>/status`, `smaps_rollup`, available cgroup
memory files, `/proc/<pid>/io`, context switches and faults, temporary-state
size, proof/transcript hashes, unchanged-verifier result, battery/thermal state,
CPU frequencies, and energy counters where reliable. Separate credential
source, witness/relation, Sumcheck, PBMO, server MSM, network and verifier
latencies. Never infer end-to-end latency by adding unrelated runs.

Required security runs include malformed source/session/layout, token reuse and
response replay, malicious output corruption, crash before and after durable
reservation, and aborted-proving cleanup. Software snapshot rollback remains a
known limitation unless a hardware-backed monotonic state mechanism is tested.
