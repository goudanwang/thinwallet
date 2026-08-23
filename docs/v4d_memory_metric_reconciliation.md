# Phase V4D Memory Metric Reconciliation

Classification: `CREDENTIAL_MEMORY_METRICS_RECONCILED`.

## Resolution

The previously reported S-W4 value of approximately 24.1 MiB was the full
process `VmHWM` reported by `/usr/bin/time -v`. It was not PBMO-only memory,
child-process memory, or an internal planner counter. The old 128/192 MiB
rejections were false rejections caused by applying a 111 MiB reserve calibrated
on large synthetic jobs while comparing it with full-process RSS.

Process RSS, `VmHWM`, cgroup `memory.current`/`memory.peak`, anonymous RSS,
file-backed RSS, PSS, internal accounted arenas, and temporary-file bytes are
now recorded separately. Maxima from different samplers are not added because
they need not occur at the same instant.

## Simultaneous Measurements

| Metric | S-W4 | WK(52,32) |
| --- | ---: | ---: |
| Final planner prediction, bytes | 17,135,616 | 226,553,856 |
| Process VmHWM, KiB | 17,720 (64 MiB run) | 221,732-222,308 (five runs) |
| Cgroup memory peak, bytes | 34,197,504 | 260,046,848 (248 MiB cap) |
| Sampled anonymous RSS peak, KiB | 12,436 | recorded per run |
| Sampled file RSS peak, KiB | 3,200 | recorded per run |
| Sampled PSS peak, KiB | 14,491 | recorded per run |
| Internal accounted arena peak | measured in raw JSON | 25,165,824 bytes |
| Temporary state peak | 62,084,923 bytes | approximately 990.1 MB |

The WK cgroup peak reaches the configured cap because clean file cache is
reclaimed under pressure. All five 248 MiB runs recorded zero OOM events and
zero swap. The process VmHWM remains about 217 MiB.

## Runtime Model

The measured seven-point model is:

```text
FixedRuntimeReserve = 4,208 KiB

WorkloadRuntimeMargin(n, shape) =
    791 * n
  + 831 KiB * credential_count
  - 56 * next_pow2(max_sparse_matrix_entries)
```

The subtraction records the measured saving from replacing retained 64-bit
address/timestamp entries with range-checked 32-bit entries. Relation
construction uses a separate conservative estimate, `850 * n + 1 MiB`.
The maximum observed prediction error is 4.92% across seven measured shapes.

Allocator live bytes are `null`: enabling the tracking allocator materially
changes the large-run memory profile, so the low-overhead headline gate did not
claim that unavailable metric.

Machine-readable data is in
`experiments/v4d/memory_metric_reconciliation.json`.
