# libspartan 2^18 Memory Failure Attribution

Phase V3A traces the complete release prover with both logical allocation
accounting and `/proc` RSS/VmHWM samples. The raw evidence is in
`experiments/v3a_memory/failure_traces.json`.

## Failure sites

| Cap | First rejected request | Call site | Live state before request | RSS before request |
| ---: | ---: | --- | ---: | ---: |
| 256 MiB | 16 MiB | `AddrTimestamps::new:audit_ts_scalar` | 244.81 MiB | 249.1 MiB |
| 512 MiB | 16 MiB | `R1CSProof::prove:phase_two_tables` | 489.0 MiB | 497.2 MiB |
| 768 MiB | 8 MiB | `SparseMatPolyEvalProof::prove` | 760.2 MiB | 763.2 MiB |

Native, plaintext-remote, semi-honest PBMO, and malicious PBMO traces reach
the same allocation classes. Each recorded failure is allocator rejection
(exit 134), not cgroup OOM, OS kill, panic, or an explicit application-level
capacity check.

At 512 MiB the rejected phase-two table overlaps the 128 MiB `comb_ops`
dense table, 32 MiB `comb_mem`, two 16 MiB audit timestamp tables, and a
16 MiB phase-one table. At 768 MiB, the request overlaps `comb_ops` and a
64 MiB `SparseMatPolyEvalProof` folded table. The failed requests themselves
are transient, while `comb_ops` remains live from encoding through sparse
polynomial evaluation. This lifetime, rather than PBMO state, creates the
useful spill opportunity.

```text
LIBSPARTAN_2P18_FAILURE_ATTRIBUTED
```
