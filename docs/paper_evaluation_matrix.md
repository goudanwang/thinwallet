# Paper Evaluation Matrix

| Evaluation item | Current evidence | Status |
| --- | --- | --- |
| Backend | libspartan 0.9.0, Ristretto255 | Fixed |
| Synthetic relation | `2^18` Boolean multiplication | Measured |
| FS5 exact boundary | 264 MiB pass 5/5; 260 MiB planner rejection 5/5 | Complete |
| FS6 256 MiB gate | 5/5; minimum margin 16.19 MiB | Pass |
| Proof/transcript identity | Byte-identical fixtures and `2^18` proof | Pass |
| Native verifier | Unchanged upstream verifier accepts | Pass |
| I/O amplification | 3.00x to 2.83x | Improved |
| Temporary storage | 578,949,319 to 411,040,768 bytes | Improved |
| Mean wall latency | 39,478.51 ms | Measured |
| Malicious PBMO/token lifecycle | Regression and 5/5 headline | Pass |
| Snapshot rollback | Software-only rollback not prevented | Open |
| Physical Android | No authorized device | Frozen |
| Real credential relation | Not yet integrated | Open |
| Production-mobile feasibility | Not established | Excluded |
