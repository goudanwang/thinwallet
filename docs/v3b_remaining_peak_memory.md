# Phase V3B Remaining FS2 Peak Memory

## Measured FS2 peak

At `n = 2^18`, after the 128 MiB `comb_ops` table was externalized, the allocator trace recorded 879,837,184 bytes of tracked logical live allocations. The 896 MiB run reached 867,768 KiB RSS. Its peak decomposition was:

| Component | Bytes |
| --- | ---: |
| Sumcheck folded tables | 585,105,408 |
| Dense multilinear polynomials | 167,772,160 |
| R1CS instance | 88,080,384 |
| Sparse polynomial structures | 37,814,272 |
| Commitment bases | 901,120 |
| PBMO token | 163,840 |

The largest individual live allocation was a 67,108,864-byte product/fold table. The next selected targets were the 33,554,432-byte `comb_mem` table, inactive product-circuit layers, and relation/instance state held past its last prover use.

## Residency audit

FS2's reduction is real resident-memory reduction: the 896 MiB profile observed 864,936 KiB anonymous RSS, 2,688 KiB file RSS, 870,564 KiB virtual size, zero swap, and 134,217,792 temporary-file bytes. No unbounded mmap was used. Privileged cold global page-cache eviction was unavailable in this WSL environment, and cgroup `memory.current`/`memory.peak` were unavailable; those fields remain null.

Status: `FS2_REMAINING_PEAK_MEMORY_ATTRIBUTED` and `FS2_REAL_RESIDENT_MEMORY_REDUCTION_PASS`.
