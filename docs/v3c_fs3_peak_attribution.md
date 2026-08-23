# Phase V3C FS3 Peak Attribution

Status: `FS3_ACTIVE_PEAK_EXACTLY_ATTRIBUTED`

The uninstrumented frozen FS3 headline mean is 514,154.4 KiB RSS. The 512 MiB
live-cut sample reached 514,136 KiB. At the sampled peak, allocations of at
least 64 KiB account for 417,137,680 bytes and the process/Rust/allocator
residual is 109,337,584 bytes.

| Live class | Bytes |
| --- | ---: |
| Active Sumcheck/product proof scope | 235,652,112 |
| Dense MLE inputs | 134,217,728 |
| Sparse polynomial structures | 37,814,272 |
| R1CS/relation objects | 8,388,608 |
| Commitment scalar layouts | 901,120 |
| PBMO objects | 163,840 |
| Runtime/allocator residual | 109,337,584 |

The raw JSON preserves the top twenty allocations and every tracked live
allocation. The broad `SparseMatPolyEvalProof::prove` allocation scope cannot
reliably recover a layer or round for old FS3 events; those fields remain null
rather than being inferred. The largest tracked object is a 67,108,864-byte
Sumcheck/product-scope table. Two 16,777,216-byte equality/audit tables and
multiple 8,388,608-byte dense and sparse objects are also live.

This is exact byte accounting at the configured 64 KiB trace threshold plus a
measured RSS residual, with 1 ms trace-alignment uncertainty. It is an
implementation attribution, not a cryptographic memory lower bound.
