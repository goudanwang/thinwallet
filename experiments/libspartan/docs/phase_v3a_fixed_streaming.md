# Phase V3A Fixed Streaming Path

FS2 replaces only the 128 MiB `comb_ops` dense table with a bounded,
file-backed canonical-scalar store. It writes elements in original order,
scans them sequentially for commitment and sparse evaluation, and preserves
PBMO row order and native blinding. This is a fixed strategy selected by an
environment flag, not an automatic scheduler.

`ProverStateStore` provides `create`, chunked write/read, sequential scan,
truncate, and remove operations. In-memory, file-backed, and read-only mmap
implementations are present. File metadata is session-bound and SHA-256
authenticated; ordering is deterministic; buffers are bounded; normal and
runner-abort cleanup remove temporary state. FS2 itself uses explicit file
reads, not an unbounded mapping.

For the fixed `2^12` fixture, FS1 and FS2 produced byte-identical transcript
logs: 6,906 events, 1,467 challenges, 3,665 scalar messages, 1,686 point
messages, and 88 protocol markers. Both transcript hashes are
`a68a34b2fe71ba5518b6b8866e16888845f623b32ca19d373532ce17ee7cdaf2`.
The serialized proof is also byte-identical (47,464 bytes, SHA-256
`a9b8bd3cc9f02c254e7990e81a38c5d8948383e3463970084978500cf617434a`).
At `2^18`, all successful modes produce the same 120,136-byte proof with
SHA-256 `e6360f619150e8141d4645a18da7d781ee84818f273cd093a088638d97b3bf8e`.
The unchanged upstream verifier accepts every successful FS2 proof.

At the controlled 896 MiB crossing, FS0 and FS1 fail 0/5 at `2^18`; FS2
succeeds 5/5 with 867,740-867,908 KiB peak RSS. Thus stable capacity rises
from `2^16` to `2^18`, a 4x relation-size increase. At 1024 MiB all modes
succeed 5/5; FS0 peaks at 998,312-998,576 KiB, FS1 at 998,804-998,992 KiB,
and FS2 at 867,640-867,912 KiB, a roughly 128 MiB physical-RSS reduction.

For FS2 at `2^18`, the state file is 134,217,728 bytes, writes total
134,217,728 bytes, reads total 268,435,456 bytes, and two complete scans are
performed. Aggregate I/O amplification is 3x state size. Mean 1024 MiB wall
latency is 46,484.25 ms; FS0 is 11,713.30 ms and FS1 is 37,968.14 ms.
Measured PBMO means inside FS2 are 260.45 ms masking, 1,184.00 ms server MSM,
0.062 ms recovery, and 0 ms batch checking in semi-honest mode. Compute and
I/O wait are not separately attributable with the current instrumentation and
remain `null`; the wall/prove and byte counters are reported without deriving
an unmeasured split.

```text
PROVER_EXTERNAL_STATE_STORE_PASS
LIBSPARTAN_FIXED_STREAMING_PATH_PASS
LIBSPARTAN_STREAMING_TRANSCRIPT_EQUIVALENCE_PASS
LIBSPARTAN_STREAMING_PROOF_BYTE_IDENTICAL_PASS
LIBSPARTAN_UNCHANGED_VERIFIER_WITH_STREAMING_PASS
LIBSPARTAN_FIXED_STREAMING_OOM_BOUNDARY_COMPLETE
THINWALLET_REAL_BACKEND_MEMORY_ADVANTAGE_ESTABLISHED
THINWALLET_MEMORY_IO_TRADEOFF_COMPLETE
PHASE_V3A_REAL_BACKEND_FIXED_STREAMING_PASS
```
