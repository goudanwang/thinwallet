# Phase V3C Active-State Streaming

Primary classification: `PHASE_V3C_ACTIVE_SUMCHECK_STREAMING_PASS`.

FS4 combines malicious or semi-honest Preprocessed PBMO, all FS3 targets,
bounded external Sumcheck folds, direct-slice dot-product state, one-at-a-time
active product hash construction, authenticated session/round/challenge state,
and an explicit memory plan. It preserves scalar operation order and the
unchanged verifier-facing proof format.

The 2^18 384 MiB headline passed 5/5 under `ulimit -v`: mean peak RSS is
375,133.6 KiB (366.34 MiB), mean capped-process wall time is 73,635.85 ms, and
mean proving time is 48,603.38 ms. Every proof is 120,136 bytes with SHA-256
`e6360f619150e8141d4645a18da7d781ee84818f273cd093a088638d97b3bf8e`.
Patched verification and separate unchanged-upstream verification both accept;
all malicious PBMO tokens finish `SPENT`, and no swap is observed.

The planner predicts 384,303,104 bytes (366.50 MiB), an absolute 0.043% error
against headline mean RSS. It retains the 111 MiB runtime reserve. FS4 reads
1,644,105,280 bytes, writes 822,062,272 bytes, has 3.0x lifetime-state I/O
amplification, and peaks at 411,040,768 bytes of temporary state, below FS3's
503,315,456 bytes.

The latency fixture's Rust monotonic timeline is 76,186.13 ms and closes at
100% across relation construction, instance construction, assignments,
generators, encoding, token setup, proving, patched verification, and cleanup.
Within its 48,986.68 ms proof interval, active Sumcheck takes 30,847.27 ms,
active product construction 4,459.59 ms, PBMO masking/server/recovery/checking
1,505.92 ms, and remaining arithmetic/proof assembly 12,173.89 ms. Nested
state-store timings are 587.20 ms read, 691.62 ms write, 30,475.50 ms fsync,
and 229.17 ms cleanup. `/usr/bin/time` reports 70,950 ms for the same process;
both raw clocks are retained because WSL exposed a roughly 7% discrepancy.

FS1, FS2, and FS4 2^12 traces each contain 6,906 byte-identical events with
SHA-256 `a68a34b2fe71ba5518b6b8866e16888845f623b32ca19d373532ce17ee7cdaf2`.
The corresponding FS4 proof hash is the frozen
`a9b8bd3cc9f02c254e7990e81a38c5d8948383e3463970084978500cf617434a`.

Security regressions pass: libspartan 50/50 plus 3/3 doc tests, PBMO 9/9,
streaming fold/state tests 4/4, and product transition injection 1/1.
`SOFTWARE_ONLY_SNAPSHOT_ROLLBACK_NOT_PREVENTED` remains unchanged.

The 352 and 320 MiB plans are deterministically rejected. The 256 MiB run is
not attempted, and both 2^20 at 512/768 MiB are planner-rejected. No swap,
unbounded mmap, hidden page-cache workaround, or disabled accounting is used.

This is a desktop WSL experiment. It makes no Android, production-wallet, or
broad mobile-feasibility claim.
