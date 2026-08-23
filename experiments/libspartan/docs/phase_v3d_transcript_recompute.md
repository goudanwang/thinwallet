# Phase V3D Transcript-Aware Recompute

Primary classification: `PHASE_V3D_320M_TRANSCRIPT_RECOMPUTE_PASS`.

FS5 keeps every FS4 active streaming path and adds compact authenticated
address/timestamp checkpoints, canonical query-time recomputation, explicit
ephemeral spill durability, single-thread execution, and a calibrated memory
planner. It does not change proof arithmetic or the verifier.

At `2^18`, the 320 MiB malicious-PBMO gate passed 5/5 with mean peak RSS
262,456.0 KiB and mean wall time 37,862.14 ms. The stronger 288 MiB boundary
also passed 5/5. The 256 MiB plan was rejected before relation allocation. The
FS5 semi-honest path passed at 320 MiB as well.

The planner predicts 275,251,200 bytes RSS versus 268,754,944 bytes measured
(2.42% error). Predicted/measured total temporary storage is
579,862,528/578,949,319 bytes; total reads are
1,979,711,488/1,979,649,600 bytes; total writes are
989,855,744/989,834,432 bytes.

The fixed `2^12` FS1/FS4/FS5 transcript has 6,906 events and SHA-256
`a68a34b2fe71ba5518b6b8866e16888845f623b32ca19d373532ce17ee7cdaf2`.
Its proof SHA-256 is
`a9b8bd3cc9f02c254e7990e81a38c5d8948383e3463970084978500cf617434a`.
All measured `2^18` FS5 proofs match the frozen FS4 proof SHA-256
`e6360f619150e8141d4645a18da7d781ee84818f273cd093a088638d97b3bf8e`
and are accepted by the unchanged upstream verifier.

The final instrumented run measured 18,634.54 ms proving, including 4,231.93
ms active Sumcheck, 1,071.11 ms product build, and 462.21 ms explicit
checkpoint recomputation. Ephemeral fsync fell from the frozen 30,475.50 ms to
zero, while token durability remained enabled.

This is desktop WSL evidence. It makes no Android or production-mobile claim.
