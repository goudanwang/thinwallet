# ThinWallet Design Evolution

| Transition | Why prior design was insufficient | Triggering evidence | Decision and cost | Result |
| --- | --- | --- | --- | --- |
| Standard EMSM -> streaming FFT-free Sumcheck direction | MSM savings did not bound the prover. | Field vectors dominated post-MSM traces. | Investigate streaming IOP structure; larger protocol-design surface. | Operator-local result only. |
| Toy direction -> real libspartan | Toy algebra could not establish backend compatibility. | Missing native transcript/PCS behavior. | Integrate maintained libspartan 0.9.0 on Ristretto255. | Real-backend baseline. |
| Single MSM adapter -> fragmented commitment audit | One adapter did not replace a complete logical commitment. | Hyrax emitted `q` exact points. | Audit every output and barrier. | R2.5 exposed full shape. |
| Fragment discovery -> PBMO formalization | Per-output correction was costly and masking assumptions unclear. | V0 dependency/security analysis. | Define batched multi-output interface and games. | PBMO research object. |
| Online Matrix-RAA -> negative result | Invertible mixing leaked rank/sparsity invariants. | Practical distinguishers. | Reject online public-linear shortcut. | V1 NO-GO. |
| Negative result -> Preprocessed PBMO | Secure online compression needed hidden correlation. | V1 leakage proofs. | One-time preprocessed tokens; storage and lifecycle cost. | V2 integration pass. |
| In-memory PBMO -> single-target spill | Prover field state dominated. | Allocation attribution. | Spill one large object; I/O cost. | FS2 about 848 MiB. |
| Single spill -> multi-target planner | Other objects overlapped at the peak. | Peak-live cut. | Budget-aware retain/spill/recompute. | FS3 about 502 MiB. |
| Planner -> active Sumcheck streaming | Active layers still materialized vectors. | FS3 traces. | External folds and bounded buffers. | FS4 about 366 MiB. |
| Active streaming -> transcript-aware recomputation | Late-use state remained live. | Fiat-Shamir barriers. | Checkpoint and canonical recomputation. | FS5 about 256 MiB. |
| Uniform persistence -> durability separation | Regenerable spill paid token-grade fsync cost. | I/O/durability traces. | Separate security-critical tokens from replayable spill. | Token safety retained. |
| Materialized opening -> streaming dereference/fusion | Full dereference/opening vectors overlapped. | FS5 operator graph. | Iterator APIs and consumer fusion. | FS6 about 240 MiB. |
| Synthetic -> realistic credential profiles | Boolean relations omitted credential peaks and semantics. | V4B/V4C deltas. | Profile M/S, Ed25519 host authentication, MiMC commitments and revocation. | Useful workload measured. |
| Ambiguous scaling -> composition/revocation separation | `WK(k,d)` implied no `r`. | Historical 52-credential fixture had one path. | `WK(k,r,d,backend)`, `WC` and `WR`; more benchmark dimensions. | V4E semantics corrected. |
| Single-total planner -> phase-aware process/cgroup planners | V4F held-out error reached 14.85% and cap-saturated cgroup peaks obscured process behavior. | Seven frozen residuals plus 2 GiB cgroup diagnostics. | Fit phase maxima on 13 disjoint calibration points; precommit 10 validation points; add a separate conservative cgroup admission rule. | V4G max new held-out error 2.802%, MAPE 0.962%; original-seven max 2.985%. |
| Desktop build -> Android ARM64 build | Desktop success does not establish device feasibility. | Cross-build succeeded but no authorized device. | Preserve build artifacts and stop before execution. | Build-only evidence; no Android claim. |

The V4E authenticated source adds compact, session-bound relation replay. Its
current result is a desktop semantic audit, not a production wallet or Android
result.

`THINWALLET_DESIGN_EVOLUTION_COMPLETE`

| Physical Android handoff -> measured Galaxy S23 | ARM64 cross-build alone did not establish execution, memory, identity, or thermal behavior. | Authorized Samsung SM-S9110 became available over ADB. | Run frozen semantics with Android-only instrumentation and a device-specific expected-value planner. | S-W1/S-W4/H0/H1/H2 pass and S-W1/H0/H2 are byte-identical; real network and controlled crash injection remain incomplete. |
