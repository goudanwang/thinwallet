# Provisional Four-Challenge Compression Map

This is a drafting aid. It does not replace the detailed TC1-TC18 ledger.

| Group | One-sentence problem | Detailed TCs | Proposed placement | Theorem/experiment | Likely reviewer question | Claim boundary |
| --- | --- | --- | --- | --- | --- | --- |
| PC1: Outsourcing/PCS compatibility | Exact fragmented PCS outputs and privacy prevent naive MSM outsourcing. | TC1-TC5 | Protocol and negative-results sections | PBMO privacy game, leakage counterexamples, all-output adapter experiment | Does outsourcing preserve the backend transcript and hide cross-output relations? | Preprocessed PBMO only; Matrix-RAA and reusable masks rejected. |
| PC2: Memory-bounded native prover execution | The complete transcript-constrained prover must fit a budget, not just one MSM. | TC8-TC13, TC15 | System design and evaluation | Peak-live planner model, byte-identical FS2-FS7 experiments | Are savings end-to-end and transcript preserving? | Desktop real-backend evidence; no physical-device claim. |
| PC3: Secure offline/online state and durability | One-time masked state must survive crashes without becoming reusable. | TC6, TC7, TC14 | Security model and implementation | Token lifecycle invariant and crash tests | What prevents rollback and reuse? | Current-history rollback only; complete software snapshot rollback remains open. |
| PC4: Realistic credential and mobile integration | Useful credential semantics introduce independent composition/revocation, phase, and OS-resource costs. | TC16-TC18 | Workloads, methodology, limitations | `WC/WR` scaling, V4G held-out phase model, and process/cgroup reconciliation | Is the workload useful, correctly parameterized, and measured on device? | Frozen desktop evidence; no accumulator or physical Android execution claim. |

`THINWALLET_FOUR_CHALLENGE_COMPRESSION_MAP_COMPLETE`

## V5A PC4 Update

PC4 now has one-device physical ARM64 evidence for S-W1, S-W4, H0, H1 and H2,
including byte-identical proofs, Android VmHWM/PSS, external-memory I/O and
sustained thermal sequences. It still lacks a real PBMO phone network path and
controlled crash injection. The evidence supports a Galaxy-S23 headless
prototype claim, not production-wallet or all-Android feasibility.

## V5B PC3 And PC4 Update

PC3 now includes real Android `kill -9`, real Wi-Fi server interruption,
durable `RESERVED -> BURNED` recovery, stable `SPENT`, bounded journal retention,
and explicit burned/spent replay rejection. Complete software snapshot rollback
remains outside the claim.

PC4 now includes a standalone PBMO server, controlled authenticated Wi-Fi TCP,
five measured runs for each of S-W1/S-W4/H0/H1/H2, phase-aligned Android memory
snapshots, and transport/server timing. It remains a one-device headless-shell
result without TLS, cellular, energy, production-wallet, or all-Android claims.
