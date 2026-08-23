# Phase V3B Budget Plan Validation

## FS3 plan

At `n = 2^18`, FS3 selects four state classes: spill `comb_ops`, spill `comb_mem`, spill inactive product-circuit layers, and deterministically rebuild relation state after releasing the original relation and `Instance` at last use. The hard limit is 512 MiB, the calibrated runtime reserve is 111 MiB, and the planner's usable prover-state budget is 401 MiB.

The planner predicts 400.5 MiB prover state. Including its 111 MiB runtime reserve, the predicted RSS ceiling is 511.5 MiB. Five measured runs averaged 514,154.4 KiB (502.10 MiB), so the prediction conservatively overstates measured RSS by 1.87%. Every emitted plan was within its usable state budget.

At 384 MiB, the planner rejects `2^18` before relation/witness construction because 400.5 MiB predicted state exceeds the 273 MiB usable budget. `2^16` succeeds at 384 MiB. The `2^20 @ 768 MiB` stretch attempt is also rejected before witness construction because no current FS3 plan fits.

## Cap results

| Cap | Workload | Result | Peak RSS KiB | Runs |
| ---: | --- | --- | ---: | ---: |
| 384 MiB | `2^18` | controlled planner rejection | null | 1 deterministic preflight |
| 512 MiB | `2^18` | pass | 514224, 514092, 514224, 514056, 514176 | 5/5 |
| 768 MiB | `2^18` | pass | 514076 | 1/1 |
| 896 MiB | `2^18` | pass | 513996 | 1/1 |

All successful proofs have SHA-256 `e6360f619150e8141d4645a18da7d781ee84818f273cd093a088638d97b3bf8e`; the unchanged original verifier accepts every proof.

For the fixed `2^12` equivalence fixture, FS1, FS2, and FS3 each emitted 6,906 transcript events. All three transcript files have SHA-256 `a68a34b2fe71ba5518b6b8866e16888845f623b32ca19d373532ce17ee7cdaf2`, and all three serialized proofs have SHA-256 `a9b8bd3cc9f02c254e7990e81a38c5d8948383e3463970084978500cf617434a`.

## Memory and I/O

FS3's 512 MiB mean RSS is 484,781.6 KiB (48.53%) below FS1 and 353,662.5 KiB (40.75%) below FS2. Selected state writes average 503,315,456 bytes and reads average 671,087,616 bytes. Relative to 503,315,456 bytes of unique stored state, aggregate I/O amplification is 2.3333x, down from FS2's 3x. Peak temporary state is 503,315,456 bytes; no mmap or swap is used.

## Latency

The five 512 MiB runs averaged 62,107.88 ms wall time and 28,236.54 ms inside `SNARK::prove`. Measured PBMO means are 256.73 ms masking, 1,186.77 ms server MSM, and 0.063 ms recovery; this semihonest headline mode has 0 ms malicious batch check. Spill read/write time, standalone Sumcheck field time, recomputation time, proof assembly, and fsync lifecycle time were not independently instrumented and remain null rather than being inferred.

Relative to FS1, the observed wall-latency increase is 51.29 ms per MiB of peak RSS saved. Relative to FS2 it is 45.23 ms/MiB. FS0 is not privacy-equivalent because it does not provide PBMO outsourcing privacy.

## Classification

`PHASE_V3B_BUDGET_AWARE_STREAMING_PASS`

This is a WSL result for a synthetic relation. It is not an Android, production mobile, or credential-workload feasibility result.
