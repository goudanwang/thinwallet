# V4G Planner Residual Analysis

## Frozen V4F Set

The seven V4F targets remained excluded from fitting and feature selection.
They were evaluated once after the V4G model and new held-out execution were
frozen. All measured peaks occurred in `ProvingPhase`.

| Point | Workload | V4F error | V4G error | Direction under V4G | Supported attribution |
| --- | --- | ---: | ---: | --- | --- |
| 1 | WK(8,0,0,None) | 1.203% | 0.229% | over | fixed/runtime and M4 proving overlap |
| 2 | WK(52,1,32,SparseMerkle) | 1.376% | 2.985% | under | padded-domain proving term versus k/r correction |
| 3 | WK(8,8,32,SparseMerkle) | 1.869% | 2.467% | under | revocation-path r term at the 2^18 proving overlap |
| 4 | WK(1,1,32,SparseMerkle) | 14.853% | 1.748% | under | 2^15 fixed proving intercept omitted by the smooth total model |
| 5 | WK(4,1,32,SparseMerkle) | 9.040% | 1.285% | over | 2^16 matrix-domain and composition overlap |
| 6 | WK(25,1,32,SparseMerkle) | 11.138% | 0.399% | under | prior full 2^18-style charge despite lower sparse density |
| 7 | WK(8,2,32,SparseMerkle) | 1.200% | 0.200% | over | balanced 2^17 revocation and streaming terms |

The exact old and new bytes, residual direction, stage traces, and provenance
are in `experiments/v4g/residual_decomposition.json` and
`results/v4g/original_seven_comparison.json`.

## Root Cause

The V4F single-total formula treated raw/padded size as a mostly smooth memory
axis. That hid three discontinuities: backend capacities round sparse matrix
domains, proving has a non-negligible fixed intercept at small n, and `k`, `r`,
and M3/M4 state alter the live overlap even when padded n is unchanged. It also
allowed relation/finalization estimates to stand in for the later proving peak.

V4G addresses these failures by taking the maximum of phase-live predictions,
using exact padded dimensions and next-power-of-two matrix capacity, and using
separate M2 and M3/M4 proving features. Runtime, thread stack, process file RSS,
and cgroup page cache are recorded separately. No unsupported byte count is
assigned to fragmentation or retained allocator pages; the measured post-trim
allocator-retained reserve was zero in the reserve experiment.

## Remaining Limits

The correction is empirical for implementation components without exact source
allocation formulas. It is validated for the frozen desktop compiler/runtime,
Profile S families, and M2/M3/M4 modes represented by the calibration and
held-out plans. It is not a physical-device model and does not claim 5% cgroup
accuracy.

`PLANNER_RESIDUALS_EXACTLY_ANALYZED`
