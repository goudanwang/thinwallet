# V4F Desktop Evaluation

## Scope

This is a WSL desktop evaluation. It does not include Android execution,
production-wallet validation, W3C VC interoperability, accumulator revocation,
an independent MiMC7 audit, or complete software snapshot-rollback protection.

The headline workloads are H0 `WK(8,0,0,None)`, H1
`WK(52,1,32,SparseMerkle)`, and H2 `WK(8,8,32,SparseMerkle)`. Modes are M0 native
in-memory, M1 plaintext remote MSM (privacy-insecure diagnostic only), M2
malicious Preprocessed PBMO in-memory, M3 FS7 semi-honest PBMO, and M4 FS7
malicious PBMO.

## Method

The controlled caps are 64, 96, 128, 192, 224, and 256 MiB. The prover is not
started when the preflight planner leaves less than 8 MiB margin; such cells are
`CONTROLLED_PLANNER_REJECTION`. Headline, minimum-stable, adjacent reported
boundary, and paper-table cells use five repetitions. Other diagnostic cells
use one repetition. Resource records distinguish process VmHWM, PSS, anonymous
and file RSS, cgroup peak, temporary storage, and I/O. Outer shell timing uses a
monotonic clock; protocol phase timing uses Rust `Instant`.

## Results

The complete headline, mode, cap, composition, revocation, latency, network,
security, ablation, planner, and proof-identity tables are under
`results/v4f/{json,csv,markdown,latex}`. Minimum stable M3/M4 caps are 64 MiB for
H0, 256 MiB for H1, and 224 MiB for H2. For H1, 224 MiB is a deterministic
planner rejection; for H2, 192 MiB is a deterministic planner rejection. H0
passes the lowest tested cap, so no lower listed failure boundary exists.

For each of H0, H1, and H2, deterministic M0/M2/M3/M4 fixtures have identical
public-input binding, relation-layout digest, witness digest, transcript bytes,
and serialized proof bytes. The unchanged upstream libspartan 0.9.0 verifier
accepts all fixtures. Security regression passes 114 recorded checks, including
the authenticated source 29/29 suite. The limitation
`SOFTWARE_ONLY_SNAPSHOT_ROLLBACK_NOT_PREVENTED` remains.

## Planner Gate

The planner was validated on seven points separate from its calibration set.
Maximum process-memory prediction error is 14.85%, above the required 5%.
Accordingly the primary classification is
`PHASE_V4F_PLANNER_VALIDATION_FAILED`; the desktop release-candidate archive is
not frozen. Final validation measurements were not used to retune the model.

## Network Boundary

The retained LAN, Wi-Fi, moderate-cellular, and high-latency values are PBMO
transport-only replay latency. Complete network presentation latency is
`NOT_MEASURED`; no end-to-end value is synthesized from separate runs.
