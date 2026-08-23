# Phase 3A Real Backend Audit

Status: `NO_SUITABLE_REAL_SUMCHECK_BACKEND`

Classification: `PHASE3A_NO_SUITABLE_BACKEND`

This audit freezes the Phase 2D production crypto baseline and evaluates
real, maintained-looking Sumcheck/SNARK backend candidates. It does not
construct another internal proof system, and it does not modify the
existing Phase 2D backend.

## Phase 2D Baseline

The immutable marker is:

```text
THINWALLET_PHASE2D_PRODUCTION_CRYPTO_BASELINE
```

The Phase 2D baseline is treated as:

```text
PHASE2D_BASELINE_FROZEN
```

The migration runner archives current JSON/log/text benchmark artifacts
from `experiments/memory-bounded-sap/` into:

```text
experiments/real-backend-migration/baseline_archive/phase2d_benchmark_archive.tar.gz
```

The repository root is not a Git worktree in the current environment, so
the baseline uses an immutable status marker rather than a Git tag.

## Selection Rule

A backend must satisfy all of the following before Phase 3A may proceed:

- maintained real backend;
- complete general-purpose relation support;
- real zero-knowledge/SNARK implementation;
- client proving path free of FFT, NTT, FRI, and large LDE work;
- compatibility with the current production group path: Arkworks BN254 G1 / Fr;
- identifiable large private-scalar MSM calls that can be replaced by
  ThinWallet production EMSM;
- unchanged native proof type, proof encoding, verifier key, and verifier.

No audited candidate met all requirements.

## Candidate Summary

| Candidate | Revision | Relation | ZK / SNARK status | FFT/LDE/FRI audit | Curve compatibility | Decision |
| --- | --- | --- | --- | --- | --- | --- |
| Spartan | crate `spartan` 0.9.0 | R1CS | Spartan SNARK/NIZK modules present | no FFT/NTT/FRI hits in local source grep | blocked: not Arkworks BN254 production EMSM stack | rejected |
| Nova | crate `nova-snark` 0.73.0 | relaxed R1CS / folding / IVC | recursive/folding SNARK implementation | `provider/mercury.rs` uses `halo2curves::fft::best_fft` | provider stack not current Arkworks BN254 EMSM | rejected |
| SLOP Spartan | crate `slop-spartan` 6.3.1 | R1CS / SP1-associated Spartan | standalone ZK/SNARK path not established | not accepted before full path instrumentation | no clear ThinWallet MSM adapter point | rejected |
| Plonky3 Sumcheck | crate `p3-sumcheck` 0.6.1 | Sumcheck component | not complete SNARK by itself | layout docs mention WHIR commitment overhead with FFT + Merkle | no group MSM backend to map | rejected |
| ark-piop | crate `ark-piop` 0.1.0 | PIOP framework | not complete backend for this phase | not accepted before full path instrumentation | arkworks-friendly but incomplete backend | rejected |

## Detailed Findings

### Spartan 0.9.0

Spartan is the closest conceptual match because it is R1CS-based and
contains multilinear polynomial and Sumcheck code. Local source inspection
found Sumcheck and commitment paths in `sumcheck.rs`, `dense_mlpoly.rs`,
`sparse_mlpoly.rs`, and `r1csproof.rs`. A source grep did not find FFT,
NTT, LDE, or FRI client paths.

It is rejected for Phase 3A because the crate's commitment backend is not
the current Arkworks BN254 G1 / Fr production EMSM stack. Replacing its
commitment/MSM path would require changing the backend group commitment
implementation, which would no longer demonstrate unchanged native proof
type and verifier compatibility.

### Nova 0.73.0

Nova is maintained-looking and includes BN256-related providers, folding
schemes, and Spartan-like compression components. It is not a minimal
one-shot Sumcheck SNARK replacement for the current ThinWallet relation
pipeline. It is primarily an IVC/folding framework over step circuits and
relaxed R1CS.

The local source audit also found a hidden client transform in the Mercury
provider path:

```text
provider/mercury.rs uses halo2curves::fft::best_fft
```

That violates the Phase 3A client FFT-free requirement for the audited
path unless a separate non-FFT provider is selected and proven from the
actual runtime path. No such complete adapter path was demonstrated here.

### SLOP Spartan 6.3.1

SLOP Spartan advertises an R1CS Spartan proof system and is part of the
SP1/SLOP ecosystem. The local audit did not establish a stable standalone
general-purpose ZK SNARK API with a clean native verifier and identifiable
BN254 private-scalar MSM adapter points. It is rejected as an ecosystem/API
mismatch for this phase.

### Plonky3 p3-sumcheck 0.6.1

This crate is a Sumcheck engine, not a full zk-SNARK backend with a final
native proof type and verifier. It has no group MSM path to replace with
ThinWallet production EMSM. The Plonky3 ecosystem may be relevant for
future proof-system redesign, but `p3-sumcheck` alone is not eligible for
Phase 3A.

### ark-piop 0.1.0

ark-piop is an arkworks-friendly PIOP framework, not a complete maintained
general-purpose zk-SNARK backend accepted by this task. The candidate is
rejected before integration because no complete native proof/verifier path
was established.

## Migration Decision

Output:

```text
NO_SUITABLE_REAL_SUMCHECK_BACKEND
PHASE3A_NO_SUITABLE_BACKEND
```

First remaining blocker:

```text
No audited candidate simultaneously provides a maintained complete
general-purpose FFT-free Sumcheck zk-SNARK, BN254/Arkworks-compatible
private-scalar MSM adapter points, and unchanged native verifier
acceptance with ThinWallet production EMSM.
```

Because no backend is selected, Phase 3A intentionally stops before native
baseline, runtime instrumentation, operator graph generation, MSM adapter
insertion, production EMSM integration, malicious-mode EMSM testing, and
RB0/RB1/RB2 memory snapshot.
