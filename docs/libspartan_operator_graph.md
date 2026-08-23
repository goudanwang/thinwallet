# libspartan 0.9.0 Operator Graph

Status: `LIBSPARTAN_OPERATOR_GRAPH_COMPLETE`

Selected backend:

```text
libspartan 0.9.0
Ristretto255 via curve25519-dalek 4.1.3
```

The unmodified native flow is:

```text
SNARKGens::new
SNARK::encode
SNARK::prove
SNARK::verify
```

## Main Operators

| Operator | Source | Privacy | Transcript barrier |
| --- | --- | --- | --- |
| WitnessGenerate | caller creates `VarsAssignment` | private | no |
| EncodeInstance | `SNARK::encode -> R1CSInstance::commit` | public R1CS | yes, `comm` is hashed |
| CommitWitness | `r1csproof.rs -> poly_vars.commit` | private witness | yes |
| SumcheckPhase1 | `R1CSProof::prove_phase_one` | private evals | yes, round messages |
| SumcheckPhase2 | `R1CSProof::prove_phase_two` | private evals | yes, round messages |
| EvalSparsePolys | `SNARK::prove eval_sparse_polys` | public R1CS at transcript challenges | yes, claims |
| R1CSEvalProof | `R1CSEvalProof::prove` | public R1CS decommitment | yes |
| ProofAssemble | `SNARK` struct construction | proof object | final |

## MSM Inventory

The largest private-scalar MSM path is the witness polynomial commitment:

```text
src/dense_mlpoly.rs::DensePolynomial::commit_inner
  -> src/commitments.rs::Commitments for [Scalar]::commit
  -> GroupElement::vartime_multiscalar_mul
```

The returned commitment is hashed into the transcript, so any remote MSM
adapter must return exactly the same Ristretto point before the challenge
is sampled.

## Adapter Blocker

libspartan 0.9.0 does not expose a public prover-only MSM provider hook.
The relevant modules are internal to the crate and call the concrete
`GroupElement::vartime_multiscalar_mul` implementation directly through
the private commitment stack.

Therefore Phase 3A-R stops at:

```text
PHASE3A_R_BLOCKED_MSM_API
```

This is not a verifier failure. The standalone Ristretto repetition-code
EMSM self-check passes independently, but it has not been inserted into
the native Spartan prover. The full RAA-over-Ristretto migration remains
open.
