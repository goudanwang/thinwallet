# A2DP Export State Candidates

This document analyzes cryptographic design candidates for exporting
authenticated enrollment state into request-bound server-completable proving
state. It does not implement code and does not claim that any candidate is
secure.

## Interface

```text
ExportState_H,S(
    authenticated_enrollment_state,
    request,
    holder_activation
) -> Sigma_R

ServerProve(
    server_state,
    request,
    Sigma_R
) -> proof
```

`Sigma_R` is the request-bound export state produced by the holder/server
interaction. It must allow the server to continue proving without learning the
holder witness or being able to forge later activations.

## Sigma_R Requirements

`Sigma_R` must satisfy:

- witness hiding
- request binding
- holder gating
- credential-selection integrity
- disclosure integrity
- cross-request non-reusability
- public verifiability
- server-only continuation
- phone does not process a witness-sized vector

All candidates below have unresolved issues. Unsolved items are marked `OPEN`.

## Candidate 1: Commitment-Based Export

Two parties convert authenticated shares into hidden commitments. The server
later proves that the committed secret state satisfies the presentation
constraints.

### Commitment Type

Possible commitments:

- Pedersen-style hiding commitments over field elements.
- Polynomial/vector commitments over witness chunks.
- Merkle commitments to committed witness fragments.
- SNARK-native commitments that can be opened or checked inside the final
  proof system.

OPEN: the commitment must be compatible with the final proof system without
requiring the phone to prepare commitments for every witness wire.

### Randomness

Randomness options:

- Phone-generated randomness: strong holder-side control, but may require the
  phone to generate O(N) randomness if commitments are per-wire.
- Server-generated randomness with holder authentication: efficient but risks
  malleability unless the holder checks binding.
- Joint randomness via coin-tossing or PRF/PCG expansion: plausible if the
  holder stores only compact seeds.

OPEN: define a randomness derivation that is request-bound, non-reusable, and
sublinear for the phone.

### Server-Only Proving

The server can continue alone only if it has enough committed state,
openings/corrections, or proof-carrying material to assemble a public proof.

OPEN: ordinary Groth16 expects concrete witness values, not only commitments.
Commitments alone do not let the server evaluate private nonlinear constraints.

### Public Verifiability

The verifier must be convinced that the commitments correspond to an
authenticated enrollment record selected by the holder.

Possible paths:

- Include commitment consistency checks inside the SNARK.
- Use an externally verifiable commitment certificate.
- Recursively verify a prior proof that links commitments to enrollment state.

OPEN: if the final proof only checks committed values but not their
authenticated origin, the server can substitute commitments.

### Ordinary Groth16 Compatibility

Ordinary Groth16 can prove statements about commitment openings if openings are
part of the witness and commitment checks are inside the circuit. It cannot
directly prove from hidden commitments without the prover knowing the witness.

OPEN: commitment-based export likely needs either a changed circuit, recursive
proofs, or a proving system that natively supports committed witnesses.

### Phone O(N) Work

Naive per-wire commitments require O(N) phone work and storage or O(N)
holder-authenticated randomness.

OPEN: the design target is to avoid requiring the phone to touch every witness
wire; whether compact commitment export can achieve this remains open.

## Candidate 2: Multilinear/Sumcheck Export

The parties jointly complete the private nonlinear layer, output a
masked/authenticated multilinear polynomial state, and let the server continue
with sumcheck, commitments, and proof assembly.

### Two-Party Output

The two-party phase might output:

- masked multilinear evaluations of witness/state polynomials
- authenticated multiplication outputs for private nonlinear gates
- public consistency metadata for request binding and credential selection
- correction material that lets the server evaluate later proof messages

OPEN: specify the exact exported polynomial state and how it binds to
enrollment records, request, disclosure, and holder activation.

### Server Multilinear Extension

The server can compute multilinear extensions if it has enough evaluations or
compressed generating material. If values remain masked, the server must be
able to carry masks through sumcheck or remove them soundly.

OPEN: define how the server evaluates required multilinear polynomials without
learning hidden witness values or requiring phone interaction during sumcheck.

### Mask Retention or Elimination

Options:

- Keep masks and run a masked sumcheck relation.
- Reveal only aggregate openings that hide individual witness entries.
- Use authenticated correction terms so the server can remove masks at proof
  assembly time.

OPEN: mask elimination must not reveal witness values and must not let the
server forge polynomial evaluations.

### Public Soundness

Internal authenticated shares are not publicly verifiable. The verifier needs a
public argument that the exported polynomial state was derived from valid
authenticated state.

OPEN: this likely requires a delegation-friendly SNARK or IOP design, not just
ordinary Groth16.

### Need for a New SNARK

This candidate is the closest to true server-only continuation, but it likely
requires redesigning around multilinear IOPs, sumcheck, and polynomial
commitments. It may not fit the existing Circom/Groth16 measurement setup.

OPEN: define the proving system and the exact public verification relation.

### Phone O(N) Work

If the phone must authenticate or mask every multilinear evaluation, online
work remains O(N). To meet the A2DP goal, the phone would need compact seeds,
preprocessed correlations, or function-dependent correction material.

OPEN: the design target is to avoid requiring the phone to touch every witness
wire; whether this can be achieved for the multilinear state remains open.

## Candidate 3: Proof-Carrying Enrollment State

Enrollment generates a recursively verifiable or accumulable proof. Each
presentation proves only request-dependent predicates and references the
enrollment proof/state.

### Credential-Key Binding

This can reduce repeated per-presentation credential-key binding if enrollment
already proves:

- issuer validity
- credential commitment correctness
- holder-key binding
- schema/policy compatibility
- version or revocation-state anchor

The presentation can then reference a proof, accumulator element, or digest of
that enrollment state.

OPEN: ordinary reference by digest is insufficient unless the presentation
proof is soundly bound to the prior proof/state.

### Holder Key Exposure

If the enrollment proof exposes a stable holder authorization key, presentations
are linkable.

Options:

- Use stable public keys and accept linkability for the baseline.
- Certify per-verifier or one-time keys.
- Hide holder binding inside a recursive proof or accumulator.

OPEN: unlinkable holder-key binding is not designed here.

### Revocation and Freshness

Revocation/freshness can be handled by:

- updating the accumulated enrollment state
- proving membership in a current non-revoked set
- carrying a monotonic version or freshness token
- binding a request nonce and expiry to the presentation

OPEN: freshness must be updateable without redoing full enrollment and without
allowing rollback to stale proofs.

### Recursive Verification Cost

Recursive verification or accumulator checks may add constraints to every
presentation. Depending on curve cycle, verifier circuit, and proof system, the
cost may exceed the 321-constraint credential-key binding currently measured.

OPEN: measure recursive verification or accumulator-check cost before claiming
this improves per-presentation performance.

### Server-Only Proving Transition

Proof-carrying enrollment state authenticates static credential facts, but it
does not automatically provide hidden witness values or authenticated
intermediate state for server-only proving.

OPEN: combine proof-carrying enrollment with an export mechanism for
request-dependent private computation.

## Comparison Table

| Property | C1 | C2 | C3 |
| --- | --- | --- | --- |
| Public verifiability | OPEN: needs proof that commitments come from authenticated enrollment state | OPEN: needs public soundness for exported multilinear state | Plausible if recursive/accumulator proof is verified publicly; OPEN for binding to presentation |
| Server-only continuation | OPEN: commitments alone do not give witness values to ordinary Groth16 prover | Most promising: designed around server continuing sumcheck/proof assembly; OPEN details | Partial: authenticates enrollment but does not by itself export request-time witness state |
| Phone online work | OPEN: naive commitments are O(N) | OPEN: may still be O(N) unless compact seeds/corrections work | Potentially compact for enrollment reference; OPEN for request-time private computation |
| Phone storage | Compact only with seed-derived randomness; OPEN | Compact only with PCG/MAC seeds; OPEN | Compact proof/root/digest state plausible; OPEN for revocation freshness |
| Ordinary Groth16 compatible | Limited: only if openings are in witness and checks are in circuit | No, likely not directly compatible | Partially: can verify references only if recursive/accumulator check is circuit-compatible |
| Requires new SNARK | Maybe, if committed-witness proving is required | Likely yes, delegation-friendly multilinear/sumcheck SNARK | Maybe, for recursion/accumulation or efficient proof-carrying state |
| Main soundness gap | Commitments may not be bound to authenticated enrollment state | Internal MAC/share soundness may not become public verifier soundness | Prior enrollment proof may not be soundly linked to request presentation |

## Assessment

Most likely to realize true server-only continuation: **Candidate 2:
Multilinear/sumcheck export**. It directly targets a handoff where the phone and
server finish private nonlinear work, then the server continues proof assembly.
It is also the most invasive because it likely requires a delegation-friendly
SNARK rather than ordinary Groth16.

Easiest prototype: **Candidate 3: Proof-carrying enrollment state**. A prototype
can first link a presentation circuit to an enrollment proof or accumulator
digest and measure the cost of recursive/accumulator verification. This will
not solve server-only continuation by itself, but it is the lowest-friction way
to test whether per-presentation credential-key binding can be moved out of the
main presentation circuit.

Largest OPEN problem: converting internally authenticated state into a publicly
verifiable, request-bound, server-completable proof state without requiring the
phone to process a witness-sized vector.
