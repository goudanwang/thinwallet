# A2DP Private-to-Server Boundary

This note analyzes where private holder work could stop and server-only proving
could begin for future A2DP experiments. It is based on the completed online
presentation measurement only. It does not claim that A2DP is implemented.

## Current Measurement

The current online presentation circuit combines:

- age predicate
- request binding
- disclosure control
- holder authorization

Measured values:

| Metric | Value |
| --- | ---: |
| Total constraints `N` | 4987 |
| Private nonlinear estimate `m` | 4601 |
| `m / N` | approximately 92.3% |
| Holder authorization | 4504 constraints |
| Age predicate private nonlinear | 97 constraints |

Conclusion: the current naive 2PC split does not provide computational
asymmetry. Request-dependent private nonlinear computation accounts for about
92.3% of the online circuit. The dominant bottleneck is in-circuit BabyJubJub
EdDSA-Poseidon holder authorization.

The measured number is not a complete credential presentation cost. Issuer
validity, credential binding, revocation, and the server-only proving transition
are not implemented.

## Candidate A: External Signature Verification + Private Credential-Key Binding

### Flow

1. The phone signs the request digest.
2. The signature and authorization public key are verified outside SNARK/2PC.
3. Enrollment state binds the credential to the authorization public key.
4. The private presentation proves only that the credential used in the
   presentation corresponds to the already bound key.

### Preventing Server Key Substitution

If signature verification is moved outside the private circuit, the server must
not be able to substitute a public key that it controls. The public key accepted
by the verifier must be cryptographically tied to enrollment state. The
presentation must prove that the selected credential is bound to the same
authorization public key whose request signature was externally verified.

Possible approaches:

- Include a commitment to the authorization public key in enrollment state.
- Prove in the presentation that the selected credential opens to that committed
  key.
- Bind the externally verified key to the same enrollment-state digest or
  accumulator element checked by the presentation.

OPEN: the exact commitment, accumulator, or proof-carrying state format is not
defined.

OPEN: the design must prevent a server from mixing a valid external signature
under one key with a different credential selected inside the presentation.

### Enrollment Proof Requirements

An enrollment proof would need to prove at least:

- issuer validity for the credential
- ownership or authorization binding between the credential and the holder
  authorization public key
- correctness of any credential commitment included in enrollment state
- consistency between the public-key commitment and later presentation state
- optional revocation or freshness material, if the final system needs it

OPEN: revocation is not included in the current measured components.

OPEN: issuer validity and credential-holder binding are not yet implemented.

### Verifier-Visible Identifiers and Linkability

If the verifier sees the same authorization public key on multiple
presentations, that public key becomes a long-term linkable identifier.

Possible mitigations:

- Use per-credential authorization keys, if credential reuse linkability is
  acceptable only within a credential scope.
- Use randomized or derived presentation keys certified by enrollment state.
- Use an unlinkable credential-binding proof that exposes only a one-time
  authorization key or a request-scoped pseudonym.

OPEN: the current experiments do not define an unlinkable public-key binding
mechanism.

OPEN: external signature verification may conflict with public verifiability if
the verifier cannot check that the signing key is credential-bound without
learning a stable identifier.

### Phone-Side Private Nonlinear Cost Reduction

Moving in-circuit holder authorization out of the private nonlinear phase could
remove most of the measured private nonlinear work:

- removable candidate: 4504 holder-authorization constraints
- remaining measured private nonlinear work: 97 age-predicate constraints
- measured Credential-Key Binding baseline: 321 nonlinear constraints
- projected Candidate A private nonlinear work:
  `321 + 97 = 418`
- projected ratio against the current online presentation size:
  `418 / 4987 = 8.38%`
- projected reduction relative to in-circuit holder authorization:
  `4504 - 321 = 4183` constraints

This is a measured linkable baseline for the credential-key binding component,
but the final Candidate A private cost is still a projected estimate. Issuer
authentication of the enrollment record and unlinkability are not implemented.

OPEN: the replacement binding proof could add nontrivial private nonlinear
constraints.

OPEN: unlinkability may require additional cryptographic machinery that changes
the cost model.

### Measured Linkable Baseline

The first implemented Candidate A baseline is:

```text
External signature verification + authenticated enrollment key binding
```

The credential-key binding circuit computes:

```text
enrollment_digest = Poseidon(
  credential_commitment,
  holder_public_key_x,
  holder_public_key_y,
  issuer_id,
  schema_id
)
```

and constrains it to equal the public `expected_enrollment_digest`.

Measured values:

| Metric | Value |
| --- | ---: |
| Binding total constraints | 321 |
| Binding nonlinear constraints | 321 |
| Public inputs | 3 |
| Private inputs | 3 |
| Witness elements | 327 |
| Witness generation mean | 62.6 ms |
| Groth16 proving mean | 1537.2 ms |
| Verification mean | 1140.0 ms |
| External signature verification mean, cold-process | 3900.2 ms |

Binding tests:

- valid key and enrollment record succeeded
- modified holder public key with the old digest failed
- modified private enrollment record with the old digest failed

External signature tests:

- correct holder signature over the request digest verified successfully
- old signature failed after modifying the request digest
- wrong signature failed

The 3900.2 ms external signature verification result is a cold-process
measurement. It starts a new Node process and includes module loading and
cryptographic initialization.

The persistent one-process benchmark separates initialization from steady-state
request work:

| Metric | Value |
| --- | ---: |
| Process startup and library init | 4536.466 ms |
| Key derivation | 10.392 ms |
| RSS after initialization | 172.867 MB |
| Poseidon request digest mean | 0.109 ms |
| EdDSA-Poseidon signing mean | 14.797 ms |
| EdDSA-Poseidon verification mean | 14.700 ms |

The old roughly 3.9 second signing and verification numbers mainly reflect
cold process startup, module loading, and one-time cryptographic initialization,
not steady-state per-request EdDSA-Poseidon work.

Security assumptions and limitations:

- `expected_enrollment_digest` is assumed to be authenticated by an issuer,
  registry, or prior enrollment proof.
- Without authenticated enrollment records, a server can register its own public
  key.
- The public long-term holder public key is linkable.
- This is a linkable baseline, not the final Candidate A design.

### Measured Candidate A Online Composition

The implemented Candidate A online circuit composes:

- age predicate
- request binding
- disclosure control
- credential-key binding

It does not include an EdDSA verification gadget. Holder request signing and
external signature verification are host-side steps and are benchmarked
separately from SNARK proving.

Measured circuit values:

| Metric | Value |
| --- | ---: |
| Total constraints `N_candidate_a` | 804 |
| Nonlinear constraints | 803 |
| Linear constraints | 1 |
| Public inputs | 13 |
| Private inputs | 4 |
| Witness elements | 798 |
| Age private nonlinear constraints | 97 |
| Credential-key-binding nonlinear constraints | 321 |
| `m_candidate_a` | 418 |

The three ratios are:

| Ratio | Formula | Value |
| --- | --- | ---: |
| Old private reduction | `(4601 - 418) / 4601` | 90.92% |
| Candidate A private fraction | `418 / 804` | 51.99% |
| Candidate A vs old total | `418 / 4987` | 8.38% |

`candidate_a_vs_old_total` is only a comparison against the old online
presentation size. It is not the private fraction of the new Candidate A
circuit.

Measured phase means:

| Stage | Mean ms | Mean peak RSS MB |
| --- | ---: | ---: |
| Holder signing, cold-process | 3898.4 | 202.823 |
| External signature verification, cold-process | 3882.8 | 197.645 |
| Witness generation | 78.0 | 54.039 |
| Groth16 proving | 1575.6 | 252.642 |
| Proof verification | 1128.8 | 204.624 |

Steady-state external authentication should use the persistent one-process
numbers:

| Operation | Mean ms | p95 ms |
| --- | ---: | ---: |
| Poseidon request digest | 0.109 | 0.123 |
| EdDSA-Poseidon signing | 14.797 | 15.229 |
| EdDSA-Poseidon verification | 14.700 | 15.119 |

Test results:

- valid presentation succeeded
- invalid nonce failed in the circuit and old external signature verification
  failed against the modified request digest
- invalid disclosure failed
- invalid holder key failed
- invalid enrollment record failed
- invalid external signature failed host-side and did not continue to proving

Remaining limitations:

- External signature verification is not a SNARK constraint.
- The current long-term holder public key is public, so presentations are
  linkable.
- `expected_enrollment_digest` authenticity still depends on external
  authentication.
- Candidate A does not implement server-only proving transition.
- Candidate A does not prove that the phone avoids witness-sized state.

## Candidate B: Enrollment-Compiled Holder Authorization

### Flow

1. During enrollment, prove issuer validity and holder-key binding.
2. During presentation, use request-specific authorization.
3. Avoid repeating full EdDSA verification inside every private 2PC execution.

### Checks That Can Move to Enrollment

The following checks are plausible enrollment-time candidates:

- issuer signature verification
- credential schema validity
- holder-key binding to the credential
- credential commitment construction
- static credential attributes or commitments
- public-key well-formedness, if the authorization key is stable or
  enrollment-certified

OPEN: none of these enrollment checks are implemented in the current online
presentation experiment.

### Request-Dependent Checks That Cannot Move Directly

The following checks depend on the current request and cannot simply be
precomputed once:

- nonce binding
- verifier domain binding
- policy binding
- requested disclosure binding
- expiry binding
- holder approval of the current disclosure set
- non-reuse or freshness of the authorization material

If the final system still requires a fresh holder authorization for every
request, something request-specific must remain online.

### Binding Request Fields and Disclosure

Presentation-time authorization must still bind:

- request digest
- nonce
- verifier domain
- policy
- requested disclosure mask
- holder-approved disclosure mask
- actual disclosure mask or its approved equivalent
- expiry
- protocol context

This can be done with an online signature, a request-scoped proof, a token, or
an enrollment-derived state update. The current circuit uses an in-circuit
BabyJubJub EdDSA-Poseidon signature, which is the dominant measured cost.

### Recursive Proof, Proof-Carrying State, or Accumulator

Enrollment-compiled authorization likely needs one of the following:

- a recursive proof that the enrollment proof established holder-key binding
  and that the presentation proof consumes that state correctly
- proof-carrying state that lets the server continue from an enrollment-certified
  credential/key relation
- an accumulator or commitment scheme that binds credential validity and holder
  key material without exposing a stable identifier

OPEN: ordinary Groth16 alone does not define a reusable private state transition
between enrollment and presentation.

OPEN: the state format must prevent replay and cross-request reuse.

OPEN: the design must specify whether the verifier checks one proof, multiple
proofs, or a recursively composed proof.

### Server Reuse of Enrollment State

The server may be able to reuse enrollment state only if that state is:

- bound to a valid credential and holder authorization relation
- unlinkable or explicitly scoped to acceptable linkability
- non-malleable by the server
- refreshed, consumed, or request-bound so stale state cannot authorize a new
  request without holder participation

OPEN: server reuse is unsafe unless request freshness and holder gating are
defined.

## Candidate C: Lightweight Request Activation Token

This candidate replaces in-circuit public signature verification with a lighter
online activation mechanism such as a MAC, PRF, OPRF, or two-party activation
token.

### Key Ownership

Possible ownership models:

- phone-only key: the phone derives or signs an activation token
- server-assisted key: phone and server hold shares for a two-party activation
  token
- issuer/enrollment-derived key: enrollment produces credential-scoped token
  material
- verifier-assisted key: the verifier participates in token derivation or
  validation

OPEN: key ownership determines both unlinkability and whether the server can
forge authorization.

### Verifier Verification

A MAC or PRF token is usually not publicly verifiable unless the verifier knows
the key or trusts another party to validate it. That weakens the public
verifiability expected from a credential presentation.

An OPRF or two-party activation token may hide the key better, but the verifier
still needs a way to check that the token is credential-bound and request-bound.

OPEN: the design must specify whether the verifier verifies the token directly,
verifies a proof about the token, or trusts server-side validation.

### Server Forgery Resistance

The server must not be able to create a fresh activation token for a request
without holder participation. This requires at least one of:

- a phone-held secret not known to the server
- a threshold protocol where the server share alone is insufficient
- a one-time or request-specific state update that the server cannot predict
- enrollment-certified token material that cannot be malleated into a new
  authorization

OPEN: if the server can compute the token alone, holder gating is lost.

### Cross-Device Recovery

If the activation key is phone-only, recovery requires key backup, rotation, or
re-enrollment. If the key is derived from a credential secret, recovery may
interact with credential portability and revocation.

OPEN: cross-device recovery is not addressed by the current experiments.

### Publicly Verifiable Presentation

A lightweight token may reduce online nonlinear constraints, but it may also
move the system away from a publicly verifiable credential presentation if the
verifier cannot independently validate holder authorization.

OPEN: a token-based design must define what the verifier can check without
trusting the server.

### Constraint Reduction Compared With Signature Verification

Compared with the measured in-circuit BabyJubJub EdDSA-Poseidon verifier, a
lighter activation token could avoid the 4504 holder-authorization constraints
if it no longer requires public signature verification inside the private
nonlinear phase.

This does not mean the final system saves exactly 4504 constraints. Replacement
logic for token verification, key binding, freshness, and unlinkability has not
been implemented or measured.

OPEN: the replacement token may require new constraints or protocol rounds that
offset part of the savings.

## Boundary Interface

The desired future boundary can be described as:

```text
Prepare_H,S(holder_state, server_state, request)
-> Sigma_R

ServerProve(server_state, request, Sigma_R)
-> proof
```

`Sigma_R` is the request-specific handoff material from the holder/server
preparation phase to the server-only proving phase.

### Requirements for `Sigma_R`

`Sigma_R` must provide:

- witness hiding
- request binding
- holder gating
- credential-selection integrity
- disclosure integrity
- non-reusability across requests
- server-only continuation
- no witness-sized phone work

These requirements are not satisfied by the current online presentation
experiment. The current experiment measures the cost of a monolithic online
circuit and does not implement server-only continuation.

## Server-Completable State Candidates

### 1. Masked Witness

A masked witness gives the server enough encoded witness material to continue
proving without learning the private witness.

Ordinary Groth16:

- cannot directly consume an externally masked witness as a normal witness
  without additional protocol machinery
- expects the prover to know the witness values used in the arithmetic circuit
- does not provide server-only continuation from masked witness state by itself

Server-independent linear operations:

- additions of masked values
- multiplication by public constants
- linear recombinations if masks are tracked consistently

Nonlinear operations still needing 2PC:

- private-private multiplication
- nonlinear hash or signature checks over private values
- range checks and bit decompositions over private values
- boolean constraints involving private bits

Phone state:

- likely O(N) if the phone must mask or authenticate every witness element
- violates the goal of no witness-sized phone work unless compressed or
  function-dependent material is used

Largest OPEN problem:

- defining a Groth16-compatible way for the server to finish proving from masked
  witness material without learning the witness and without requiring O(N)
  phone work.

### 2. Authenticated Shared Multiplication Outputs

This state gives the server authenticated results for multiplication gates or
nonlinear operations that involved holder-private values.

Ordinary Groth16:

- cannot directly verify authenticated multiplication transcripts unless the
  circuit or proving system is extended to consume them
- still expects one prover to provide a consistent witness for all wires

Server-independent linear operations:

- public linear combinations
- addition of authenticated shares when the authentication scheme supports it
- propagation of public constants and public request fields

Nonlinear operations still needing 2PC:

- every private-dependent multiplication not already materialized in
  authenticated state
- consistency checks proving multiplication outputs match hidden inputs
- nonlinear operations introduced by authentication verification itself

Phone state:

- may still be O(m), where `m` is the number of private nonlinear operations
- for the current online circuit, `m = 4601`, so this is still large unless
  holder authorization is moved out or compiled away

Largest OPEN problem:

- reducing phone work below O(m) while preserving soundness of private
  multiplication outputs used in the final proof.

### 3. Commitments Plus Function-Dependent Correction Material

This state commits to private witness or credential material and gives the
server correction material tailored to the function and request.

Ordinary Groth16:

- can verify commitments only if commitment openings or commitment consistency
  checks are represented inside the circuit
- does not automatically let the server derive missing private witness values
  from commitments
- may need a custom preprocessing, recursive proof, or proof-carrying state
  layer

Server-independent linear operations:

- linear combinations of committed or masked values when the commitment scheme
  is homomorphic
- public request hashing and public mask checks
- public parts of proof preparation

Nonlinear operations still needing 2PC:

- private credential predicates unless precomputed correction material covers
  them
- private key binding checks
- any request-dependent private hash, signature, or comparison not moved to a
  different boundary

Phone state:

- could be sublinear in `N` if correction material is compact and
  function-dependent
- may become O(function complexity) or O(m) if every private nonlinear gate
  needs its own correction

Largest OPEN problem:

- constructing correction material that is compact, request-bound,
  witness-hiding, and compatible with public verification.

## Recommended Next Technical Task

Determine whether holder authorization can be moved outside the private
nonlinear phase while preserving credential-key binding, request binding, and
unlinkability.
