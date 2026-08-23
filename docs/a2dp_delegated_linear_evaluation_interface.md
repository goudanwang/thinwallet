# Delegated Committed Linear-Evaluation Interface

This note defines the open interface suggested by the C2 export-state toy
experiments. It is a research question, not a proposed secure primitive and
not a claim of novelty.

## Open Question

```text
Can we construct a request-bound delegated committed linear-evaluation
mechanism that allows a server holding only authenticated preprocessing
state to produce publicly verifiable commitments to adaptively selected
linear functions of a hidden vector, without learning the vector or the
function outputs?
```

## Minimal Interface

```text
StateCommit(
    authenticated_state
) -> (
    public_state_commitment C_state,
    server_evaluation_state st_S,
    compact_phone_state st_H
)

Activate(
    st_H,
    request_id,
    enrollment_state_id
) -> activation_capability tau_R

EvalCommittedLinear(
    st_S,
    tau_R,
    transcript_prefix,
    linear_function ell
) -> (
    value_commitment C_v,
    evaluation_proof pi_v
)

VerifyCommittedLinear(
    C_state,
    request_id,
    enrollment_state_id,
    transcript_prefix,
    ell,
    C_v,
    pi_v
) -> {0,1}
```

The interface must not output plaintext:

```text
v = <ell, w>
```

It should output only `C_v` and a public verification proof.

## Target Properties

The target properties are:

- adaptive evaluation: `ell` may depend on prior transcript commitments;
- public verifiability;
- server does not learn the hidden state `w`;
- server does not learn plaintext function outputs `<ell,w>`;
- the phone exits after `Activate`;
- phone online work is `O(polylog N)`;
- phone persistent state is `O(polylog N)` or credential-size;
- server preprocessing may be `O(N)`;
- per-request `Sigma_R` or `tau_R` is `O(polylog N)`;
- request binding;
- enrollment-state binding;
- no state or session mixing;
- verifier does not read `O(N)` commitments;
- repeated committed evaluations do not create plaintext linear observations.

## Not Direct Homomorphic Commitment Use

Plain homomorphic commitments are enough for linear algebra only when the
server already has the required committed basis elements.

For a scalar toy, `C_z` is sufficient because every needed hidden value is a
public linear function of the same scalar `z`.

For a vector state, the server must answer adaptive queries:

```text
C_v = Commit(<ell,w>, r_ell)
```

from a compact public anchor. A plain commitment does not automatically provide
a public proof that `C_v` was derived from the authenticated vector state.

## Delegated PCS Opening

A standard polynomial commitment can make verifier work succinct if the prover
can produce openings. However, with only:

```text
C_f = PCS.Commit(f)
```

the server generally cannot compute:

```text
v = f(r)
opening_proof
```

after an adaptive challenge `r`, unless it has the polynomial table,
coefficients, or some delegated proving state.

Therefore the open direction is not ordinary commitment-only PCS. It would
need a delegated opening capability that preserves hiding and is bound to the
authenticated enrollment state.

## Function-Specific Preprocessing

Function-specific preprocessing may help if the query family is known before
export. The obstacle is that Sumcheck queries are adaptive:

```text
ell_j = ell_j(C_alpha_1, C_beta_1, r_1, ..., r_{j-1})
```

where the Fiat-Shamir challenges depend on prior committed messages.

Fixed tokens generated before the transcript begins are insufficient unless
they cover the adaptive query family compactly. The earlier toy experiments
showed that naive fixed correction material tends to become `Omega(N)`.

## Possible Need for a New Evaluation Mechanism

The desired object may require a commitment/evaluation mechanism with all of:

- compact authenticated state commitment;
- hidden vector state;
- adaptive committed linear evaluation;
- public proof of correct evaluation;
- server-only proof generation from preprocessing state;
- request-bound activation.

This document does not name this as a new primitive or claim that such a
mechanism exists. It records the exact interface needed by the C2 direction.

## Co-Design With Sumcheck

The scalar experiment changed the Sumcheck transcript from field-valued
messages to commitment-valued messages:

```text
(alpha_j, beta_j)
```

became:

```text
(C_alpha_j, C_beta_j)
```

The Fiat-Shamir challenge was derived from commitment serializations, and the
verifier checked group equations.

A vector version likely must be co-designed with the transcript. It is not
enough to bolt a vector commitment onto a standard field-valued Sumcheck if the
server cannot produce adaptive committed evaluations with public binding.

## Minimum V4 Requirement

The minimum useful V4 candidate must provide:

```text
request-bound activation
compact public authenticated state anchor
adaptive committed linear evaluation
server-only evaluation proof generation
no plaintext witness or evaluation outputs
O(polylog N) phone online work
O(polylog N) per-request export material
sublinear verifier work
```

Until such an interface is instantiated, general vector-state C2 remains
`OPEN`, even though the scalar commitment-valued Sumcheck toy is `GO`.
