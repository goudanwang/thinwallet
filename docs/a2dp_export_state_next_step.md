# A2DP Export State Next Step

This document selects the next export-state direction based on:

- `docs/a2dp_authenticated_enrollment_state.md`
- `docs/a2dp_export_state_candidates.md`

It does not implement a complete protocol and does not claim that any candidate
is secure.

## Scoring Method

Scores are from 1 to 5.

For these criteria, higher is better:

- novelty
- malicious-server security potential
- phone online asymmetry
- public verifiability
- implementation feasibility
- compatibility with current Circom measurements

For `risk of hidden O(N) phone work`, higher is worse:

- 1 means low risk
- 5 means high risk

## Candidate Scores

| Criterion | C1: Commitment export | C2: Multilinear/sumcheck export | C3: Proof-carrying enrollment |
| --- | ---: | ---: | ---: |
| Novelty | 3 | 5 | 3 |
| Malicious-server security potential | 3 | 4 | 4 |
| Phone online asymmetry | 2 | 5 | 3 |
| Public verifiability | 3 | 3 | 4 |
| Implementation feasibility | 3 | 1 | 4 |
| Compatibility with current Circom measurements | 3 | 1 | 3 |
| Risk of hidden O(N) phone work | 5 | 4 | 2 |

## Selection

Primary candidate: **C2: Multilinear/sumcheck export**.

Reason: it is the only candidate that directly targets the desired shape of
server-only continuation. The holder/server interaction can finish the private
nonlinear layer, and the server can then attempt to continue with sumcheck,
polynomial commitments, and proof assembly.

Fallback candidate: **C3: Proof-carrying enrollment state**.

Reason: it is the easiest path to prototype with the current measurement style.
It can test whether per-presentation credential-key binding can be moved into
an enrollment proof or accumulator reference, even though it does not by itself
solve request-time server-only continuation.

Candidate 1 remains useful as a subcomponent, but by itself it risks becoming a
commitment wrapper that still requires the phone to touch O(N) shares or leaves
ordinary Groth16 without the concrete witness it expects.

## Minimal Toy Construction

The toy construction must answer only this question:

```text
Can two parties transform a small authenticated private computation
output into a commitment or polynomial state that the server can use
to complete a publicly verifiable proof without learning the secret?
```

It must not include full credentials, signature verification, revocation, or
Android.

### Secret Input

Use one small private value:

```text
x
```

The toy predicate is:

```text
y = x^2 + request_challenge
```

`request_challenge` is public and request-bound. `x` remains hidden.

The toy public statement is:

```text
There exists a hidden x, bound to authenticated state, such that
y = x^2 + request_challenge
and the exported state was authorized for this request.
```

### Phone State

The phone holds:

```text
phone_state = (
    x_H,
    mac_key_or_pcg_seed_H,
    authenticated_root,
    activation_secret
)
```

Where:

- `x_H` is the phone share of `x`.
- `mac_key_or_pcg_seed_H` authenticates request-time shares or corrections.
- `authenticated_root` anchors the persistent toy enrollment record.
- `activation_secret` gates this request.

The design target is to avoid requiring the phone to touch every witness wire;
whether this can be achieved remains open.

### Server State

The server holds:

```text
server_state = (
    x_S,
    authenticated_share_tags,
    enrollment_record,
    preprocessing_state
)
```

Where:

- `x_S` is the server share of `x`.
- `authenticated_share_tags` bind shares to the toy enrollment record and
  session.
- `enrollment_record` contains a toy state identifier and commitment/root data.
- `preprocessing_state` is any prover-side data needed after export.

### Two-Party Computation

The phone and server jointly compute only the private nonlinear layer:

```text
x = x_H + x_S
z = x^2
y = z + request_challenge
```

The two-party phase must authenticate:

- selected enrollment record
- current request
- multiplication output `z`
- output `y`
- session identifier

OPEN: the exact MAC, PCG, or authenticated multiplication protocol is not fixed
in this document.

### Sigma_R Fields

The toy `Sigma_R` is:

```text
Sigma_R = (
    request_id,
    enrollment_state_id,
    public_request_challenge,
    public_y,
    commitment_to_hidden_x_or_poly_state,
    commitment_to_z_or_poly_state,
    server_opening_or_masked_evaluation_material,
    holder_activation_tag,
    transcript_digest,
    export_soundness_metadata
)
```

Field meanings:

- `request_id`: prevents cross-request reuse.
- `enrollment_state_id`: binds the export to the selected authenticated state.
- `public_request_challenge`: public request value used in the toy predicate.
- `public_y`: output of the toy private computation.
- `commitment_to_hidden_x_or_poly_state`: hides `x` while binding the server to
  the exported state.
- `commitment_to_z_or_poly_state`: binds the multiplication output.
- `server_opening_or_masked_evaluation_material`: lets the server continue
  proving without learning `x`.
- `holder_activation_tag`: proves current phone participation to the two-party
  protocol.
- `transcript_digest`: binds the export transcript.
- `export_soundness_metadata`: any public or proof-carrying material needed to
  make verifier checks sound.

OPEN: the most important unknown is whether
`server_opening_or_masked_evaluation_material` can be compact and still
publicly sound.

### Server Continuation

After receiving `Sigma_R`, the server attempts to compute:

```text
proof = ServerProve(server_state, request, Sigma_R)
```

The server may:

- derive the multilinear polynomial state for the toy computation
- run sumcheck or a small polynomial-check protocol
- commit to the exported polynomial state
- assemble a public proof that checks the relation for `y`

The server must not learn `x`.

OPEN: ordinary Groth16 is not expected to directly support this handoff. The
toy may require a small custom IOP or polynomial commitment proof.

### Verifier Checks

The verifier checks:

```text
Verify(
    request_id,
    enrollment_state_id,
    public_request_challenge,
    public_y,
    proof
) -> accept/reject
```

Verifier requirements:

- `proof` is bound to `request_id`.
- `proof` is bound to `enrollment_state_id`.
- `public_y` satisfies the committed polynomial relation.
- The exported state is not reusable for a different request.
- The proof does not reveal `x`.

OPEN: public verification must not rely on the verifier knowing internal MAC
keys.

### Unsupported Security Properties

The toy does not support:

- credential semantics
- issuer signatures
- holder signature verification
- revocation
- unlinkability
- Android execution
- production randomness
- full malicious-security proof
- complete A2DP server-only proving transition

### GO/NO-GO Metric

Unique GO/NO-GO metric:

```text
GO only if the server can produce a publicly verifiable proof after the
two-party export, without learning x, and the phone's online work is
strictly smaller than touching every witness/polynomial entry in the toy
relation.
```

NO-GO if any of the following occurs:

- public verification requires revealing an internal MAC key
- the server cannot continue proving without another phone round
- the server must learn `x`
- the phone must process every witness or polynomial entry
- the proof is not bound to `request_id` and `enrollment_state_id`

## Next Work Item

Prototype the toy only at the protocol-state level first:

1. Specify `Sigma_R` precisely for the toy relation.
2. Decide whether the exported state is a commitment state, multilinear
   polynomial state, or proof-carrying digest.
3. Check whether the verifier can reject substitution, replay, and forged
   export metadata without knowing internal MAC keys.
4. Measure phone work against the toy relation size.
