# A2DP Authenticated Enrollment State

This document designs protocol state and security boundaries for a future A2DP
direction. It does not implement a new circuit and does not claim that A2DP is
complete.

## Current Measurements

Measured baseline values:

```text
Old online presentation:
N_old = 4987
m_old = 4601

Candidate A:
N_candidate_a = 804
m_candidate_a = 418
private nonlinear reduction = 90.92%
```

Interpretation:

- `418 / 804 = 51.99%` is the current Candidate A private fraction.
- `418 / 4987 = 8.38%` is only a comparison against the old total circuit size.
  It is not the private fraction of the Candidate A circuit.
- Candidate A still does not implement a server-only proving transition.

## Enrollment Record

Define an abstract enrollment record:

```text
E_C = (
    credential_commitment,
    holder_authorization_key,
    issuer_policy,
    schema_policy,
    credential_version,
    revocation_handle,
    state_identifier
)
```

The verifier does not specify a concrete credential. The wallet privately
chooses an enrollment record that satisfies the verifier policy.

The record is not itself sufficient unless its authenticity and freshness are
defined by the protocol state. In particular, the server must not be able to
replace `holder_authorization_key`, substitute a different credential, or roll
back `credential_version`.

## Party State

The phone should keep only compact long-term state, for example:

```text
phone_state = (
    holder_secret_key,
    credential_share_seed,
    authenticated_record_root,
    latest_version,
    rollback_counter
)
```

The server stores larger state:

```text
server_state = (
    server credential shares,
    enrollment records,
    authentication tags,
    proving/preprocessing state
)
```

The design must not assume that the phone stores a full witness, a
witness-sized MAC vector, or any other O(N) per-circuit proving state.

## Core State Invariants

The future state protocol must maintain these invariants:

1. The server cannot replace the holder key in an enrollment record with a key
   it controls.
2. The server cannot replace the credential selected by the holder.
3. The server cannot roll back to an old credential version.
4. The server cannot mix shares from different credentials or sessions.
5. Without current phone participation, the server cannot activate a new
   presentation.
6. Presentation state must bind the current request.
7. Phone state must be O(lambda) or credential-size, not witness-size.

## State Authentication Schemes

### A. Phone-Held Merkle/Root Anchor

The phone stores an authenticated root over enrollment records. The server
provides the selected record and an inclusion proof. The phone checks the
record against its root before authorizing a request.

Key substitution:

- Prevented if `holder_authorization_key` is inside the committed record and the
  phone accepts only records under its authenticated root.
- The server cannot swap in its own key without breaking the inclusion proof.

Credential-selection integrity:

- The holder can privately choose which record under the root to activate.
- The server must prove or provide inclusion for the holder-selected record.
- The request authorization must bind the selected record or its
  `state_identifier`.

Rollback protection:

- Requires the phone to track `latest_version` or a monotonic rollback counter.
- A root alone does not prevent rollback unless the accepted root/version is
  fresh or monotonic.

Phone storage:

- Compact: root, version, holder secret, and small rollback metadata.
- Does not require witness-sized phone storage.

Phone online computation:

- Verify an inclusion path and freshness/version metadata.
- Sign or activate the request-bound selected record.
- Work is credential-size or logarithmic in the record set, not circuit-witness
  sized.

Public holder key:

- If the record exposes a stable `holder_authorization_key`, presentations are
  linkable.
- Per-verifier or one-time keys could reduce linkability, but that is not
  implemented.

Need to recompute 321-constraint binding:

- Still needed in ordinary Groth16 unless the authenticated root check is
  soundly connected to the proving state.
- The circuit currently recomputes the enrollment digest to bind the holder key
  to private record material.

Server-only proving transition:

- This scheme can provide a compact anchor for a later server-completable state.
- OPEN: how the root-checked record becomes a request-bound proving state that
  ordinary verification accepts without rechecking the full binding circuit.

### B. Authenticated Secret Shares

Credential shares, holder-key binding, and version state carry distributed MACs
or similar authentication. The phone stores short MAC keys or PCG seeds rather
than all authentication tags.

Key substitution:

- Prevented if the holder key and credential shares are MAC-authenticated under
  keys unknown to the server alone.
- The server cannot forge a different key binding without valid authentication
  material.

Credential-selection integrity:

- Strong if each credential/session has domain-separated authenticated shares.
- The holder activation must select one credential namespace and bind the
  request to that namespace.

Rollback protection:

- Requires authenticated version counters or freshness state.
- The phone must reject old counters or stale state identifiers.

Phone storage:

- Potentially compact: holder secret, MAC/PCG seed, latest version, rollback
  counter.
- Does not require witness-sized MAC vectors if tags can be derived or checked
  from short seeds.

Phone online computation:

- Authenticate or derive request-specific checks for selected state.
- Potentially O(lambda) plus credential metadata if the server can complete
  proving from authenticated shares.
- The design target is to avoid requiring the phone to touch every witness wire;
  whether this can be achieved remains open.

Public holder key:

- Not inherently required as a stable public input.
- The holder key could be authenticated inside shares or exposed depending on
  the chosen presentation interface.

Linkability:

- Potentially better than a public stable key if activation uses
  request-scoped authenticated material.
- Linkability depends on whether public state identifiers or authorization keys
  repeat across presentations.

Need to recompute 321-constraint binding:

- Potentially avoidable only if the authenticated share protocol gives a sound
  path from authenticated enrollment state to server-completable proving state.
- Until then, ordinary Groth16 still needs an in-circuit check or equivalent
  proof that the public key and private credential material are bound.

Server-only proving transition:

- This is the most natural fit for server-completable proving because it can
  authenticate hidden intermediate values and prevent mixing across sessions.
- OPEN: constructing compact, request-bound authenticated state that the final
  proof can consume soundly.

### C. Issuer-Signed Enrollment Record

The issuer signs the enrollment record. Presentation uses the signed record as
authenticated input.

Key substitution:

- Prevented if the issuer signature covers `holder_authorization_key`,
  `credential_commitment`, policy fields, version, revocation handle, and state
  identifier.
- The server cannot replace the key without invalidating the issuer signature.

Credential-selection integrity:

- The holder can choose among issuer-signed records.
- The request authorization must bind the selected signed record or its digest.

Rollback protection:

- Not solved by a static issuer signature alone.
- Requires revocation status, version freshness, or phone-maintained monotonic
  state.

Phone storage:

- Compact if the phone stores selected record identifiers, holder key material,
  and latest version metadata.
- The server can store full signed records.

Phone online computation:

- Verify or rely on issuer signatures, check version/freshness, and authorize
  the request.
- If issuer signature verification must be proven to the verifier inside the
  presentation circuit, the circuit may become expensive again.

Public holder key:

- Likely public if the verifier checks the issuer-signed record directly.
- This creates linkability unless keys are one-time, per-verifier, or hidden by
  an unlinkable proof.

Linkability:

- High for stable signed holder keys.
- Lower only with randomized enrollment records, one-time certified keys, or
  unlinkable credential systems, none of which are currently implemented.

Need to recompute 321-constraint binding:

- If the issuer signature is verified outside the circuit and trusted by the
  verifier, the 321-constraint binding might move out of the presentation
  circuit.
- If public verifiability requires a SNARK proof that the signed record matches
  the private credential material, some in-circuit binding or equivalent proof
  remains necessary.

Server-only proving transition:

- Signed records authenticate enrollment but do not by themselves create
  server-completable proving state.
- OPEN: how a signed record transitions into hidden, request-bound proving
  material without leaking a stable key. The design target is to avoid requiring
  the phone to touch every witness wire; whether this can be achieved remains
  open.

## Public Verifiability Gap

Distributed MACs and authenticated shares are useful inside a two-party
protocol, but they do not by themselves give the verifier a public check.

The verifier does not know the MAC key, so it cannot directly verify that the
server's authenticated shares were honestly derived from the holder-selected
enrollment record. The phone and server can check MACs internally, but after
the phone exits the online phase the server must hold some request-bound
handoff material `Sigma_R` that lets it continue proving.

The final public SNARK proof must remain soundly bound to the authenticated
enrollment state. Otherwise, the server could pass internal MAC checks in one
context while producing a proof about a different credential record, holder key,
or request. Directly revealing the MAC key is not an option, because that would
let the server forge future authenticated shares.

Therefore a new authenticated-share-to-proof-state transformation is required:

```text
authenticated enrollment state
    ->
request-bound Sigma_R
    ->
server-completable proving state
    ->
publicly verifiable proof
```

This transformation is not implemented. It must preserve witness hiding,
request binding, holder gating, credential-selection integrity, disclosure
integrity, and non-reusability without giving the server enough information to
forge later activations.

## Why the 321 Constraints Cannot Simply Be Deleted

The current ordinary Groth16 Candidate A circuit proves key binding by
recomputing the enrollment digest:

```text
enrollment_digest = Poseidon(
  credential_commitment,
  holder_public_key_x,
  holder_public_key_y,
  issuer_id,
  schema_id
)
```

This costs 321 nonlinear constraints and ties the public holder key to private
enrollment material inside the proof.

Those constraints can only move out of each presentation if a new A2DP
state-transition protocol soundly guarantees:

```text
authenticated enrollment state
    ->
server-completable proving state
```

and the final proof remains soundly bound to that authenticated state.

Otherwise, deleting the key-binding circuit creates a soundness gap: the server
could present a request signature under one key while proving about different
private credential material, or could substitute a record not chosen by the
holder.

## Optimistic Lower Bound

Only as an optimistic bound:

```text
If per-presentation key binding is safely compiled into enrollment:

N_optimistic ~= 804 - 321 = 483
m_optimistic ~= 97
m_optimistic / N_optimistic ~= 20.08%
```

This is not a measured result.

It does not include:

- authenticated-state checking
- issuer validity
- revocation
- server-only proving transition

It also does not prove that phone work is sublinear or that phone state avoids
witness-sized material.

## Preferred Enrollment-State Direction

Preferred architecture: **Hybrid A+B**.

```text
Hybrid A+B:
- phone-held authenticated root for persistent enrollment records;
- authenticated secret shares for request-time private computation.
```

Division of responsibility:

- The phone-held authenticated root protects persistent credential records,
  holder-key binding, credential version, and rollback state.
- Authenticated secret shares protect 2PC intermediate values, prevent mixing
  different credential/session state, and detect malicious server deviation in
  request-time private computation.
- A holder signature or request activation token gates the current request and
  binds the holder's participation to the request being presented.

Rationale against the stated goals:

- Single malicious server: the root prevents persistent record substitution,
  while authenticated shares protect request-time hidden computation against
  mixing and malicious deviation.
- Compact phone state: the phone can plausibly store holder secret material, an
  authenticated root, MAC or PCG seeds, latest version, and rollback counters
  rather than full witness state.
- No witness-sized phone work: the design target is to avoid requiring the
  phone to touch every witness wire; whether this can be achieved remains open.
- Holder-private credential choice: domain-separated credential/share
  namespaces under a phone-held root can support holder selection without
  verifier-specified credential IDs.
- Substitution and rollback resistance: the root anchors holder-key binding and
  version state, while monotonic counters prevent stale replay if implemented
  correctly.
- Compatibility with server-only proving state: authenticated shares are still
  needed for hidden intermediate values, but the persistent record root gives a
  compact anchor for enrollment-state authenticity.

This preference is not a proof of security. The core unresolved question is how
the root-anchored record and authenticated-share state are consumed by a
publicly verifiable proof. The design target is to avoid requiring the phone to
touch every witness wire; whether this can be achieved remains open.

## Next Question

```text
How can an authenticated enrollment record be transformed into a
request-bound server-completable proving state without rechecking the
full credential-key binding inside every presentation circuit?
```
