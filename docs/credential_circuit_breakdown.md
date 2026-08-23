# Credential Circuit Breakdown

This document records component-level measurements for credential-related
circuits. Results here are not full credential presentation costs unless the
included components explicitly say so.

## Age Predicate

### Security Semantics

The age predicate proves that a private `birth_day_index` is less than or equal
to a public `cutoff_day_index`.

`cutoff_day_index` is request-dependent: it represents the latest birth date,
expressed as an integer day index from a shared epoch, for a holder who is old
enough under the verifier's current request policy. The verifier learns the
cutoff and the predicate result, but not the holder's birth day index.

This circuit does not validate calendar dates. It assumes legal date handling
and date-to-day-index conversion were already enforced by issuer/enrollment
logic. Those parts are excluded from this component result.

### Inputs

| Input | Visibility | Meaning |
| --- | --- | --- |
| `birth_day_index` | Private | Holder birth date as an integer day index. |
| `cutoff_day_index` | Public | Request-specific cutoff day index for the age policy. |

The circuit has one public output, `is_old_enough`, and constrains it to equal
`1`. It does not expose a stable credential ID as a public input.

### Measured Results

| Metric | Value |
| --- | ---: |
| Total R1CS constraints | 98 |
| Nonlinear constraints | 97 |
| Nonlinear constraint source | Circom `compile.log` direct output |
| Linear constraints | 1 |
| Wires | 97 |
| Public inputs | 1 |
| Private inputs | 1 |
| Outputs | 1 |
| Witness elements | 97 |
| Witness file size | 3180 bytes |
| R1CS file size | 19488 bytes |
| WASM file size | 38407 bytes |
| Proving-key size | 61865 bytes |
| Verification-key size | 3116 bytes |
| Proof size | 805 bytes |
| Public-input size | 18 bytes |

The nonlinear constraint value is taken directly from Circom compiler output.
It is not derived from total constraints. If a future toolchain does not report
this field directly and reliably, record `null`; do not infer it by subtraction
or by assuming a constraint composition.

### Benchmark Results

All benchmark runs used the valid input
`birth_day_index = 9000, cutoff_day_index = 10000`. Witness generation,
Groth16 proving, and verification were measured separately. Setup time is not
included in proving time.

| Stage | Raw times (ms) | Mean | Median | Min | Max | Exit status |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| Witness generation | `[43, 42, 43, 43, 40]` | 42.2 | 43 | 40 | 43 | `[0, 0, 0, 0, 0]` |
| Groth16 proving | `[1632, 1518, 1528, 1528, 1542]` | 1549.6 | 1528 | 1518 | 1632 | `[0, 0, 0, 0, 0]` |
| Verification | `[1168, 1252, 1146, 1157, 1141]` | 1172.8 | 1157 | 1141 | 1252 | `[0, 0, 0, 0, 0]` |

| Stage | Raw peak RSS (MB) | Mean | Median | Min | Max |
| --- | --- | ---: | ---: | ---: | ---: |
| Witness generation | `[40.5, 40.375, 40.25, 40.375, 40.375]` | 40.375 | 40.375 | 40.25 | 40.5 |
| Groth16 proving | `[217.516, 217.434, 217.41, 218.348, 217.148]` | 217.571 | 217.434 | 217.148 | 218.348 |
| Verification | `[205.93, 204.547, 206.133, 205.633, 205.324]` | 205.513 | 205.633 | 204.547 | 206.133 |

### Constraint Composition

The current 98 constraints are composed as follows:

| Component | Constraints | Type |
| --- | ---: | --- |
| `birth_day_index` `Num2Bits(32)` range check | 32 | Nonlinear |
| `cutoff_day_index` `Num2Bits(32)` range check | 32 | Nonlinear |
| `LessEqThan(32)` internal `Num2Bits(33)` decomposition | 33 | Nonlinear |
| Forced comparison result `is_old_enough === 1` | 1 | Linear |

This means the circuit intentionally has three bit-decomposition blocks: two
independent 32-bit range checks for the inputs and the internal 33-bit
decomposition used by `LessEqThan(32)`. This is repeated range-check-style
constraint work, but it is kept because the current requirement is to constrain
both inputs to 32 bits and to use the formal circomlib comparison gadget.

### Negative Test

The invalid input was:

```json
{
  "birth_day_index": "10001",
  "cutoff_day_index": "10000"
}
```

The build script observed `invalid_witness_exit_status = 1` and
`invalid_check_exit_status = 1`, with `expected_failure = true`. This is the
expected result: the invalid input is rejected rather than silently accepted.

### Included Components

- 32-bit range check for `birth_day_index`.
- 32-bit range check for `cutoff_day_index`.
- `birth_day_index <= cutoff_day_index` comparison using circomlib
  `LessEqThan`.
- Groth16 proof and verification for this age predicate circuit.

### Excluded Components

- issuer signature verification
- holder authorization
- credential commitment
- date validity
- date-to-day-index conversion
- selective disclosure
- revocation
- A2DP delegation

### Interpretation

This result is only the cost of a request-dependent predicate over a private
birth day index and a public cutoff. It is not the cost of a full credential
presentation, because it excludes credential authenticity, holder binding,
commitment opening, disclosure policy enforcement, revocation, and A2DP
delegation logic. Those components must be measured separately before any
combined presentation number is reported.

## Disclosure Control

### Security Semantics

The disclosure control component proves consistency among three public 8-bit
masks:

- `requested_disclosure_mask`: the verifier-requested disclosure set.
- `holder_approved_mask`: the holder-approved subset.
- `actual_disclosure_mask`: the server-used disclosure set.

The circuit enforces that `holder_approved_mask` is a subset of
`requested_disclosure_mask`, and that `actual_disclosure_mask` is exactly equal
to `holder_approved_mask`.

This component only proves consistency among public masks. It does not prove
anything about disclosed attribute values, credential validity, or holder
authorization. Only a later holder signature or equivalent authorization
binding over `holder_approved_mask` can prevent a server from choosing a new
approval set on the holder's behalf.

### Inputs

All inputs are public:

| Input | Visibility | Meaning |
| --- | --- | --- |
| `requested_disclosure_mask` | Public | Verifier-requested disclosure bit mask. |
| `holder_approved_mask` | Public | Holder-approved disclosure bit mask. |
| `actual_disclosure_mask` | Public | Server-used disclosure bit mask. |

### Measured Results

| Metric | Value |
| --- | ---: |
| Total R1CS constraints | 33 |
| Nonlinear constraints | 32 |
| Nonlinear constraint source | Circom `compile.log` direct output |
| Linear constraints | 1 |
| Wires | 18 |
| Public inputs | 3 |
| Private inputs | 0 |
| Outputs | 0 |
| Witness elements | 18 |
| Witness file size | 652 bytes |
| R1CS file size | 6196 bytes |
| WASM file size | 35972 bytes |
| Proving-key size | 18018 bytes |
| Verification-key size | 3298 bytes |
| Proof size | 807 bytes |
| Public-input size | 20 bytes |

### Benchmark Results

All benchmark runs used the valid disclosure input. Witness generation,
Groth16 proving, and verification were measured separately. Setup time is not
included in proving time.

| Stage | Raw times (ms) | Mean | Median | Min | Max | Exit status |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| Witness generation | `[43, 42, 41, 42, 42]` | 42.0 | 42 | 41 | 43 | `[0, 0, 0, 0, 0]` |
| Groth16 proving | `[1552, 1542, 1547, 1549, 1524]` | 1542.8 | 1547 | 1524 | 1552 | `[0, 0, 0, 0, 0]` |
| Verification | `[1150, 1134, 1111, 1141, 1118]` | 1130.8 | 1134 | 1111 | 1150 | `[0, 0, 0, 0, 0]` |

| Stage | Raw peak RSS (MB) | Mean | Median | Min | Max |
| --- | --- | ---: | ---: | ---: | ---: |
| Witness generation | `[40.5, 40.375, 40.25, 40.375, 40.5]` | 40.4 | 40.375 | 40.25 | 40.5 |
| Groth16 proving | `[213.316, 214.078, 211.18, 213.973, 213.273]` | 213.164 | 213.316 | 211.18 | 214.078 |
| Verification | `[204.25, 203.906, 204.262, 205.449, 204.477]` | 204.469 | 204.262 | 203.906 | 205.449 |

### Constraint Composition

The compiled circuit reports 33 total constraints:

| Component | Constraints | Type |
| --- | ---: | --- |
| Three `Num2Bits(8)` bitness checks | 24 | Nonlinear |
| Holder-approved subset checks | 8 | Nonlinear |
| Remaining optimized public-mask consistency constraint | 1 | Linear |

Source-level checks also include eight bit equality constraints
`actual[i] === approved[i]` and the mask recomposition constraints generated by
`Num2Bits(8)`. Circom reports only one linear constraint after optimization, so
those source-level linear checks are not separately counted in the compiled
R1CS.

### Tests

- Valid masks: witness generation, witness check, proof generation, and proof
  verification succeeded.
- Invalid expansion: witness generation returned status `1`, recorded as
  expected failure.
- Invalid request: witness generation returned status `1`, recorded as
  expected failure.

### Included Components

- 8-bit mask range constraints.
- Holder-approved subset check.
- Actual disclosure equals holder-approved disclosure.
- Groth16 proof and verification.

### Excluded Components

- disclosed attribute values
- credential verification
- holder signature/authorization
- request hashing
- credential selection
- canonical field-to-mask encoding
- revocation
- secret sharing
- A2DP delegation

## Request Binding

### Security Semantics

The request binding component proves that the public request fields bind to a
public `expected_request_digest` under the real circomlib `Poseidon(6)` gadget.
It binds the verifier domain hash, nonce, policy hash, requested disclosure
mask, expiry, and context hash into one digest.

This component does not include a credential ID, stable wallet handle,
signature verification, credential verification, secret sharing, or full A2DP
delegation. Canonical encoding and string-to-field conversion are excluded.

### Inputs

All inputs are public:

| Input | Visibility | Meaning |
| --- | --- | --- |
| `verifier_domain_hash` | Public | Field element representing the verifier domain. |
| `nonce` | Public | Request nonce. |
| `policy_hash` | Public | Field element representing the policy. |
| `requested_disclosure_mask` | Public | Disclosure mask requested by the verifier. |
| `expiry` | Public | Request expiry value. |
| `context_hash` | Public | Field element representing request context. |
| `expected_request_digest` | Public | Expected Poseidon digest over the six request fields. |

### Measured Results

| Metric | Value |
| --- | ---: |
| Total R1CS constraints | 354 |
| Nonlinear constraints | 354 |
| Nonlinear constraint source | Circom `compile.log` direct output |
| Linear constraints | 0 |
| Wires | 361 |
| Public inputs | 7 |
| Private inputs | 0 |
| Outputs | 0 |
| Witness elements | 361 |
| Witness file size | 11628 bytes |
| R1CS file size | 341796 bytes |
| WASM file size | 2297888 bytes |
| Proving-key size | 517687 bytes |
| Verification-key size | 4025 bytes |
| Proof size | 806 bytes |
| Public-input size | 154 bytes |

### Benchmark Results

All benchmark runs used the valid request binding input. Witness generation,
Groth16 proving, and verification were measured separately. Setup time is not
included in proving time.

| Stage | Raw times (ms) | Mean | Median | Min | Max | Exit status |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| Witness generation | `[70, 67, 69, 70, 65]` | 68.2 | 69 | 65 | 70 | `[0, 0, 0, 0, 0]` |
| Groth16 proving | `[1521, 1528, 1512, 1491, 1510]` | 1512.4 | 1512 | 1491 | 1528 | `[0, 0, 0, 0, 0]` |
| Verification | `[1105, 1102, 1095, 1080, 1102]` | 1096.8 | 1102 | 1080 | 1105 | `[0, 0, 0, 0, 0]` |

| Stage | Raw peak RSS (MB) | Mean | Median | Min | Max |
| --- | --- | ---: | ---: | ---: | ---: |
| Witness generation | `[50.625, 50.488, 50.473, 50.613, 50.617]` | 50.563 | 50.613 | 50.473 | 50.625 |
| Groth16 proving | `[232.461, 232.125, 232.055, 232.457, 232.605]` | 232.341 | 232.457 | 232.055 | 232.605 |
| Verification | `[205.273, 204.555, 204.508, 204.66, 204.062]` | 204.612 | 204.555 | 204.062 | 205.273 |

### Constraint Composition

The current 354 constraints are all reported as nonlinear by Circom:

| Component | Constraints | Type |
| --- | ---: | --- |
| Active Poseidon `x^5` S-boxes after constant folding | 354 | Nonlinear |
| Digest equality to `expected_request_digest` | 0 | Linear |

`Poseidon(6)` uses state width `t = 7`, 8 full rounds, and 63 partial rounds.
That gives 119 S-box slots. In this compiled circuit, one initial-state S-box
slot is constant-folded, leaving 118 active S-boxes. Each active `x^5` S-box
compiles to three multiplication constraints, for `118 * 3 = 354` nonlinear
constraints. The digest equality is absorbed without a separately reported
linear constraint in this R1CS.

### Tests

- Valid request fields with the correct digest: witness generation, witness
  check, proof generation, and proof verification succeeded.
- Invalid nonce with the old digest: witness generation returned status `1`,
  recorded as expected failure.
- Invalid verifier domain with the old digest: witness generation returned
  status `1`, recorded as expected failure.

### Included Components

- Poseidon(6) request digest over `verifier_domain_hash`.
- Poseidon(6) request digest over `nonce`.
- Poseidon(6) request digest over `policy_hash`.
- Poseidon(6) request digest over `requested_disclosure_mask`.
- Poseidon(6) request digest over `expiry`.
- Poseidon(6) request digest over `context_hash`.
- Public equality check against `expected_request_digest`.
- Groth16 proof and verification for this request binding circuit.

### Excluded Components

- signature verification
- credential verification
- credential ID binding
- stable wallet handle binding
- canonical encoding
- string-to-field conversion
- secret sharing
- selective disclosure
- revocation
- A2DP delegation

## Holder Authorization

### Security Semantics

The holder authorization component proves that a private BabyJubJub holder key
authorized the current public request material. The authorized message is:

```text
auth_digest = Poseidon(
  request_digest,
  holder_approved_mask,
  selection_commitment,
  protocol_context
)
```

The circuit computes `auth_digest`, verifies a real circomlib
EdDSA-Poseidon signature over that digest, and forces verification to be
enabled. The holder public key and signature are private witness values, so the
stable holder key is not exposed as a public input.

This component does not prove that the private holder key is bound to any valid
credential. Credential-holder binding is excluded. Selection commitment
generation and selection commitment binding to a credential are also excluded.

### Inputs

Public inputs:

| Input | Visibility | Meaning |
| --- | --- | --- |
| `request_digest` | Public | Request digest being authorized. |
| `holder_approved_mask` | Public | Holder-approved disclosure mask. |
| `selection_commitment` | Public | Commitment to the holder's selected credential or selection material. |
| `protocol_context` | Public | Protocol/domain context field. |

Private inputs:

| Input | Visibility | Meaning |
| --- | --- | --- |
| `holder_public_key_x` | Private | BabyJubJub holder public key x-coordinate. |
| `holder_public_key_y` | Private | BabyJubJub holder public key y-coordinate. |
| `signature_R8x` | Private | EdDSA-Poseidon R8 x-coordinate. |
| `signature_R8y` | Private | EdDSA-Poseidon R8 y-coordinate. |
| `signature_S` | Private | EdDSA-Poseidon scalar S. |

### Measured Results

| Metric | Value |
| --- | ---: |
| Total R1CS constraints | 4504 |
| Nonlinear constraints | 4504 |
| Nonlinear constraint source | Circom `compile.log` direct output |
| Linear constraints | 0 |
| Wires | 4510 |
| Public inputs | 4 |
| Private inputs | 5 |
| Outputs | 0 |
| Witness elements | 4510 |
| Witness file size | 144396 bytes |
| R1CS file size | 1423284 bytes |
| WASM file size | 2818040 bytes |
| Proving-key size | 3156172 bytes |
| Verification-key size | 3480 bytes |
| Proof size | 804 bytes |
| Public-input size | 64 bytes |

### Benchmark Results

All benchmark runs used the valid holder authorization input. Witness
generation, Groth16 proving, and verification were measured separately. Setup
time is not included in proving time.

| Stage | Raw times (ms) | Mean | Median | Min | Max | Exit status |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| Witness generation | `[94, 92, 88, 87, 91]` | 90.4 | 91 | 87 | 94 | `[0, 0, 0, 0, 0]` |
| Groth16 proving | `[1698, 1661, 1583, 1623, 1621]` | 1637.2 | 1623 | 1583 | 1698 | `[0, 0, 0, 0, 0]` |
| Verification | `[1093, 1101, 1098, 1107, 1094]` | 1098.6 | 1098 | 1093 | 1107 | `[0, 0, 0, 0, 0]` |

| Stage | Raw peak RSS (MB) | Mean | Median | Min | Max |
| --- | --- | ---: | ---: | ---: | ---: |
| Witness generation | `[55.434, 55.398, 55.219, 55.262, 55.344]` | 55.331 | 55.344 | 55.219 | 55.434 |
| Groth16 proving | `[422.398, 423.027, 423.984, 420.434, 420.676]` | 422.104 | 422.398 | 420.434 | 423.984 |
| Verification | `[204.371, 204.594, 204.262, 204.738, 205.199]` | 204.633 | 204.594 | 204.262 | 205.199 |

### Constraint Composition

The compiled circuit reports 4504 total constraints, all nonlinear. The
toolchain does not directly report fine-grained subcomponent counts for the
EdDSA verifier, so these are not inferred.

Source components:

- Poseidon(4) authorization digest.
- EdDSA-Poseidon challenge hash `Poseidon(5)`.
- `S` subgroup-order check.
- Hash-to-bits decomposition.
- BabyJubJub fixed-base multiplication for `S * B8`.
- BabyJubJub variable-base multiplication for `h * 8A`.
- BabyJubJub additions and doublings.
- Enabled equality checks forcing verifier success.

### Tests

- Valid signature: witness generation, witness check, proof generation, and
  proof verification succeeded.
- Invalid request digest with the old signature: witness generation returned
  status `1`, recorded as expected failure.
- Invalid signature with the original request: witness generation returned
  status `1`, recorded as expected failure.

### Included Components

- Poseidon(4) authorization digest over `request_digest`.
- Poseidon(4) authorization digest over `holder_approved_mask`.
- Poseidon(4) authorization digest over `selection_commitment`.
- Poseidon(4) authorization digest over `protocol_context`.
- BabyJubJub EdDSA-Poseidon signature verification.
- Private holder public key witness.
- Private EdDSA signature witness.
- Groth16 proof and verification.

### Excluded Components

- credential-holder binding
- selection commitment generation
- selection commitment credential binding
- credential ID
- credential verification
- issuer signature verification
- request hashing
- canonical encoding
- revocation
- secret sharing
- A2DP delegation

## Online Presentation

### Security Semantics

The online presentation circuit composes the currently implemented online
components:

- age predicate
- request binding
- disclosure control
- holder authorization

It proves that a private `birth_day_index` satisfies the public age cutoff,
that the public request fields hash to the public `request_digest`, that the
actual disclosure mask equals the holder-approved mask and does not exceed the
verifier-requested mask, and that a private BabyJubJub holder key signed the
current request digest, holder-approved mask, selection commitment, and
protocol context.

The verifier does not specify a credential ID. No stable credential ID is a
public input. The holder public key and signature remain private witness
values.

This is not a complete credential presentation cost. Issuer validity,
credential binding, revocation, and the server-only proving transition are not
implemented in this circuit.

### Inputs

Public inputs:

| Input | Visibility | Meaning |
| --- | --- | --- |
| `cutoff_day_index` | Public | Request-specific age cutoff day index. |
| `verifier_domain_hash` | Public | Field element representing the verifier domain. |
| `nonce` | Public | Request nonce. |
| `policy_hash` | Public | Field element representing the policy. |
| `requested_disclosure_mask` | Public | Disclosure mask requested by the verifier. |
| `expiry` | Public | Request expiry value. |
| `context_hash` | Public | Field element representing request context. |
| `request_digest` | Public | Expected Poseidon digest over the request fields. |
| `holder_approved_mask` | Public | Holder-approved disclosure mask. |
| `actual_disclosure_mask` | Public | Server-used disclosure mask. |
| `selection_commitment` | Public | Commitment to the selected credential or selection material. |
| `protocol_context` | Public | Protocol/domain context for holder authorization. |

Private inputs:

| Input | Visibility | Meaning |
| --- | --- | --- |
| `birth_day_index` | Private | Holder birth date as an integer day index. |
| `holder_public_key_x` | Private | BabyJubJub holder public key x-coordinate. |
| `holder_public_key_y` | Private | BabyJubJub holder public key y-coordinate. |
| `signature_R8x` | Private | EdDSA-Poseidon R8 x-coordinate. |
| `signature_R8y` | Private | EdDSA-Poseidon R8 y-coordinate. |
| `signature_S` | Private | EdDSA-Poseidon scalar S. |

### Measured Results

| Metric | Value |
| --- | ---: |
| Total R1CS constraints | 4987 |
| Nonlinear constraints | 4986 |
| Nonlinear constraint source | Circom `compile.log` direct output |
| Linear constraints | 1 |
| Wires | 4979 |
| Public inputs | 12 |
| Private inputs | 6 |
| Outputs | 0 |
| Witness elements | 4979 |
| Witness file size | 159404 bytes |
| R1CS file size | 1790096 bytes |
| WASM file size | 3796418 bytes |
| Proving-key size | 3702031 bytes |
| Verification-key size | 4947 bytes |
| Proof size | 805 bytes |
| Public-input size | 209 bytes |
| Request-dependent private nonlinear constraints estimate `m` | 4601 |

### Component Constraints

| Component | Total constraints | Nonlinear constraints | Private inputs |
| --- | ---: | ---: | ---: |
| Age predicate | 98 | 97 | 1 |
| Request binding | 354 | 354 | 0 |
| Disclosure control | 33 | 32 | 0 |
| Holder authorization | 4504 | 4504 | 5 |
| Online presentation compiled total | 4987 | 4986 | 6 |

The current estimate `m = 4601` counts request-dependent private nonlinear
constraints from the private age predicate path and holder authorization path:
`97 + 4504 = 4601`. Request binding and disclosure control use public request
and mask values in this circuit, so they are not counted in this private
nonlinear estimate.

### Benchmark Results

All benchmark runs used the valid online presentation input. Witness
generation, Groth16 proving, and verification were measured separately. Setup
time is not included in proving time.

| Stage | Raw times (ms) | Mean | Median | Min | Max | Exit status |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| Witness generation | `[106, 106, 110, 112, 103]` | 107.4 | 106 | 103 | 112 | `[0, 0, 0, 0, 0]` |
| Groth16 proving | `[1758, 1719, 1718, 1717, 1770]` | 1736.4 | 1719 | 1717 | 1770 | `[0, 0, 0, 0, 0]` |
| Verification | `[1173, 1126, 1118, 1123, 1145]` | 1137.0 | 1126 | 1118 | 1173 | `[0, 0, 0, 0, 0]` |

| Stage | Raw peak RSS (MB) | Mean | Median | Min | Max |
| --- | --- | ---: | ---: | ---: | ---: |
| Witness generation | `[59.512, 59.328, 59.234, 59.473, 59.445]` | 59.398 | 59.445 | 59.234 | 59.512 |
| Groth16 proving | `[434.711, 433.27, 433.027, 430.699, 433.5]` | 433.041 | 433.27 | 430.699 | 434.711 |
| Verification | `[204.27, 204.832, 204.402, 204.664, 204.668]` | 204.567 | 204.664 | 204.27 | 204.832 |

### Tests

- Valid presentation: witness generation, witness check, proof generation, and
  proof verification succeeded.
- Invalid nonce with the old request digest and holder signature: witness
  generation returned status `1`, recorded as expected failure.
- Invalid disclosure expansion: witness generation returned status `1`,
  recorded as expected failure.
- Invalid signature: witness generation returned status `1`, recorded as
  expected failure.

### Included Components

- age predicate
- request binding
- disclosure control
- holder authorization
- Groth16 proof and verification

### Excluded Components

- issuer validity
- issuer signature verification
- credential binding
- credential commitment opening
- credential ID
- revocation
- server-only proving transition
- secret sharing
- A2DP delegation

## Credential-Key Binding (Candidate A Linkable Baseline)

### Security Semantics

This component measures the first Candidate A baseline:
external request-signature verification plus authenticated enrollment key
binding. The circuit does not verify an EdDSA signature. Instead, it proves that
the public holder authorization key is bound to private enrollment material by
recomputing:

```text
enrollment_digest = Poseidon(
  credential_commitment,
  holder_public_key_x,
  holder_public_key_y,
  issuer_id,
  schema_id
)
```

and constraining it to equal `expected_enrollment_digest`.

Security assumptions:

- `expected_enrollment_digest` is assumed to be authenticated by an issuer,
  registry, or prior enrollment proof.
- If the enrollment record is not externally authenticated, a server can
  register or substitute its own public key.
- The holder public key is public and long-term in this baseline, so repeated
  presentations are linkable.
- This is a linkable baseline, not the final unlinkable design.

### Inputs

Public inputs:

| Input | Visibility | Meaning |
| --- | --- | --- |
| `holder_public_key_x` | Public | BabyJubJub holder public key x-coordinate used for external signature verification. |
| `holder_public_key_y` | Public | BabyJubJub holder public key y-coordinate used for external signature verification. |
| `expected_enrollment_digest` | Public | Authenticated enrollment digest, under the external-record assumption. |

Private inputs:

| Input | Visibility | Meaning |
| --- | --- | --- |
| `credential_commitment` | Private | Credential commitment or enrollment commitment material. |
| `issuer_id` | Private | Issuer identifier included in the enrollment digest. |
| `schema_id` | Private | Schema identifier included in the enrollment digest. |

### Measured Results

| Metric | Value |
| --- | ---: |
| Total R1CS constraints | 321 |
| Nonlinear constraints | 321 |
| Nonlinear constraint source | Circom `compile.log` direct output |
| Linear constraints | 0 |
| Wires | 327 |
| Public inputs | 3 |
| Private inputs | 3 |
| Outputs | 0 |
| Witness elements | 327 |
| Witness file size | 10540 bytes |
| R1CS file size | 297748 bytes |
| WASM file size | 2110265 bytes |
| Proving-key size | 459514 bytes |
| Verification-key size | 3297 bytes |
| Proof size | 807 bytes |
| Public-input size | 247 bytes |

### Constraint Composition

| Component | Constraints | Type |
| --- | ---: | --- |
| `Poseidon(5)` enrollment digest | 321 | Nonlinear |
| Digest equality to `expected_enrollment_digest` | 0 | Linear |

No EdDSA verification gadget is included in the circuit. External signature
verification is benchmarked separately and does not contribute to the R1CS
constraint count.

### Benchmark Results

All benchmark runs used the valid credential-key binding input. Witness
generation, Groth16 proving, Groth16 verification, and external signature
verification were measured separately. Setup time is not included in proving
time.

| Stage | Raw times (ms) | Mean | Median | Min | Max | Exit status |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| Witness generation | `[66, 62, 62, 61, 62]` | 62.6 | 62 | 61 | 66 | `[0, 0, 0, 0, 0]` |
| Groth16 proving | `[1549, 1566, 1544, 1502, 1525]` | 1537.2 | 1544 | 1502 | 1566 | `[0, 0, 0, 0, 0]` |
| Verification | `[1124, 1124, 1144, 1134, 1174]` | 1140.0 | 1134 | 1124 | 1174 | `[0, 0, 0, 0, 0]` |
| External signature verification (cold-process) | `[3945, 3938, 3884, 3878, 3856]` | 3900.2 | 3884 | 3856 | 3945 | `[0, 0, 0, 0, 0]` |

| Stage | Raw peak RSS (MB) | Mean | Median | Min | Max |
| --- | --- | ---: | ---: | ---: | ---: |
| Witness generation | `[49.961, 50.441, 50.316, 50.125, 50.441]` | 50.257 | 50.316 | 49.961 | 50.441 |
| Groth16 proving | `[230.039, 230.523, 230.469, 230.582, 230.887]` | 230.5 | 230.523 | 230.039 | 230.887 |
| Verification | `[204.441, 204.551, 204.258, 205.23, 205.266]` | 204.749 | 204.551 | 204.258 | 205.266 |
| External signature verification (cold-process) | `[172.016, 172.066, 172.109, 206.262, 179.977]` | 180.486 | 172.109 | 172.016 | 206.262 |

The external signature verification benchmark above is a cold-process
measurement: each run starts a Node process and includes Node/circomlibjs
loading and cryptographic initialization. It is not included in R1CS
constraints.

### Persistent External Auth Benchmark

The persistent benchmark uses one Node process. It initializes circomlibjs,
BabyJubJub/EdDSA, Poseidon, and the holder key once, performs 20 warm-up runs,
then measures 100 steady-state request operations using
`process.hrtime.bigint()`.

| Metric | Value |
| --- | ---: |
| Process startup and library init | 4536.466 ms |
| Key derivation | 10.392 ms |
| RSS after initialization | 172.867 MB |
| Warm-up runs | 20 |
| Measured runs | 100 |

| Operation | Mean ms | Median | Min | Max | p95 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Poseidon request digest | 0.109 | 0.107 | 0.103 | 0.140 | 0.123 |
| EdDSA-Poseidon signing | 14.797 | 14.716 | 14.293 | 19.111 | 15.229 |
| EdDSA-Poseidon verification | 14.700 | 14.671 | 14.254 | 15.479 | 15.119 |

Persistent verification tests:

- correct signature verified successfully
- old signature failed after modifying the message
- modified signature failed

This shows the previous roughly 3.9 second external-auth measurements mainly
reflected cold process startup, module loading, and one-time cryptographic
initialization rather than steady-state per-request signing or verification.

### Tests

- Valid key and enrollment state: witness generation, witness check, proof
  generation, and proof verification succeeded.
- Invalid key with the old digest: witness generation returned status `1`,
  recorded as expected failure.
- Invalid record with the old digest: witness generation returned status `1`,
  recorded as expected failure.

Host-side external signature tests:

- correct holder signature over the request digest verified successfully
- old signature failed after modifying the request digest
- wrong signature failed

### Candidate A Projected Private Cost

Old private cost from the measured online presentation:

| Component | Constraints |
| --- | ---: |
| Holder authorization | 4504 |
| Age predicate private nonlinear | 97 |
| `m_old` | 4601 |

Candidate A projected private cost:

| Component | Constraints |
| --- | ---: |
| Credential-key binding nonlinear constraints | 321 |
| Age predicate private nonlinear | 97 |
| `m_candidate_a` | 418 |
| `m_candidate_a / 4987` | 8.38% |

This is a projected estimate. Issuer-authenticated enrollment and unlinkability
are not implemented. The reduction relative to the old in-circuit holder
authorization path is `4504 - 321 = 4183` constraints.

### Included Components

- Poseidon enrollment-state binding.
- Holder public key substitution resistance under the authenticated-record
  assumption.
- External request-signature verification benchmark.
- Groth16 proof and verification for the credential-key binding circuit.

### Excluded Components

- issuer authentication of enrollment record
- unlinkability
- per-verifier or one-time authorization key
- issuer signature verification
- revocation
- secret sharing
- server-only proving transition
- A2DP delegation

## Candidate A Online Presentation

### Security Semantics

This circuit composes the Candidate A online baseline:

- age predicate
- request binding
- disclosure control
- credential-key binding
- external request-signature signing and verification outside the SNARK

The circuit proves that the request fields hash to the public `request_digest`,
the age predicate holds, the holder-approved disclosure mask is a subset of the
requested mask, actual disclosure equals holder-approved disclosure, and the
public holder key is consistent with an authenticated enrollment digest. It does
not include the EdDSA verification gadget.

External signature verification is not part of SNARK constraints. The current
long-term holder public key is public, so this baseline is linkable.
`expected_enrollment_digest` authenticity still depends on external issuer,
registry, or prior enrollment-proof authentication.

Candidate A does not implement the server-only proving transition and does not
prove that the phone avoids witness-sized state.

### Measured Results

| Metric | Value |
| --- | ---: |
| Total R1CS constraints `N_candidate_a` | 804 |
| Nonlinear constraints | 803 |
| Linear constraints | 1 |
| Wires | 798 |
| Public inputs | 13 |
| Private inputs | 4 |
| Outputs | 0 |
| Witness elements | 798 |
| Witness file size | 25612 bytes |
| R1CS file size | 664576 bytes |
| WASM file size | 2998688 bytes |
| Proving-key size | 1038866 bytes |
| Verification-key size | 5129 bytes |
| Proof size | 803 bytes |
| Public-input size | 423 bytes |

### Component Constraints

| Component | Total constraints | Nonlinear constraints | Private inputs |
| --- | ---: | ---: | ---: |
| Age predicate | 98 | 97 | 1 |
| Request binding | 354 | 354 | 0 |
| Disclosure control | 33 | 32 | 0 |
| Credential-key binding | 321 | 321 | 3 |
| Candidate A online compiled total | 804 | 803 | 4 |

`m_candidate_a` is defined as age private nonlinear constraints plus
credential-key-binding private nonlinear constraints:

```text
m_candidate_a = 97 + 321 = 418
```

The three reported ratios are distinct:

| Ratio | Formula | Value |
| --- | --- | ---: |
| Old private reduction | `(4601 - m_candidate_a) / 4601` | 90.92% |
| Candidate A private fraction | `m_candidate_a / N_candidate_a` | 51.99% |
| Candidate A vs old total | `m_candidate_a / 4987` | 8.38% |

`candidate_a_vs_old_total` is only a comparison against the old online
presentation size. It is not the private fraction of the Candidate A circuit.

### Benchmark Results

All benchmark runs used the valid Candidate A input. Holder signing, external
signature verification, witness generation, Groth16 proving, and proof
verification were measured separately. External signature time is not included
in R1CS proving time.

| Stage | Raw times (ms) | Mean | Median | Min | Max | Exit status |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| Holder signing (cold-process) | `[3885, 3978, 3860, 3895, 3874]` | 3898.4 | 3885 | 3860 | 3978 | `[0, 0, 0, 0, 0]` |
| External signature verification (cold-process) | `[3871, 3891, 3915, 3829, 3908]` | 3882.8 | 3891 | 3829 | 3915 | `[0, 0, 0, 0, 0]` |
| Witness generation | `[77, 78, 78, 79, 78]` | 78.0 | 78 | 77 | 79 | `[0, 0, 0, 0, 0]` |
| Groth16 proving | `[1584, 1566, 1558, 1591, 1579]` | 1575.6 | 1579 | 1558 | 1591 | `[0, 0, 0, 0, 0]` |
| Verification | `[1135, 1129, 1134, 1122, 1124]` | 1128.8 | 1129 | 1122 | 1135 | `[0, 0, 0, 0, 0]` |

| Stage | Raw peak RSS (MB) | Mean | Median | Min | Max |
| --- | --- | ---: | ---: | ---: | ---: |
| Holder signing (cold-process) | `[205.957, 204.043, 191.918, 205.625, 206.574]` | 202.823 | 205.625 | 191.918 | 206.574 |
| External signature verification (cold-process) | `[198.109, 205.504, 206.207, 205.188, 173.219]` | 197.645 | 205.188 | 173.219 | 206.207 |
| Witness generation | `[54.047, 54.035, 53.871, 54.121, 54.121]` | 54.039 | 54.047 | 53.871 | 54.121 |
| Groth16 proving | `[252.352, 252.52, 252.957, 252.578, 252.805]` | 252.642 | 252.578 | 252.352 | 252.957 |
| Verification | `[204.043, 205.707, 204.5, 204.516, 204.352]` | 204.624 | 204.5 | 204.043 | 205.707 |

The host-side signing and verification timings above are cold-process
measurements. They include starting Node and loading/initializing circomlibjs.
They are reported as measured and are not subtracted from any other phase.

For steady-state external auth, use the persistent one-process benchmark:

| Operation | Mean ms | Median | Min | Max | p95 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Poseidon request digest | 0.109 | 0.107 | 0.103 | 0.140 | 0.123 |
| EdDSA-Poseidon signing | 14.797 | 14.716 | 14.293 | 19.111 | 15.229 |
| EdDSA-Poseidon verification | 14.700 | 14.671 | 14.254 | 15.479 | 15.119 |

Persistent initialization measurements:

| Metric | Value |
| --- | ---: |
| Process startup and library init | 4536.466 ms |
| Key derivation | 10.392 ms |
| RSS after initialization | 172.867 MB |

### Tests

- Valid presentation: external signature verification, witness generation,
  witness check, proof generation, and proof verification succeeded.
- Invalid nonce: circuit witness generation returned status `1`, and the old
  external signature also failed against the modified request digest.
- Invalid disclosure expansion: witness generation returned status `1`.
- Invalid holder key: witness generation returned status `1`.
- Invalid enrollment record: witness generation returned status `1`.
- Invalid external signature: host-side verification returned status `1`; the
  script does not continue to proving for that invalid signature path.

### Included Components

- age predicate
- request binding
- disclosure control
- Poseidon enrollment-state credential-key binding
- external request-signature signing benchmark
- external request-signature verification benchmark
- Groth16 proof and verification

### Excluded Components

- in-circuit EdDSA verification gadget
- issuer authentication of enrollment record
- unlinkability
- per-verifier or one-time authorization key
- issuer signature verification
- credential ID
- revocation
- secret sharing
- server-only proving transition
- proof that the phone does not handle witness-sized state
- A2DP delegation
