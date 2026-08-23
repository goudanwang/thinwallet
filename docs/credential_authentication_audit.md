# Credential Authentication Audit

Classification: `CREDENTIAL_AUTHENTICATION_BACKEND_SELECTED`

## Decision

Phase V4B selects a 91-round MiMC7 native-field PRF-MAC over the
curve25519-dalek scalar field. The circuit also recomputes a public issuer-key
commitment. The statement is issuer-authenticated only under both assumptions:
the issuer alone knows the symmetric MAC key, and a registry or issuer
authenticates the public key commitment. The measured per-credential issuer
authentication cost is 3,652 constraints: 731 for key commitment, 2,920 for
the eight-block credential MAC, and one tag equality.

This is a research baseline. It is not a standardized credential signature,
does not provide public-key signature semantics, and has not received an
independent cryptographic audit. MiMC round constants are deterministically
domain-separated for this experiment. A hash equality without the MAC and the
authenticated key anchor is explicitly not treated as issuer authentication.

## Candidate Comparison

| Candidate | Security and proof semantics | Arithmetic | Availability | Constraints | Risk |
| --- | --- | --- | --- | ---: | --- |
| Standard signature, non-native | EUF-CMA signature and issuer PKI verified in proof | Non-native | No maintained local gadget | null | High |
| Native Schnorr-like signature | Public-key authenticity if the group gadget is sound | Native field plus group gadget | No audited local gadget | null | High |
| Native MiMC7 PRF-MAC | Symmetric issuer authentication under authenticated-key-commitment assumption | Native | Implemented | 3,652 per credential | Medium-high |
| Hash-authenticated record | Only commitment membership unless its root is externally authenticated | Native | Partial | null | High |
| External signature plus binding | Standard external signature, but exact hidden-record binding must remain sound | Split | Candidate A only | null | High |

Unknown counts are `null`; they were not inferred from unrelated gadgets. The
machine-readable comparison is in
`experiments/credential_workloads/authentication_matrix.json`.

## Threat Boundary

The relation rejects attribute, issuer, holder-binding, MAC, nonce, expiry,
revocation, and composition mutations. It does not establish the registry's
honesty, key provisioning, issuer key rotation, hardware key protection, or a
standard interoperable credential format. Complete local-state snapshot
rollback remains outside the software-only threat model.
