# ThinWallet Prototype Protocol Specification

## Profile S Issuance

1. Resolve an authenticated issuer Ed25519 verification key and its SHA-256 key
   identifier.
2. Encode credential type, issuer, credential ID, holder binding, schema and
   attributes, expiry, revocation ID, issuance epoch, and fresh random salt as
   native scalars.
3. Compute the domain-separated MiMC7 `cred_com` defined in
   `theory/signed_credential_commitment.md`.
4. Sign `protocol_version || credential_type || cred_com || issuance_epoch`
   using the fixed canonical binary encoding.
5. Give the holder the signed public package plus private fields and salt.

## Revocation Publication

The registry signs:

```text
protocol_version || registry_id || credential_type || sparse_merkle_root
|| epoch || valid_from || valid_until
```

The verifier checks strict Ed25519 verification, registry identity, credential
type, minimum epoch, and validity interval. The proof public inputs bind root,
epoch, and the credential revocation identifier used by the path.

## Presentation

1. The holder application decodes the exact canonical credential package,
   resolves the issuer key, and strictly verifies each issuer signature.
2. It verifies the signed registry statement and freshness policy when the
   workload includes revocation.
3. It creates a typed verified transcript and compares every signed field to
   the actual R1CS public-input vector. There is no unbound success Boolean.
4. The R1CS proves the commitment opening, holder/nonce binding, disclosure,
   range/expiry/revocation predicates, and cross-credential relations requested
   by the workload.
5. E0 proves locally. E3/E4 replace the selected private fragmented commitment
   MSM using semi-honest or malicious Preprocessed PBMO while preserving native
   commitment order, blinding, transcript order, proof type, and encoding.
6. The unchanged upstream libspartan 0.9.0 verifier checks the serialized proof.
   The application also retains the exact issuer/registry verification
   transcript associated with those public inputs.

The current protocol is a desktop experimental profile. It is not a W3C VC
encoding, production wallet, or Android protocol result.
