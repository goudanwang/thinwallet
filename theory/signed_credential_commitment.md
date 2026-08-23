# Signed Credential Commitment

## Field Commitment

The prototype scalar field is the Ristretto255 scalar field used by the frozen
libspartan backend. Let `H_M` be the existing 91-round native-field MiMC7 sponge
with domain-separated round constants. Profile S defines:

```text
holder_binding = H_M(D_HOLDER, holder_secret)

cred_com = H_M(
    D_CREDENTIAL_COMMITMENT,
    credential_type,
    issuer_id,
    credential_id,
    holder_binding,
    schema_id,
    age,
    country,
    expiry,
    revocation_id,
    issuance_epoch,
    random_salt
)
```

The implementation uses domains `0x53484f4c` and `0x53434f4d`. The random salt
is a private scalar and must be independently sampled per issuance. The current
fixture uses a deterministic salt only for reproducibility.

The construction is computationally binding under collision resistance of this
MiMC7 instantiation. It is computationally hiding only when the salt has enough
unpredictable entropy and the hash behaves as assumed. No independent audit of
this exact MiMC7 commitment is claimed. A maintained Ristretto-scalar Poseidon
R1CS gadget was not already available in the frozen local backend, so switching
hashes would have changed both the proof relation and the trusted code surface.

## Signed Statement

The issuer signs this fixed, canonical byte string:

```text
"THINWALLET-PROFILE-S-CREDENTIAL-V1"
|| u16_be(protocol_version)
|| u64_be(credential_type)
|| canonical_scalar_32(cred_com)
|| u64_be(issuance_epoch)
```

`issuer_id` and the SHA-256 issuer-public-key ID are resolved by the
authenticated issuer registry. The package is fixed length, uses big-endian
integers and canonical scalar encodings, and rejects trailing data.

## Application/SNARK Boundary

Before proving, the application strictly verifies the Ed25519 signature and
constructs a typed `VerifiedCredentialStatement`. It compares that statement
field-for-field against the actual R1CS public-input vector. The relevant public
inputs are:

```text
credential_type
issuer_id
issuer_public_key_id reduced into the scalar field
issuance_epoch
cred_com
presentation nonce
disclosure mask and disclosed values
revocation root, epoch, and revocation identifier when applicable
```

The protocol version is fixed by the application and circuit domains. Private
inputs contain the credential identifier, holder secret, schema, undisclosed
attributes, expiry, revocation identifier opening, and salt. There is no caller
supplied `signature_verified` Boolean.

The R1CS recomputes `holder_binding` and `cred_com`, enforces equality to the
public commitment, and uses the same hidden wires for holder/nonce binding,
selective disclosure, equality/range/expiry predicates, revocation, and
cross-credential relations.

Output: `SIGNED_CREDENTIAL_COMMITMENT_FORMALIZED`.
