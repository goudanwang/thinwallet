# Authenticated Credential Source

## Construction

The V4E compact source uses versioned, domain-separated XChaCha20-Poly1305.
`CredentialSourceKeyProvider` supplies a 256-bit key by key identifier; the
experiment includes `SoftwareCredentialSourceKeyProvider`. This is authenticated
encryption, not a checksum. A production keystore integration is not claimed.

The encrypted header commits to protocol/backend revision, relation layout,
proof session, `k/r/d/backend`, canonical `RevSet`, registry identity/root/epoch,
public-input digest, generation, source length and source digest. Each record is
an independently authenticated frame whose AAD binds the source digest and
canonical record index. Fixed-width integers are big-endian and bincode uses
fixed-width canonical options with trailing bytes rejected.

Each record carries package/issuer/type/commitment/epoch/salt/hidden and
disclosed bindings/holder/expiry/revocation/predicate fields. Revoked-policy
records additionally carry leaf, path index, and exactly `d` siblings. A
package digest binds all fields, and the sparse path is recomputed against the
header registry root.

## Replay

`CredentialSourceWriter` writes a uniquely named temporary file, flushes and
syncs it, atomically renames it, syncs the parent on Unix, and removes the
temporary file on failure. `CredentialSourceReader` decrypts one bounded frame
at a time and supports independent relation, witness and prover passes.
Canonical indices, exact record count, source length, package digest, RevSet,
path length/index/root and final EOF are checked on every pass.

`CredentialRelationReplay` and `CredentialWitnessReplay` expose deterministic
pass digests. The V4E fixture audit rebuilds the relation and verifies byte
identity of every A/B/C entry, witness scalar and public input.

## Security Boundary

AEAD and binding tests reject byte/tag corruption, truncation, extra/missing or
reordered records, wrong session/layout/backend/RevSet/root/epoch/public input,
and path/record substitutions. The in-process journal rejects generation
rollback relative to retained history.

`SOFTWARE_ONLY_SNAPSHOT_ROLLBACK_NOT_PREVENTED`: rolling back the entire valid
software state, key and journal snapshot is outside this construction. The
source also does not itself establish issuer trust; issuer verification remains
part of the Profile S relation and host policy.
