# ThinWallet Credential Workloads

Classification: `THINWALLET_CREDENTIAL_WORKLOAD_SUITE_DEFINED`

All relations use the curve25519-dalek scalar field and deterministic fixtures.
The current fragmented commitment backend requires a square `q x m` shape, so
each credential relation is executed at `2^14` even where the raw R1CS would
fit in `2^13`. Padding is reported, not hidden.

## Credential State

A credential contains issuer ID, schema ID, credential ID, a MiMC7 commitment
to the holder secret, age, country code, expiry day index, revocation index,
and an issuer MiMC7 PRF-MAC. The public registry state authenticates the issuer
key commitment. W3/W4 additionally use a sparse-Merkle non-revocation leaf,
path, index, public root, and root epoch. A fresh request supplies nonce,
disclosure mask, day/range policy, and revocation epoch.

## W0 Synthetic Regression

The preserved power-of-two Boolean multiplication relation is only a controlled
scaling baseline. It has no credential security semantics.

## W1 Single Credential

Public inputs are issuer ID, issuer-key commitment, nonce, request digest,
disclosure mask, disclosed age, and disclosed country. Private witness includes
the issuer MAC key, MAC, holder secret, hidden credential fields, expiry, and
revocation index. The relation verifies issuer MAC and key binding, holder
possession through request activation, nonce/session binding, and selective
disclosure. It rejects modified attributes, issuer, holder, MAC, or nonce.

## W2 Predicate Credential

W2 adds public minimum/maximum age and current day. It proves the hidden age is
inside the inclusive 32-bit interval and current day is no later than the
issuer-authenticated expiry. It includes positive, exact-boundary, out-of-range,
and expired cases.

## W3 Revocable Credential

W3 adds a depth-8 sparse-Merkle non-membership proof: the authenticated
credential revocation index selects every path edge, the leaf is constrained
to zero, the root is public, and root epoch must equal request epoch. A root is
fresh only according to the verifier's external policy for accepting that
epoch. Revoked leaves, stale epochs, and malformed paths are rejected.

## W4 Multi-Credential Presentation

W4 authenticates two credentials under two issuer keys, proves both bind to the
same hidden holder secret, proves equality of a hidden attribute, applies one
inclusive range/expiry predicate, and applies one authenticated revocation
predicate. Neither credential ID is public. A cross-holder or hidden-equality
mismatch is rejected.

## Threat Model

The server may deviate, replay, substitute records, corrupt PBMO output, or mix
sessions. The issuer/registry authentication anchor and accepted fresh
revocation root are trusted public inputs. Issuer compromise, malicious
registry state, complete local snapshot rollback, Android execution, and
production wallet readiness are excluded.
