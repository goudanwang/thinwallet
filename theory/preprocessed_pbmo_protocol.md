# Preprocessed Private Batched Multi-Output MSM

## Scope

This document defines the Phase V2 shared-basis protocol. It is an experimental
construction and not a production-security claim. The frozen online Matrix-RAA
construction is not used.

Let `Z in Fr^(q x m)` be private and let `G=(G_0,...,G_(m-1))` be the public,
pre-installed Ristretto basis. The required ordered outputs are
`C_j = sum_i Z[j,i] G_i` for `j in [0,q)`.

## Algorithms

### Setup

`Setup(version, backend_revision, relation_shape, logical_commitment_id, G)`
canonically encodes the ordered compressed basis, computes `basis_digest`, and
defines a token family bound to `(version, backend, relation, layout, q, m)`.

### TokenGenerate

For a fresh random `token_id` and 256-bit seed `s_l`, derive each scalar

```text
R[j,i] = HMAC-SHA-512(s_l,
    domain || version || token_id || basis_digest || backend_revision ||
    logical_commitment_id || relation_shape || q || m || j || i || counter)
    reduced from 512 bits into Ristretto Fr.
```

For each row, materialize only `R_j`, compute `D_j = MSM(R_j,G)`, persist the
canonical compressed `D_j`, then release `R_j`. Working mask storage is `O(m)`,
not `O(qm)`; chunk generation may lower the live scalar buffer further, while
the dalek MSM API still consumes one row.

### TokenReserve

Append and `fsync` `AVAILABLE -> RESERVED` in the authenticated hash-chain
journal before returning permission to send the first masked byte. A reserved
token can only become `SPENT` or `BURNED`.

### ClientMaskStream

For ordered row chunks, regenerate `R[j,start..end]`, compute
`V[j,i]=Z[j,i]+R[j,i]`, emit a binary frame bound to version, session, proof,
token, logical commitment, basis, dimensions, row and column interval, then
release the chunk. The basis is never uploaded.

### ServerEvaluate

The server validates frame order and context, accumulates chunk MSMs against its
pre-installed basis, and returns ordered `Y_j = MSM(V_j,G)`.

### ClientRecover

After output count/order binding, compute `C_j = Y_j-D_j`. In libspartan the
native prover then adds its unchanged per-row blind `r_j h` locally.

### BatchVerify

In malicious mode, first hash all ordered outputs. Derive post-commitment
`rho_j` from the bound transcript, token ID, output digest and row index. Compute

```text
Y_rho = sum_j rho_j Y_j
A_i   = sum_j rho_j V[j,i]
T     = MSM(A,G)
```

and accept only when `T=Y_rho`. Masked rows are replayed from a bounded,
file-backed spool. This is one `m`-term local MSM, not `q` independent checks.

### TokenFinalize

On success append and `fsync` `RESERVED -> SPENT`; on abort, timeout, failed
integrity, or uncertain completion append and `fsync` `RESERVED -> BURNED`.
Finalization to the same terminal state is idempotent.

### TokenRecoverAfterCrash

Verify every journal MAC and hash-chain link. Burn every recovered `RESERVED`
token. If a journal-only rollback says `AVAILABLE` while the authenticated token
file records a later state, burn it. Never return a possibly released token to
`AVAILABLE`.

## Binary Token

The version-2 format stores magic/version, authenticated binding metadata,
token ID, creation epoch, lifecycle state, journal reference, `q` canonical
Ristretto encodings, a 24-byte XChaCha20 nonce, and an AEAD ciphertext/tag for
the seed. Metadata and correction points are AEAD associated data. The
`TokenStoreKeyProvider` abstraction supplies the local key; Phase V2 implements
only a software test provider.

```text
PREPROCESSED_PBMO_PROTOCOL_FORMALIZED
```

