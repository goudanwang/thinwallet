# Phase V2 Preprocessed PBMO Result

## Construction

Phase V2 replaces frozen Matrix-RAA with a fresh one-time seed-expanded matrix
mask. Offline generation computes `D_j=MSM(R_j,G)` one row at a time. Online,
the client streams `V=Z+R`, the server returns `Y_j=MSM(V_j,G)`, and the client
recovers `C_j=Y_j-D_j`. Malicious mode derives challenges only after binding all
ordered outputs and checks one random linear combination with one `m`-term MSM.

The implementation is in the proof-system-independent
`experiments/preprocessed-pbmo` crate. The libspartan fork only maps the complete
fragmented witness commitment to this API; native `r_j h` blinding remains local.

## Measured Token Generation

| q=m | Token bytes | Offline ms | Peak RSS MB |
| ---: | ----------: | ---------: | ----------: |
| 64   | 2,414       | 28.416     | 2.375       |
| 128  | 4,464       | 92.976     | 2.609       |
| 256  | 8,560       | 328.576    | 2.375       |
| 512  | 16,752      | 1,142.375  | 2.500       |

The generator holds one row of `m` scalars, the `m`-point basis, and `q`
correction points; it never materializes the `q*m` mask matrix. Energy fields
are `null` because no Android energy measurement was performed.

## Standalone Online PBMO

| q=m | Semi ms | Malicious ms | Batch-check ms | Upload bytes | Download bytes |
| ---: | ------: | -----------: | -------------: | -----------: | -------------: |
| 64   | 62.278  | 64.248       | 1.805          | 134,400      | 2,048          |
| 128  | 130.297 | 139.350      | 6.082          | 537,600      | 4,096          |
| 256  | 404.223 | 462.241      | 21.655         | 2,150,400    | 8,192          |
| 512  | 1,404.223 | 1,555.346  | 74.354         | 8,601,600    | 16,384         |

Basis upload is zero. The encoded upload includes bound binary frame headers in
addition to `q*m*32` scalar bytes. Malicious mode additionally writes and reads
exactly `q*m*32` spool bytes, performs `2qm` aggregate field operations, `q`
point-weighting operations, and one `m`-term local MSM. Its random-challenge
soundness bound is at most `1/|Fr|` for a fixed nonzero ordered output error.
The online latency includes durable reservation and terminal finalization.

## Libspartan Integration

For relation sizes `2^12`, `2^14`, `2^16`, and `2^18`, upstream, patched-native,
plaintext-remote, preprocessed semi-honest, and preprocessed malicious proofs
have one identical SHA-256 per size. Proof sizes are respectively 47,464,
62,664, 84,840, and 120,136 bytes. Every proof is accepted by the unchanged
upstream 0.9.0 verifier. Hashes of `group.rs`, `nizk/mod.rs`, `nizk/bullet.rs`,
`r1csproof.rs`, `sumcheck.rs`, and `transcript.rs` are byte-identical to the
upstream source.

```text
LIBSPARTAN_FULL_PREPROCESSED_PBMO_PASS
LIBSPARTAN_PREPROCESSED_PBMO_PROOF_BYTE_IDENTICAL_PASS
LIBSPARTAN_UNCHANGED_VERIFIER_WITH_PBMO_PASS
```

## Lifecycle and Limits

All injected crashes after durable reservation recover to `BURNED`; a crash
before reservation leaves the token `AVAILABLE`. Success reaches `SPENT`, abort
reaches `BURNED`, and terminal finalization is idempotent. AEAD tampering,
relation mismatch, clone insertion, token reuse, output corruption/permutation,
replay-shaped output, cross-session swap, and journal-only rollback tests pass.

A purely local software provider cannot detect restoration of the token file,
journal, local keys, and counters to one earlier valid whole-device snapshot.
This requires trusted monotonic hardware or an independent external witness.
The result is not a production-security, Android, or mobile-feasibility claim.

## Memory-Cap Smoke Test

| Cap MiB | Native max | Plain max | Preprocessed max |
| ------: | ---------: | --------: | ---------------: |
| 128     | `2^14`     | `2^14`    | `2^14`           |
| 256     | `2^16`     | `2^16`    | `2^16`           |
| 512     | `2^16`     | `2^16`    | `2^16`           |

`2^18` failed with allocation/OOM-class errors under 256 and 512 MiB for all
three modes. This is preliminary only: the complete controlled OOM boundary and
ThinWallet streaming comparison remain Phase V3 work.

```text
PHASE_V2_PREPROCESSED_PBMO_LIBSPARTAN_PASS
```
