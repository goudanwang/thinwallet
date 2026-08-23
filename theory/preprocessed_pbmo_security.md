# Preprocessed PBMO Security Boundary

## Chosen-Matrix Privacy

An adversarial server chooses equal-shape matrices `Z0,Z1` and receives the
public metadata plus masked stream `V=Z_b+R` for a hidden bit `b`.

If `R` is truly uniform in `Fr^(q x m)` and used once, addition is a field
one-time pad: `V` is uniform and independent of `b`, giving information-
theoretic privacy. Phase V2 expands a random 256-bit seed with domain-separated
HMAC-SHA-512 and maps each 512-bit output into Ristretto `Fr`; privacy is therefore
computational under HMAC-SHA-512 PRF security, the hash-to-field model, seed
secrecy, and strict one-time use. Wide reduction has statistical distance less
than `2^-259` from uniform because the scalar order is below `2^253` and the
source is 512 bits.

Across polynomially many sessions, hybrid replacement of each fresh PRF matrix
with an independent uniform matrix reduces distinguishing advantage to the sum
of PRF/hash-to-field advantages. Public dimensions and bound metadata are not
hidden.

## Mandatory One-Time Use

Reusing one token gives

```text
V^(1)-V^(2) = (Z^(1)+R)-(Z^(2)+R) = Z^(1)-Z^(2).
```

The implementation demonstrates this leakage and rejects a second begin on the
same in-memory token. Durable use additionally relies on reserve-before-send,
terminal burn/spend states, and journal recovery.

## Domain and Relation Binding

Mask derivation binds protocol version, token ID, basis digest, backend revision,
logical commitment ID, relation/layout shape, `q`, `m`, row, column, and counter.
Use after a basis, proving-key basis, backend, dimension, or commitment-layout
change is rejected. Session and proof IDs are bound in every streaming frame;
ordered outputs are bound before malicious challenges.

## Storage and Rollback

XChaCha20-Poly1305 protects seed confidentiality and authenticates metadata and
correction points. A keyed, append-only hash-chain journal provides crash
consistency and detects ordinary corruption or partial local rollback against a
newer token file.

It does not solve whole-device snapshot rollback. An attacker restoring the
token database, journal, local keys, and counters to one earlier valid snapshot
is indistinguishable to local software. Strong rollback protection requires a
real `HardwareMonotonicProvider` or independent non-colluding
`ExternalWitnessProvider`; Phase V2 implements neither.

## Explicit Non-Claims

The in-process server transport is a binary protocol prototype, not an audited
network service. The batch check protects correctness, not privacy. Timing,
side-channel resistance, key erasure, Android keystore integration, cloud sync,
arbitrary snapshot rollback, and production security remain outside Phase V2.

```text
PREPROCESSED_PBMO_PRIVACY_ARGUMENT_COMPLETE
PREPROCESSED_PBMO_TOKEN_REUSE_ATTACK_PASS
PREPROCESSED_PBMO_FIELD_SAMPLING_PASS
PREPROCESSED_PBMO_DOMAIN_SEPARATION_PASS
SOFTWARE_CRASH_CONSISTENCY_PASS
SOFTWARE_ONLY_SNAPSHOT_ROLLBACK_NOT_PREVENTED
STRONG_ROLLBACK_PROTECTION_REQUIRES_EXTERNAL_ASSUMPTION
```
