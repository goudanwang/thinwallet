# Phase 3A-R2 Single-MSM Integration

Final classification:

```text
PHASE3A_R2_SINGLE_MSM_INTEGRATION_PASS
```

## Frozen Baseline

The baseline is `spartan` 0.9.0 at upstream commit
`2b791bd7d572433b245eba7d5e5aeba3301ec8f5`, with
`curve25519-dalek` 4.1.3. The unmodified source is frozen at
`experiments/libspartan/vendor/spartan-upstream-0.9.0/`.

The deterministic regression vector uses 4,096 Boolean multiplication
constraints and a fixed transcript label. A test-only Cargo feature fixes the
`RandomTape` seed in a separate testable upstream copy and the patched fork.
Default builds retain upstream `OsRng`. This test feature is not a production
randomness mode.

## Minimal Fork

The fork adds `ProverMsmProvider` and three implementations:

- `NativeMsmProvider`;
- `PlainRemoteMsmProvider`;
- `RepetitionCodeIntegrationMsmProvider`.

The selected call is
`dense_mlpoly.private_commit.0.chunk.0`, the first 64-scalar chunk of the
private witness polynomial commitment. Its basis digest is
`1361fef165b194d29da3739f9d183a88312f31d08b03ade508a962f798ed9901`.
The resulting point is committed in the `r1cs_witness_commitment` transcript
phase.

Proof structures, proof encoding, transcript source, verifier API, and
verifier source remain unchanged. Patched-native, plaintext-remote, and
integration-only proofs are byte-identical to the deterministic upstream
proof. Each patched proof also deserializes as the upstream proof type and is
accepted by the original crates.io 0.9.0 verifier.

## Binding And Snapshot

The provider request binds `session_id`, `proof_id`, `msm_id`, basis digest,
transcript phase, scalar count, and request digest. Tests reject replay,
swapped MSM identifiers, wrong bases, wrong sessions, truncated streams, and
duplicate chunk indices.

For the selected 64-scalar call, the plaintext remote snapshot recorded 2,048
scalar bytes, 2,048 basis bytes, 4,534 upload bytes, 32 download bytes, 0.080 ms
native MSM latency, 1.036 ms remote-provider latency, and 17.59 MB process peak
RSS. These are one-run integration measurements, not an OOM or performance
study.

The repetition-code provider recorded a byte-identical MSM point and verifier
acceptance, but every relevant artifact carries:

```text
INTEGRATION_ONLY_NOT_SECURITY_CLAIM
```

It provides no privacy or production malicious-security claim.
