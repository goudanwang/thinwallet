# Phase V4A Android Headless Port

## Status

The Rust core and `thinwallet_android_bench` cross-compile for Android ARM64,
but the physical-device gate is not satisfied. `adb 37.0.0` reports no attached
device. The primary classification is therefore `PHASE_V4A_INCONCLUSIVE`, and
the preliminary mobile classification is
`THINWALLET_ANDROID_RESULT_INCONCLUSIVE`.

No Android latency, memory, storage, network, energy, thermal, transcript, or
proof-equivalence measurement exists. These fields are null rather than copied
from WSL. Stage B JNI is deliberately not attempted because the required Stage
A physical-device execution has not succeeded.

## Implemented Host Boundary

The headless runner exposes `generate-token`, `inspect-token`, `prove-native`,
`prove-pbmo-in-memory`, `prove-fs2`, `prove-fs3`, `verify-proof`,
`run-security-tests`, `print-memory-profile`, and `print-device-profile`.
State, temporary, memory-budget, proof, and JSON output locations are supplied
through `THINWALLET_*` environment variables. The ARM64 executable uses the
same Cargo.lock, libspartan 0.9.0, curve25519-dalek 4.1.3, canonical bincode
proof representation, PBMO token codec, state store, and token journal as the
frozen desktop build.

The deployment script rejects emulators and non-ARM64 devices. On a physical
device it uses `/data/local/tmp` only for Stage A shell execution; a future JNI
stage must pass the application's internal files directory instead. Shared
external storage and mmap are not enabled.

## Desktop Smoke Test

The deterministic `2^12` A0/A1/A2/A3 smoke proofs are byte-identical and have
SHA-256 `a9b8bd3cc9f02c254e7990e81a38c5d8948383e3463970084978500cf617434a`.
The serialized proof is 47,464 bytes and is accepted by the unchanged upstream
libspartan verifier. This proves runner-path consistency on x86_64 only; it is
not Android equivalence evidence.

The current PBMO provider serializes its binary frames in process and does not
contain an independent TCP server. Consequently, the required separate-machine
network execution remains blocked even after a device becomes available.
`SOFTWARE_ONLY_SNAPSHOT_ROLLBACK_NOT_PREVENTED` remains unchanged.

