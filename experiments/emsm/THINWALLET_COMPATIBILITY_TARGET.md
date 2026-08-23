# ThinWallet compatibility target

## Scope freeze

Phase A is an audit only. It does not change the ThinWallet prover, PBMO
protocol, verifier, proof encoding, transcript, Android build, or experiment
mode definitions.

The current audited source identity is:

| Item | Value |
| --- | --- |
| current source-tree SHA-256 | `1bdf76cd73bfc87f1ac509d5fab20c112451168988eaaa6ba0842499433dec5f` |
| frozen Phase-3 result source-tree SHA-256 | `3e962046c1e4b1ea1b617c75ce79726315c8ea51327aca2bbbc072dc718f209a` |
| `experiments/libspartan/Cargo.lock` SHA-256 | `c3c432c53d9a978884d3a66b6d9341611bfadec6496664ee0563ec8786d85ca0` |
| libspartan base revision | crates.io `spartan 0.9.0`, locally vendored and patched |
| Android target | `aarch64-linux-android` |

The current tree hash differs from the frozen Phase-3 result hash because later
diagnostic instrumentation exists in the tree. EMSM comparisons must identify
the exact source hash used; they must not silently combine the two baselines.

## Frozen experiment modes

The definitions in `scripts/thinwallet_bench.py` remain authoritative:

| Mode | Commitment path | Memory architecture | PBMO token lifecycle |
| --- | --- | --- | --- |
| `native` | unmodified baseline libspartan prover | off | off |
| `pbmo-only` | malicious PBMO commitment provider | off | on |
| `memory-only` | native commitment provider | on | off |
| `full` | malicious PBMO commitment provider | on | on |

The following are also frozen:

- deferred-verifier measurement scope;
- native proof bytes and serialization;
- Merlin/Fiat--Shamir transcript order and labels;
- unchanged native verifier;
- PBMO reserve, consume, finalize, and cleanup lifecycle;
- Phase-2 compatibility audit requirements;
- Phase-3 low-overhead instrumentation semantics.

An EMSM baseline may replace only the prover-side private MSM provider in a
separately labelled mode. It may not alter the relation, public inputs, witness,
proof object, native blinding, transcript, or verifier.

## Algebra and encoding

| Component | ThinWallet target |
| --- | --- |
| group | Ristretto255 (`curve25519-dalek 4.1.3`) |
| scalar field | the prime-order Ristretto255 scalar field |
| point encoding | canonical 32-byte compressed Ristretto encoding |
| scalar encoding | canonical 32-byte little-endian scalar encoding; non-canonical values rejected |
| MSM | `curve25519_dalek::traits::VartimeMultiscalarMul` |
| public basis | ordered `Vec<RistrettoPoint>` from libspartan `MultiCommitGens` |
| generator derivation | SHAKE256 over the generator label and compressed Ristretto basepoint |
| basis identity | SHA3-256 over a domain tag, length, and ordered compressed points |

The relevant implementation locations are:

- `vendor/spartan-0.9.0/src/group.rs:6-24,87-116`;
- `vendor/spartan-0.9.0/src/commitments.rs:8-32,69-90`;
- `vendor/spartan-0.9.0/src/prover_msm.rs:252-259,386-410`.

## Actual workload dimensions

These values were read from frozen Phase-3 `manifest.json` files rather than
hard-coded expectations.

| Label | Workload | Constraints | Padded size | Witness elements | q | m |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| S-W1 | S-W1 | 5,543 | 8,192 | 5,515 | 64 | 128 |
| S-W4 | S-W4 | 16,135 | 16,384 | 16,082 | 128 | 128 |
| H0 | S-WK-k8-r0-d0-none | 36,531 | 65,536 | 36,522 | 256 | 256 |
| H1 | S-WK-k52-r1-d32-sparse_merkle | 252,855 | 262,144 | 253,050 | 512 | 512 |
| H2 | S-WK-k8-r8-d32-sparse_merkle | 223,955 | 262,144 | 224,170 | 512 | 512 |

Each workload requires `q` ordered commitments to distinct private rows against
one shared ordered public basis. An acceptable EMSM adapter must return exactly
those points in order.

