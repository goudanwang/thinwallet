# Android and aarch64 feasibility

## Artifact audit

| Check | Result |
| --- | --- |
| `no_std` | no; official package uses `std` |
| native C/C++ dependencies | none identified in the direct EMSM path |
| threading | Rayon enabled by default; parallel thresholds and host-oriented comments are hard-coded |
| SIMD/x86/AVX | no explicit EMSM AVX call found; `ark-ff` enables `asm`, so target behavior remains unverified |
| Android CI/build instructions | none |
| mmap | none in official EMSM |
| setup persistence format | none |
| matrix storage | compact two-permutation RAA descriptor in code, not a dense `n x N` matrix |
| temporary access | random permutation access and dense `N`/`n` vectors |
| NDK compatibility | OPEN; no aarch64 Android build was performed in Phase A |

The official code is not directly deployable on Android because it has no
stable wire/storage format, no NDK target proof, and uses Arkworks rather than
ThinWallet's Ristretto backend. A Ristretto-native Rust port may be technically
buildable for `aarch64-linux-android`, but that is an untested implementation
path, not an artifact capability.

## Dimension-derived storage diagnostic

The following uses the smallest published set
`n=32768, N=131072, t=1178` and ThinWallet's 32-byte Ristretto/scalar
encodings. It is not a benchmark and is marked `derived_estimate=true`.

| Item | Derived size |
| --- | ---: |
| basis of `n` compressed points | 1,048,576 bytes |
| basis-dependent `h` of `N` compressed points | 4,194,304 bytes |
| two `N`-entry permutation arrays on 64-bit aarch64, excluding `Vec` overhead | 2,097,152 bytes |
| one semi-honest ciphertext row | 1,048,576 bytes |
| one malicious ciphertext row pair | 2,097,152 bytes |
| sparse scalar payload for one `e`, excluding indices/container overhead | 37,696 bytes |
| sparse scalar payload for malicious `(e,e_ck)`, excluding indices/container overhead | 75,392 bytes |

If all ciphertext rows are retained simultaneously, semi-honest encoded scalar
payload is 64, 128, 256, or 512 MiB for `q=64,128,256,512`; malicious mode
doubles those figures. A streaming row protocol could avoid retaining all
rows, but the official artifact does not provide or validate such a protocol.

The shared basis means public setup is not multiplied by `q`. Fresh private
state and ciphertexts are multiplied by `q`. Runtime heap layout, allocator
overhead, dense RAA temporaries, thread stacks, and code size are `null` until
measured on an implemented backend.

## Feasibility conclusion

Android/aarch64 is **OPEN**, not rejected. There is no evidence for an
x86-only mathematical dependency, but there is also no official Android
support or build result. Phase A therefore makes no phone-memory, OOM, latency,
or energy claim.

