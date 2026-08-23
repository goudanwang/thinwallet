# EMSM source audit

## Authoritative sources

1. Local paper PDF: Abbaszadeh, Hafezi, Lipmaa, and Zajac, *Single-Server
   Private Outsourcing of zk-SNARKs*.
2. IACR ePrint record: <https://eprint.iacr.org/2025/2113>.
3. Author-linked official repository:
   <https://github.com/h-hafezi/server-aided-snarks>.
4. Author slide deck:
   <https://hosseinhafezi.com/asset/Server-aided%20%28ZKProofs8%29.pdf>.

The local PDF is the controlling source for algorithms and parameters because
it is newer than the pinned repository code.

## Source record

| Field | Audit result |
| --- | --- |
| `paper_title` | `Single-Server Private Outsourcing of zk-SNARKs` |
| `paper_version` | local PDF metadata dated 2026-05-19; ePrint 2025/2113 revision current on that date |
| `publication_year` | 2025 ePrint; IEEE S&P 2026 venue |
| `paper_hash_if_local` | SHA-256 `189bb212385e56a2b9ac2d27f5ab1297c60b304209b2f5e90f8fbc68ff78bb94` |
| `official_repository_url_or_null` | `https://github.com/h-hafezi/server-aided-snarks` |
| `repository_commit` | `41c6f7b856cb03131d405723df49a6fc33e2a452` |
| `artifact_version` | Cargo package `server-aided-SNARK 0.1.0` |
| `license` | `null`; no license file or Cargo license declaration at the pinned commit |
| `build_status` | debug tests pass; release/all-features tests fail one `should_panic` test |
| `supported_platforms` | not declared; audited only on Ubuntu 22.04 WSL x86_64 |
| `supported_curves` | generic Arkworks `CurveGroup`; EMSM benches use BN254 G1; unit tests also use BLS12-381 |
| `supported_security_levels` | published concrete table for 100-bit dual-LPN security only |
| `semi_honest_implementation_available` | yes, low-level library path |
| `malicious_implementation_available` | partial benchmark composition only; no complete malicious protocol API/check |
| `parameter_generator_available` | no generator found in the official repository |
| `Android/aarch64_support` | not declared and not tested by the official artifact |
| `external_source_verification` | available |

## Repository audit

The pinned repository has no README, release tag, license file, checked-in
`Cargo.lock`, examples directory, Android documentation, or serialization/wire
protocol for EMSM. Its default feature enables Rayon parallelism. The resolved
core versions include:

- `ark-bn254 0.4.0` at curves revision `8c0256a`;
- `ark-ec 0.4.2`, `ark-ff 0.4.2`, and `ark-serialize 0.4.2` at algebra revision
  `2a80c54`;
- `ark-std 0.4.0`.

The official EMSM code is in:

- `src/emsm/emsm.rs`;
- `src/emsm/raa_code.rs`;
- `src/emsm/dual_lpn.rs`;
- `src/emsm/sparse_vec.rs`;
- `src/emsm/pederson.rs`.

## Fidelity gaps between paper and artifact

The current paper Table 2 gives `t=1178` at `n=2^15`. The pinned artifact
benchmarks use `2*298=596` at that length (and another benchmark uses 588).
Those values are stale relative to the current paper and are not accepted as
published parameters.

The paper defines the error distribution as uniform over weight-`t` vectors.
Artifact `SparseVector::error_vec` chooses one position from each fixed chunk.
That is not the same distribution. A faithful port must follow the paper unless
the authors publish a proof covering the chunked sampler.

The malicious benchmark constructs two masks and two server MSMs, but it does
not execute the final paper check `dm_ck == c * dm`. Therefore it is not a
complete malicious baseline.

The artifact's EMSM unit test compares the recovered point to the negation of
the plaintext MSM. That sign convention must be resolved before integration;
the paper's Figure 2 defines subtraction without this unexplained negation.

## Excluded sources

Local analytical EMSM prototypes, prior ThinWallet notes using `t=100` or
`t=128`, blogs, unattributed forks, and hand-derived short-row parameters are
not authoritative baseline sources.

