# Official artifact build report

## Identity

| Item | Value |
| --- | --- |
| repository | `https://github.com/h-hafezi/server-aided-snarks.git` |
| pinned commit | `41c6f7b856cb03131d405723df49a6fc33e2a452` |
| package | `server-aided-SNARK 0.1.0` |
| clone location | independent WSL directory `/home/ubuntu/codex-emsm-official/repo` |
| host | Ubuntu 22.04 WSL2 x86_64 |
| rustc | `1.92.0 (ded5c06cf 2025-12-08)` |
| cargo | `1.92.0 (344c4567c 2025-10-21)` |
| patches applied | none |

The official checkout was not copied into or linked as a ThinWallet dependency.
Cargo generated an untracked lock file for the independent build because the
official commit does not include one.

## Commands and results

```text
cargo test
exit status: 0
29 unit tests passed
2 doctests passed
```

```text
cargo test --release --all-features
exit status: 101
28 unit tests passed
1 unit test failed
```

The release failure is:

```text
emsm::pederson::tests::test_commitment_too_many_scalars
test did not panic as expected
```

The guard used by that test is a debug assertion, so it is disabled in a
release build. This is reported rather than patched. Compiler warnings also
identify undeclared `std`/`r1cs` cfg values and a module-level `no_std`
attribute that is not at crate root.

No official examples directory or executable example was present, so there
was no example command to run. Criterion benchmarks were intentionally not run
because Phase A forbids EMSM performance conclusions.

## Preserved logs

- `official-build/build_identity.txt`
- `official-build/rustc_vV.txt`
- `official-build/uname.txt`
- `official-build/cargo_tree.stdout`
- `official-build/cargo_tree.stderr`
- `official-build/cargo_test_debug.stdout`
- `official-build/cargo_test_debug.stderr`
- `official-build/cargo_test_release.stdout`
- `official-build/cargo_test_release.stderr`

## Build interpretation

The debug test result establishes that the pinned source compiles and its
included test suite runs in the audited WSL environment. It does not establish:

- agreement with the current paper parameter table;
- a uniform weight-`t` sampler;
- completion of the malicious acceptance check;
- an Android/aarch64 build;
- a Ristretto backend;
- an ordered `q`-row ThinWallet integration;
- production security or performance.

