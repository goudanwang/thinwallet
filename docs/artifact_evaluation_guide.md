# Artifact Evaluation Guide

## Environment

Use Ubuntu 22.04 under WSL and the repository-pinned Rust toolchain. Phase V4C
is desktop-only. No Android command or physical-device result is part of this
artifact.

## Frozen Baseline

`archive/phase_v4b_real_credentials/` contains 515 V4B files. Verify exact
content with `MANIFEST.sha256`; its SHA-256 is
`0db48faf2db439712477fc5573ac60952f6dcb30a1cd585c2f2d986b9d6fec5b`.

## Build And Security Tests

```bash
cd experiments/libspartan
cargo build --release --bin phase_v2_pbmo --bin phase_v4c_profile_s
./target/release/phase_v4c_profile_s \
  ../credential_workloads/results/v4c/profile_s_audit.json
cargo fmt --all -- --check
cargo test --release
cargo test --release --manifest-path ../preprocessed-pbmo/Cargo.toml
```

## Full Evaluation

```bash
cd experiments/credential_workloads
python3 run_v4c_evaluation.py
python3 benchmark_v4c_verifier.py
python3 collect_v4c_metrics.py
```

Raw runs are in `results/v4c/runs/`. Machine-readable outputs are
`profile_s_audit.json`, `verifier_benchmark.json`, `phase_v4c_results.json`, and
`phase_v4c_summary.json`. Trace repetitions use ID 901; headline repetitions
1-5 deliberately have tracing disabled. The earlier failed log-17 attempts use
ID 902 and preserve the CLI allow-list error; successful corrected runs use ID
903.

Expected W4 cap behavior is controlled rejection at 128/192 MiB and completion
at 224/256 MiB. Re-runs produce new timing values and must not overwrite the
interpretation of archived measurements.
