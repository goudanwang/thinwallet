# Phase V4D Artifact Evaluation Plan

## Environment

Use the recorded WSL environment and the locked Rust dependencies. Run from
`experiments/libspartan`. Cgroup tests require root only to create transient
systemd services; the prover itself runs as user `ubuntu`.

## Verification

```bash
./scripts/check_v4d.sh
python3 ../credential_workloads/collect_v4d_metrics.py
```

Expected executed checks are fmt, Clippy, workspace release tests,
preprocessed-PBMO tests, patched-Spartan tests, Profile-S audit, and PBMO token
security smoke tests. JSON files must parse with `python3 -m json.tool`.

## Memory Gate

```bash
sudo ./scripts/run_v4d_gate.sh 248 1 5
```

Each repetition must have prover exit 0, unchanged verifier exit 0, OOM and
OOM-kill counters 0, swap 0, the expected proof SHA-256, and cgroup peak no
larger than 248 MiB. The 240 MiB result is a single exploratory run, not a
five-run stable boundary.

## Identity

Compare E0, FS6, and FS7 proof SHA-256 values. For the S-W4 trace fixture,
compare all 12,250 JSONL events and the transcript SHA-256. Do not normalize or
re-serialize proof/transcript files before hashing.

## Limitations

The V4D-specific compact witness and multi-credential revocation security tests
are absent and must remain reported as incomplete. Do not execute Android as
part of this desktop artifact evaluation.
