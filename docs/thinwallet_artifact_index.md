# ThinWallet Artifact Index

Commands run from the repository root unless noted.

| Artifact | Purpose | Phase | Reproduction command | Expected marker |
| --- | --- | --- | --- | --- |
| `theory/joint_credential_presentation.md` | Joint relation and RevSet definition | V4E | Documentation review | `JOINT_CREDENTIAL_PRESENTATION_FORMALIZED` |
| `theory/workload_parameterization.md` | Canonical `WK(k,r,d,backend)` | V4E/V4F | `cargo run --release --bin phase_v4e_credential_source` | Workload semantics frozen; V4F matrix complete |
| `theory/authenticated_credential_source.md` | Source format/security boundary | V4E | Same V4E audit command | Auth/source tests in JSON |
| `experiments/libspartan/src/credential_source/mod.rs` | AEAD source, replay and journal | V4E | `cargo test --release` in `experiments/libspartan` | Tests exit 0 |
| `experiments/libspartan/src/credential_workloads/profile_s.rs` | Profile S and WC/WR relations | V4C/V4E | V4E audit command | Scaling arrays emitted |
| `experiments/libspartan/src/profile_s_issuance.rs` | Ed25519 issuer package/security tests | V4C | `cargo run --release --bin phase_v4c_profile_s` | V4C pass marker |
| `experiments/preprocessed-pbmo/src` | PBMO implementation and token lifecycle | V2 | `cargo test --release --manifest-path experiments/preprocessed-pbmo/Cargo.toml` | Tests exit 0 |
| `experiments/libspartan/vendor/spartan-0.9.0/src` | FS execution paths and memory operators | V3/V4D | `cargo test --release --manifest-path experiments/libspartan/Cargo.toml` | Tests exit 0 |
| `experiments/credential_workloads/results/v4d` | Proof/transcript/memory fixtures | V4D | `python3 experiments/credential_workloads/collect_v4d_metrics.py` | V4D summary JSON |
| `experiments/credential_workloads/results/v4e/phase_v4e_semantic_audit.json` | Auth source, identity and WC/WR audit | V4E | V4E audit command | Current classification field |
| `docs/v4e_desktop_semantic_status.md` | Completed/null V4E result boundary | V4E | Documentation and JSON cross-check | `PHASE_V4E_EVALUATION_INCOMPLETE` |
| `archive/phase_v4d_pre_semantic_cleanup` | Immutable pre-cleanup hash index | V4E | `powershell -NoProfile -File archive/phase_v4d_pre_semantic_cleanup/generate_manifest.ps1` | `PHASE_V4D_PRE_SEMANTIC_STATE_FROZEN` |
| `docs/thinwallet_technical_challenges.md` | TC1-TC18 ledger | V4E | Documentation review | `THINWALLET_TECHNICAL_CHALLENGE_LEDGER_COMPLETE` |
| `docs/thinwallet_design_evolution.md` | Decision history | V4E | Documentation review | `THINWALLET_DESIGN_EVOLUTION_COMPLETE` |
| `docs/thinwallet_memory_optimization_timeline.md` | Metric-qualified memory timeline | V4E | Documentation review | `THINWALLET_MEMORY_TIMELINE_COMPLETE` |
| `docs/thinwallet_paper_challenge_compression_map.md` | Four-group drafting map | V4E | Documentation review | `THINWALLET_FOUR_CHALLENGE_COMPRESSION_MAP_COMPLETE` |
| `archive/phase_v4e_functional_complete` | Frozen V4E functional state | V4F | Verify `SHA256SUMS` | `PHASE_V4E_FUNCTIONAL_STATE_FROZEN` |
| `results/v4f/raw/runs` | Per-run V4F resource, latency, proof, and verifier records | V4F | `experiments/libspartan/scripts/run_v4f_evaluation.sh all` | Headline/composition/revocation matrices complete |
| `results/v4f/json` | Machine-readable V4F paper tables | V4F | `python3 experiments/libspartan/scripts/collect_v4f_results.py` | Eleven JSON tables |
| `results/v4f/csv` | CSV V4F paper tables | V4F | Same collector | Eleven CSV tables |
| `results/v4f/markdown` | Markdown V4F paper tables | V4F | Same collector | Eleven Markdown tables |
| `results/v4f/latex` | LaTeX V4F paper tables | V4F | Same collector | Eleven LaTeX tables |
| `results/v4f/security_regression.json` | Source, Profile S, PBMO, and release-test regression | V4F | `experiments/libspartan/scripts/run_v4f_security.sh` | `FINAL_DESKTOP_SECURITY_REGRESSION_PASS` |
| `results/v4f/evaluation_summary.json` | V4F gate summary | V4F | V4F collector | `FINAL_DESKTOP_PLANNER_VALIDATION_FAIL` |
| `docs/v4f_desktop_evaluation.md` | Final desktop methodology and result boundary | V4F | Documentation/table cross-check | `PHASE_V4F_PLANNER_VALIDATION_FAILED` |
| `archive/phase_v4f_evaluation_complete` | Frozen trusted V4F execution evidence before planner correction | V4G | Verify `SHA256SUMS` | `PHASE_V4F_MEASURED_RESULTS_FROZEN` |
| `planner/models/process_memory_v4g.json` | Frozen phase-aware process VmHWM model | V4G | Verify adjacent SHA-256 file | `V4G_PROCESS_MEMORY_MODEL_FROZEN` |
| `planner/models/cgroup_memory_v4g.json` | Separate conservative cgroup admission model | V4G | Verify adjacent SHA-256 file | `PROCESS_AND_CGROUP_PLANNERS_SEPARATED` |
| `experiments/v4g/calibration_set.json` | 13-point, three-repetition calibration set | V4G | `python3 experiments/v4g/fit_phase_model.py` | `V4G_PLANNER_CALIBRATION_SET_COMPLETE` |
| `experiments/v4g/final_held_out_plan.json` | Precommitted ten-point validation plan and predictions | V4G | Verify adjacent SHA-256 file before execution | `FINAL_HELD_OUT_PLAN_PRECOMMITTED` |
| `results/v4g` | Raw V4G runs, validation gates, and seven paper tables | V4G | `python3 experiments/v4g/collect_v4g_results.py` | `V4G_PLANNER_PAPER_TABLES_GENERATED` |
| `docs/v4g_cgroup_accounting_analysis.md` | Tight-cap saturation diagnosis | V4G | Cross-check 2 GiB diagnostic sidecars | `CGROUP_PEAK_SATURATION_EXPLAINED` |
| `docs/v4g_planner_residual_analysis.md` | Frozen seven-point residual attribution | V4G | Cross-check original comparison JSON | `PLANNER_RESIDUALS_EXACTLY_ANALYZED` |
| `archive/thinwallet_desktop_release_candidate` | Frozen desktop source, evidence, security, planner, and handoff package | V4G | `sha256sum -c SHA256SUMS` inside the archive | `THINWALLET_DESKTOP_RELEASE_CANDIDATE_FROZEN` |
| `docs/android_*` and `scripts/android` | Physical-device handoff only | V4F/V5A | Requires explicit authorization | No Android execution |
| `android` | ARM64 cross-build artifacts only | V4D | Existing Android build instructions | Build marker only; no execution marker |

Security games and negative results are indexed through the PBMO source/tests,
V1 audit artifacts, Profile S security matrix, and V4E `security_tests` array.
V4F deterministic headline fixtures are frozen under
`results/v4f/headline_fixtures`. V4F did not create a release candidate while
its planner exceeded 5%; V4G created the desktop archive only after both
held-out gates and headline cap revalidation passed.

`THINWALLET_ARTIFACT_INDEX_UPDATED_V4G`

## V5A Physical Android Artifacts

| Artifact | Purpose | Status |
| --- | --- | --- |
| `results/v5a/device` | Sanitized authorization and device profile | Physical ARM64 gate passed |
| `results/v5a/raw/runs` | 75 Android run records and memory/thermal traces | S-W1/S-W4/H0/H1/H2 plus sustained sequences |
| `results/v5a/identity` | Cross-architecture proof/transcript and verifier evidence | Byte-identical pass |
| `results/v5a/tokens` | Twelve foreground token-generation batches | Token evaluation pass |
| `results/v5a/json`, `csv`, `markdown`, `latex` | Machine- and paper-readable summaries | Generated; network/crash gaps retained |
| `planner/models/process_memory_android_v5a.json` | Device-specific expected-value planner | Validation pass, not portable or kernel-enforced |
| `archive/thinwallet_android_device_v5a` | Sanitized frozen V5A evidence | Incomplete evaluation archive |

`THINWALLET_ARTIFACT_INDEX_UPDATED_V5A`
