# ThinWallet Lightweight Supplementary Experiment Report

Date: 2026-08-23

## Scope

- Offline only: no network access, dependency installation, phone execution, or formal proving campaign.
- WSL toolchain: `cargo 1.92.0`, `rustc 1.92.0`, `python 3.10.12`.
- New code is confined to `experiments/lightweight_tests/`; production sources were not edited.
- The only proving performed was a small `log_size=12` synthetic host integration check.

## 1. Standalone Verifier

**Result: PASS, 30/30 found proofs independently verified; missing headline proofs: 0.**

The audit found all 30 measured DEVICE-S23 proof files: H1/H2 x Memory-local, Selected (Memory-remote), and PBMO-enabled (Full-remote), five repetitions per cell. Each proof is 155,632 bytes. `results/standalone_verifier.csv` contains one record and proof SHA-256 per run.

The standalone executable is `thinwallet-standalone-verifier`, SHA256 `d864905064415fd60bfda8708f99cf353a9670ee8e4f51e09c280f12648fcf87`. It is a separate process and does not invoke `phase_v2_pbmo`. It links only the vendored baseline verifier identified as `spartan-baseline-testable-0.9.0-tree-sha256:64028097e7122bb7f50a4ad77e23a967f74cbce9a2eaf244164c8c38c574a921`.

No standalone public-input byte file was stored per run. The verifier reconstructed inputs and the public relation from the saved authenticated credential source, checked the source's domain-separated public-input digest, then independently encoded the public instance. The resulting raw concatenated-input SHA256 is H1 `2ce6310448458261065c5d6ff577597886db4f81f45e8ea2bdae3fabf1eb3995` and H2 `e778b6dc20ca83f3e66038dc1010d4ddb44d1ccf26a55744034653014081ab46`.

Proof manifest (full paths are `experiments/android_phase5f_c/results/runs/<run_id>/proof.bin`):

- H1 M1: r1 `edc44cd2c74c8bddb628dde3ee7c5b3d698e8de380f5e7cbf07d4e1875342606`; r2 `c78b23e08a1b2d1412a7cd47f5b04e94e966c243af515485c45f9075179812c1`; r3 `c4d0284a5f525226f8d56bdb80b661f3d636138aed0ae5e413af7abbaa0dbc52`; r4 `0f5ce1ea20bad6863182d98685b670b02286b6ec255345178dfe6995eff635f3`; r5 `f31071e2dfe47d52e421bb84a801b45d0ac392102139a6238eb0ce0b0a02a3df`.
- H1 M2: r1 `9bbf217a3bdbcbd80952ad7e47a2114a7524a15bbca1c199cb95fe44e2de720a`; r2 `1c0f2f33b40a1c7f342a17f8ce836ca45e6a12ccd347412b46cc849e6d6b5bc4`; r3 `cd9d4cf1acfedde9b523cf7448b7a22bb6901fd5e4b5e6c23beea581992c8836`; r4 `376cea28df9b69285d1131e4fb2770d56b6ab1f8a31aa8d4163c7a621eb44c77`; r5 `a3884b8e88168de0fe9e48ed0e52a03cf4ff17831598884256fda5acf1c14f15`.
- H1 M4: r1 `abad9aad80cb6e8575fe511c968815063e60af657d28b9c4d43931677d967580`; r2 `eb3f698b787e505a5f176ef9f7a1fe99d34197619c37cb3232d21d15d2185784`; r3 `078c13956bcca908ff1b9d50741f92b9805f30fb33bf84771b83995b30b2e76a`; r4 `aaf6717d503989a303222931de8c30740761ea98de3976090e884bca0cc27548`; r5 `e8266d41ceed68543919583cdcb8e1584dc9d8060dc4c499f96ff2c0bb90a7e4`.
- H2 M1: r1 `a5e7f5d0b0c0ac4caa870fd89428d08a485cfc8a4ac1c0ab23708962a1312f67`; r2 `db2891be68ac438d23ad67fe78200dece7cc04e79221005152843f92b6544af0`; r3 `435eea16ce027771ab51e777ecdb2b0f01d8e191e77328ad70b28787ef64d9a7`; r4 `95bde1b2836b6f2e551ac4a1d0dadb365371a381e80af078e321385d310cb908`; r5 `34a1239fe7bc4bdf5d92fcfbdd010b92b781696bcce59a01284bc7a7cc650f71`.
- H2 M2: r1 `ed7cfa00ff1628547809b48ee96434ba779bd75cc2fd5d60c13f3cd8fc8e92b8`; r2 `b8f1f174f9d956f0404b06d2df83ed2b85c62cf10a416abc8e381e2e725f9ee9`; r3 `bb1ddcb2116af86e933ba30543fd50e85791d11c9bc1a6520ac271725a4fcdc5`; r4 `c1a4f554fe160e9dde5be738cf41344767d207be19f9443c74b2cb6af66ebbbc`; r5 `6d868ce947aa954efb98d58239091bdbab1b1d18e33cf7e905995ce667a8531e`.
- H2 M4: r1 `acdc907353a635822585c95baddb7ed40c8bc089df5ee97d3287de425a48a20d`; r2 `eb889cc501c1b6a5482d660442869f19151c491c5d0e1ac9a5e04a87c4a3a7ea`; r3 `a1703df45e32a4b77f353f2074a2b66177b7d4c891e267554a21287b505b7eb1`; r4 `2937c0c1652351a103e5a8669cbae063ea589d6087514a0572cdd786a38e24bf`; r5 `932a8a59ae553c44a993b5dc5ed3c5fed931e82abc722d7aae780cf0a9447bea`.

## 2. Selected-Path Tests

**Result: PASS, 3/3.** Full commands and assertions are in `results/selected_path_tests.txt`.

1. `selected_without_pbmo`: actual host client/server run used low-residency streaming, local row MSM, one ARE request, native Eval verification, and full baseline/patched verification. Local Eval calls were zero. No PBMO token, token file, journal, store, load, or generation occurred.
2. `selected_are_fail_closed`: malformed Eval proof, response bound to another invocation, and completed-invocation replay were each rejected; no proof file was released and stderr recorded “without local fallback.”
3. `pbmo_release_after_verify_and_spent`: an actual small loopback PBMO run passed patched and baseline full verification, observed durable `SPENT`/`TOKEN_FINALIZED`, and released a proof. The current source orders patched verification, baseline verification, `mark_spent`, then proof write.

Test binaries: client SHA256 `bbf75bb54fd3380b0aab760377ae0101714176bbe491a6f85b8989417ddc2b6b`; ARE server `ae7204a4ca94bc76d372c6fecc768c59819eb9a0c35faf97d7e0597aa97ccc46`; PBMO client `306a9537301be7a8707f9821e6f3d631e6a4540ed667647eee561fba1634a8a5`.

## 3. Selected Versus PBMO-Enabled Recalculation

Statistics are mechanically computed from existing formal records: wall and process CPU are medians over n=5; PSS and VmHWM are maxima over n=5; delta is PBMO-enabled minus Selected. PBMO provisioning is a separate n=5 campaign and is excluded from the request-critical wall/CPU values.

| Workload | Selected / PBMO wall s (delta) | Selected / PBMO CPU s (delta) | Selected / PBMO peak PSS MiB (delta) | Selected / PBMO VmHWM MiB (delta) |
| --- | --- | --- | --- | --- |
| H1 | 102.710431002 / 102.475289544 (-0.235141458) | 65.480137330 / 63.775621197 (-1.704516133) | 203.369140625 / 198.728515625 (-4.640625000) | 210.765625000 / 210.972656250 (+0.207031250) |
| H2 | 101.866143815 / 101.252543451 (-0.613600364) | 64.394170279 / 62.961266145 (-1.432904134) | 199.711914062 / 198.165039062 (-1.546875000) | 205.601562500 / 205.558593750 (-0.042968750) |

- ARE request/response medians are identical between Selected and PBMO-enabled: H1 136,972/126,736 bytes; H2 130,828/126,736 bytes.
- PBMO upload median: H1 8,831,496 bytes; H2 8,831,495 bytes.
- PBMO provisioning median wall / maximum PSS: H1 3.837705311 s / 84.281250 MiB; H2 3.822890675 s / 79.437500 MiB.
- Every formal PBMO-enabled row loads one preprovisioned token and records zero online token generation. Therefore the small negative request-window deltas do not include provisioning and do not establish an end-to-end PBMO benefit.

## Data Integrity

- `experiments/android_phase5f_c/honest_runs.json`: SHA256 `6410a84495cdaab4e163c1dc6a54f5552faae39db8cec71d367d0afc21114dc2`.
- `experiments/pbmo_preprocessing/pbmo_preprocessing_summary.json`: SHA256 `67d339d6ba4f340ce286477e05be8e0dd570bd0e33ab548cb11b30c6928f4d40`.
- H1 credential source: SHA256 `ba1e8a97acf058cb136a42cab540425e59e67be9e8459f1a4f1aeda6acb77412`; H2 source: `5953512b05281841d42a7f0dca6d0c807aa34a72066d45560532ef553715a01d`.
- PBMO transport H1 r1-r5 SHA256: `3cd0dbd230978a1f0767a47608f65308b6b0c67a68564113105c33f655f8dcfa`; `2eec67fd336b891bf32fbf13ac55a758c7a113b8ba83ebf6abab27aaea150156`; `d85ee698cc13695ac8c477e6143643b67c5536d67c72616f634fb16cda902c3c`; `89f82fd803007144f9ff42078e33780548dba06d573c754cef3a210010f001c6`; `f71902b9da0f7c33e4f889e1f2a56f0e0c212e896d1e5721fea5d618449e6bd0`.
- PBMO transport H2 r1-r5 SHA256: `ccd62def4afd7243ad53e07420510f1cf9ac9e356d2712d63c909b7054b41676`; `dcff146f39b5a4dfb4588f77a72ee1c9f90e0f889c1bd462d883636881aebd98`; `27a16b2a3dc53db3c54f01a792ed4fde4fdd1f84f31a8a3370f9e6ce8ec3d167`; `525b5612abcc8cba7ecc76504d08e568401823edf7a6e2b241dc3edd7abbb630`; `b6a4079e7c10feaf95975e6b11e25fdc3a99da25acc8f499b762272ad4cbdece`.
- Production sources inspected by tests: `phase_v2_pbmo.rs` SHA256 `4acc9de2a26687aac1203461751c107acc42fae030a43cf446b5d6e5b3c4fb1b`; `remote_eval.rs` SHA256 `a798bdce3680e1e6266fdfb77901b8283e8a1fc62b06192dd7119afc19f57ebe`.
- Outputs: `results/standalone_verifier.csv` SHA256 `646704f11bc65a24a61f85a9d61d2612a5bb749d1259a9e18870654a8535c72d`; `results/selected_path_tests.txt` `6b5d518eb9171fdf83971232368fdae645c61e51e4d6132ab2fcd9cdb0072391`; `results/selected_vs_pbmo.csv` `c19789be9aeb2d178d736d1be928c37d87cd1e141b0a660aa20f9ce779a94108`.

## Remaining Partial Conclusions

- **PARTIAL:** public inputs were reproducibly reconstructed and checked against the authenticated source digest, but original per-run serialized input files were not retained.
- **PARTIAL:** Selected-path and PBMO release tests use a small synthetic host relation, not H1/H2 on Android.
- **PARTIAL:** standalone compatibility is pinned by a source-tree hash, not a recoverable upstream Git commit or separately distributed verifier release.
- **PARTIAL:** n=5 formal differences are unpaired and provisioning is a separate campaign; they do not prove PBMO has positive or negative end-to-end production value.
