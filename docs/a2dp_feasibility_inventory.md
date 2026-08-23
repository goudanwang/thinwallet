# A2DP Feasibility Inventory

This document records the current repository state for a feasibility experiment on A2DP (Asymmetric Two-Party Delegated Proving). It is an inventory only: no protocol implementation, dependency installation, or code changes have been performed.

## 1. Repository Languages, Build System, and Directory Structure

### Languages

The current repository contains Markdown documentation only.

Detected file types:

| File Type | Current Use |
| --- | --- |
| Markdown (`.md`) | Research definition and related-work analysis |

No Rust, TypeScript, JavaScript, Circom, C/C++, Python, Solidity, Android, or iOS source files are currently present in the repository.

### Build System

No build system is currently detected.

Not present:

* `Cargo.toml`
* `package.json`
* `pnpm-lock.yaml`
* `yarn.lock`
* `package-lock.json`
* `Makefile`
* `CMakeLists.txt`
* Gradle build files
* Circom project files
* SnarkJS artifacts

### Directory Structure

Current repository structure:

```text
.
└── docs/
    ├── project_definition.md
    ├── related_work_evidence.md
    └── related_work_matrix.md
```

The repository currently has no `src/`, `circuits/`, `experiments/`, `scripts/`, `test/`, or `benchmarks/` directory.

## 2. Existing zkSNARK or Circuit Implementation

No zkSNARK implementation, circuit implementation, witness generator, proving script, verifier, or benchmark harness is currently present.

The project definition states a tentative MVP direction using Groth16 and an `age >= 18` credential presentation circuit, but this is a design target rather than implemented code.

## 3. Existing Proving Backend Inventory

Because no circuit or proving backend is present, the following fields are currently not applicable.

| Item | Current Repository Status |
| --- | --- |
| Proving backend | Not present |
| Constraint system | Not present |
| Curve | Not present |
| Witness generation entry | Not present |
| Setup entry | Not present |
| Prove entry | Not present |
| Verify entry | Not present |
| How to obtain constraint count | Not available from current repository |
| How to measure witness size | Not available from current repository |
| How to measure proving time | Not available from current repository |
| How to measure peak RSS | Not available from current repository |

For a future Circom 2 + SnarkJS experiment, these measurements can be made reproducibly with generated R1CS/WASM artifacts and external measurement tools, but no such artifacts exist yet in this repository.

## 4. Existing Primitive or Gadget Inventory

No implemented primitives or gadgets were found.

| Primitive / Gadget | Current Repository Status |
| --- | --- |
| Issuer signature verification | Not present |
| Holder signature verification | Not present |
| Poseidon or other SNARK-friendly hash | Not present |
| Range comparison | Not present |
| Selective disclosure | Not present |
| Merkle/revocation proof | Not present |

The research documents mention holder authorization, issuer signatures, selective disclosure, `age >= 18`, and possible revocation mechanisms as design requirements or open decisions. They do not provide executable circuits or reusable gadgets.

## 5. Best Location for an Independent Experiment

The best location for an isolated feasibility experiment is:

```text
experiments/a2dp-circuit/
```

Rationale:

* The current repository has no implementation directories, so an `experiments/` namespace keeps exploratory artifacts separate from research documents.
* `a2dp-circuit/` is narrow enough to hold circuit-level experiments without implying a finished protocol implementation.
* The directory can later contain a self-contained README, dependency manifest, circuits, inputs, scripts, generated artifacts, and measurement notes.
* Keeping the experiment isolated reduces the risk of confusing a quick R1CS feasibility study with the final mobile implementation stack.

Suggested future layout, not created in this task:

```text
experiments/a2dp-circuit/
├── README.md
├── package.json
├── circuits/
├── inputs/
├── scripts/
├── build/
└── measurements/
```

## 6. Recommended Minimum Experiment Backend

Because the repository does not currently adopt any circuit/proving backend, the recommended minimum backend is:

```text
Circom 2 + circomlib + snarkjs
```

Recommended proof path:

| Component | Recommendation | Reason |
| --- | --- | --- |
| Circuit language | Circom 2 | Fast path to reproducible R1CS experiments |
| Gadget library | circomlib | Provides common SNARK-friendly building blocks such as Poseidon and comparators |
| Proving backend | SnarkJS Groth16 | Aligns with the project definition's initial Groth16 MVP |
| Curve | BN254, unless a later experiment requires another curve | SnarkJS Groth16 commonly supports this path and it is adequate for early R1CS decomposition |
| Constraint system | R1CS | The immediate goal is constraint decomposition and measurement, not final mobile stack selection |

This recommendation is for feasibility measurement only. It should not be treated as a final decision for the mobile wallet, cloud prover, confidential component, or production credential format.

## 7. Measurement Plan for the Recommended Backend

The current repository cannot yet perform these measurements, but the future experiment should collect them in a repeatable way.

| Measurement | Future Method |
| --- | --- |
| Constraint count | Use the generated R1CS metadata, for example via SnarkJS R1CS inspection commands |
| Witness size | Measure generated witness file size and, if needed, count witness field elements from the witness artifact |
| Witness generation time | Time the witness generation command separately from setup/prove/verify |
| Proving time | Time Groth16 proof generation separately from witness generation |
| Verification time | Time local verification separately |
| Peak RSS | On Linux, run witness generation and proving under an external peak-memory tool such as `/usr/bin/time -v`; on Windows, use a separate process monitor or run the benchmark in Linux/WSL for comparable RSS reporting |
| Artifact sizes | Record R1CS, WASM, proving key, verification key, witness, proof, and public-input sizes |

The experiment should avoid mixing witness generation time with proving time unless the measurement explicitly reports an end-to-end number.

## 8. Current Missing Dependencies

No dependency declarations are currently present in the repository.

If the recommended backend is adopted later, the experiment will need dependency declarations or installation instructions for:

* Circom 2 compiler;
* Node.js package manifest for SnarkJS tooling;
* `snarkjs`;
* `circomlib`;
* a deterministic script runner, such as npm scripts or a Makefile;
* a Linux-compatible peak RSS measurement tool for reproducible memory measurements.

These dependencies have not been installed or added in this task.

## 9. Immediate Next Files to Create Later

The next implementation-preparation step should create only experiment scaffolding, not the A2DP protocol itself.

Recommended next files:

```text
experiments/a2dp-circuit/README.md
experiments/a2dp-circuit/package.json
experiments/a2dp-circuit/circuits/age18_presentation.circom
experiments/a2dp-circuit/inputs/sample_age18_input.json
experiments/a2dp-circuit/scripts/measure.sh
experiments/a2dp-circuit/measurements/README.md
```

The first circuit should be intentionally small and measurement-oriented: an issuer-bound credential stub, a holder-authorization stub, an `age >= 18` range check, and explicit public inputs for verifier, nonce, predicate identifier, disclosure set, credential reference, and protocol version. Any real signature scheme, revocation mechanism, or split-prover protocol should be added only after the baseline constraint and measurement harness are stable.
