# A2DP Measurement Plan

This document defines the common measurement format for all subsequent A2DP
circuit experiments. The goal is reproducible component-level accounting, not a
single ambiguous end-to-end runtime.

Do not merge benchmark phases into one aggregate time. Each reported result
must identify the exact phase being measured, the command or procedure used,
the included components, and the excluded components.

## Required Metrics

All A2DP circuit experiments must record the following fields. If a field cannot
be measured reliably by the current toolchain, write `null`; do not write `0`.

| Metric | Description |
| --- | --- |
| `total_r1cs_constraints` | Total R1CS constraints reported for the compiled circuit. |
| `nonlinear_constraints` | Nonlinear constraints, only if the tool can provide this reliably. |
| `wires` | Number of R1CS wires. |
| `public_inputs` | Number of public inputs. |
| `private_inputs` | Number of private inputs. |
| `outputs` | Number of circuit outputs. |
| `witness_elements` | Number of elements in the generated witness. |
| `witness_file_size_bytes` | Size of the `.wtns` file. |
| `witness_generation_ms` | Application witness generation time, measured separately. |
| `groth16_proving_ms` | Groth16 proof generation time, measured separately. |
| `verification_ms` | Proof verification time, measured separately. |
| `peak_rss_mb` | Peak resident set size for each measured stage. |
| `r1cs_file_size_bytes` | Size of the `.r1cs` file. |
| `wasm_file_size_bytes` | Size of the generated witness `.wasm` file. |
| `proving_key_size_bytes` | Size of the final proving key / `.zkey` file. |
| `verification_key_size_bytes` | Size of the verification key JSON file. |
| `proof_size_bytes` | Size of the proof JSON file. |
| `public_input_size_bytes` | Size of the public input JSON file. |

## Measurement Phases

Every experiment must distinguish these phases:

1. `application_input_preparation`

   Preparing application-level inputs before witness generation. This includes
   parsing credentials, selecting disclosures, building policy inputs, hashing
   request material, and any host-side formatting needed before invoking the
   witness generator.

2. `application_witness_generation`

   Generating the witness for the application circuit from prepared inputs. For
   Circom/snarkjs experiments, this is the witness generation command and must
   be measured independently from proving.

3. `extended_witness_generation`

   Any additional witness expansion, preprocessing, or derived witness material
   that is not part of the base application witness command. If no such step
   exists, record `null` and explain that it is not applicable.

4. `trusted_setup_preprocessing`

   Trusted setup or preprocessing work, including Powers of Tau preparation,
   Groth16 setup, proving-key generation, and verification-key export. This
   phase must not be hidden inside proving time.

5. `proof_generation`

   Groth16 proof generation from a proving key and witness. This must be timed
   separately from witness generation and verification.

6. `proof_verification`

   Verification of the proof against the verification key and public inputs.
   This must be timed separately from witness generation and proof generation.

## Benchmark Rules

Use the following fixed environment unless a later document explicitly updates
the baseline:

| Item | Version / value |
| --- | --- |
| Environment | WSL |
| Circom | 2.1.9 |
| Node | 20.15.1 |
| npm | 10.7.0 |
| Python | 3.10.12 |
| snarkjs | 0.7.5 |
| circomlib | 2.0.5 |
| Curve | BN254 / bn128 |

Benchmark requirements:

- Run each measured phase at least 5 times.
- Report raw data, mean, median, minimum, and maximum.
- Use `/usr/bin/time -v` to measure peak RSS where available.
- Measure witness generation, proving, and verification separately.
- Write `null` for fields that cannot be measured; do not write `0`.
- Do not subtract the sanity benchmark from application timings to estimate
  "real" performance.
- Treat the sanity multiplier only as a fixed-overhead reference for the
  toolchain.

## External Authentication Timing Modes

External holder authentication measurements must distinguish:

- `cold_process_cli_latency`: launching a new process and loading the runtime
  for each operation. Existing Candidate A signing and verification values near
  3.9 seconds are cold-process measurements.
- `one_time_cryptographic_initialization`: one-time Node module loading,
  circomlibjs/BabyJubJub/EdDSA builder initialization, Poseidon builder
  initialization, and key derivation before serving requests.
- `steady_state_per_request_latency`: repeated request digest, signing, and
  verification inside one already-initialized process.

The persistent external auth benchmark records:

| Metric | Value |
| --- | ---: |
| Process startup and library init | 4536.466 ms |
| Key derivation | 10.392 ms |
| RSS after initialization | 172.867 MB |
| Warm-up runs | 20 |
| Measured runs | 100 |
| Poseidon request digest mean | 0.109 ms |
| EdDSA-Poseidon signing mean | 14.797 ms |
| EdDSA-Poseidon verification mean | 14.700 ms |

The steady-state values must not overwrite the cold-process values; both answer
different measurement questions.

## Sanity Multiplier Baseline

The current sanity baseline is the `sanity_multiplier` circuit in
`experiments/a2dp-circuit`.

| Metric | Value |
| --- | ---: |
| Constraints | 1 |
| Witness times (ms) | `[42, 39, 39, 40, 40]` |
| Proving times (ms) | `[1711, 1719, 1701, 1689, 1752]` |
| Verification times (ms) | `[1243, 1213, 1229, 1223, 1219]` |
| Witness peak RSS (MB) | `[40.25, 40.375, 40.125, 40.25, 40.25]` |
| Proving peak RSS (MB) | `[212.027, 212.285, 211.66, 212.301, 211.938]` |
| Verification peak RSS (MB) | `[203.969, 204.109, 204.301, 203.867, 204.84]` |

Summary values for the comparison table:

| Stage | Mean ms | Median ms | Min ms | Max ms |
| --- | ---: | ---: | ---: | ---: |
| Witness generation | 40.0 | 40 | 39 | 42 |
| Groth16 proving | 1714.4 | 1711 | 1689 | 1752 |
| Verification | 1225.4 | 1223 | 1213 | 1243 |

| RSS stage | Mean MB | Median MB | Min MB | Max MB |
| --- | ---: | ---: | ---: | ---: |
| Witness generation | 40.25 | 40.25 | 40.125 | 40.375 |
| Groth16 proving | 212.04 | 212.027 | 211.66 | 212.301 |
| Verification | 204.217 | 204.109 | 203.867 | 204.84 |

These results mainly reflect fixed overhead from the CLI, Node, WASM execution,
file loading, and cryptographic library initialization. They must not be
interpreted as the actual cost of a single constraint.

## Credential Experiment Principles

Future credential experiments must follow these rules:

- The verifier specifies only policy, accepted issuer/schema, requested
  disclosure, nonce, domain, expiry, and context.
- The verifier does not specify a concrete credential ID.
- The holder chooses the credential.
- A stable credential ID is not used as a public input.
- Signature verification stubs that always return true are not allowed.
- Security components that are not implemented must be marked `BLOCKED` or
  `EXCLUDED`.
- Each component must support separate constraint accounting.
- Every result must state which components are included and which components are
  excluded.

## Unified Comparison Table

| Circuit                          | Constraints | Private inputs | Witness ms | Prove ms | Verify ms | Prove RSS MB |
| -------------------------------- | ----------: | -------------: | ---------: | -------: | --------: | -----------: |
| Sanity multiplier                |           1 |              2 |       40.0 |   1714.4 |    1225.4 |       212.04 |
| Age predicate                    |          98 |              1 |       43.6 |   1542.8 |    1132.0 |       217.09 |
| Request binding                  |         354 |              0 |       68.2 |   1512.4 |    1096.8 |       232.34 |
| Disclosure control               |          33 |              0 |       42.0 |   1542.8 |    1130.8 |       213.16 |
| Holder authorization             |        4504 |              5 |       90.4 |   1637.2 |    1098.6 |       422.10 |
| Credential-key binding           |         321 |              3 |       62.6 |   1537.2 |    1140.0 |       230.50 |
| Candidate A online presentation  |         804 |              4 |       78.0 |   1575.6 |    1128.8 |       252.64 |
| Online presentation              |        4987 |              6 |      107.4 |   1736.4 |    1137.0 |       433.04 |
| Baseline presentation            |         TBD |            TBD |        TBD |      TBD |       TBD |          TBD |
| Enrollment-compiled presentation |         TBD |            TBD |        TBD |      TBD |       TBD |          TBD |
