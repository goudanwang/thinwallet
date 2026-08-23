# R3 Sumcheck/IOP Prototype

R3 explores whether a Sumcheck/IOP-style proof system can make large prover
messages linear in the private state, so that a single semi-honest server can
compute them over masked or committed state while the phone handles only a
small nonlinear private core.

This is not Groth16 prover outsourcing, arbitrary R1CS private proving, or
issuer-native committed credential architecture.

The current result is a custom IOP/proof-bundle prototype:

```text
R3_SUMCHECK_BASELINE_PASS
R3_MASKED_LINEAR_MODE_CORRECT
R3_COMMITTED_LINEAR_MODE_CORRECT
R3_PRIVATE_CORE_CORRECT
R3_PROOF_BUNDLE_VERIFIES_IN_TOY_MODE
R3_NEGATIVE_TESTS_PASS
```

Final classification:

```text
R3_PROMISING_COMMITTED_LINEAR_CUSTOM_BUNDLE
```

## Sumcheck Baseline

| k | N | Correct | Prover ms | Field ops | Transcript bytes |
| ---: | ---: | --- | ---: | ---: | ---: |
| 4 | 16 | yes | 0.115 | 60 | 1,295 |
| 8 | 256 | yes | 0.205 | 1,020 | 2,364 |
| 10 | 1,024 | yes | 0.752 | 4,092 | 2,902 |
| 12 | 4,096 | yes | 2.213 | 16,380 | 3,435 |

## Representative Case

For `N=16384`, `q=32`, `s=64`, `descriptor=sparse`, `core=product`:

| Mode | Phone ms | Phone field ops | Server ms | Communication | Bundle bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| R3-M masked | 0.634 | 320 | 0.730 | 525,312 B | 4,964 |
| R3-C committed | 0.019 | 64 | 60.533 | 1,088 B | 5,024 |

The committed mode is promising for phone online asymmetry, but only as a
custom proof bundle. It is not a standard SNARK proof.
