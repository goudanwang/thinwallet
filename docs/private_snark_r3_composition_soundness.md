# R3 Small-Core Composition Soundness

The unified transcript order is:

1. protocol domain fixed;
2. request digest fixed;
3. `T` fixed;
4. R3 linear transcript digest fixed;
5. `S` and canonical `S_digest` fixed;
6. selected `A_i` fixed;
7. private core type and public parameters fixed;
8. `C_z` fixed;
9. activation fixed;
10. opening/core proof first messages fixed;
11. Fiat-Shamir challenges derived;
12. responses appended.

All component proofs absorb:

```text
request_digest
T
R3_linear_transcript_digest
S_digest
private_core_type
C_z
activation_digest
```

The composition verifier checks opening PoK, batched opening PoK, linear core
proof, activation binding, canonical `S`, and the frozen R3 linear path marker:

```text
R3_LINEAR_PATH_FROZEN
```

Attack tests:

```text
R3_SMALL_CORE_ATTACK_TESTS_PASS
```

All 25 required mutation/replay/malformed cases are rejected in the implemented
linear-core toy.

Open issue:

```text
SELECTED_COMMITMENT_MEMBERSHIP_OPEN
```

The verifier needs an authenticated way to know selected `A_i` belong to the
committed vector anchored by `T`.
