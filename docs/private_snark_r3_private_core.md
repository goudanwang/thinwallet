# R3 Private Core

The phone computes a small private nonlinear core over selected entries `x_S`.

Implemented core types:

- `product`: `z = product_{i in S} x_i`;
- `low_degree_poly`: `z = sum alpha_i x_i^2 + beta_i x_i + gamma`;
- `range_toy`: toy bit-decomposition check over a small number of values.

The prototype records:

```text
R3_PRIVATE_CORE_CORRECT
R3_PRIVATE_CORE_SCALES_WITH_SMALL_S
```

For committed mode with `N=16384`, `q=8`, `descriptor=sparse`, `core=product`:

| s | Private core ops | Core ms | Phone online ms |
| ---: | ---: | ---: | ---: |
| 1 | 1 | 0.001 | 0.001 |
| 4 | 4 | 0.002 | 0.002 |
| 16 | 16 | 0.006 | 0.006 |
| 64 | 64 | 0.019 | 0.019 |

This confirms the intended toy behavior: private core cost scales with `s`, not
full `N`.

The L0 path reveals `z` and is marked:

```text
PRIVATE_CORE_REVEALED_IN_TOY
R3_L0_CORRECTNESS_ONLY
```

The L1 path commits to `z` but does not prove it soundly yet:

```text
R3_L1_CORE_COMMITMENT_PLACEHOLDER
PRIVATE_CORE_SOUNDNESS_OPEN
```
