# PBMO Cost Model And Baselines

Status markers: `PBMO_FORMAL_MODEL_COMPLETE`, `PBMO_BASELINES_FORMALIZED`

Let each row have `m` private scalars, let there be `q` ordered outputs, and let
an ordinary EMSM correction use sparse weight `t`. The `t=100` and `t=128`
columns below are analytical security-budget-matched weights, not validated
dual-LPN/RAA parameters.

## B0: Local MSMs

```text
C_j = MSM(Z_j,G)
client group terms = q*m
```

There is no upload and no outsourcing privacy issue, but the client performs
all group work.

## B1: Independent EMSM

For independently sampled masks `R_j=Enc(e_j)`:

```text
V_j = Z_j + R_j
Y_j = MSM(V_j,G)
D_j = MSM(e_j,h)
C_j = Y_j - D_j
```

Client correction terms are `q*t`, plus `q` output subtractions. Privacy can be
reduced row-by-row only if every EMSM instance, setup access, and reuse rule is
secure.

## B2: Flattened EMSM

Flattening `vec(Z)` can produce one masked scalar stream, but the target remains
`q` exact group outputs. A correction vector `(D_1,...,D_q)` is required. With
no additional structure, sparse correction support is row-local and expected
correction work remains `q*t`; returning one accumulated point changes the
functionality.

## B3: Identical Row Mask

```text
V_j = Z_j + r
D = MSM(r,G)
C_j = MSM(V_j,G) - D
```

The correction can be reused, but `V_j-V_k=Z_j-Z_k`. Its low group cost is not
a privacy baseline.

## B4: Rank-k Row Mask

```text
V = Z + A*B, A in F^(q x k), B in F^(k x m), k<q.
```

For every `c` in the left kernel of `A`, `c^T V=c^T Z`. At least `q-k`
independent row relations leak when `rank(A)<=k`. Public output mixing cannot
repair this defect.

## Decision Sizes

| q=m | B0 terms | B1/B2, t=100 | B1/B2, t=128 | Preprocessed online |
| ---: | ---: | ---: | ---: | ---: |
| 64 | 4,096 | 6,400 | 8,192 | 64 subtractions |
| 128 | 16,384 | 12,800 | 16,384 | 128 subtractions |
| 256 | 65,536 | 25,600 | 32,768 | 256 subtractions |
| 512 | 262,144 | 51,200 | 65,536 | 512 subtractions |
| 1,024 | 1,048,576 | 102,400 | 131,072 | 1,024 subtractions |

Preprocessing moves `q*m` mask-generation MSM terms (or equivalent setup work)
and `q` correction points offline; it does not eliminate them.

## Decision Gate

| Construction | Correction | Client RAM | Setup/client storage | Communication | Assumption | Proof changes | Risk |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Independent EMSM | `q*t` | streamable `O(t)` plus chunk | EMSM `h`/setup | `qm` fields + `q` points | per-row EMSM privacy | none if exact points recovered | high cumulative correction |
| Flattened EMSM | expected `q*t` | streamable | flattened setup | `qm` fields + `q` points | needs output-aware correction | none only with exact vector | structure absent |
| Matrix-RAA | family-dependent, target `<q*t` | potentially row/block | factor descriptors and `H/K` | `qm` fields + `q` points | OPEN matrix pseudorandomness | none algebraically | no reduction; rank tests |
| Preprocessed PBMO | online `q` subtractions | row + one token | `qm` mask fields or regenerable seed plus `q` one-time points | `qm` fields + `q` points | one-time pad freshness/authentication | none | token storage/rollback |
| PCS-aware masking | not available | n/a | n/a | n/a | native PCS absorption | would be required | blocked for libspartan |

Primary classification: `PHASE_V0_PREPROCESSED_PBMO_ONLY`.

