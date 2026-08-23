# Keyed Matrix-RAA Assumption Mapping

Result: `KEYED_MATRIX_RAA_REQUIRES_NEW_ASSUMPTION`

The target distribution is a sequence of full matrix samples

```text
R_l = A_s E_l B_s^T in F_p^(q x m),
```

where both transforms are secret and reused, each `E_l` is fresh and sparse,
and an adversary may obtain known-plaintext mask samples. This section checks
definitions, not name similarity.

| Candidate assumption | Dimensions | Public information | Noise/source distribution | Samples and field | Missing match | Reduction |
| --- | --- | --- | --- | --- | --- | --- |
| Standard/dual LPN | public coefficient matrix and noisy linear samples | public random code/sample matrix | dense secret linear form plus additive Bernoulli-like noise | usually many vectors, classically `F_2` | PBMO has hidden two-sided dictionaries, a sparse latent matrix, and no public noisy linear equation | no |
| Sparse LPN | public sparse coefficient matrix | sparse matrix is public | secret linear form plus separate noise | vector samples, primarily binary definitions | PBMO sparsity is the hidden source `E`, while the transforms are secret | no |
| Dense-Sparse LPN | public `T M` and sample `s T M+e` | the dense-sparse product is public | additive Bernoulli noise on a codeword | defined with explicit matrix/sample/noise parameters, principally `F_2` construction | PBMO publishes neither `T M` nor a noisy codeword; it outputs noiseless bilinear mixing of hidden sparse matrices | no |
| Ring-LPN | public ring multiplier and noisy product | quotient ring and multiplier are public | additive sparse/error polynomial | repeated ring samples, commonly binary extension rings | PBMO has two unrelated secret field transforms and no public ring multiplication relation | no |
| Module-LPN analogue | public module/ring matrix and noisy module product | module action is public | additive error in a module | module-vector samples | no canonical module action, public coefficient object, or matching error term exists here | no |
| Quasi-cyclic syndrome decoding | public QC parity-check/code and syndrome | QC structure and syndrome relation are public | find low-weight error matching syndrome | usually binary QC code parameters | PBMO hides transforms, exposes the mixed matrix itself, and has no public syndrome equation | no |

Representative primary definitions include
[Alekhnovich's sparse-LPN lineage](https://doi.org/10.1109/SFCS.2003.1238204),
[Dense-Sparse LPN](https://eprint.iacr.org/2024/175.pdf), and
[Lapin/Ring-LPN](http://www.iacr.org/archive/fse2012/75490350/75490350.pdf).
These assumptions differ in which matrix is public, where additive noise
appears, and what the adversary receives. Those differences are exactly what a
reduction must preserve.

## Why Analogy Is Insufficient

Vectorizing gives

```text
vec(R_l) = (B_s tensor A_s) vec(E_l).
```

This is a reused hidden sparse-dictionary distribution. Standard LPN gives the
attacker a public linear system corrupted by noise; here the dictionary itself
is secret, samples are noiseless images of sparse latent vectors, and
Kronecker/two-sided structure is reused. A proof would need to reduce chosen
matrix privacy, including known-plaintext mask samples, to a stated hard
problem over the same large field. No surveyed assumption supplies that game.

Moreover, at the evaluated fixed row weight, rank deficiency already
distinguishes the distribution. A new assumption cannot validly assume away an
efficient invariant of its proposed parameters.

