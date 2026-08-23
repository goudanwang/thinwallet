# EMSM parameter notes

## Published regime

Paper Table 2 publishes nine concrete sets:

```text
n: 2^15  2^16  2^17  2^18  2^19  2^20  2^21  2^22  2^23
t: 1178  1164  1150  1136  1122  1108  1094  1080  1066
```

For every row, `R=1/4`, `N=4n`, relative distance `delta=0.05`, and
`lambda=100`. This confirms both earlier qualitative expectations: evaluated
lengths start at `2^15`, and `t` is around `10^3`. Only the exact table values
are accepted.

The paper's evaluated field is BN254 Fr, a 254-bit prime field with modulus:

```text
21888242871839275222246405745257275088548364400416034343698204186575808495617
```

This value was cross-checked against the pinned Arkworks BN254 field
declaration. The paper's RAA discussion is stated for prime fields `F_q` with
`q>=3`, but that generic statement is not a concrete Ristretto parameter
validation.

Paper page 9 states the known-linear-test condition:

```text
exp(-delta*t) <= 2^(-lambda + log2(N))
```

The paper says `lambda=128` would not change `t` much, but it does not publish
the corresponding table. Computing replacement values from the inequality
would be a new local parameter choice, so Phase A records them as `null`.

## Distinct error notions

The following must not be conflated:

- dual-LPN computational security, targeted at 100 bits in Table 2;
- the extrapolated probability (at most `2^-21` for `n>=2^15`) that a sampled
  RAA generator misses the stated distance threshold;
- malicious response-check error at most `1/|F_q|`.

The `2^-21` figure is not the EMSM privacy security level.

## Generator sampling

The paper cites prior work for a generator-sampling procedure with runtime
`O(N*w*log N)`, but calls concrete security and performance of that procedure
for EMSM an open question. No parameter generator or generator-validation tool
was found in the official repository. Consequently:

- a random pair of permutations is not automatically a certified setup;
- the server may generate public setup only if the client verifies it as
  required by the security model;
- setup verification is linear in the basis length and must be reported.

## Artifact parameters are not current paper parameters

The pinned artifact contains benchmark constants below `2^15` and uses
`t=596` or `t=588` at `2^15`. These constants predate the current paper table
and are not accepted as authoritative parameter sets.

Local ThinWallet files that derive 100- or 128-bit values from the displayed
inequality are analytical experiments, not author-published EMSM parameters.
They cannot be used to label a baseline paper-faithful.

## Parameter status for ThinWallet

There is no published direct parameter set for `n=128`, `256`, or `512`.
Embedding a short row into the smallest published `n=32768` vector is
algebraically possible by public zero padding, but the paper does not specify
this as its short-row deployment or analyze its comparison fairness. It also
retains the paper's 100-bit parameter target rather than ThinWallet's roughly
128-bit curve target.

Therefore direct short-row security status is
`unsupported_or_unverified`. The published-regime padding calculation in the
compatibility table is a diagnostic, not an approved implementation parameter
set.
