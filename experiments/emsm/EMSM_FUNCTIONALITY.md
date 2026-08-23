# Exact EMSM functionality

## Syntax and target functionality

Paper Section 3.1 defines a public ordered basis
`g=(g_1,...,g_n) in G^n`, a private scalar vector `z in F_q^n`, and output
`<z,g>`. Its protocol syntax is:

```text
Setup(1^lambda, g) -> pp
Encrypt(pp, z) -> (ct, st)
Evaluate(pp, ct) -> em
Decrypt(pp, em, st) -> dm or bottom
```

The construction is stated in paper Figure 2 and Sections 3.2-3.3:

```text
G <- code-generator distribution, G in F_q^(n x N)
h = G^T g, h in G^N
e <- uniform weight-t error distribution in F_q^N
r = G e, r in F_q^n
v = r + z
em = <v,g>
dm = em - <e,h> = <z,g>
```

This preserves the paper's matrix direction and notation. The RAA
instantiation is:

```text
G = F_r * M_sigma1 * A * M_sigma2 * A
N = 4n
```

Source: paper pages 9, 11-14, especially Figure 2.

## Dimensions and state

| Item | Exact role |
| --- | --- |
| `z_dimension` | `n` private field elements |
| `G_dimension` | `n x N` public code generator |
| `e_dimension` | `N` field elements |
| `e_hamming_weight` | `t` |
| `public_preprocessing` | `G` and basis-dependent `h=G^T g` |
| `private_preprocessing` | fresh `e` and derived `r=Ge`; the paper does not standardize an offline API |
| `reusable_state` | fixed public `G` and `h` may be reused polynomially many times for the same basis |
| `per_request_randomness` | `e` must be fresh for every encrypted input |
| `server_input` | the complete masked vector `v` |
| `server_output` | one group point `<v,g>` per basis |
| `client_correction` | sparse `t`-term MSM `<e,h>` and one group subtraction |
| `correctness_condition` | recovered point equals `<z,g>` |

`G` is public setup state. `h` depends on the ordered basis and can be reused
only while that basis and setup identity remain fixed. The full `v` is sent to
the server.

Privacy rests on the stated dual-LPN assumption for the selected code
distribution and error distribution. The RAA concrete discussion additionally
uses a relative-distance condition and the known-linear-test bound on paper
page 9. It is not information-theoretic masking.

## Malicious construction

Figure 2 adds independent `e_ck`, a hidden uniform scalar `c`, and:

```text
r_ck = G e_ck
v_ck = r_ck + c*z
em_ck = <v_ck,g>
dm_ck = em_ck - <e_ck,h>
accept iff dm_ck == c*dm
```

Thus malicious EMSM uses two ciphertext vectors, two server MSM outputs, two
sparse corrections, and one hidden random linear check. The paper gives error
at most `1/|F_q|` for an incorrect server response. This is not the same as the
dual-LPN privacy parameter.

## Reuse and multi-basis behavior

Paper Section 3.2 permits one ciphertext to be evaluated against multiple
public bases only when all evaluations intentionally reveal linkage to the
same private input. Each basis needs its own `h`.

The paper does not permit reusing a mask/ciphertext for distinct inputs.
Indeed, for two rows, `(z_1+r)-(z_2+r)=z_1-z_2`, so reuse leaks their
difference. ThinWallet rows therefore require independent fresh masks.

Public `G` may be shared across rows. Basis-dependent `h` may also be shared
because ThinWallet rows use one public basis. Request randomness and malicious
checks remain independent per row unless a separately proven aggregation is
introduced; no such aggregation is part of this baseline.

