# Setup Random Linear Check

V2 derives:

```text
alpha_i = HashToField(
    setup_check_domain,
    manifest_digest,
    client_nonce,
    check_round,
    i
)
```

The nonce is generated after `root_g` and `root_h` are fixed.

The check verifies:

```text
sum_i alpha_i h_i = sum_j beta_j g_j
beta = G alpha
```

Equivalently:

```text
<alpha, h> = <G alpha, g>
```

Let:

```text
Delta_i = h_i - (G^T g)_i
```

The check accepts an incorrect h only if:

```text
sum_i alpha_i Delta_i = Identity
```

For nonzero Delta and uniform alpha sampled after Delta is committed through
`root_h`, the per-round soundness error is at most `1 / |F|`, subject to group
and scalar-field compatibility assumptions.

This is an algebraic randomized equality check. It is not a SNARK, does not
prove dual-LPN hardness, and requires canonical group encodings and subgroup
checks in a production group implementation.

