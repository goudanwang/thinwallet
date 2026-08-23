# EMSM and Hyrax composition

## Shape mismatch

The paper optimizes:

```text
one private input z x one or more public bases g_j
```

ThinWallet requires:

```text
q distinct private rows Z_i x one shared basis G -> q ordered points C_i
```

The paper's multi-basis reuse is not the transpose of ThinWallet's workload.
It does not authorize ciphertext reuse across distinct rows.

## Composition candidates

### Independent row-wise EMSM

For every row `i`, sample fresh semi-honest `e_i` or fresh malicious
`(e_i,e_ck_i,c_i)`, send an independent request, recover `C_i`, and preserve
the input order. This is functionally correct.

The public code descriptor and basis-dependent `h` can be shared because the
basis is shared. The private masks and malicious checks repeat per row. The
server necessarily learns that requests belong to the same batch if the
transport/session groups them; that metadata is outside the EMSM privacy
claim.

This is the only acceptable baseline composition if Phase B is ever approved.

### Reusing one mask across rows

This is excluded. If rows use the same `r`, the server computes:

```text
(z_i + r) - (z_j + r) = z_i - z_j
```

The formal same-input/multi-basis optimization does not cover this case.

### Aggregating rows

One linear combination of rows can return only one linear combination of the
native points. It does not return all `q` ordered outputs. Recovering the
missing outputs would require extra equations, extra protocol messages, or a
changed proof/transcript. None is in the official EMSM construction.

### Sharing G or h

The paper permits fixed public setup to be reused polynomially many times with
fresh error vectors. Thus the RAA descriptor `G` can be shared. Since all rows
use the same ordered basis, one `h=G^T g` can be shared as public
preprocessing. Sharing does not extend to `e`, `e_ck`, or `c`.

## Short-row padding

No published set directly supports `m=128`, `256`, or `512`. The smallest
published set has:

```text
n=32768, N=131072, t=1178, lambda=100
```

A public zero-padding embedding preserves the algebraic MSM output if the
extra basis positions and ordering are fixed. However, no official
short-row/padding profile, 128-bit table, or Android artifact is published.
The compatibility CSV therefore treats the padded dimensions as diagnostic
and the security/deployment status as unsupported or unverified.

The fact that `t > m` is not by itself a security or applicability proof.
It does show that, under this diagnostic padding, the client's correction has
2.30 to 9.20 times as many terms as the native short-row MSM. Any claimed
amortization would need a real implementation and measurement; Phase A makes
no such performance claim.

## Frozen baseline definition

```text
independent row-wise malicious EMSM,
fresh randomness per row,
one shared verified public setup and basis-dependent h,
q ordered outputs,
native libspartan blinding after recovery,
unchanged proof transcript and verifier
```

This is a design definition only. It is not yet an available baseline because
the short-row/security-level and backend-port questions remain unresolved.

