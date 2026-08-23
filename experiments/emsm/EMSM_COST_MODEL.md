# EMSM cost model

## Conventions

Let `n` be the EMSM input length, `N=4n`, `t` the error weight, and `q` the
number of distinct ThinWallet rows. `MSM_l` denotes an `l`-term group MSM.
Counts below come from paper Figure 2 and Sections 3.2-3.3. They are formulas,
not benchmarks.

The paper does not define an offline request-state API. Therefore request
encryption is charged online unless a future implementation explicitly
generates one-time state offline and reports its time, storage, and
consumption. Reusable public setup is reported separately.

## Reusable public setup

For one ordered basis:

```text
sample/verify public RAA descriptor G
h = G^T g
RAA preprocessing: 2N group additions
public state: compact G descriptor plus N group points h
```

The setup can be shared across all `q` rows using the same basis. Verification
of setup is not free and the paper describes linear group work for it.

## Semi-honest independent EMSM

Per row:

```text
sample fresh weight-t e
r = G e                    at most 3N field additions for RAA encoding
v = r + z                  n field additions
upload v                   n encoded field elements
server                     one MSM_n
download em                one encoded group point
client correction          one MSM_t plus one group subtraction
```

For `q` distinct rows, multiply every per-row term by `q`; do not reuse `e`.
There is one online request and one response per row, which can be transported
as a batch without changing the logical one-round-trip protocol.

Semi-honest EMSM gives input privacy against the stated dual-LPN assumption,
but it does not detect a maliciously incorrect server output.

## Malicious independent EMSM

Per row, Figure 2 adds:

```text
fresh independent e_ck and hidden c
r_ck = G e_ck
v_ck = r_ck + c*z
upload (v,v_ck)            2n encoded field elements
server                     two MSM_n
download (em,em_ck)        two encoded group points
client correction          two MSM_t and two group subtractions
check                      dm_ck == c*dm
```

In addition to two RAA encodings and two vector additions, computing `c*z`
uses `n` field multiplications. The final equality requires one public group
scalar multiplication by the client. Incorrect-output acceptance is at most
`1/|F_q|` in the paper model.

The malicious check is per row in the independent baseline. PBMO's aggregate
check may not be imported to reduce this cost.

## Storage model

Public setup contains one compact RAA descriptor and one `N`-point `h` per
basis. Private one-time state contains one sparse vector in semi-honest mode
and two sparse vectors plus `c` in malicious mode. Exact encoded bytes are
`null` until a wire/storage format is fixed.

The server may stream rows, but the official artifact does not provide a
ThinWallet ordered-batch streaming protocol. Any all-row resident estimate
must be reported separately from per-row working storage.

