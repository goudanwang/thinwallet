# PBMO Batched Malicious Integrity Check

Status marker: `PBMO_BATCHED_MALICIOUS_CHECK_ANALYZED`

## Check

The server first commits to the complete ordered vector of returned points,
including session, request, basis digest, dimensions, and output indices. Only
then derive independent field coefficients

```text
rho_j = HashToField("PBMO-batch-v0", sid, request_digest,
                    basis_digest, committed_output_vector, j).
```

Check

```text
sum_j rho_j C_j = MSM(sum_j rho_j Z_j, G).
```

For returned errors `E_j=C'_j-C_j`, acceptance of a wrong vector means
`sum_j rho_j E_j=0`. In a prime-order cyclic group, after fixing a nonzero
error vector and sampling at least one fresh independent coefficient, the
probability is at most `1/|F|` in the random-challenge model. Fiat-Shamir adds
the random-oracle and transcript-binding assumptions.

## Ordering And Binding

The hash must follow commitment to every output. Hashing incrementally before
all outputs are fixed lets the server adapt later points. Canonical point
encoding, row count, order, basis digest, request, and session must all be
included. Replays need a client freshness anchor, not only a hash label.

## Cost And Limits

The client must form the aggregate private scalar row
`z*=sum_j rho_j Z_j`, costing `qm` field multiply-adds in a streaming pass. A
single additional EMSM can outsource the one `m`-term aggregate MSM; this adds
one encoded row upload and one returned point plus its EMSM correction/check
material. If the client already has authenticated masked rows, the aggregate
may be formed during streaming, but its exact privacy argument must be stated.

One aggregate check is sufficient for field-size malicious output soundness
under the ordering assumptions. It does not provide PBMO input privacy, reduce
the `q` recovery corrections, authenticate setup by itself, or make a
client-secret MAC publicly verifiable.

