# Keyed Matrix-RAA Security Games

Status: `KEYED_MATRIX_RAA_MODEL_COMPLETE`

## Single-Sample Chosen-Matrix Privacy

The challenger samples one secret transform key `(A_s,B_s)` and creates all
client and server setup state. The adversary receives public parameters and
every setup artifact visible to the server. It chooses arbitrary
`Z0,Z1 in F^(q x m)` with equal public dimensions and leakage metadata. The
challenger samples fresh sparse `E`, chooses `b`, and returns the complete
pre-recovery server view for `V=Z_b+A_s E B_s^T`, including chunks, ordering,
access traces, server randomness, `Y`, lengths, and failures. The adversary
outputs `b'`.

Encoding privacy requires `|Pr[b'=b]-1/2|` negligible. This game deliberately
permits chosen `Z0,Z1`; restricting them to random witnesses would miss the
public-coset attack.

If recovered outputs `C` are later revealed to the server or verifier, they are
unavoidable functionality leakage. The corresponding game either ends before
that disclosure or requires `Z0,Z1` to induce the same declared public output.
It is impossible to demand arbitrary chosen-input indistinguishability while
also handing the adversary distinguishable deterministic outputs.

## Multi-Sample Privacy Under Key Reuse

One `(A_s,B_s)` is fixed for all sessions. The adversary obtains polynomially
many encoding views. For each query it may choose a pair `(Z0_l,Z1_l)` with
matching metadata; one hidden bit selects all challenge inputs and every query
uses independently sampled fresh `E_l`. Queries may be adaptive and may include
known-plaintext sessions by choosing equal pairs. Consequently the adversary
can collect raw mask samples from known plaintexts and attempt sparse-dictionary,
moment, tensor, displacement, or key-recovery attacks before choosing later
challenge matrices.

The view includes session identifiers, request binding, response points,
accept/reject behavior, timing classes, and any setup query pattern. Advantage
is defined as in the single-sample game.

## Active Server Extension

A malicious server may corrupt, reorder, truncate, replay, and adapt responses.
Privacy must hold including selective failures. Output integrity is a separate
game and may use the PBMO random-linear batch check; passing that check does not
establish mask pseudorandomness.

## Necessary Conditions

- `E_l` is fresh and independently generated for every session.
- The transform key is never revealed through field values or secret-indexed
  setup access patterns.
- Any exposed related basis such as `G_hat` is included in the assumption.
- Security covers polynomially many masks under one key, not only one sample.
- The server-view distribution is compared for chosen matrices, not only for
  zero input.

No reduction for these games is claimed in Phase V1.

