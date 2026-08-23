# Shared-Basis PBMO-MSM

Status marker: `PBMO_FORMAL_MODEL_COMPLETE`

## Functionality

Let `F` be a prime field and `Group` a prime-order additive group with scalar
field `F`. The client holds a private matrix `Z in F^(q x m)`. Both parties know
the ordered basis `G = (G_1, ..., G_m)`. The required ordered output vector is

```text
C = (C_1, ..., C_q)
C_j = sum_i Z[j,i] G_i.
```

Dimensions, basis identifier, protocol version, and agreed leakage metadata are
public. Matrix entries and mask material are private. This is a functionality,
not a secure construction.

## Algorithms

`Setup(1^lambda, q, m, basis_id, G)` returns public parameters `pp`, client
state `st_H`, server preprocessing state `st_S`, and a parameter manifest. It
binds the group, field, ordered basis digest, dimensions, and protocol version.

`ClientEncode(pp, st_H, sid, request, Z)` returns an encoded stream `V`, recovery
state `rec`, and client commitment/authentication metadata `tau_H`. Encoding
must be fresh for `(sid, request)` and support row/block streaming.

`ServerEvaluate(pp, st_S, sid, request, V, tau_H)` returns an ordered vector
`Y`, a server commitment `tau_S`, and optional integrity proof `pi_S`. The
server must commit to all outputs before any batching challenge is derived.

`ClientRecover(pp, rec, sid, request, Y, tau_S, pi_S)` either rejects or returns
the exact ordered vector `C`.

`VerifyServerResult(pp, sid, request, public_metadata, C, tau_H, tau_S, pi_S)`
returns a bit. In a public-verification variant it cannot depend on a secret
known only to the client. A client-only MAC check is therefore not by itself a
public verification algorithm.

## Required Properties

Correctness requires honest execution to return every exact `C_j`, including
row order and native commitment blinding terms where the target PCS has them.

Privacy requires the server's complete view to hide `Z` beyond declared public
metadata. It covers encoded streams, setup queries, access patterns, timing
classes, correction retrieval, transcripts, failures, and persistent state.

Malicious output integrity requires rejection when any returned output differs
from the required ordered result, except with a stated negligible soundness
error. Privacy and integrity are separate claims.

Replay/session binding requires every token, chunk, basis digest, output index,
challenge, and response to bind `sid`, request digest, dimensions, and protocol
version. One-time state is consumed atomically; rollback or reuse is rejected.

## Streaming And Cost Vocabulary

Streaming execution means the client may read `Z` and emit/consume data in
bounded rows or blocks without retaining `Theta(qm)` field elements. This does
not imply low total work or low communication.

- Client RAM: maximum live volatile bytes, excluding mapped persistent files.
- Persistent storage: setup data and unused one-time tokens retained by client.
- Communication: client-to-server and server-to-client bytes, including proofs.
- Client field operations: additions, multiplications, PRG expansion, and hashes,
  separately from group operations.
- Client group operations: scalar multiplications and group additions, with
  output subtraction counted explicitly.
- Server group operations: all MSM terms and group additions used to produce
  the ordered output vector and integrity material.

No metric may silently move work from online execution into unreported setup.

