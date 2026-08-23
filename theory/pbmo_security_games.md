# PBMO Security Games

Status marker: `PBMO_FORMAL_MODEL_COMPLETE`

## Semi-Honest Server Privacy

The adversary chooses `Z0,Z1 in F^(q x m)` with identical public dimensions,
basis, row labels, request class, and all declared leakage metadata. The
challenger samples `b`, performs honest setup and client encoding on `Zb`, and
gives the adversary the complete server view: public parameters, persistent
server state, encoded chunks and access pattern, client messages, transcript,
server randomness, output messages, lengths, and declared timing metadata.

The advantage is

```text
| Pr[b' = b] - 1/2 |.
```

Privacy requires negligible advantage. Requiring equal metadata prevents the
game from pretending that deliberately public dimensions are hidden. It does
not permit row differences, low-rank projections, token reuse, or support-query
patterns to leak.

## Malicious Server Privacy

The server may deviate, reorder, truncate, replay, corrupt persistent state,
and choose responses adaptively. Its view additionally contains accept/reject
behavior and any subsequent client message. Privacy requires indistinguishable
views for admissible `Z0,Z1`, including selective-failure behavior. The client
must not reveal a secret-dependent diagnostic.

## Malicious Output Integrity

The adversary receives an honestly encoded unknown `Z`, then returns arbitrary
`Y,tau_S,pi_S`. It wins if recovery accepts but any output differs from
`MSM(Z_j,G)` or the ordered vector is rebound to another session/request. The
winning probability must be negligible under the stated assumption. A random
linear batch check gives only its explicit field-size soundness bound and does
not establish input privacy.

## Replay And State Games

The adversary wins the replay game if a consumed token, activation, encoded
matrix, or server response is accepted under a second session or request. It
wins the rollback game if restoring old server state causes the client to
accept a stale token/version. Session identifiers alone are insufficient unless
the client maintains a monotonic or otherwise non-replayable state anchor.

## Streaming Security

Streaming implementations are evaluated with access traces included in the
view. A bounded-memory implementation that makes secret-indexed setup queries
does not meet privacy merely because its arithmetic mask equation is correct.
Likewise, external files count as persistent state and their integrity and
freshness must be authenticated.

## Claim Levels

- `FUNCTIONAL`: algebraic output equality only.
- `SEMI_HONEST_PRIVATE`: privacy game proven for honest evaluation.
- `MALICIOUS_PRIVATE`: active privacy and selective-failure resistance proven.
- `MALICIOUS_INTEGRITY`: accepted outputs are correct and session-bound.
- `PUBLICLY_VERIFIABLE`: verification needs no client-only secret.

Phase V0 reaches only formalization and toy attack/correctness evidence.

