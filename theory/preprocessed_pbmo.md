# Preprocessed PBMO Baseline

Status marker: `PREPROCESSED_PBMO_BASELINE_COMPLETE`

## Construction

For each session token `u`, offline processing samples independent full-size
masks `R[u,j] in F^m` and computes

```text
D[u,j] = MSM(R[u,j],G), j=1..q.
```

The token stores or deterministically regenerates every `R[u,j]`, stores the
ordered `q` correction points, and authenticates `u`, basis digest, dimensions,
protocol version, and allowed request class.

Online, the client streams `V_j=Z_j+R[u,j]`. The server returns
`Y_j=MSM(V_j,G)`. After integrity checking, the client outputs
`C_j=Y_j-D[u,j]` and atomically consumes `u`.

## Costs

- Online client field work: `qm` additions plus mask read/expansion.
- Online client group work: `q` point subtractions, plus integrity work.
- Offline client/setup group work: `q` `m`-term MSMs unless a trusted
  preprocessing service produces authenticated tokens.
- Token material: `qm` field elements (or a seed whose secure expansion is
  justified) and `q` group points, plus authentication metadata.
- Communication: `qm` field elements up and `q` group points down, before
  integrity proof material.
- RAM: row/block bounded; persistent token storage, not RAM, carries the large
  state.

## Security Boundary

Reusing a token exposes differences between presentations exactly as in the
identical-mask theorem. Crash recovery must atomically mark a token consumed;
server rollback must not restore client acceptance. Request/session binding
must prevent a token or response from being replayed under another request.

Idle-time generation may move battery-intensive MSM work away from latency
critical periods, but it does not reduce total phone work and creates large
persistent storage and lifecycle obligations. This is the only Phase V0
baseline without an immediate algebraic privacy attack, assuming truly fresh,
independent, authenticated one-time masks. It is not the preferred final mobile
architecture.

