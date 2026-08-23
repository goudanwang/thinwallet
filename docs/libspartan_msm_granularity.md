# libspartan MSM Granularity Audit

Final classification:

```text
PHASE3A_R2_5_BLOCKED_CHUNK_TRANSCRIPT_BARRIERS
```

## Scope And Method

The audit traced every private physical MSM reached from
`DensePolynomial::commit_inner` while proving the same deterministic Boolean
multiplication R1CS at `2^12`, `2^14`, `2^16`, and `2^18` variables and
constraints. Every generated proof was accepted by the unchanged native
libspartan verifier.

The thresholds used below are configurable engineering categories, not
theoretical performance or security boundaries:

- `LOCAL_SMALL`: at most 256 logical scalars;
- `OPTIONAL_REMOTE`: at most 4,096;
- `REMOTE_CANDIDATE`: at most 65,536;
- `REMOTE_STRONG_CANDIDATE`: above 65,536.

## Physical-To-Logical Map

| Workload | Physical chunks | Scalars/chunk | Logical scalars | Unique MSM bases | Transcript point absorptions | Class |
| ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `2^12` | 64 | 64 | 4,096 | 64 | 64 | `OPTIONAL_REMOTE` |
| `2^14` | 128 | 128 | 16,384 | 128 | 128 | `REMOTE_CANDIDATE` |
| `2^16` | 256 | 256 | 65,536 | 256 | 256 | `REMOTE_CANDIDATE` |
| `2^18` | 512 | 512 | 262,144 | 512 | 512 | `REMOTE_STRONG_CANDIDATE` |

Each row chunk uses the same generator range `G[0..R_size]`, plus its own
blind on `h`. The chunks are therefore not disjoint ranges of one ordinary
MSM. The native logical object is an ordered vector:

```text
PolyCommitment.C = (C_0, C_1, ..., C_{L-1})
C_i = MSM(Z_i, G[0..R_size]) + blind_i * h
```

No physical result is accumulated into one larger group element. Each `C_i`
is retained as a separate proof field and `PolyCommitment::append_to_transcript`
absorbs each compressed point in order.

## Transcript Boundary

There is no Fiat-Shamir challenge between adjacent `C_i` appends: all chunk
points are produced before the next challenge. This means one network session
could upload all scalar chunks and receive a vector of points in one response.

It does not make the requested interface soundly compatible:

```text
finalize(session) -> GroupElement
```

Native libspartan requires `L` group elements, not their sum. Replacing the
ordered vector with one accumulated point would change the proof type,
serialized proof bytes, transcript input, and verifier semantics. The reported
`LIBSPARTAN_CHUNK_LEVEL_TRANSCRIPT_BARRIERS_DETECTED` therefore denotes ordered
point-absorption/proof-arity barriers, not adaptive Fiat-Shamir challenges
between chunks.

## Runtime Snapshot

| Workload | Prove ms | Peak RSS MB | Proof bytes | Native verify |
| ---: | ---: | ---: | ---: | --- |
| `2^12` | 274.713 | 17.18 | 47,464 | pass |
| `2^14` | 952.495 | 61.34 | 62,664 | pass |
| `2^16` | 3,603.001 | 236.71 | 84,840 | pass |
| `2^18` | 13,789.285 | 935.77 | 120,136 | pass |

These are single-run audit snapshots, not benchmarks or production performance
claims.

## Stop Decision

The audit found logical private scalar volume above `2^12`, but did not find a
single large private MSM returning one point. The required logical provider was
therefore not implemented. Communication accounting and logical remote
performance measurements would describe a different vector-valued interface
and are intentionally left for a separately scoped design task.

No full RAA-over-Ristretto migration was started. The existing repetition-code
provider remains `INTEGRATION_ONLY_NOT_SECURITY_CLAIM`.
