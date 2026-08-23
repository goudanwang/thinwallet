# Streaming EMSM Privacy Boundary

Phase 2A implements the EMSM algebraic flow:

```text
server observes v = z + G e
server computes em = <v, g>
client computes dm = em - <e, h>
h = G^T g
```

The server does not receive `z` or `e` directly. However, in the implemented H1 h-delivery model, the client asks the h server for the sparse indices in `support(e)`.

This creates an unresolved privacy boundary:

- Merkle inclusion proves membership in the published h vector.
- It does not prove that h was correctly generated as `G^T g`.
- Direct sparse h queries may reveal `support(e)`.
- The implementation does not prove that revealing `support(e)` is harmless for dual-LPN privacy.

Comparison:

| Model | Storage | Privacy status |
| --- | --- | --- |
| H0 local complete h | O(N) client storage | avoids support-query leakage, but violates bounded client storage |
| H1 direct sparse h queries | O(t) client storage | `REMOTE_H_SUPPORT_LEAKAGE_OPEN` |
| H2 private/authenticated h retrieval | bounded client storage | requires PIR/ORAM/private retrieval, not implemented |

Phase 2A output exactly:

```text
REMOTE_H_SUPPORT_LEAKAGE_OPEN
```

Because this issue was open, the Phase 2A primary classification was:

```text
STREAMING_EMSM_BLOCKED_BY_REMOTE_H_PRIVACY
```

Phase 2B corrects this by rejecting H1:

```text
H1_DIRECT_SPARSE_H_QUERY_INSECURE
REMOTE_H_SUPPORT_LEAKAGE_NOT_ACCEPTABLE
```

and replacing direct remote h queries with H0 local mmap h storage. The updated
mainline claim is:

```text
STREAMING_EMSM_PRIVATE_WITH_LOCAL_H_STORAGE
```

This still does not claim no persistent setup, malicious-server security,
Android deployment, or NDSS readiness.
