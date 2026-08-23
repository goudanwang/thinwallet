# Streaming EMSM Design

Remote MSM has two Phase 1 modes:

- M0 plaintext remote MSM, classified `PLAINTEXT_REMOTE_MSM_INSECURE`;
- M1 streaming EMSM adapter boundary, classified `EMSM_ADAPTER_ONLY`.

M0 measures plumbing only. The client uploads plaintext scalars, so it provides no witness privacy and cannot be used as the final private outsourcing construction.

M1 records the required boundary:

```text
r = G e
v = z + r
server returns <v,g>
client recovers <z,g> = <v,g> - <e,h>
```

No paper-faithful streaming EMSM implementation is available in this repository, so Phase 1 is classified `MEMORY_BOUNDED_SAP_BLOCKED_BY_EMSM_STREAMING`.

