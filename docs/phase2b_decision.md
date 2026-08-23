# Phase 2B Decision

Primary classification:

```text
PHASE2B_PASS_WITH_LOCAL_MMAP_H
```

Mainline classification after Phase 2B:

```text
STREAMING_EMSM_PRIVATE_WITH_LOCAL_H_STORAGE
```

Rationale:

- H1 direct remote sparse h queries are insecure because they reveal
  `support(e)`.
- H0 keeps h access local, so the proving server does not observe support
  indices.
- H0 preserves native Sumcheck proof compatibility.
- H0 uses bounded temporary h buffers and mmap/positional access rather than
  loading complete h into RAM.
- H2 is not implemented because no auditable single-server PIR dependency was
  found locally.

Limits:

- H0 requires persistent public setup storage.
- Setup correctness is signed/preverified, not independently rederived by the
  verifier.
- The result is not malicious-server EMSM and not Android deployment.

