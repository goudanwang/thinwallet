# PBMO Spool Audit

## Scope

This audit covers the malicious preprocessed PBMO provider used by the Phase 3
four-mode experiments. It does not alter PBMO algebra, the Fiat-Shamir
transcript, proof encoding, verification, or one-time token semantics.

## Aggregate-check replay

The malicious aggregate check requires a replay of the complete ordered masked
matrix. For a commitment with shape `q x m`, every masked scalar is appended in
canonical 32-byte form. After the server outputs are fixed, the client derives
the post-commitment coefficients `rho_j`, replays all `q*m` scalars, and builds

```text
a_i = sum_j rho_j * masked_scalar[j,i].
```

It then performs one `m`-term MSM and compares it with the `q`-point linear
combination of the server outputs. The replay is therefore `Theta(q*m)` reads
and field operations. It does not retain the matrix in client RAM.

## Location and lifecycle

When `THINWALLET_EXPERIMENT_TEMP_DIR` is set, the spool is now placed inside
that unique run root. Otherwise the non-experiment default remains the system
temporary directory. The lifecycle is:

1. register one `pbmo_request_spool` artifact;
2. append each streamed chunk;
3. replay the complete file during the aggregate check;
4. delete it after success, integrity failure, or session drop.

Phase 3 directly records each append, logical bytes written, peak/final logical
size, allocated size when Linux reports it, and removal. Directory polling is
not the sole source. For S-W1 (`q=64`, `m=128`), the measured spool is exactly
`64*128*32 = 262,144` bytes, is replayed once, and has final size zero. The
implementation performs 128 create-capable append opens/writes against one
spool artifact.

## Phase 2 discrepancy

The Phase 2 value of 2,820 bytes was not the PBMO matrix footprint. The spool
was created under the process-global temporary directory rather than the
run-specific experiment root, then deleted before the recursive directory
sample. The reported 2,820 bytes primarily covered the token file and metadata
visible under the experiment root. Phase 3 fixes the measurement boundary; it
does not reinterpret the old number.

## Artifact categories

The direct accounting schema includes:

- `sumcheck_spill`
- `opening_spill`
- `pbmo_request_spool`
- `pbmo_response_spool`
- `token_file`
- `miscellaneous`

There is no file-backed PBMO response spool in the current implementation, so
that category is recorded with zero artifacts. Responses are decoded from the
transport buffer. Token preprocessing is measured separately from the online
four-mode runs.

## Design consistency

The implementation is consistent with the memory-bounded client design for
the masked request matrix: only a streamed chunk and the `m` aggregate
coefficients are live in RAM. It does incur `Theta(q*m)` temporary storage and
replay I/O. Removing that replay would require a different malicious aggregate
check or authenticated streaming construction; it cannot be claimed from the
current code.
