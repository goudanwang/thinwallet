# EMSM Phase A feasibility decision

## 1. Executive decision

**D. PARAMETER_GAP**

**Confidence: high.**

The EMSM algorithm is sufficiently specified to study and port, but no trusted
parameter set directly covers ThinWallet's `m=128/256/512` Ristretto rows at a
fair matching security level. The only current paper table starts at
`n=2^15`, targets 100-bit security for the BN254 evaluation setting, and the
official artifact's smaller/stale constants disagree with that table.

## 2. Authoritative sources

The controlling source is the local 2026-05-19 revision of IACR ePrint
2025/2113, SHA-256
`189bb212385e56a2b9ac2d27f5ab1297c60b304209b2f5e90f8fbc68ff78bb94`.
The author-linked official repository is pinned at
`41c6f7b856cb03131d405723df49a6fc33e2a452`.

## 3. Exact EMSM functionality

For public `g in G^n` and private `z in F_q^n`, setup samples public
`G in F_q^(n x N)` and computes `h=G^T g`. Fresh sparse `e` gives
`v=z+Ge`; the server returns `<v,g>` and the client subtracts `<e,h>`.

## 4. Security assumptions

Privacy is computational under the paper's dual-LPN assumption instantiated
with an RAA code distribution. Setup validity and code-distance assumptions
are part of the boundary. Fresh errors are mandatory. Malicious correctness
uses independent `e_ck`, hidden `c`, a second ciphertext, and check
`dm_ck=c*dm`, with error at most `1/|F_q|`.

## 5. Published parameter regime

The only accepted table has `lambda=100`, `R=1/4`, `N=4n`,
`delta=0.05`, `n=2^15..2^23`, and `t=1178..1066`. There is no published
128-bit table and no official short-row generator. The artifact benchmark
constants are not a substitute because they disagree with the current paper.

## 6. Hyrax row-length compatibility

ThinWallet uses `m=128,256,512`, none directly supported. Diagnostic padding to
the smallest published set gives `n=32768,N=131072,t=1178`, with correction to
native term ratios 9.203125, 4.6015625, and 2.30078125 respectively. This is
not an approved short-row parameter profile or a performance conclusion.

## 7. Workload-shape compatibility

ThinWallet has `q` distinct rows, one shared basis, and `q` ordered outputs.
The paper optimizes one private input across one or more bases. The only
acceptable composition is independent row-wise EMSM with shared public setup
and fresh private randomness per row.

## 8. Semi-honest availability

A low-level semi-honest library path exists and its debug tests pass. It lacks
a ThinWallet wire protocol, Ristretto backend, approved short-row parameters,
and Android integration.

## 9. Malicious availability

The paper fully specifies the two-ciphertext malicious check. The repository
contains a benchmark composition but omits the final acceptance check and does
not expose a complete malicious protocol API. A malicious port is therefore a
future implementation task, not a ready artifact.

## 10. Curve and field compatibility

The protocol algebra can be ported to Ristretto, and `h` can be computed using
the current basis. The official Arkworks BN254 path is not directly type- or
wire-compatible. Replacing libspartan's proof group is forbidden; a future
port must remain inside the commitment adapter. Security parameters and
published performance do not automatically transfer across the port.

## 11. Android feasibility

OPEN. No official Android/aarch64 support, storage format, or build exists.
The Rust path has no obvious mandatory C dependency, but uses `std`, Rayon,
Arkworks features, random-access permutations, and dense temporaries. No S23
memory, latency, energy, or OOM claim is justified.

## 12. Required implementation effort

After parameter resolution, a faithful port would need audited parameter and
setup validation, exact uniform weight-`t` sampling, RAA encoding, the complete
semi-honest and malicious protocols, Ristretto canonical wire encoding,
independent ordered-row composition, durable state lifecycle, and negative
tests. The likely new crate/modules are listed in
`EMSM_INTEGRATION_API.md`.

## 13. Risks to comparison fairness

Primary risks are using stale artifact `t`, deriving local short-row values,
comparing 100-bit EMSM with a roughly 128-bit Ristretto baseline, reusing row
masks, omitting setup verification/storage, comparing semi-honest EMSM to
malicious PBMO, or importing PBMO aggregation into EMSM.

## 14. Recommended next phase

Do not enter protocol implementation yet. First obtain an author-backed
short-row/128-bit parameter-generation and setup-validation procedure, or
obtain explicit justification that public zero padding into a published set
is the intended baseline at a matching security level. Only then consider a
Ristretto adapter port.

## 15. Claims that remain forbidden

Phase A does not support claiming:

- that EMSM is implemented or integrated in ThinWallet;
- that artifact benchmark constants are current paper parameters;
- that `m=128/256/512` has a published secure direct parameter set;
- that the diagnostic padded profile is fair or efficient;
- that the artifact provides complete malicious security;
- that Ristretto inherits the paper's concrete parameter evidence;
- that Android/aarch64 is supported;
- any EMSM latency, memory, communication, energy, OOM, or comparative win;
- any modification or improvement to PBMO;
- any Phase-B completion.

