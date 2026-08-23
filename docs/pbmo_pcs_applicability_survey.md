# PBMO PCS Applicability Survey

Status marker: `PBMO_APPLICABILITY_SCOPE_COMPLETE`

## Scope Rule

PBMO is relevant only when a prover must commit to `q` distinct private scalar
vectors using the same ordered group basis and preserve `q` distinct outputs.
Sumcheck use alone does not imply this shape. Hash/code commitments have no MSM
to outsource, while a whole-polynomial KZG/IPA commitment may need only one
ordinary EMSM.

| Family | Medium | Commitment shape | Private MSM volume | PBMO applicability |
| --- | --- | --- | --- | --- |
| Spartan/Hyrax-style, audited libspartan | group | `q` row points, shared `m`-basis, per-row blind | `m` per row, `qm` total | direct match; ordinary EMSM is row-by-row only |
| Testudo | pairing groups | `sqrt(N)` PST row points then MIPP compression | `sqrt(N)` per row, `N` total | applies to internal row-commit stage |
| IPA multilinear PCS (Dory family) | group/pairing group | normally one vector commitment plus recursive opening points | initial work linear; round work protocol-specific | conditional, only if implementation exposes multiple same-basis private vectors |
| Gemini elastic PCS | KZG pairing group | one point per univariate polynomial | polynomial degree per commitment | ordinary EMSM normally sufficient; PBMO only across a polynomial batch |
| ZeroMorph | hiding KZG | input and auxiliary whole-polynomial commitments | polynomial-dependent, linear total class | same conditional batch case, not intrinsic fragmentation |
| SamaritanPCS | KZG instantiation | one commitment per polynomial with batching | linear input commitment work | ordinary EMSM per commitment; PBMO conditional across a batch |
| HyperPlonk | generic PCS; implementation choice mKZG | one per polynomial for mKZG, or hash roots for FRI | PCS-dependent | conditional for group choices; none for hash-only choice |
| BaseFold/DeepFold-style FRI PCS | hashes/Merkle/code | encoded oracle roots and openings | no elliptic-curve commitment MSM | PBMO does not apply |

## Source Notes

- [Spartan](https://www.microsoft.com/en-us/research/publication/spartan-efficient-and-general-purpose-zksnarks-without-trusted-setup/)
  is a Sumcheck-based framework parameterized by multilinear polynomial
  commitments. The concrete fragmented shape here is established by the local
  libspartan 0.9.0 source audit, not asserted for every Spartan instantiation.
- [Hyrax](https://eprint.iacr.org/2017/1132.pdf) supplies the square-root
  commitment lineage used by the audited implementation.
- [Testudo](https://eprint.iacr.org/2023/961.pdf) explicitly commits to each
  row of a square matrix using PST and then compresses the row-commitment vector
  with MIPP.
- [Dory](https://eprint.iacr.org/2020/1274.pdf) represents the IPA/generalized
  inner-product family; its protocol output structure is not automatically the
  libspartan `q x m` shape.
- [Gemini](https://eprint.iacr.org/2022/420.pdf) uses an elastic KZG
  realization with one group commitment per univariate polynomial.
- [ZeroMorph](https://eprint.iacr.org/2023/917.pdf) transforms multilinear
  evaluation proofs into commitments under an additively homomorphic
  univariate PCS and instantiates hiding KZG.
- [Samaritan](https://eprint.iacr.org/2025/419.pdf) is another generic
  univariate-to-multilinear transform, with a KZG instantiation and batching.
- [HyperPlonk](https://eprint.iacr.org/2022/1355.pdf) is PCS-generic. Its PCS
  choice must be inspected before applying an MSM outsourcing conclusion.
- [BaseFold](https://eprint.iacr.org/2023/1705.pdf) and
  [DeepFold](https://www.usenix.org/conference/usenixsecurity25/presentation/guo-yanpei)
  are hash/code-based multilinear PCS examples; their commitment layer is not
  an elliptic-curve MSM.

The machine-readable matrix is
`experiments/pbmo_survey/pcs_matrix.json`. Unknown protocol-dependent counts
are recorded as `null` or textual dependencies rather than invented numbers.

