# EMSM And PBMO Boundary

Status marker: `PBMO_EXISTING_EMSM_BOUNDARY_COMPLETE`

| Primitive | Private input | Public basis | Outputs | Mask reuse | Correction | libspartan applicability |
| --- | --- | --- | ---: | --- | --- | --- |
| Single-input/single-output EMSM | `z in F^m` | one `G in Group^m` | 1 | only for that output and session | typically `t` terms | applies to one row commitment |
| Same-input/multi-basis EMSM | one `z in F^m` | `s` bases `G^(1)..G^(s)` | `s` | encoded `z` may be reused only if the construction proves multi-basis privacy | usually one correction per basis | not the observed shape; libspartan rows differ |
| Multi-input/multi-output PBMO | `Z in F^(q x m)` | one shared ordered `G` | `q` | row masks cannot be reused without a matrix privacy argument | target below `q*t`, not achieved by flattening alone | exactly matches the audited row matrix |
| Fragmented shared-basis commitment | row chunks `Z_j` | same `G`, plus per-row `h` blind | `q` ordered commitment points | native blind is independent per row; outsourcing masks are separate | exact point per row required | libspartan 0.9.0 shape |

The distinguishing feature is input multiplicity. Same-input multi-basis EMSM
amortizes one private vector across bases. PBMO must hide `q` distinct vectors
while preserving `q` distinct outputs. In audited libspartan, adjacent points
are not separated by a Fiat-Shamir challenge, but all points are retained and
absorbed in order; that batching opportunity does not collapse the output
functionality to one MSM.

