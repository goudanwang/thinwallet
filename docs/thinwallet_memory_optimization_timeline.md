# ThinWallet Memory-Optimization Timeline

These rows are historical evidence, not one homogeneous benchmark series.
Workload, cap mechanism and metric must be read with every value.

| Stage | Approximate memory | Workload | Cap/metric | Source | Comparable? |
| --- | ---: | --- | --- | --- | --- |
| Native / PBMO-only | 975-999 MiB | Synthetic real-backend baseline | Process peak, uncapped | V3A/V3B results | Comparable only to the same synthetic shape. |
| FS2 | 848 MiB | Synthetic baseline | Process RSS/VmHWM | comb-ops spill results | Same synthetic family; spill I/O added. |
| FS3 | 502 MiB | Synthetic baseline | Controlled budget plus process peak | multi-target planner results | Same family; planner policy differs. |
| FS4 | 366 MiB | Synthetic baseline | Process peak | active Sumcheck/product streaming | Same family; extra external folds. |
| FS5 | 256 MiB | Synthetic baseline | Real cgroup boundary and process peak | transcript-aware recomputation results | Same family; durability split. |
| FS6 | 240 MiB | Synthetic baseline | Process/cgroup peak | dereference/opening fusion results | Same family; fused consumers. |
| FS7 credential | 217.1 MiB process peak (222,308 KiB) | Historical `WK(52,1,32,SparseMerkle)` with one revocation path | 248 MiB cgroup, process VmHWM; cgroup result recorded separately | `experiments/credential_workloads/results/v4d` | **Not directly comparable** to synthetic rows: real credential relation and shape differ. |
| V4G planner validation | Not a memory-reduction stage | 13 calibration plus 10 precommitted held-out Profile S points | Process VmHWM accuracy; cgroup admission reported separately | `results/v4g` | New held-out max 2.802%, MAPE 0.962%; no synthetic optimization claim. |

V4E does not continue synthetic optimization below 256 MiB. Its missing work is
the corrected workload evaluation matrix, not another synthetic memory stage.

`THINWALLET_MEMORY_TIMELINE_COMPLETE`

| V5A Galaxy S23 A3 | 48.07 / 210.08 / 204.71 MiB mean VmHWM for H0/H1/H2 | Frozen Profile-S H0/H1/H2 | Android process VmHWM; planner budget is not a hard cap | `results/v5a/json/collected_results.json` | Cross-platform process-memory comparison only; PSS, page cache, storage and thermal conditions differ. |
