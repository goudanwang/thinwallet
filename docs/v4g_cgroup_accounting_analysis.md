# V4G Cgroup Accounting Analysis

## Result

`CGROUP_PEAK_SATURATION_EXPLAINED`

The V4F values equal to 64, 256, and 224 MiB were observations under tight
`memory.max` boundaries, not unconstrained working-set targets. V4G repeated
H0, H1, and H2 M4 under a 2 GiB limit and sampled process and cgroup metrics
independently. No run swapped, crossed `memory.high`, or reported a cgroup OOM
event.

| Workload | VmHWM MiB | PSS MiB | process anon MiB | process file MiB | cgroup peak MiB | sampled cgroup anon max MiB | sampled cgroup file max MiB | inactive-file max MiB | active-file max MiB | temp max MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| H0 | 47.738 | 35.419 | 33.191 | 3.250 | 73.008 | 33.797 | 34.070 | 33.891 | 0.418 | 138.224 |
| H1 | 217.145 | 213.274 | 209.395 | 3.375 | 428.188 | 199.312 | 264.730 | 262.531 | 0.125 | 944.271 |
| H2 | 203.898 | 203.065 | 200.898 | 3.125 | 417.598 | 201.520 | 263.926 | 265.730 | 0.078 | 944.267 |

Provenance is under `results/v4g/raw/runs/v4g_cgroup_diag_*`; every row records
zero swap and zero `memory.events` counts.

## Explanation

The process HWM is dominated by anonymous prover state. The cgroup additionally
charges file pages populated by temporary spill I/O. H1 and H2 each create
about 944 MiB of temporary state, while the unconstrained cgroup peak contains
roughly 264 MiB of sampled file pages and only about 0.1 MiB of active-file
pages. This is consistent with reclaimable spill page cache, not an additional
264 MiB live process allocation.

The per-category `memory.stat` values above are maxima sampled at different
times. In particular, sampled anon max plus sampled file max is not a valid
simultaneous total and may exceed `memory.peak`. No child workload process was
left running, `shmem` remained zero, and `memory.high` was not configured. The
tight V4F caps forced page-cache reclaim and allowed `memory.peak` to reach the
configured `memory.max`; that boundary observation is unsuitable as a process
or unconstrained-cgroup regression target.

## Planning Boundary

Process prediction is evaluated against `/proc` `VmHWM`. Cgroup admission is a
separate conservative decision covering process anonymous memory, resident file
pages, reclaimable spill cache, service/child accounting, and kernel accounting
granularity. V4G makes no 5% cgroup-peak accuracy claim. The process model does
not normalize a saturated cgroup value or fit it as if it were process memory.

