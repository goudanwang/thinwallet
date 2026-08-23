# V5A Android Memory Metric Definition

The Android evaluation reports each memory domain separately. Values are not
interchangeable and a planner budget is not an operating-system hard limit.

| Metric | Source | Meaning |
| --- | --- | --- |
| VmRSS | `/proc/<pid>/status` | Resident pages attributed to the process at a sample. |
| VmHWM | `/proc/<pid>/status` | Kernel process resident high-water mark; the primary process-peak metric. |
| VmSize | `/proc/<pid>/status` | Virtual address-space size, not resident memory. |
| VmSwap | `/proc/<pid>/status` | Process pages swapped at the sample. |
| RSS/PSS | `/proc/<pid>/smaps_rollup` | Resident and proportionally shared resident pages. |
| Anonymous/file PSS | `smaps_rollup` | Anonymous and file-backed proportional memory when readable. |
| MemAvailable | `/proc/meminfo` | System-wide reclaim-aware available memory, not process headroom. |
| zram/swap | `/proc/meminfo`, zram sysfs | System compression/swap state; a zero process VmSwap is separate. |
| Temporary bytes | `du` plus state-store counters | External-memory files; not process RSS or page cache. |
| Planner budget | ThinWallet admission input | Expected-value policy with safety allowance, not a kernel cap. |

The runtime probe measured a 3,637,248-byte post-warm-up fixed reserve and a
475,136-byte worker/thread increment. The device planner uses a conservative
8 MiB runtime reserve. Android calibration is separate from the frozen desktop
V4G model.

The monitor requested 100 ms sampling, but each sample required several ADB
round trips. VmHWM remains authoritative for a missed between-sample peak. PSS
is the maximum observed sample. No cgroup hard limit was active. All headline
A3 process VmSwap maxima were zero.

Output: `ANDROID_MEMORY_METRICS_DEFINED`.
