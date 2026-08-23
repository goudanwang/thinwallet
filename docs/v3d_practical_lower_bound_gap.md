# V3D Practical Lower-Bound Gap

Status: `FS4_PRACTICAL_LOWER_BOUND_GAP_ATTRIBUTED`

## Measurement basis

The frozen FS4 planner prediction is 384,303,104 bytes (366.50 MiB), while
the V3C retained-state estimate plus the unchanged 111 MiB runtime reserve is
323,043,328 bytes (308.08 MiB). Their model gap is 61,259,776 bytes
(58.42 MiB).

V3D repeated an uninstrumented FS4 run and sampled `/proc/<pid>/status` and
`smaps_rollup`. Its peak sample was 383,995,904 bytes, giving an exact
probe-to-estimate gap of 60,952,576 bytes. The sample contained 380,981,248
bytes anonymous RSS, 3,014,656 bytes file-backed RSS, 382,775,296 bytes PSS,
zero swap, one thread, and 135,168 bytes resident stack.

## Exact attribution

| Gap class | Bytes | Measurement |
| --- | ---: | --- |
| File-backed RSS | 3,014,656 | `/proc/<pid>/status` at the RSS peak |
| Thread-stack residency | 135,168 | `VmStk` at the RSS peak |
| Anonymous transcript overlap / allocator / runtime, not separable | 57,802,752 | Exact remainder |
| **Total** | **60,952,576** | Matches the detailed probe gap exactly |

The last class is deliberately retained as unknown. The uninstrumented kernel
sample cannot distinguish active fold buffers, transcript-barrier overlap,
cryptographic scratch, allocator fragmentation, and other anonymous runtime
residency byte-for-byte. Assigning those bytes to finer categories would be an
estimate rather than a measurement.

The separate allocator-instrumented FS4 trace reported 344,392,720 requested
bytes and the same tracked vector capacity for allocations at least 64 KiB, so
tracked vector excess capacity was zero in that run. The trace changes the
peak materially and therefore is not subtracted from the uninstrumented RSS.
Allocator fragmentation, page-resident temporary-file data, small network
buffers, and per-component cryptographic scratch remain `null` because this
toolchain does not expose reliable direct measurements for them.

The practical gap is an implementation observation, not a cryptographic lower
bound.
