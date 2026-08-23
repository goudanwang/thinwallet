# V3D Runtime and Allocator Residual Audit

Status: `V3D_RUNTIME_ALLOCATOR_RESIDUAL_AUDIT_COMPLETE`

The V3C residual was 109,337,584 bytes. V3D did not lower the planner's 111 MiB
runtime reserve to force acceptance. Instead, FS5 removed duplicated logical
state and ran with `RAYON_NUM_THREADS=1`; this build has no multicore feature,
so the measured prover had one thread.

The uninstrumented FS5 `/proc` probe measured a 262,444 KiB peak RSS, zero
swap, at most one thread, a 135,168-byte stack mapping, and at most 3,072 KiB
file-backed RSS. Maximum sampled PSS was 261,222 KiB. The sampled fields are
read sequentially and are not an atomic kernel snapshot, so differences
between individual RSS subfields are not treated as allocator measurements.

Large tracked vectors use exact capacity in the allocator trace. Allocator
fragmentation, retained freed arenas, TLS allocations, curve scratch, standard
library buffers, and small network buffers cannot be separated reliably with
the current system allocator and are recorded as `null`. No allocator purge,
custom arena, reduced unsafe stack, unbounded mmap, or page-cache exclusion was
used. The remaining reserve therefore stays conservative.
