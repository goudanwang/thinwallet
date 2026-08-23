# Phase V4 Android Native Port Plan

The Android phase should port the release prover and fixed state-store path to
a minimal native library before any UI work. Required gates are deterministic
proof equivalence, bounded allocator behavior, app-private temporary files,
cleanup after process death, device-specific RSS sampling, and unchanged
native verifier acceptance.

The plan must test representative low-, middle-, and high-memory devices and
must not infer feasibility from WSL RSS alone. Hardware-backed rollback state
is a separate deployment profile, not a prerequisite silently assumed by the
software-only prototype.
