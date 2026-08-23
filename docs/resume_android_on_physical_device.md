# Resume Android on a Physical Device

Desktop credential memory optimization stops after Phase V4D. No Android run
was performed in this phase.

## Prerequisites

1. Use a physical arm64 Android device with documented model, SoC, RAM,
   Android version, kernel, battery state, and thermal state.
2. Rebuild the frozen native backend and verify the V4D proof/transcript fixture
   hashes before packaging.
3. Keep Ed25519 `verify_strict`, Profile-S field ordering, MiMC7 parameters,
   PBMO token semantics, and the unchanged libspartan verifier fixed.
4. Disable swap-like application behavior and record Android low-memory kills.

## Required Measurements

Measure cold and warm runs separately. Record Java/Kotlin heap, native heap,
RSS/PSS, file-backed pages, temporary storage, wall and CPU time, energy,
thermal throttling, upload/download bytes, proof hash, verifier result, and
token durability. Repeat the useful WK(52,32) workload at least five times.

The desktop cgroup result is not an Android memory claim. Android evaluation
must decide whether further work below 192 MiB is justified.
