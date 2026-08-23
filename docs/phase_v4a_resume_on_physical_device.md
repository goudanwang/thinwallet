# Phase V4A Resume On Physical Device

Resume only when an authorized physical ARM64 Android device is available.
Use the frozen V4A archive and verify its manifest and SHA-256 before reuse.
Rebuild the current FS4 runner for ARM64, then execute memory, latency, energy,
thermal, token-lifecycle, and unchanged-verifier checks on the physical device.

The existing ARM64 cross-build is not device execution and supports no Android
performance or feasibility claim.
