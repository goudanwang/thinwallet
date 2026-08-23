# Resume Android V4A When A Device Is Available

Desktop memory optimization is frozen after
`PHASE_V3E_256M_STREAMING_DEREFERENCE_PASS`.

Resume V4A only when an authorized physical ARM64 Android device is available.
Rebuild the frozen native revision, record the device/OS/toolchain identity,
enforce the same explicit memory budget, and run proof generation plus the
unchanged verifier. Collect device RSS, Java/native heap, page-cache behavior,
thermal state, wall/CPU time, I/O, proof hash, and token lifecycle.

The WSL result is not a substitute for this evaluation and makes no Android or
production-mobile feasibility claim.
