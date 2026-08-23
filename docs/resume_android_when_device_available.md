# Resume Android When A Device Is Available

Android remains frozen. Resume only after an authorized physical ARM64 Android
device is available.

Required next checks are: build `ed25519-dalek 2.2.0` and the existing Spartan/
PBMO stack for the pinned Android target; verify canonical package and strict
signature failures on-device; run S-W1 through S-W4 under measured memory,
energy, thermal, storage, and network conditions; compare proof bytes with the
desktop fixture; and record device/OS/toolchain identifiers.

Do not infer Android feasibility from pure-Rust source compatibility or WSL
measurements.
