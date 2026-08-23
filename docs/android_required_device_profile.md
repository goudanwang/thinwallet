# Required Android Device Profile

Phase V5A requires an explicitly authorized physical ARM64 (`arm64-v8a`)
Android device. Emulators and desktop ARM64 cross-builds are excluded.

Record the model, SoC, CPU topology/frequency policy, Android/API/kernel, total
and available RAM, free storage, UFS/eMMC type where exposed, app sandbox and
filesystem, battery percentage/temperature, charging state, thermal status,
airplane/Wi-Fi/cellular state, and background-process policy. Record ADB serial
and authorization without publishing a device-unique identifier.

The device must support a repeatable method for process RSS/PSS/VmHWM, cgroup
limits where available, temporary-file and read/write accounting, CPU frequency
and thermal monitoring, and energy collection where the OS exposes a reliable
counter. Unsupported counters are `null`, never zero.
