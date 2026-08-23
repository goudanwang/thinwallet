# Android Build Environment

Status: `ANDROID_TOOLCHAIN_PINNED` for cross-compilation only. No physical-device
execution result is implied by this file.

The Phase V4A native core is built in Ubuntu 22.04 under WSL2 with Rust 1.92.0
for `aarch64-linux-android`. The installed NDK is r27c (revision
27.2.12479018), its LLVM linker is Clang 18.0.3, and the minimum Android API is
23. Release builds use `target-cpu=generic` and Rust's system allocator. The
dependency graph remains fixed by `experiments/libspartan/Cargo.lock`, including
libspartan 0.9.0 and curve25519-dalek 4.1.3.

The toolchain is installed below `/home/ubuntu/.local/android`; it does not
require root privileges. Windows platform-tools 37.0.0 are installed below
`.tools/android/platform-tools`. At the time of the initial audit, `adb devices
-l` returned no attached device. Device execution, JNI, storage profiling,
network PBMO, memory calibration, and performance results therefore require a
subsequent physical ARM64 device run.

Use `android/scripts/build_android_arm64.sh` to reproduce the cross-build. The
script validates the pinned versions before invoking Cargo and refuses a
different NDK revision or Rust release.

