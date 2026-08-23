#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
crate="$repo_root/experiments/libspartan"
ndk="$HOME/.local/android/android-ndk-r27c"
linker="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android23-clang"

source "$HOME/.cargo/env"

rustc --version | grep -Fq 'rustc 1.92.0 '
grep -Fq 'Pkg.Revision = 27.2.12479018' "$ndk/source.properties"
test -x "$linker"
rustup target list --installed | grep -Fxq aarch64-linux-android

export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$linker"
export RUSTFLAGS='-C target-cpu=generic'

cd "$crate"
cargo build --locked --release --target aarch64-linux-android --bin phase_v2_pbmo
if cargo metadata --no-deps --format-version 1 | grep -Fq 'thinwallet_android_bench'; then
  cargo build --locked --release --target aarch64-linux-android --bin thinwallet_android_bench
fi
cargo build --locked --release --target aarch64-linux-android \
  --bin phase_v4c_profile_s \
  --bin phase_v4e_credential_source \
  --bin phase_v4g_runtime_reserve
