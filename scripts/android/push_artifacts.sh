#!/usr/bin/env bash
set -euo pipefail
: "${THINWALLET_ANDROID_AUTHORIZED:?set THINWALLET_ANDROID_AUTHORIZED=YES only for an authorized physical device}"
[[ "$THINWALLET_ANDROID_AUTHORIZED" == YES ]]
binary="${1:?path to frozen ARM64 binary}"
fixture_dir="${2:?path to frozen V4F fixtures}"
serial="${ANDROID_SERIAL:?set ANDROID_SERIAL}"
remote="/data/local/tmp/thinwallet-v5a"
adb -s "$serial" get-state >/dev/null
adb -s "$serial" shell 'test "$(getprop ro.product.cpu.abi)" = arm64-v8a'
adb -s "$serial" shell "mkdir -p '$remote/fixtures' '$remote/results'"
adb -s "$serial" push "$binary" "$remote/thinwallet_android_bench"
adb -s "$serial" push "$fixture_dir/." "$remote/fixtures/"
adb -s "$serial" shell "chmod 700 '$remote/thinwallet_android_bench'"
