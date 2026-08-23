#!/usr/bin/env bash
set -euo pipefail
: "${THINWALLET_ANDROID_AUTHORIZED:?set THINWALLET_ANDROID_AUTHORIZED=YES only for an authorized physical device}"
[[ "$THINWALLET_ANDROID_AUTHORIZED" == YES ]]
serial="${ANDROID_SERIAL:?set ANDROID_SERIAL}"
workload="${1:?H0, H1, or H2}"
repetition="${2:?repetition}"
remote="/data/local/tmp/thinwallet-v5a"
run="$remote/results/${workload}_r${repetition}"
adb -s "$serial" shell "mkdir -p '$run'; getprop >'$run/environment.txt'; cat /proc/meminfo >>'$run/environment.txt'; df -T '$remote' >>'$run/environment.txt'; dumpsys battery >>'$run/environment.txt'; dumpsys thermalservice >>'$run/environment.txt' 2>&1 || true; for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq; do echo \"\$f \$(cat \$f 2>/dev/null)\"; done >>'$run/environment.txt'; printf '%s\n' '$remote/thinwallet_android_bench $workload' >'$run/command.txt'; '$remote/thinwallet_android_bench' '$workload' >'$run/stdout' 2>'$run/stderr'; printf '%s\n' \$? >'$run/exit_status'"
