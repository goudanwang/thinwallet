param(
    [int]$LogSize = 12,
    [int]$MemoryBudgetMiB = 512,
    [string]$Adb = "E:\thinwallet\.tools\android\platform-tools\adb.exe"
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$binary = Join-Path $repo "experiments\libspartan\target\aarch64-linux-android\release\thinwallet_android_bench"
$results = Join-Path $repo "experiments\libspartan\results\v4a_android"
New-Item -ItemType Directory -Force -Path $results | Out-Null

$devices = & $Adb devices | Select-String "`tdevice$"
if ($devices.Count -ne 1) {
    throw "A single authorized physical Android device is required; found $($devices.Count)."
}
if ((& $Adb shell getprop ro.product.cpu.abi).Trim() -notmatch "arm64-v8a") {
    throw "The attached device is not ARM64."
}
if ((& $Adb shell getprop ro.kernel.qemu).Trim() -eq "1") {
    throw "Emulators are excluded from Phase V4A."
}

$remote = "/data/local/tmp/thinwallet-v4a"
& $Adb shell "rm -rf $remote && mkdir -p $remote/state $remote/tmp $remote/results"
& $Adb push $binary "$remote/thinwallet_android_bench"
& $Adb shell "chmod 700 $remote/thinwallet_android_bench"
& $Adb shell "$remote/thinwallet_android_bench print-device-profile" |
    Set-Content -Encoding ascii (Join-Path $results "device_profile.json")
& $Adb shell "$remote/thinwallet_android_bench print-memory-profile" |
    Set-Content -Encoding ascii (Join-Path $results "startup_memory.json")
& $Adb shell "THINWALLET_STATE_DIR=$remote/state THINWALLET_TEMP_DIR=$remote/tmp THINWALLET_MEMORY_BUDGET_MIB=$MemoryBudgetMiB THINWALLET_PROOF_OUT=$remote/results/proof.bin THINWALLET_RESULT_OUT=$remote/results/prove.json $remote/thinwallet_android_bench prove-fs3 $LogSize"
& $Adb shell "$remote/thinwallet_android_bench verify-proof $remote/results/proof.bin $LogSize"
& $Adb pull "$remote/results" $results

