#!/usr/bin/env bash
set -euo pipefail
: "${THINWALLET_ANDROID_AUTHORIZED:?set THINWALLET_ANDROID_AUTHORIZED=YES only for an authorized physical device}"
[[ "$THINWALLET_ANDROID_AUTHORIZED" == YES ]]
serial="${ANDROID_SERIAL:?set ANDROID_SERIAL}"
destination="${1:?local destination directory}"
mkdir -p "$destination"
adb -s "$serial" pull /data/local/tmp/thinwallet-v5a/results/. "$destination/"
(cd "$destination" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS)
