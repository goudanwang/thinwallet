#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
scripts/run_v3b_once.sh FS3 18 768 2
scripts/run_v3b_once.sh FS3 18 896 2
scripts/run_v3b_once.sh FS3 16 384 1
