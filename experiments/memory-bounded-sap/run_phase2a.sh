#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

python3 emsm_real/run_phase2a.py
