#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

python3 setup_verification/run_phase2c.py
