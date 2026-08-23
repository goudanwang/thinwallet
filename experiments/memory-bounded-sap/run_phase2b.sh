#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

python3 h_access/run_phase2b.py
