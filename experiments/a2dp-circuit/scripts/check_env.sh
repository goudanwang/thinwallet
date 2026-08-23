#!/usr/bin/env bash
set -u

export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

missing=0

check_cmd() {
    name="$1"
    if command -v "$name" >/dev/null 2>&1; then
        printf '%s: ' "$name"
        case "$name" in
            circom)
                "$name" --version 2>&1 | head -n 1
                ;;
            node|npm|python3)
                "$name" --version 2>&1 | head -n 1
                ;;
            *)
                command -v "$name"
                ;;
        esac
    else
        echo "$name: missing"
        missing=1
    fi
}

check_cmd circom
check_cmd node
check_cmd npm
check_cmd python3

if [ "$missing" -ne 0 ]; then
    echo "Environment check failed: install the missing tools before running the sanity build."
    exit 1
fi

echo "Environment check passed."
