#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build/disclosure_control"
CIRCUIT="$ROOT/circuits/disclosure_control_main.circom"
SNARKJS="$ROOT/node_modules/.bin/snarkjs"
PTAU="$ROOT/build/pot12_final.ptau"

R1CS="$BUILD/disclosure_control_main.r1cs"
WASM="$BUILD/disclosure_control_main_js/disclosure_control_main.wasm"
WITNESS_JS="$BUILD/disclosure_control_main_js/generate_witness.js"
ZKEY0="$BUILD/disclosure_control_0000.zkey"
ZKEY="$BUILD/disclosure_control_final.zkey"
VKEY="$BUILD/verification_key.json"

cd "$ROOT"

bash scripts/check_env.sh

if [ ! -x "$SNARKJS" ]; then
    echo "snarkjs: missing local executable at $SNARKJS"
    echo "Run 'npm install' from $ROOT before running this build."
    exit 1
fi

if [ ! -f "$PTAU" ]; then
    echo "Missing local test Powers of Tau at $PTAU"
    echo "Run scripts/build_sanity.sh first to generate the non-production test ptau."
    exit 1
fi

echo "Using local test Powers of Tau from sanity build: $PTAU"
echo "This Powers of Tau is for local measurement only and is not production-safe."

mkdir -p "$BUILD"
find "$BUILD" -mindepth 1 -exec rm -rf {} +

echo "Compiling disclosure control circuit..."
circom "$CIRCUIT" --r1cs --wasm --sym -o "$BUILD" 2>&1 | tee "$BUILD/compile.log"

echo "Extracting R1CS info..."
"$SNARKJS" r1cs info "$R1CS" | tee "$BUILD/r1cs_info.txt"

echo "Generating valid witness..."
node "$WITNESS_JS" "$WASM" "$ROOT/inputs/disclosure_valid.json" "$BUILD/valid.wtns"

echo "Checking valid witness..."
"$SNARKJS" wtns check "$R1CS" "$BUILD/valid.wtns" | tee "$BUILD/valid_witness_check.log"

echo "Running Groth16 setup..."
"$SNARKJS" groth16 setup "$R1CS" "$PTAU" "$ZKEY0"
"$SNARKJS" zkey contribute "$ZKEY0" "$ZKEY" \
    --name="disclosure control zkey contribution" -v -e="disclosure control test entropy"
"$SNARKJS" zkey export verificationkey "$ZKEY" "$VKEY"

echo "Generating valid Groth16 proof..."
"$SNARKJS" groth16 prove "$ZKEY" "$BUILD/valid.wtns" "$BUILD/valid_proof.json" "$BUILD/valid_public.json"

echo "Verifying valid Groth16 proof..."
"$SNARKJS" groth16 verify "$VKEY" "$BUILD/valid_public.json" "$BUILD/valid_proof.json" | tee "$BUILD/valid_verify.log"

confirm_invalid() {
    name="$1"
    input="$ROOT/inputs/disclosure_${name}.json"
    witness="$BUILD/${name}.wtns"

    echo "Confirming $name input is rejected..."
    set +e
    node "$WITNESS_JS" "$WASM" "$input" "$witness" \
        >"$BUILD/${name}_witness_stdout.log" 2>"$BUILD/${name}_witness_stderr.log"
    witness_status=$?
    check_status=1
    if [ "$witness_status" -eq 0 ]; then
        "$SNARKJS" wtns check "$R1CS" "$witness" \
            >"$BUILD/${name}_check_stdout.log" 2>"$BUILD/${name}_check_stderr.log"
        check_status=$?
    fi
    set -e

    if [ "$witness_status" -eq 0 ] && [ "$check_status" -eq 0 ]; then
        echo "$name input unexpectedly satisfied the circuit."
        exit 1
    fi

    {
        echo "${name}_witness_exit_status=$witness_status"
        echo "${name}_check_exit_status=$check_status"
        echo "${name}_expected_failure=true"
    } | tee "$BUILD/${name}_rejection.log"
}

confirm_invalid invalid_expansion
confirm_invalid invalid_request

echo "Disclosure control build complete. Generated files are in $BUILD."
