#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build/age_predicate"
CIRCUIT="$ROOT/circuits/age_predicate_main.circom"
SNARKJS="$ROOT/node_modules/.bin/snarkjs"
PTAU="$ROOT/build/pot12_final.ptau"

R1CS="$BUILD/age_predicate_main.r1cs"
WASM="$BUILD/age_predicate_main_js/age_predicate_main.wasm"
WITNESS_JS="$BUILD/age_predicate_main_js/generate_witness.js"
ZKEY0="$BUILD/age_predicate_0000.zkey"
ZKEY="$BUILD/age_predicate_final.zkey"
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

echo "Compiling age predicate circuit..."
circom "$CIRCUIT" --r1cs --wasm --sym -o "$BUILD" 2>&1 | tee "$BUILD/compile.log"

echo "Extracting R1CS info..."
"$SNARKJS" r1cs info "$R1CS" | tee "$BUILD/r1cs_info.txt"

make_witness() {
    name="$1"
    input="$ROOT/inputs/age_${name}.json"
    witness="$BUILD/${name}.wtns"

    echo "Generating $name witness..."
    node "$WITNESS_JS" "$WASM" "$input" "$witness"

    echo "Checking $name witness..."
    "$SNARKJS" wtns check "$R1CS" "$witness" | tee "$BUILD/${name}_witness_check.log"
}

make_witness boundary
make_witness valid

echo "Running Groth16 setup..."
"$SNARKJS" groth16 setup "$R1CS" "$PTAU" "$ZKEY0"
"$SNARKJS" zkey contribute "$ZKEY0" "$ZKEY" \
    --name="age predicate zkey contribution" -v -e="age predicate test entropy"
"$SNARKJS" zkey export verificationkey "$ZKEY" "$VKEY"

prove_and_verify() {
    name="$1"
    witness="$BUILD/${name}.wtns"
    proof="$BUILD/${name}_proof.json"
    public="$BUILD/${name}_public.json"

    echo "Generating $name Groth16 proof..."
    "$SNARKJS" groth16 prove "$ZKEY" "$witness" "$proof" "$public"

    echo "Verifying $name Groth16 proof..."
    "$SNARKJS" groth16 verify "$VKEY" "$public" "$proof" | tee "$BUILD/${name}_verify.log"
}

prove_and_verify boundary
prove_and_verify valid

echo "Confirming invalid input is rejected..."
set +e
node "$WITNESS_JS" "$WASM" "$ROOT/inputs/age_invalid.json" "$BUILD/invalid.wtns" \
    >"$BUILD/invalid_witness_stdout.log" 2>"$BUILD/invalid_witness_stderr.log"
invalid_witness_status=$?
invalid_check_status=1
if [ "$invalid_witness_status" -eq 0 ]; then
    "$SNARKJS" wtns check "$R1CS" "$BUILD/invalid.wtns" \
        >"$BUILD/invalid_check_stdout.log" 2>"$BUILD/invalid_check_stderr.log"
    invalid_check_status=$?
fi
set -e

if [ "$invalid_witness_status" -eq 0 ] && [ "$invalid_check_status" -eq 0 ]; then
    echo "Invalid input unexpectedly satisfied the circuit."
    exit 1
fi

{
    echo "invalid_witness_exit_status=$invalid_witness_status"
    echo "invalid_check_exit_status=$invalid_check_status"
    echo "expected_failure=true"
} | tee "$BUILD/invalid_rejection.log"

echo "Age predicate build complete. Generated files are in $BUILD."
