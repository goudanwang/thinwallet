#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"
CIRCUIT="$ROOT/circuits/sanity_multiplier.circom"
INPUT="$ROOT/inputs/sanity_multiplier.json"
SNARKJS="$ROOT/node_modules/.bin/snarkjs"

cd "$ROOT"

bash scripts/check_env.sh

if [ ! -x "$SNARKJS" ]; then
    echo "snarkjs: missing local executable at $SNARKJS"
    echo "Run 'npm install' from $ROOT before running this build."
    exit 1
fi

mkdir -p "$BUILD"
find "$BUILD" -mindepth 1 ! -name .gitkeep -exec rm -rf {} +

echo "Compiling Circom circuit..."
circom "$CIRCUIT" --r1cs --wasm --sym -o "$BUILD"

echo "Generating witness..."
node "$BUILD/sanity_multiplier_js/generate_witness.js" \
    "$BUILD/sanity_multiplier_js/sanity_multiplier.wasm" \
    "$INPUT" \
    "$BUILD/sanity_multiplier.wtns"

echo "Extracting R1CS info..."
"$SNARKJS" r1cs info "$BUILD/sanity_multiplier.r1cs" | tee "$BUILD/r1cs_info.txt"

echo "Preparing Powers of Tau..."
"$SNARKJS" powersoftau new bn128 12 "$BUILD/pot12_0000.ptau" -v
"$SNARKJS" powersoftau contribute "$BUILD/pot12_0000.ptau" "$BUILD/pot12_0001.ptau" \
    --name="sanity contribution" -v -e="sanity multiplier entropy"
"$SNARKJS" powersoftau prepare phase2 "$BUILD/pot12_0001.ptau" "$BUILD/pot12_final.ptau" -v

echo "Running Groth16 setup..."
"$SNARKJS" groth16 setup "$BUILD/sanity_multiplier.r1cs" "$BUILD/pot12_final.ptau" "$BUILD/sanity_multiplier_0000.zkey"
"$SNARKJS" zkey contribute "$BUILD/sanity_multiplier_0000.zkey" "$BUILD/sanity_multiplier_final.zkey" \
    --name="sanity zkey contribution" -v -e="sanity zkey entropy"
"$SNARKJS" zkey export verificationkey "$BUILD/sanity_multiplier_final.zkey" "$BUILD/verification_key.json"

echo "Generating Groth16 proof..."
"$SNARKJS" groth16 prove "$BUILD/sanity_multiplier_final.zkey" "$BUILD/sanity_multiplier.wtns" "$BUILD/proof.json" "$BUILD/public.json"

echo "Verifying Groth16 proof..."
"$SNARKJS" groth16 verify "$BUILD/verification_key.json" "$BUILD/public.json" "$BUILD/proof.json" | tee "$BUILD/verify.log"

echo "Sanity build complete. Generated files are in $BUILD."
