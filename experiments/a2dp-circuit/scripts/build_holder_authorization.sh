#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build/holder_authorization"
CIRCUIT="$ROOT/circuits/holder_authorization_main.circom"
SNARKJS="$ROOT/node_modules/.bin/snarkjs"
PTAU="$ROOT/build/pot13_final.ptau"

R1CS="$BUILD/holder_authorization_main.r1cs"
WASM="$BUILD/holder_authorization_main_js/holder_authorization_main.wasm"
WITNESS_JS="$BUILD/holder_authorization_main_js/generate_witness.js"
ZKEY0="$BUILD/holder_authorization_0000.zkey"
ZKEY="$BUILD/holder_authorization_final.zkey"
VKEY="$BUILD/verification_key.json"

cd "$ROOT"

bash scripts/check_env.sh

if [ ! -x "$SNARKJS" ]; then
    echo "snarkjs: missing local executable at $SNARKJS"
    echo "Run 'npm install' from $ROOT before running this build."
    exit 1
fi

if ! node -e 'require("circomlibjs")' >/dev/null 2>&1; then
    echo "circomlibjs: missing local package required for real EdDSA-Poseidon input generation."
    echo "Run 'npm install' from $ROOT before running this build."
    exit 1
fi

mkdir -p "$BUILD"
find "$BUILD" -mindepth 1 -exec rm -rf {} +

echo "Compiling holder authorization circuit..."
circom "$CIRCUIT" --r1cs --wasm --sym -o "$BUILD" 2>&1 | tee "$BUILD/compile.log"

echo "Extracting R1CS info..."
"$SNARKJS" r1cs info "$R1CS" | tee "$BUILD/r1cs_info.txt"

if [ ! -f "$PTAU" ]; then
    echo "Generating local test Powers of Tau for holder authorization: $PTAU"
    echo "This Powers of Tau is for local measurement only and is not production-safe."
    "$SNARKJS" powersoftau new bn128 13 "$ROOT/build/pot13_0000.ptau" -v
    "$SNARKJS" powersoftau contribute "$ROOT/build/pot13_0000.ptau" "$ROOT/build/pot13_0001.ptau" \
        --name="holder authorization test contribution" -v -e="holder authorization entropy"
    "$SNARKJS" powersoftau prepare phase2 "$ROOT/build/pot13_0001.ptau" "$PTAU" -v
else
    echo "Using existing local test Powers of Tau: $PTAU"
    echo "This Powers of Tau is for local measurement only and is not production-safe."
fi

echo "Generating real BabyJubJub EdDSA-Poseidon authorization inputs..."
node <<'NODE'
const fs = require("fs");
const path = require("path");
const { buildEddsa, buildPoseidon } = require("circomlibjs");

function stringifyBigInts(value) {
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(stringifyBigInts);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, stringifyBigInts(v)]));
  }
  return value;
}

(async () => {
  const root = process.cwd();
  const inputsDir = path.join(root, "inputs");
  const buildDir = path.join(root, "build", "holder_authorization");

  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  const prvKey = Buffer.from(
    "0001020304050607080900010203040506070809000102030405060708090001",
    "hex"
  );
  const pubKey = eddsa.prv2pub(prvKey);

  const request = {
    request_digest: "12345678901234567890",
    holder_approved_mask: "3",
    selection_commitment: "9876543210987654321",
    protocol_context: "42",
  };
  const authDigest = poseidon([
    F.e(request.request_digest),
    F.e(request.holder_approved_mask),
    F.e(request.selection_commitment),
    F.e(request.protocol_context),
  ]);
  const signature = eddsa.signPoseidon(prvKey, authDigest);
  if (!eddsa.verifyPoseidon(authDigest, signature, pubKey)) {
    throw new Error("Generated EdDSA-Poseidon signature did not verify in circomlibjs.");
  }

  const valid = {
    ...request,
    holder_public_key_x: F.toObject(pubKey[0]),
    holder_public_key_y: F.toObject(pubKey[1]),
    signature_R8x: F.toObject(signature.R8[0]),
    signature_R8y: F.toObject(signature.R8[1]),
    signature_S: signature.S,
  };
  const invalidRequest = {
    ...valid,
    request_digest: "12345678901234567891",
  };
  const invalidSignature = {
    ...valid,
    signature_S: BigInt(signature.S) + 1n,
  };

  for (const [name, data] of [
    ["holder_authorization_valid.json", valid],
    ["holder_authorization_invalid_request.json", invalidRequest],
    ["holder_authorization_invalid_signature.json", invalidSignature],
  ]) {
    fs.writeFileSync(
      path.join(inputsDir, name),
      JSON.stringify(stringifyBigInts(data), null, 2) + "\n"
    );
  }
  fs.writeFileSync(
    path.join(buildDir, "auth_digest.txt"),
    F.toObject(authDigest).toString() + "\n"
  );
})();
NODE

echo "Generating valid witness..."
node "$WITNESS_JS" "$WASM" "$ROOT/inputs/holder_authorization_valid.json" "$BUILD/valid.wtns"

echo "Checking valid witness..."
"$SNARKJS" wtns check "$R1CS" "$BUILD/valid.wtns" | tee "$BUILD/valid_witness_check.log"

echo "Running Groth16 setup..."
"$SNARKJS" groth16 setup "$R1CS" "$PTAU" "$ZKEY0"
"$SNARKJS" zkey contribute "$ZKEY0" "$ZKEY" \
    --name="holder authorization zkey contribution" -v -e="holder authorization zkey entropy"
"$SNARKJS" zkey export verificationkey "$ZKEY" "$VKEY"

echo "Generating valid Groth16 proof..."
"$SNARKJS" groth16 prove "$ZKEY" "$BUILD/valid.wtns" "$BUILD/valid_proof.json" "$BUILD/valid_public.json"

echo "Verifying valid Groth16 proof..."
"$SNARKJS" groth16 verify "$VKEY" "$BUILD/valid_public.json" "$BUILD/valid_proof.json" | tee "$BUILD/valid_verify.log"

confirm_invalid() {
    name="$1"
    input="$ROOT/inputs/holder_authorization_${name}.json"
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

confirm_invalid invalid_request
confirm_invalid invalid_signature

echo "Holder authorization build complete. Generated files are in $BUILD."
