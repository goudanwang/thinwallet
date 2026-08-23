#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build/request_binding"
CIRCUIT="$ROOT/circuits/request_binding_main.circom"
SNARKJS="$ROOT/node_modules/.bin/snarkjs"
PTAU="$ROOT/build/pot12_final.ptau"

R1CS="$BUILD/request_binding_main.r1cs"
WASM="$BUILD/request_binding_main_js/request_binding_main.wasm"
WITNESS_JS="$BUILD/request_binding_main_js/generate_witness.js"
ZKEY0="$BUILD/request_binding_0000.zkey"
ZKEY="$BUILD/request_binding_final.zkey"
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

echo "Compiling request binding circuit..."
circom "$CIRCUIT" --r1cs --wasm --sym -o "$BUILD" 2>&1 | tee "$BUILD/compile.log"

echo "Extracting R1CS info..."
"$SNARKJS" r1cs info "$R1CS" | tee "$BUILD/r1cs_info.txt"

echo "Computing valid request digest with a temporary Poseidon helper..."
python3 - <<'PY'
import json
import os

root = os.getcwd()
build = os.path.join(root, "build", "request_binding")
helper = os.path.join(build, "request_binding_digest_helper.circom")
base = {
    "verifier_domain_hash": "123456789",
    "nonce": "987654321",
    "policy_hash": "111111111",
    "requested_disclosure_mask": "5",
    "expiry": "20000",
    "context_hash": "222222222",
}
with open(helper, "w", encoding="utf-8") as handle:
    handle.write("""pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";

template RequestBindingDigestHelper() {
    signal input verifier_domain_hash;
    signal input nonce;
    signal input policy_hash;
    signal input requested_disclosure_mask;
    signal input expiry;
    signal input context_hash;
    signal output digest;

    component request_hash = Poseidon(6);
    request_hash.inputs[0] <== verifier_domain_hash;
    request_hash.inputs[1] <== nonce;
    request_hash.inputs[2] <== policy_hash;
    request_hash.inputs[3] <== requested_disclosure_mask;
    request_hash.inputs[4] <== expiry;
    request_hash.inputs[5] <== context_hash;
    digest <== request_hash.out;
}

component main = RequestBindingDigestHelper();
""")
with open(os.path.join(build, "digest_input.json"), "w", encoding="utf-8") as handle:
    json.dump(base, handle, indent=2)
    handle.write("\n")
PY

mkdir -p "$BUILD/digest_helper_build"
circom "$BUILD/request_binding_digest_helper.circom" --wasm --sym -o "$BUILD/digest_helper_build" \
    >"$BUILD/digest_helper_compile.log" 2>&1
node "$BUILD/digest_helper_build/request_binding_digest_helper_js/generate_witness.js" \
    "$BUILD/digest_helper_build/request_binding_digest_helper_js/request_binding_digest_helper.wasm" \
    "$BUILD/digest_input.json" \
    "$BUILD/digest_helper.wtns"
"$SNARKJS" wtns export json "$BUILD/digest_helper.wtns" "$BUILD/digest_helper_witness.json"

python3 - <<'PY'
import json
import os

root = os.getcwd()
build = os.path.join(root, "build", "request_binding")
inputs = os.path.join(root, "inputs")
with open(os.path.join(build, "digest_helper_witness.json"), "r", encoding="utf-8") as handle:
    witness = json.load(handle)
digest = witness[1]

valid = {
    "verifier_domain_hash": "123456789",
    "nonce": "987654321",
    "policy_hash": "111111111",
    "requested_disclosure_mask": "5",
    "expiry": "20000",
    "context_hash": "222222222",
    "expected_request_digest": digest,
}
invalid = dict(valid)
invalid["nonce"] = "987654322"
invalid_domain = dict(valid)
invalid_domain["verifier_domain_hash"] = "123456790"

for name, data in [
    ("request_binding_valid.json", valid),
    ("request_binding_invalid.json", invalid),
    ("request_binding_invalid_domain.json", invalid_domain),
]:
    with open(os.path.join(inputs, name), "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")

with open(os.path.join(build, "expected_request_digest.txt"), "w", encoding="utf-8") as handle:
    handle.write(digest + "\n")
PY

make_witness() {
    name="$1"
    input="$ROOT/inputs/request_binding_${name}.json"
    witness="$BUILD/${name}.wtns"

    echo "Generating $name witness..."
    node "$WITNESS_JS" "$WASM" "$input" "$witness"

    echo "Checking $name witness..."
    "$SNARKJS" wtns check "$R1CS" "$witness" | tee "$BUILD/${name}_witness_check.log"
}

make_witness valid

echo "Running Groth16 setup..."
"$SNARKJS" groth16 setup "$R1CS" "$PTAU" "$ZKEY0"
"$SNARKJS" zkey contribute "$ZKEY0" "$ZKEY" \
    --name="request binding zkey contribution" -v -e="request binding test entropy"
"$SNARKJS" zkey export verificationkey "$ZKEY" "$VKEY"

echo "Generating valid Groth16 proof..."
"$SNARKJS" groth16 prove "$ZKEY" "$BUILD/valid.wtns" "$BUILD/valid_proof.json" "$BUILD/valid_public.json"

echo "Verifying valid Groth16 proof..."
"$SNARKJS" groth16 verify "$VKEY" "$BUILD/valid_public.json" "$BUILD/valid_proof.json" | tee "$BUILD/valid_verify.log"

confirm_invalid() {
    name="$1"
    input="$ROOT/inputs/request_binding_${name}.json"
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

confirm_invalid invalid
confirm_invalid invalid_domain

echo "Request binding build complete. Generated files are in $BUILD."
