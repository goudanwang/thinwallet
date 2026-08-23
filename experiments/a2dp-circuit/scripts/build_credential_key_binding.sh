#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build/credential_key_binding"
CIRCUIT="$ROOT/circuits/credential_key_binding_main.circom"
SNARKJS="$ROOT/node_modules/.bin/snarkjs"
PTAU="$ROOT/build/pot12_final.ptau"

R1CS="$BUILD/credential_key_binding_main.r1cs"
WASM="$BUILD/credential_key_binding_main_js/credential_key_binding_main.wasm"
WITNESS_JS="$BUILD/credential_key_binding_main_js/generate_witness.js"
ZKEY0="$BUILD/credential_key_binding_0000.zkey"
ZKEY="$BUILD/credential_key_binding_final.zkey"
VKEY="$BUILD/verification_key.json"

cd "$ROOT"

bash scripts/check_env.sh

if [ ! -x "$SNARKJS" ]; then
    echo "snarkjs: missing local executable at $SNARKJS"
    echo "Run 'npm install' from $ROOT before running this build."
    exit 1
fi

if ! node -e 'require("circomlibjs")' >/dev/null 2>&1; then
    echo "circomlibjs: missing local package required for Poseidon and EdDSA host-side tests."
    echo "Run 'npm install' from $ROOT before running this build."
    exit 1
fi

if [ ! -f "$PTAU" ]; then
    echo "Missing local test Powers of Tau at $PTAU"
    echo "Run scripts/build_sanity.sh first to generate the non-production test ptau."
    exit 1
fi

echo "Using local test Powers of Tau: $PTAU"
echo "This Powers of Tau is for local measurement only and is not production-safe."

mkdir -p "$BUILD"
find "$BUILD" -mindepth 1 -exec rm -rf {} +

echo "Compiling credential-key binding circuit..."
circom "$CIRCUIT" --r1cs --wasm --sym -o "$BUILD" 2>&1 | tee "$BUILD/compile.log"

echo "Extracting R1CS info..."
"$SNARKJS" r1cs info "$R1CS" | tee "$BUILD/r1cs_info.txt"

echo "Generating deterministic enrollment inputs and host-side signature tests..."
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
  const buildDir = path.join(root, "build", "credential_key_binding");
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  const prvKey = Buffer.from(
    "1011121314151617181910111213141516171819101112131415161718191011",
    "hex"
  );
  const pubKey = eddsa.prv2pub(prvKey);

  const enrollment = {
    credential_commitment: "123456789012345678901",
    holder_public_key_x: F.toObject(pubKey[0]),
    holder_public_key_y: F.toObject(pubKey[1]),
    issuer_id: "7777777",
    schema_id: "8888888",
  };
  const enrollmentDigest = poseidon([
    F.e(enrollment.credential_commitment),
    F.e(enrollment.holder_public_key_x),
    F.e(enrollment.holder_public_key_y),
    F.e(enrollment.issuer_id),
    F.e(enrollment.schema_id),
  ]);

  const valid = {
    ...enrollment,
    expected_enrollment_digest: F.toObject(enrollmentDigest),
  };

  const otherPrvKey = Buffer.from(
    "2021222324252627282920212223242526272829202122232425262728292021",
    "hex"
  );
  const otherPubKey = eddsa.prv2pub(otherPrvKey);
  const invalidKey = {
    ...valid,
    holder_public_key_x: F.toObject(otherPubKey[0]),
    holder_public_key_y: F.toObject(otherPubKey[1]),
  };
  const invalidRecord = {
    ...valid,
    credential_commitment: "123456789012345678902",
  };

  for (const [name, data] of [
    ["credential_key_binding_valid.json", valid],
    ["credential_key_binding_invalid_key.json", invalidKey],
    ["credential_key_binding_invalid_record.json", invalidRecord],
  ]) {
    fs.writeFileSync(
      path.join(inputsDir, name),
      JSON.stringify(stringifyBigInts(data), null, 2) + "\n"
    );
  }

  const requestDigest = F.e("424242424242424242");
  const signature = eddsa.signPoseidon(prvKey, requestDigest);
  const wrongSignature = {
    R8: signature.R8,
    S: BigInt(signature.S) + 1n,
  };
  const changedRequestDigest = F.e("424242424242424243");
  const signatureTests = {
    valid_signature_verifies: eddsa.verifyPoseidon(requestDigest, signature, pubKey),
    modified_request_old_signature_verifies: eddsa.verifyPoseidon(changedRequestDigest, signature, pubKey),
    wrong_signature_verifies: eddsa.verifyPoseidon(requestDigest, wrongSignature, pubKey),
  };
  signatureTests.status =
    signatureTests.valid_signature_verifies === true &&
    signatureTests.modified_request_old_signature_verifies === false &&
    signatureTests.wrong_signature_verifies === false
      ? "ok"
      : "failed";

  const externalFixture = {
    request_digest: F.toObject(requestDigest),
    changed_request_digest: F.toObject(changedRequestDigest),
    holder_public_key_x: F.toObject(pubKey[0]),
    holder_public_key_y: F.toObject(pubKey[1]),
    signature_R8x: F.toObject(signature.R8[0]),
    signature_R8y: F.toObject(signature.R8[1]),
    signature_S: signature.S,
    wrong_signature_S: wrongSignature.S,
  };

  fs.writeFileSync(
    path.join(buildDir, "external_signature_fixture.json"),
    JSON.stringify(stringifyBigInts(externalFixture), null, 2) + "\n"
  );
  fs.writeFileSync(
    path.join(buildDir, "external_signature_tests.json"),
    JSON.stringify(stringifyBigInts(signatureTests), null, 2) + "\n"
  );
  fs.writeFileSync(
    path.join(buildDir, "enrollment_digest.txt"),
    F.toObject(enrollmentDigest).toString() + "\n"
  );

  const verifier = `const fs = require("fs");
const path = require("path");
const { buildEddsa, buildPoseidon } = require("circomlibjs");

(async () => {
  const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, "external_signature_fixture.json"), "utf8"));
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const pubKey = [F.e(fixture.holder_public_key_x), F.e(fixture.holder_public_key_y)];
  const signature = {
    R8: [F.e(fixture.signature_R8x), F.e(fixture.signature_R8y)],
    S: BigInt(fixture.signature_S),
  };
  const ok = eddsa.verifyPoseidon(F.e(fixture.request_digest), signature, pubKey);
  if (!ok) {
    throw new Error("External EdDSA-Poseidon verification failed.");
  }
})();
`;
  fs.writeFileSync(path.join(buildDir, "external_signature_verify.js"), verifier);
})();
NODE

echo "Generating valid witness..."
node "$WITNESS_JS" "$WASM" "$ROOT/inputs/credential_key_binding_valid.json" "$BUILD/valid.wtns"

echo "Checking valid witness..."
"$SNARKJS" wtns check "$R1CS" "$BUILD/valid.wtns" | tee "$BUILD/valid_witness_check.log"

echo "Running Groth16 setup..."
"$SNARKJS" groth16 setup "$R1CS" "$PTAU" "$ZKEY0"
"$SNARKJS" zkey contribute "$ZKEY0" "$ZKEY" \
    --name="credential key binding zkey contribution" -v -e="credential key binding entropy"
"$SNARKJS" zkey export verificationkey "$ZKEY" "$VKEY"

echo "Generating valid Groth16 proof..."
"$SNARKJS" groth16 prove "$ZKEY" "$BUILD/valid.wtns" "$BUILD/valid_proof.json" "$BUILD/valid_public.json"

echo "Verifying valid Groth16 proof..."
"$SNARKJS" groth16 verify "$VKEY" "$BUILD/valid_public.json" "$BUILD/valid_proof.json" | tee "$BUILD/valid_verify.log"

echo "Running host-side external signature tests..."
node "$BUILD/external_signature_verify.js"
python3 - <<'PY'
import json
import os

root = os.getcwd()
path = os.path.join(root, "build", "credential_key_binding", "external_signature_tests.json")
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)
if data.get("status") != "ok":
    raise SystemExit(f"External signature tests failed: {data}")
print(json.dumps(data, indent=2))
PY

confirm_invalid() {
    name="$1"
    input="$ROOT/inputs/credential_key_binding_${name}.json"
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

confirm_invalid invalid_key
confirm_invalid invalid_record

echo "Credential-key binding build complete. Generated files are in $BUILD."
