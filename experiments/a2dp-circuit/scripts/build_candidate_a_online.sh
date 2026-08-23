#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build/candidate_a_online"
CIRCUIT="$ROOT/circuits/candidate_a_online_presentation.circom"
SNARKJS="$ROOT/node_modules/.bin/snarkjs"
PTAU="$ROOT/build/pot12_final.ptau"

R1CS="$BUILD/candidate_a_online_presentation.r1cs"
WASM="$BUILD/candidate_a_online_presentation_js/candidate_a_online_presentation.wasm"
WITNESS_JS="$BUILD/candidate_a_online_presentation_js/generate_witness.js"
ZKEY0="$BUILD/candidate_a_online_0000.zkey"
ZKEY="$BUILD/candidate_a_online_final.zkey"
VKEY="$BUILD/verification_key.json"

cd "$ROOT"

bash scripts/check_env.sh

if [ ! -x "$SNARKJS" ]; then
    echo "snarkjs: missing local executable at $SNARKJS"
    echo "Run 'npm install' from $ROOT before running this build."
    exit 1
fi

if ! node -e 'require("circomlibjs")' >/dev/null 2>&1; then
    echo "circomlibjs: missing local package required for host-side signing and verification."
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

echo "Compiling Candidate A online presentation circuit..."
circom "$CIRCUIT" --r1cs --wasm --sym -o "$BUILD" 2>&1 | tee "$BUILD/compile.log"

echo "Extracting R1CS info..."
"$SNARKJS" r1cs info "$R1CS" | tee "$BUILD/r1cs_info.txt"

echo "Generating deterministic Candidate A inputs and external signature fixtures..."
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
  const buildDir = path.join(root, "build", "candidate_a_online");
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  const holderPrivateKeyHex = "1011121314151617181910111213141516171819101112131415161718191011";
  const prvKey = Buffer.from(holderPrivateKeyHex, "hex");
  const pubKey = eddsa.prv2pub(prvKey);

  const base = {
    birth_day_index: "9000",
    cutoff_day_index: "10000",
    verifier_domain_hash: "123456789",
    nonce: "987654321",
    policy_hash: "111111111",
    requested_disclosure_mask: "7",
    expiry: "20000",
    context_hash: "222222222",
    holder_approved_mask: "3",
    actual_disclosure_mask: "3",
    credential_commitment: "123456789012345678901",
    issuer_id: "7777777",
    schema_id: "8888888",
  };

  const requestDigest = poseidon([
    F.e(base.verifier_domain_hash),
    F.e(base.nonce),
    F.e(base.policy_hash),
    F.e(base.requested_disclosure_mask),
    F.e(base.expiry),
    F.e(base.context_hash),
  ]);
  const enrollmentDigest = poseidon([
    F.e(base.credential_commitment),
    F.e(pubKey[0]),
    F.e(pubKey[1]),
    F.e(base.issuer_id),
    F.e(base.schema_id),
  ]);
  const signature = eddsa.signPoseidon(prvKey, requestDigest);
  if (!eddsa.verifyPoseidon(requestDigest, signature, pubKey)) {
    throw new Error("Generated external EdDSA-Poseidon request signature did not verify.");
  }

  const valid = {
    ...base,
    request_digest: F.toObject(requestDigest),
    holder_public_key_x: F.toObject(pubKey[0]),
    holder_public_key_y: F.toObject(pubKey[1]),
    expected_enrollment_digest: F.toObject(enrollmentDigest),
  };

  const otherPrvKey = Buffer.from(
    "2021222324252627282920212223242526272829202122232425262728292021",
    "hex"
  );
  const otherPubKey = eddsa.prv2pub(otherPrvKey);

  const invalidNonce = { ...valid, nonce: "987654322" };
  const invalidDisclosure = { ...valid, actual_disclosure_mask: "7" };
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
    ["candidate_a_valid.json", valid],
    ["candidate_a_invalid_nonce.json", invalidNonce],
    ["candidate_a_invalid_disclosure.json", invalidDisclosure],
    ["candidate_a_invalid_key.json", invalidKey],
    ["candidate_a_invalid_record.json", invalidRecord],
  ]) {
    fs.writeFileSync(path.join(inputsDir, name), JSON.stringify(stringifyBigInts(data), null, 2) + "\n");
  }

  const wrongSignature = {
    R8: signature.R8,
    S: BigInt(signature.S) + 1n,
  };
  const changedRequestDigest = poseidon([
    F.e(base.verifier_domain_hash),
    F.e("987654322"),
    F.e(base.policy_hash),
    F.e(base.requested_disclosure_mask),
    F.e(base.expiry),
    F.e(base.context_hash),
  ]);

  const fixture = {
    holder_private_key_hex: holderPrivateKeyHex,
    request_digest: F.toObject(requestDigest),
    changed_request_digest: F.toObject(changedRequestDigest),
    holder_public_key_x: F.toObject(pubKey[0]),
    holder_public_key_y: F.toObject(pubKey[1]),
    signature_R8x: F.toObject(signature.R8[0]),
    signature_R8y: F.toObject(signature.R8[1]),
    signature_S: signature.S,
    wrong_signature_S: wrongSignature.S,
  };
  fs.writeFileSync(path.join(buildDir, "external_signature_fixture.json"), JSON.stringify(stringifyBigInts(fixture), null, 2) + "\n");

  const signatureTests = {
    valid_signature_verifies: eddsa.verifyPoseidon(requestDigest, signature, pubKey),
    modified_nonce_old_signature_verifies: eddsa.verifyPoseidon(changedRequestDigest, signature, pubKey),
    wrong_signature_verifies: eddsa.verifyPoseidon(requestDigest, wrongSignature, pubKey),
  };
  signatureTests.status =
    signatureTests.valid_signature_verifies === true &&
    signatureTests.modified_nonce_old_signature_verifies === false &&
    signatureTests.wrong_signature_verifies === false
      ? "ok"
      : "failed";
  fs.writeFileSync(path.join(buildDir, "external_signature_tests.json"), JSON.stringify(stringifyBigInts(signatureTests), null, 2) + "\n");

  const signer = `const fs = require("fs");
const path = require("path");
const { buildEddsa, buildPoseidon } = require("circomlibjs");

(async () => {
  const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, "external_signature_fixture.json"), "utf8"));
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const prvKey = Buffer.from(fixture.holder_private_key_hex, "hex");
  const signature = eddsa.signPoseidon(prvKey, poseidon.F.e(fixture.request_digest));
  if (!signature || signature.S === undefined) {
    throw new Error("Signing failed.");
  }
})();
`;
  fs.writeFileSync(path.join(buildDir, "holder_sign_request.js"), signer);

  const verifier = `const fs = require("fs");
const path = require("path");
const { buildEddsa, buildPoseidon } = require("circomlibjs");

(async () => {
  const mode = process.argv[2] || "valid";
  const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, "external_signature_fixture.json"), "utf8"));
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const pubKey = [F.e(fixture.holder_public_key_x), F.e(fixture.holder_public_key_y)];
  const signature = {
    R8: [F.e(fixture.signature_R8x), F.e(fixture.signature_R8y)],
    S: BigInt(mode === "invalid_signature" ? fixture.wrong_signature_S : fixture.signature_S),
  };
  const message = F.e(mode === "invalid_nonce" ? fixture.changed_request_digest : fixture.request_digest);
  const ok = eddsa.verifyPoseidon(message, signature, pubKey);
  if (!ok) {
    throw new Error("External EdDSA-Poseidon verification failed for mode " + mode + ".");
  }
})();
`;
  fs.writeFileSync(path.join(buildDir, "external_signature_verify.js"), verifier);

  fs.writeFileSync(path.join(buildDir, "request_digest.txt"), F.toObject(requestDigest).toString() + "\n");
  fs.writeFileSync(path.join(buildDir, "enrollment_digest.txt"), F.toObject(enrollmentDigest).toString() + "\n");
})();
NODE

echo "Verifying external holder signature before witness/proof generation..."
node "$BUILD/external_signature_verify.js" valid

echo "Confirming modified nonce rejects the old external signature..."
set +e
node "$BUILD/external_signature_verify.js" invalid_nonce >"$BUILD/invalid_external_nonce_stdout.log" 2>"$BUILD/invalid_external_nonce_stderr.log"
invalid_external_nonce_status=$?
node "$BUILD/external_signature_verify.js" invalid_signature >"$BUILD/invalid_external_signature_stdout.log" 2>"$BUILD/invalid_external_signature_stderr.log"
invalid_external_signature_status=$?
set -e
if [ "$invalid_external_nonce_status" -eq 0 ] || [ "$invalid_external_signature_status" -eq 0 ]; then
    echo "External signature negative test unexpectedly passed."
    exit 1
fi
{
    echo "invalid_nonce_external_signature_exit_status=$invalid_external_nonce_status"
    echo "invalid_signature_external_signature_exit_status=$invalid_external_signature_status"
    echo "expected_failure=true"
} | tee "$BUILD/external_signature_rejection.log"

echo "Generating valid witness..."
node "$WITNESS_JS" "$WASM" "$ROOT/inputs/candidate_a_valid.json" "$BUILD/valid.wtns"

echo "Checking valid witness..."
"$SNARKJS" wtns check "$R1CS" "$BUILD/valid.wtns" | tee "$BUILD/valid_witness_check.log"

echo "Running Groth16 setup..."
"$SNARKJS" groth16 setup "$R1CS" "$PTAU" "$ZKEY0"
"$SNARKJS" zkey contribute "$ZKEY0" "$ZKEY" \
    --name="candidate a online zkey contribution" -v -e="candidate a online entropy"
"$SNARKJS" zkey export verificationkey "$ZKEY" "$VKEY"

echo "Generating valid Groth16 proof..."
"$SNARKJS" groth16 prove "$ZKEY" "$BUILD/valid.wtns" "$BUILD/valid_proof.json" "$BUILD/valid_public.json"

echo "Verifying valid Groth16 proof..."
"$SNARKJS" groth16 verify "$VKEY" "$BUILD/valid_public.json" "$BUILD/valid_proof.json" | tee "$BUILD/valid_verify.log"

confirm_invalid() {
    name="$1"
    input="$ROOT/inputs/candidate_a_${name}.json"
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

confirm_invalid invalid_nonce
confirm_invalid invalid_disclosure
confirm_invalid invalid_key
confirm_invalid invalid_record

echo "Candidate A online build complete. Generated files are in $BUILD."
