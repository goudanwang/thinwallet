import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { createRequire } from "module";

const require = createRequire(import.meta.url);
const { buildEddsa, buildPoseidon } = require("circomlibjs");

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, "..");
const resultsDir = path.join(root, "results");
const rawPath = path.join(resultsDir, "external_auth_persistent_raw.json");
const metricsPath = path.join(resultsDir, "external_auth_persistent_metrics.json");

const WARMUP_RUNS = 20;
const MEASURED_RUNS = 100;

function nowNs() {
  return process.hrtime.bigint();
}

function nsToMs(ns) {
  return Number(ns) / 1_000_000;
}

function timed(fn) {
  const start = nowNs();
  const value = fn();
  const elapsedMs = nsToMs(nowNs() - start);
  return { value, elapsedMs };
}

async function timedAsync(fn) {
  const start = nowNs();
  const value = await fn();
  const elapsedMs = nsToMs(nowNs() - start);
  return { value, elapsedMs };
}

function stringifyBigInts(value) {
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(stringifyBigInts);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, stringifyBigInts(item)]));
  }
  return value;
}

function stats(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const sum = values.reduce((acc, value) => acc + value, 0);
  const median =
    sorted.length % 2 === 0
      ? (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2
      : sorted[Math.floor(sorted.length / 2)];
  const p95 = sorted[Math.ceil(sorted.length * 0.95) - 1];
  return {
    mean: Number((sum / values.length).toFixed(6)),
    median: Number(median.toFixed(6)),
    min: Number(sorted[0].toFixed(6)),
    max: Number(sorted[sorted.length - 1].toFixed(6)),
    p95: Number(p95.toFixed(6)),
  };
}

function rssMb() {
  return Number((process.memoryUsage().rss / 1024 / 1024).toFixed(3));
}

function versionFromPackage(packagePath) {
  return JSON.parse(fs.readFileSync(path.join(root, packagePath), "utf8")).version;
}

function requestDigest(poseidon, F, request) {
  return poseidon([
    F.e(request.verifier_domain_hash),
    F.e(request.nonce),
    F.e(request.policy_hash),
    F.e(request.requested_disclosure_mask),
    F.e(request.expiry),
    F.e(request.context_hash),
  ]);
}

function measuredOperation(eddsa, poseidon, F, privateKey, publicKey, request) {
  const digestTiming = timed(() => requestDigest(poseidon, F, request));
  const digest = digestTiming.value;
  const signingTiming = timed(() => eddsa.signPoseidon(privateKey, digest));
  const signature = signingTiming.value;
  const verificationTiming = timed(() => eddsa.verifyPoseidon(digest, signature, publicKey));
  if (!verificationTiming.value) {
    throw new Error("Generated signature did not verify during measured operation.");
  }
  return {
    digest_ms: digestTiming.elapsedMs,
    signing_ms: signingTiming.elapsedMs,
    verification_ms: verificationTiming.elapsedMs,
  };
}

const node_process_uptime_at_script_start_ms = Number((process.uptime() * 1000).toFixed(6));

const initTiming = await timedAsync(async () => {
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  return { eddsa, poseidon };
});

const { eddsa, poseidon } = initTiming.value;
const F = poseidon.F;

const keyTiming = timed(() => {
  const privateKey = Buffer.from(
    "1011121314151617181910111213141516171819101112131415161718191011",
    "hex"
  );
  const publicKey = eddsa.prv2pub(privateKey);
  return { privateKey, publicKey };
});

const { privateKey, publicKey } = keyTiming.value;
const rss_after_initialization_mb = rssMb();

const request = {
  verifier_domain_hash: "123456789",
  nonce: "987654321",
  policy_hash: "111111111",
  requested_disclosure_mask: "7",
  expiry: "20000",
  context_hash: "222222222",
};

for (let i = 0; i < WARMUP_RUNS; i += 1) {
  measuredOperation(eddsa, poseidon, F, privateKey, publicKey, request);
}

const runs = [];
for (let i = 0; i < MEASURED_RUNS; i += 1) {
  runs.push({
    iteration: i + 1,
    ...measuredOperation(eddsa, poseidon, F, privateKey, publicKey, request),
  });
}

const digest = requestDigest(poseidon, F, request);
const signature = eddsa.signPoseidon(privateKey, digest);
const valid_signature_verifies = eddsa.verifyPoseidon(digest, signature, publicKey);

const modifiedRequest = { ...request, nonce: "987654322" };
const modifiedDigest = requestDigest(poseidon, F, modifiedRequest);
const modified_message_old_signature_verifies = eddsa.verifyPoseidon(modifiedDigest, signature, publicKey);

const wrongSignature = {
  R8: signature.R8,
  S: BigInt(signature.S) + 1n,
};
const modified_signature_verifies = eddsa.verifyPoseidon(digest, wrongSignature, publicKey);

const process_startup_and_library_init_ms = Number(
  (node_process_uptime_at_script_start_ms + initTiming.elapsedMs).toFixed(6)
);
const key_derivation_ms = Number(keyTiming.elapsedMs.toFixed(6));

const raw = {
  experiment: "external_auth_persistent",
  measurement_mode: "persistent_node_process",
  warmup_runs: WARMUP_RUNS,
  measured_runs: MEASURED_RUNS,
  timing_method: "process.hrtime.bigint()",
  node_process_uptime_at_script_start_ms,
  library_builder_initialization_ms: Number(initTiming.elapsedMs.toFixed(6)),
  process_startup_and_library_init_ms,
  key_derivation_ms,
  rss_after_initialization_mb,
  tool_versions: {
    node: process.version,
    circomlibjs: versionFromPackage("node_modules/circomlibjs/package.json"),
  },
  request,
  public_key: {
    holder_public_key_x: F.toObject(publicKey[0]).toString(),
    holder_public_key_y: F.toObject(publicKey[1]).toString(),
  },
  runs,
  verification_tests: {
    valid_signature_verifies,
    modified_message_old_signature_verifies,
    modified_signature_verifies,
    status:
      valid_signature_verifies === true &&
      modified_message_old_signature_verifies === false &&
      modified_signature_verifies === false
        ? "ok"
        : "failed",
  },
};

const digestTimes = runs.map((run) => run.digest_ms);
const signingTimes = runs.map((run) => run.signing_ms);
const verificationTimes = runs.map((run) => run.verification_ms);

const metrics = {
  experiment: "external_auth_persistent",
  status: raw.verification_tests.status,
  measurement_mode: "persistent_node_process",
  timing_method: "process.hrtime.bigint()",
  warmup_runs: WARMUP_RUNS,
  measured_runs: MEASURED_RUNS,
  process_startup_and_library_init_ms,
  node_process_uptime_at_script_start_ms,
  library_builder_initialization_ms: raw.library_builder_initialization_ms,
  key_derivation_ms,
  rss_after_initialization_mb,
  tool_versions: raw.tool_versions,
  digest_ms: digestTimes,
  signing_ms: signingTimes,
  verification_ms: verificationTimes,
  summary: {
    digest_ms: stats(digestTimes),
    signing_ms: stats(signingTimes),
    verification_ms: stats(verificationTimes),
  },
  verification_tests: raw.verification_tests,
  notes: [
    "This benchmark uses one persistent Node process.",
    "circomlibjs EdDSA and Poseidon builders are initialized once before warm-up and measurement.",
    "holder key and public key derivation are performed once before warm-up and measurement.",
    "The 100 measured operations do not call builders and do not start new Node processes.",
  ],
};

fs.mkdirSync(resultsDir, { recursive: true });
fs.writeFileSync(rawPath, JSON.stringify(stringifyBigInts(raw), null, 2) + "\n");
fs.writeFileSync(metricsPath, JSON.stringify(stringifyBigInts(metrics), null, 2) + "\n");

console.log(path.relative(root, rawPath));
console.log(path.relative(root, metricsPath));
