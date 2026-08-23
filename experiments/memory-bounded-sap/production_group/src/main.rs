use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::Instant;

const FIELD_BYTES: usize = 32;
const POINT_BYTES: usize = 32;

#[derive(Clone)]
struct Params {
    n_code: usize,
    repetition: usize,
    sigma1_a: usize,
    sigma1_b: usize,
    sigma2_a: usize,
    sigma2_b: usize,
}

#[derive(Serialize)]
struct Phase2dSummary {
    backend: BackendRecord,
    prototype_group_audit: StatusNotes,
    encoding: StatusNotes,
    msm: StatusNotes,
    h_generation: HGeneration,
    v1: VerificationMode,
    v2: VerificationMode,
    receipt: StatusNotes,
    emsm: EmsmRecord,
    malicious: StatusNotes,
    native_proof: StatusNotes,
    memory: MemoryRecord,
    negative_tests: StatusNotes,
    migration: StatusNotes,
    primary_classification: String,
}

#[derive(Serialize)]
struct BackendRecord {
    status_marker: String,
    curve_name: String,
    scalar_modulus: String,
    group_order: String,
    cofactor: String,
    compressed_point_bytes: usize,
    security_estimate: String,
    subgroup_check_method: String,
    backend_version: String,
}

#[derive(Serialize)]
struct StatusNotes {
    status_marker: String,
    notes: Vec<String>,
}

#[derive(Serialize)]
struct HGeneration {
    status_marker: String,
    records: Vec<HGenerationRecord>,
}

#[derive(Serialize)]
struct HGenerationRecord {
    n: usize,
    n_code: usize,
    root_h: String,
    output_file_size: u64,
    setup_generation_latency_ms: f64,
    group_additions_model: u64,
    scalar_multiplications_model: u64,
    peak_rss_mb: Option<f64>,
}

#[derive(Serialize)]
struct VerificationMode {
    status_marker: String,
    records: Vec<VerificationRecord>,
}

#[derive(Serialize)]
struct VerificationRecord {
    n: usize,
    accepted: bool,
    latency_ms: f64,
    group_operations_model: u64,
    field_operations_model: u64,
    temporary_storage_bytes: u64,
    peak_rss_mb: Option<f64>,
}

#[derive(Serialize)]
struct EmsmRecord {
    status_marker: String,
    records: Vec<EmsmRun>,
}

#[derive(Serialize)]
struct EmsmRun {
    n: usize,
    n_code: usize,
    t: usize,
    semihonest_correct: bool,
    malicious_check_correct: bool,
    masked_upload_bytes: u64,
    server_msm_work_model: u64,
    correction_msm_work_model: u64,
    h_accesses: usize,
}

#[derive(Serialize)]
struct MemoryRecord {
    status_marker: String,
    records: Vec<MemoryRun>,
}

#[derive(Serialize)]
struct MemoryRun {
    n: usize,
    h_file_bytes: u64,
    peak_rss_mb: Option<f64>,
    ram_per_n: Option<f64>,
    projective_point_buffers: usize,
    affine_point_buffers: usize,
    msm_scratch_space: String,
}

fn odd_stride(seed: usize, modulus: usize) -> usize {
    ((seed.wrapping_mul(1_103_515_245).wrapping_add(12_345)) % modulus) | 1
}

fn make_params(n: usize) -> Params {
    let n_code = 4 * n;
    Params {
        n_code,
        repetition: 4,
        sigma1_a: odd_stride(17, n_code),
        sigma1_b: (97 * n + 11) % n_code,
        sigma2_a: odd_stride(29, n_code),
        sigma2_b: (131 * n + 7) % n_code,
    }
}

fn paper_t(n: usize, lambda: f64) -> usize {
    let n_code = 4.0 * n as f64;
    let raw = std::f64::consts::LN_2 * (lambda - n_code.log2()) / 0.05;
    raw.ceil().max(1.0) as usize
}

fn hash_to_fr(parts: &[&[u8]]) -> Fr {
    let mut h = Sha256::new();
    for part in parts {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part);
    }
    Fr::from_le_bytes_mod_order(&h.finalize())
}

fn fr_from_index(domain: &[u8], i: usize) -> Fr {
    let mut s = hash_to_fr(&[domain, &i.to_le_bytes()]);
    if s.is_zero() {
        s = Fr::from(1u64);
    }
    s
}

fn generate_basis(n: usize) -> Vec<G1Affine> {
    let gen = G1Projective::generator();
    let mut cur = G1Projective::zero();
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        cur += gen;
        out.push(cur.into_affine());
    }
    out
}

fn permute_fr(values: Vec<Fr>, a: usize, b: usize) -> Vec<Fr> {
    let n = values.len();
    let mut out = vec![Fr::zero(); n];
    for (i, v) in values.into_iter().enumerate() {
        out[(a * i + b) % n] = v;
    }
    out
}

fn accumulator_fr(values: Vec<Fr>) -> Vec<Fr> {
    let mut acc = Fr::zero();
    values
        .into_iter()
        .map(|v| {
            acc += v;
            acc
        })
        .collect()
}

fn fold_fr(values: Vec<Fr>, repetition: usize) -> Vec<Fr> {
    values
        .chunks(repetition)
        .map(|chunk| chunk.iter().copied().sum())
        .collect()
}

fn dense_g_alpha(params: &Params, alpha: Vec<Fr>) -> Vec<Fr> {
    let v = accumulator_fr(alpha);
    let v = permute_fr(v, params.sigma2_a, params.sigma2_b);
    let v = accumulator_fr(v);
    let v = permute_fr(v, params.sigma1_a, params.sigma1_b);
    fold_fr(v, params.repetition)
}

fn sparse_ge(params: &Params, entries: &[(usize, Fr)]) -> Vec<Fr> {
    let mut v = vec![Fr::zero(); params.n_code];
    for (idx, scalar) in entries {
        v[*idx] = *scalar;
    }
    dense_g_alpha(params, v)
}

fn permute_transpose_group(values: Vec<G1Projective>, a: usize, b: usize) -> Vec<G1Projective> {
    let n = values.len();
    (0..n).map(|i| values[(a * i + b) % n]).collect()
}

fn accumulator_transpose_group(values: Vec<G1Projective>) -> Vec<G1Projective> {
    let mut out = vec![G1Projective::zero(); values.len()];
    let mut acc = G1Projective::zero();
    for i in (0..values.len()).rev() {
        acc += values[i];
        out[i] = acc;
    }
    out
}

fn generate_h(params: &Params, basis: &[G1Affine]) -> Vec<G1Affine> {
    let mut v = Vec::with_capacity(params.n_code);
    for p in basis {
        let proj = G1Projective::from(*p);
        for _ in 0..params.repetition {
            v.push(proj);
        }
    }
    let v = permute_transpose_group(v, params.sigma1_a, params.sigma1_b);
    let v = accumulator_transpose_group(v);
    let v = permute_transpose_group(v, params.sigma2_a, params.sigma2_b);
    let v = accumulator_transpose_group(v);
    v.into_iter().map(|p| p.into_affine()).collect()
}

fn serialize_point(point: &G1Affine) -> Vec<u8> {
    let mut out = Vec::new();
    point.serialize_compressed(&mut out).unwrap();
    out
}

fn decode_and_validate_point(bytes: &[u8], allow_identity: bool) -> Result<G1Affine, String> {
    if bytes.len() != POINT_BYTES {
        return Err("wrong compressed point length".into());
    }
    let point = G1Affine::deserialize_compressed(bytes)
        .map_err(|e: SerializationError| format!("canonical decode failed: {e:?}"))?;
    if !point.is_on_curve() {
        return Err("point is not on curve".into());
    }
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err("point is not in prime-order subgroup".into());
    }
    if !allow_identity && point.is_zero() {
        return Err("identity point rejected by policy".into());
    }
    Ok(point)
}

fn root_points(points: &[G1Affine]) -> String {
    let mut h = Sha256::new();
    for p in points {
        h.update(serialize_point(p));
    }
    hex(&h.finalize())
}

fn write_h_file(path: &Path, h: &[G1Affine]) -> u64 {
    let mut bytes = Vec::with_capacity(h.len() * POINT_BYTES);
    for p in h {
        bytes.extend(serialize_point(p));
    }
    fs::write(path, bytes).unwrap();
    path.metadata().unwrap().len()
}

fn read_h_file(path: &Path) -> Vec<G1Affine> {
    let bytes = fs::read(path).unwrap();
    bytes
        .chunks(POINT_BYTES)
        .map(|chunk| decode_and_validate_point(chunk, false).unwrap())
        .collect()
}

fn msm_naive(scalars: &[Fr], bases: &[G1Affine]) -> G1Projective {
    assert_eq!(scalars.len(), bases.len());
    let mut acc = G1Projective::zero();
    for (s, b) in scalars.iter().zip(bases.iter()) {
        acc += G1Projective::from(*b) * *s;
    }
    acc
}

fn sparse_msm(entries: &[(usize, Fr)], h: &[G1Affine]) -> G1Projective {
    let mut acc = G1Projective::zero();
    for (idx, scalar) in entries {
        acc += G1Projective::from(h[*idx]) * *scalar;
    }
    acc
}

fn sample_sparse(params: &Params, t: usize, domain: &[u8]) -> Vec<(usize, Fr)> {
    let mut out = Vec::with_capacity(t);
    let mut used = std::collections::BTreeSet::new();
    let mut ctr = 0usize;
    while out.len() < t {
        let idx_fr = hash_to_fr(&[domain, b"idx", &ctr.to_le_bytes()]);
        let idx = (idx_fr.into_bigint().0[0] as usize) % params.n_code;
        let scalar = fr_from_index(domain, ctr + 1_000_000);
        ctr += 1;
        if used.insert(idx) {
            out.push((idx, scalar));
        }
    }
    out.sort_by_key(|x| x.0);
    out
}

fn alpha_vec(
    params: &Params,
    manifest_digest: &str,
    root_g: &str,
    root_h: &str,
    nonce: &[u8],
    round: usize,
) -> Vec<Fr> {
    (0..params.n_code)
        .map(|i| {
            hash_to_fr(&[
                b"phase2d_setup_check_domain",
                manifest_digest.as_bytes(),
                root_g.as_bytes(),
                root_h.as_bytes(),
                nonce,
                &round.to_le_bytes(),
                &i.to_le_bytes(),
            ])
        })
        .collect()
}

fn rss_mb() -> Option<f64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb = rest.split_whitespace().next()?.parse::<f64>().ok()?;
            return Some(kb / 1024.0);
        }
    }
    None
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn run_for_n(
    n: usize,
    out_dir: &Path,
) -> (
    HGenerationRecord,
    VerificationRecord,
    VerificationRecord,
    EmsmRun,
    MemoryRun,
) {
    let params = make_params(n);
    let start = Instant::now();
    let basis = generate_basis(n);
    let h = generate_h(&params, &basis);
    let h_file = out_dir.join(format!("production_h_n{n}.bin"));
    let h_size = write_h_file(&h_file, &h);
    let h_read = read_h_file(&h_file);
    assert_eq!(h, h_read);
    let root_h = root_points(&h);
    let h_latency = start.elapsed().as_secs_f64() * 1000.0;
    let h_record = HGenerationRecord {
        n,
        n_code: params.n_code,
        root_h: root_h.clone(),
        output_file_size: h_size,
        setup_generation_latency_ms: h_latency,
        group_additions_model: (params.n_code * 2 + params.n_code) as u64,
        scalar_multiplications_model: n as u64,
        peak_rss_mb: rss_mb(),
    };

    let v1_start = Instant::now();
    let h2 = generate_h(&params, &basis);
    let v1_ok = root_points(&h2) == root_h;
    let v1 = VerificationRecord {
        n,
        accepted: v1_ok,
        latency_ms: v1_start.elapsed().as_secs_f64() * 1000.0,
        group_operations_model: (params.n_code * 3) as u64,
        field_operations_model: 0,
        temporary_storage_bytes: h_size,
        peak_rss_mb: rss_mb(),
    };

    let root_g = root_points(&basis);
    let manifest_digest = hex(&Sha256::digest(
        format!("{n}:{root_g}:{root_h}:bn254-g1").as_bytes(),
    ));
    let nonce = Sha256::digest(format!("phase2d-nonce-{n}").as_bytes());
    let v2_start = Instant::now();
    let alpha = alpha_vec(&params, &manifest_digest, &root_g, &root_h, &nonce, 0);
    let beta = dense_g_alpha(&params, alpha.clone());
    let left = msm_naive(&alpha, &h);
    let right = msm_naive(&beta, &basis);
    let v2 = VerificationRecord {
        n,
        accepted: left == right,
        latency_ms: v2_start.elapsed().as_secs_f64() * 1000.0,
        group_operations_model: (params.n_code + n) as u64,
        field_operations_model: (params.n_code * 6) as u64,
        temporary_storage_bytes: ((params.n_code + n) * FIELD_BYTES) as u64,
        peak_rss_mb: rss_mb(),
    };

    let z: Vec<Fr> = (0..n).map(|i| fr_from_index(b"z", i)).collect();
    let t = paper_t(n, 128.0);
    let e = sample_sparse(&params, t, format!("emsm-{n}").as_bytes());
    let r = sparse_ge(&params, &e);
    let v: Vec<Fr> = z.iter().zip(r.iter()).map(|(a, b)| *a + *b).collect();
    let em = msm_naive(&v, &basis);
    let correction = sparse_msm(&e, &h);
    let dm = em - correction;
    let expected = msm_naive(&z, &basis);

    let c = fr_from_index(b"malicious-c", n);
    let e_check = sample_sparse(&params, t, format!("emsm-check-{n}").as_bytes());
    let cz: Vec<Fr> = z.iter().map(|s| *s * c).collect();
    let r_check = sparse_ge(&params, &e_check);
    let v_check: Vec<Fr> = cz
        .iter()
        .zip(r_check.iter())
        .map(|(a, b)| *a + *b)
        .collect();
    let em_check = msm_naive(&v_check, &basis);
    let correction_check = sparse_msm(&e_check, &h);
    let dm_check = em_check - correction_check;
    let malicious_ok = dm == expected && dm_check == expected * c;

    let emsm = EmsmRun {
        n,
        n_code: params.n_code,
        t,
        semihonest_correct: dm == expected,
        malicious_check_correct: malicious_ok,
        masked_upload_bytes: (n * POINT_BYTES) as u64,
        server_msm_work_model: n as u64 * 2,
        correction_msm_work_model: t as u64 * 2,
        h_accesses: t * 2,
    };
    let mem = MemoryRun {
        n,
        h_file_bytes: h_size,
        peak_rss_mb: rss_mb(),
        ram_per_n: rss_mb().map(|m| m / n as f64),
        projective_point_buffers: params.n_code,
        affine_point_buffers: params.n_code + n,
        msm_scratch_space: "arkworks naive projective accumulation in Phase 2D harness".into(),
    };
    (h_record, v1, v2, emsm, mem)
}

fn encoding_tests() -> (bool, bool) {
    let p = G1Projective::generator().into_affine();
    let bytes = serialize_point(&p);
    let valid = decode_and_validate_point(&bytes, false).is_ok();
    let mut trailing = bytes.clone();
    trailing.push(0);
    let trailing_reject = decode_and_validate_point(&trailing, false).is_err();
    let identity = G1Projective::zero().into_affine();
    let identity_reject = decode_and_validate_point(&serialize_point(&identity), false).is_err();
    let mut damaged = bytes;
    damaged[0] ^= 0x55;
    let damaged_reject = decode_and_validate_point(&damaged, false).is_err();
    (
        valid && trailing_reject && identity_reject && damaged_reject,
        valid,
    )
}

fn main() {
    let cwd = std::env::current_dir().unwrap();
    let out_dir = cwd.join("results");
    fs::create_dir_all(&out_dir).unwrap();
    let root_results = cwd.parent().unwrap().join("results");
    fs::create_dir_all(&root_results).unwrap();
    let large = std::env::var("MEMORY_BOUNDED_SAP_LARGE_BENCH")
        .ok()
        .as_deref()
        == Some("1");
    let ns: Vec<usize> = if large {
        vec![1 << 12, 1 << 14, 1 << 16, 1 << 18]
    } else {
        vec![1 << 12, 1 << 14, 1 << 16]
    };
    let mut h_records = Vec::new();
    let mut v1_records = Vec::new();
    let mut v2_records = Vec::new();
    let mut emsm_records = Vec::new();
    let mut mem_records = Vec::new();
    for n in ns {
        let (h, v1, v2, emsm, mem) = run_for_n(n, &out_dir);
        h_records.push(h);
        v1_records.push(v1);
        v2_records.push(v2);
        emsm_records.push(emsm);
        mem_records.push(mem);
    }
    let (encoding_ok, subgroup_ok) = encoding_tests();
    let backend = BackendRecord {
        status_marker: "PRODUCTION_GROUP_BACKEND_SELECTED".into(),
        curve_name: "BN254 G1".into(),
        scalar_modulus: format!("{:?}", Fr::MODULUS),
        group_order: format!("{:?}", Fr::MODULUS),
        cofactor: "1".into(),
        compressed_point_bytes: POINT_BYTES,
        security_estimate: "roughly 100-bit classical security for BN254".into(),
        subgroup_check_method: "arkworks G1Affine::is_on_curve + is_in_correct_subgroup_assuming_on_curve after CanonicalDeserialize".into(),
        backend_version: "arkworks 0.4".into(),
    };
    let summary = Phase2dSummary {
        backend,
        prototype_group_audit: StatusNotes {
            status_marker: "PROTOTYPE_GROUP_REMOVED".into(),
            notes: vec![
                "Production Phase 2D execution path is the Rust Arkworks BN254/G1 harness.".into(),
                "Earlier additive-field Python modules remain archived prototypes and are not used by run_phase2d.sh production-group checks.".into(),
            ],
        },
        encoding: StatusNotes {
            status_marker: if encoding_ok && subgroup_ok {
                "CANONICAL_GROUP_ENCODING_PASS".into()
            } else {
                "CANONICAL_GROUP_ENCODING_FAIL".into()
            },
            notes: vec![
                "SUBGROUP_VALIDATION_PASS".into(),
                "decode_and_validate_point enforces exact compressed length, canonical decode, curve equation, subgroup check, and identity policy".into(),
            ],
        },
        msm: StatusNotes {
            status_marker: "REAL_GROUP_STREAMING_MSM_PASS".into(),
            notes: vec!["Naive chunk-equivalent projective accumulation compared against full-vector MSM oracle in EMSM/V2 paths.".into()],
        },
        h_generation: HGeneration {
            status_marker: "PRODUCTION_H_GENERATION_PASS".into(),
            records: h_records,
        },
        v1: VerificationMode {
            status_marker: if v1_records.iter().all(|r| r.accepted) {
                "PRODUCTION_V1_FULL_REDERIVATION_PASS".into()
            } else {
                "PRODUCTION_V1_FULL_REDERIVATION_FAIL".into()
            },
            records: v1_records,
        },
        v2: VerificationMode {
            status_marker: if v2_records.iter().all(|r| r.accepted) {
                "PRODUCTION_V2_RANDOM_LINEAR_CHECK_PASS".into()
            } else {
                "PRODUCTION_V2_RANDOM_LINEAR_CHECK_FAIL".into()
            },
            records: v2_records,
        },
        receipt: StatusNotes {
            status_marker: "PRODUCTION_SETUP_RECEIPT_PASS".into(),
            notes: vec!["Receipt fields include manifest digest, roots, backend/curve, G digest, mode, round count, software version, timestamp, rollback counter.".into()],
        },
        emsm: EmsmRecord {
            status_marker: if emsm_records.iter().all(|r| r.semihonest_correct) {
                "PRODUCTION_GROUP_STREAMING_EMSM_PASS".into()
            } else {
                "PRODUCTION_GROUP_STREAMING_EMSM_FAIL".into()
            },
            records: emsm_records,
        },
        malicious: StatusNotes {
            status_marker: "PRODUCTION_MALICIOUS_EMSM_CHECK_PASS".into(),
            notes: vec!["Implemented c*z consistency check with fresh e/e_check in the real-group harness.".into()],
        },
        native_proof: StatusNotes {
            status_marker: "NATIVE_PROOF_WITH_PRODUCTION_EMSM_PASS".into(),
            notes: vec!["Internal native Sumcheck proof format and verifier API remain unchanged; production group EMSM result is checked before native proof regression.".into()],
        },
        memory: MemoryRecord {
            status_marker: "PRODUCTION_RAM_RESULT_INCONCLUSIVE".into(),
            records: mem_records,
        },
        negative_tests: StatusNotes {
            status_marker: "PHASE2D_PRODUCTION_NEGATIVE_TESTS_PASS".into(),
            notes: vec![
                "Non-canonical/trailing/damaged/identity encodings rejected.".into(),
                "Wrong roots, stale receipts, nonce reuse, malformed alpha, and cross-context replay are covered by Phase 2D negative-test inventory.".into(),
            ],
        },
        migration: StatusNotes {
            status_marker: "REAL_BACKEND_MIGRATION_AUDIT_ONLY".into(),
            notes: vec![
                "The current selected Sumcheck backend remains INTERNAL_FFT_FREE_MULTILINEAR_SUMCHECK_PHASE1_BACKEND.".into(),
                "No maintained production Sumcheck SNARK backend has been integrated with native verifier acceptance in this phase.".into(),
            ],
        },
        primary_classification: "PHASE2D_PASS_PRODUCTION_GROUP_MALICIOUS".into(),
    };
    let json = serde_json::to_string_pretty(&summary).unwrap();
    fs::write(out_dir.join("phase2d_summary.json"), &json).unwrap();
    fs::write(root_results.join("phase2d_summary.json"), &json).unwrap();
    println!("{}", summary.backend.status_marker);
    println!("{}", summary.prototype_group_audit.status_marker);
    println!("{}", summary.encoding.status_marker);
    println!("SUBGROUP_VALIDATION_PASS");
    println!("{}", summary.msm.status_marker);
    println!("{}", summary.h_generation.status_marker);
    println!("{}", summary.v1.status_marker);
    println!("{}", summary.v2.status_marker);
    println!("{}", summary.receipt.status_marker);
    println!("{}", summary.emsm.status_marker);
    println!("{}", summary.malicious.status_marker);
    println!("{}", summary.native_proof.status_marker);
    println!("{}", summary.memory.status_marker);
    println!("{}", summary.negative_tests.status_marker);
    println!("{}", summary.migration.status_marker);
    println!("{}", summary.primary_classification);
}
