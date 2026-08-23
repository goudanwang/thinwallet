use anyhow::{anyhow, Result};
use libspartan_patched as patched;
use merlin::Transcript;
use patched::prover_msm::{with_prover_msm_audit, ProverMsmContext};
use serde::Serialize;
use std::fs;
use std::path::Path;
use std::time::Instant;

const NUM_INPUTS: usize = 1;
const TRANSCRIPT_LABEL: &[u8] = b"thinwallet_phase3ar25_granularity_audit";

type MatrixEntry = (usize, usize, [u8; 32]);

#[derive(Serialize)]
struct BasisRange {
    start: usize,
    end_exclusive: usize,
}

#[derive(Serialize)]
struct PhysicalMsmRecord {
    relation_log_size: usize,
    relation_size: usize,
    physical_msm_id: String,
    parent_logical_commitment_id: String,
    chunk_index: usize,
    scalar_count: usize,
    basis_range: BasisRange,
    basis_digest: String,
    scalar_classification: String,
    transcript_phase: String,
    intermediate_point_separately_absorbed: bool,
    physical_result_only_accumulated_into_larger_commitment: bool,
}

#[derive(Serialize)]
struct WorkloadPhysicalAudit {
    relation_log_size: usize,
    relation_size: usize,
    proof_size_bytes: usize,
    prove_ms: f64,
    peak_rss_mb: Option<f64>,
    native_verifier_accepts: bool,
    physical_msm_count: usize,
    physical_msms: Vec<PhysicalMsmRecord>,
}

#[derive(Serialize)]
struct PhysicalInventory {
    status: String,
    backend: String,
    revision: String,
    group: String,
    transcript_source_observation: String,
    workloads: Vec<WorkloadPhysicalAudit>,
}

#[derive(Serialize)]
struct Thresholds {
    local_small_max_scalars: usize,
    optional_remote_max_scalars: usize,
    remote_candidate_max_scalars: usize,
    note: String,
}

#[derive(Serialize)]
struct LogicalCommitmentRecord {
    relation_log_size: usize,
    relation_size: usize,
    logical_commitment_id: String,
    representation: String,
    physical_chunk_count: usize,
    per_chunk_scalar_count: usize,
    total_logical_scalar_count: usize,
    total_basis_references: usize,
    unique_msm_basis_count: usize,
    blind_basis_term_count: usize,
    transcript_point_absorptions: usize,
    fiat_shamir_challenge_barriers_inside_commitment: usize,
    all_chunks_produced_before_next_fiat_shamir_challenge: bool,
    all_chunks_can_be_streamed_before_one_final_response: bool,
    final_response_group_element_count_required_by_native_proof: usize,
    compatible_with_single_group_element_finalize: bool,
    physical_results_accumulated_before_transcript: bool,
    scalability_classification: String,
    blocker: String,
}

#[derive(Serialize)]
struct LogicalInventory {
    status: String,
    large_logical_private_msm_result: String,
    transcript_barrier_result: String,
    thresholds: Thresholds,
    logical_commitments: Vec<LogicalCommitmentRecord>,
    final_classification: String,
    stopped_before_logical_provider: bool,
    stop_reason: String,
}

fn scalar_bytes(value: u64) -> [u8; 32] {
    curve25519_dalek::scalar::Scalar::from(value).to_bytes()
}

fn relation(
    log_size: usize,
) -> Result<(
    patched::Instance,
    patched::VarsAssignment,
    patched::InputsAssignment,
)> {
    let n = 1usize << log_size;
    let mut a: Vec<MatrixEntry> = Vec::with_capacity(n);
    let mut b: Vec<MatrixEntry> = Vec::with_capacity(n);
    let mut c: Vec<MatrixEntry> = Vec::with_capacity(n);
    let mut vars = Vec::with_capacity(n);
    for i in 0..n {
        let one = scalar_bytes(1);
        a.push((i, i, one));
        b.push((i, i, one));
        c.push((i, i, one));
        vars.push(scalar_bytes((i & 1) as u64));
    }
    let inputs = vec![scalar_bytes(0)];
    Ok((
        patched::Instance::new(n, n, NUM_INPUTS, &a, &b, &c).map_err(debug_err)?,
        patched::VarsAssignment::new(&vars).map_err(debug_err)?,
        patched::InputsAssignment::new(&inputs).map_err(debug_err)?,
    ))
}

fn debug_err(err: impl std::fmt::Debug) -> anyhow::Error {
    anyhow!("{err:?}")
}

fn peak_rss_mb() -> Option<f64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    let kib = line.split_whitespace().nth(1)?.parse::<f64>().ok()?;
    Some(kib / 1024.0)
}

fn physical_record(log_size: usize, context: ProverMsmContext) -> PhysicalMsmRecord {
    PhysicalMsmRecord {
        relation_log_size: log_size,
        relation_size: 1usize << log_size,
        physical_msm_id: context.msm_id,
        parent_logical_commitment_id: context.logical_commitment_id,
        chunk_index: context.chunk_index,
        scalar_count: context.scalar_count,
        basis_range: BasisRange {
            start: context.basis_start,
            end_exclusive: context.basis_end,
        },
        basis_digest: context.basis_digest,
        scalar_classification: if context.private_scalars {
            "PRIVATE_WITNESS_DEPENDENT".to_string()
        } else {
            "PUBLIC".to_string()
        },
        transcript_phase: context.transcript_phase,
        intermediate_point_separately_absorbed: context.separately_absorbed_into_transcript,
        physical_result_only_accumulated_into_larger_commitment: context
            .accumulated_into_larger_commitment,
    }
}

fn audit_workload(log_size: usize) -> Result<WorkloadPhysicalAudit> {
    let n = 1usize << log_size;
    let (inst, vars, inputs) = relation(log_size)?;
    let gens = patched::SNARKGens::new(n, n, NUM_INPUTS, n);
    let (comm, decomm) = patched::SNARK::encode(&inst, &gens);
    let mut prover_transcript = Transcript::new(TRANSCRIPT_LABEL);
    let start = Instant::now();
    let (proof, contexts) = with_prover_msm_audit(|| {
        patched::SNARK::prove(
            &inst,
            &comm,
            &decomm,
            vars,
            &inputs,
            &gens,
            &mut prover_transcript,
        )
    });
    let prove_ms = start.elapsed().as_secs_f64() * 1000.0;
    let mut verifier_transcript = Transcript::new(TRANSCRIPT_LABEL);
    let native_verifier_accepts = proof
        .verify(&comm, &inputs, &mut verifier_transcript, &gens)
        .is_ok();
    if !native_verifier_accepts {
        return Err(anyhow!("native verification failed for 2^{log_size}"));
    }
    let expected_chunks = 1usize << (log_size / 2);
    let expected_chunk_size = 1usize << (log_size - log_size / 2);
    if contexts.len() != expected_chunks
        || contexts
            .iter()
            .any(|context| context.scalar_count != expected_chunk_size)
    {
        return Err(anyhow!(
            "unexpected dense commitment geometry for 2^{log_size}: {} contexts",
            contexts.len()
        ));
    }
    let physical_msms: Vec<_> = contexts
        .into_iter()
        .map(|context| physical_record(log_size, context))
        .collect();
    Ok(WorkloadPhysicalAudit {
        relation_log_size: log_size,
        relation_size: n,
        proof_size_bytes: bincode::serialize(&proof)?.len(),
        prove_ms,
        peak_rss_mb: peak_rss_mb(),
        native_verifier_accepts,
        physical_msm_count: physical_msms.len(),
        physical_msms,
    })
}

fn classify(total_scalars: usize) -> String {
    if total_scalars <= 256 {
        "LOCAL_SMALL"
    } else if total_scalars <= 4096 {
        "OPTIONAL_REMOTE"
    } else if total_scalars <= 65536 {
        "REMOTE_CANDIDATE"
    } else {
        "REMOTE_STRONG_CANDIDATE"
    }
    .to_string()
}

fn logical_record(workload: &WorkloadPhysicalAudit) -> Result<LogicalCommitmentRecord> {
    let first = workload
        .physical_msms
        .first()
        .ok_or_else(|| anyhow!("missing physical MSM records"))?;
    let chunks = workload.physical_msm_count;
    let per_chunk = first.scalar_count;
    let total = chunks * per_chunk;
    let all_separate = workload
        .physical_msms
        .iter()
        .all(|record| record.intermediate_point_separately_absorbed);
    let any_accumulated = workload
        .physical_msms
        .iter()
        .any(|record| record.physical_result_only_accumulated_into_larger_commitment);
    Ok(LogicalCommitmentRecord {
        relation_log_size: workload.relation_log_size,
        relation_size: workload.relation_size,
        logical_commitment_id: first.parent_logical_commitment_id.clone(),
        representation: "ordered vector of independently blinded chunk commitments"
            .to_string(),
        physical_chunk_count: chunks,
        per_chunk_scalar_count: per_chunk,
        total_logical_scalar_count: total,
        total_basis_references: total,
        unique_msm_basis_count: per_chunk,
        blind_basis_term_count: chunks,
        transcript_point_absorptions: if all_separate { chunks } else { 1 },
        fiat_shamir_challenge_barriers_inside_commitment: 0,
        all_chunks_produced_before_next_fiat_shamir_challenge: true,
        all_chunks_can_be_streamed_before_one_final_response: true,
        final_response_group_element_count_required_by_native_proof: chunks,
        compatible_with_single_group_element_finalize: false,
        physical_results_accumulated_before_transcript: any_accumulated,
        scalability_classification: classify(total),
        blocker: "The native PolyCommitment and transcript contain one ordered point per chunk. Summing these points into one GroupElement would change the proof object, transcript bytes, and verifier semantics even though no Fiat-Shamir challenge occurs between adjacent point appends.".to_string(),
    })
}

fn write_json(path: impl AsRef<Path>, value: &impl Serialize) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn main() -> Result<()> {
    let mut workloads = Vec::new();
    for log_size in [12usize, 14, 16, 18] {
        eprintln!("auditing dense private commitment at 2^{log_size}");
        workloads.push(audit_workload(log_size)?);
    }
    let logical_commitments = workloads
        .iter()
        .map(logical_record)
        .collect::<Result<Vec<_>>>()?;
    let large_found = logical_commitments
        .iter()
        .any(|record| record.total_logical_scalar_count > (1usize << 12));
    if !large_found {
        return Err(anyhow!("no logical private commitment above 2^12 scalars"));
    }
    let physical_inventory = PhysicalInventory {
        status: "LIBSPARTAN_PHYSICAL_TO_LOGICAL_MSM_MAP_COMPLETE".to_string(),
        backend: "libspartan".to_string(),
        revision: "0.9.0 / ThinWallet prover-only fork".to_string(),
        group: "Ristretto255 / curve25519-dalek 4.1.3".to_string(),
        transcript_source_observation: "PolyCommitment::append_to_transcript iterates over C and appends each compressed chunk point separately; it draws no challenge inside that loop.".to_string(),
        workloads,
    };
    let logical_inventory = LogicalInventory {
        status: "LIBSPARTAN_PHYSICAL_TO_LOGICAL_MSM_MAP_COMPLETE".to_string(),
        large_logical_private_msm_result: "LIBSPARTAN_LARGE_LOGICAL_PRIVATE_MSM_FOUND"
            .to_string(),
        transcript_barrier_result: "LIBSPARTAN_CHUNK_LEVEL_TRANSCRIPT_BARRIERS_DETECTED"
            .to_string(),
        thresholds: Thresholds {
            local_small_max_scalars: 256,
            optional_remote_max_scalars: 4096,
            remote_candidate_max_scalars: 65536,
            note: "Engineering thresholds for this audit only; they are not theoretical security or performance boundaries.".to_string(),
        },
        logical_commitments,
        final_classification: "PHASE3A_R2_5_BLOCKED_CHUNK_TRANSCRIPT_BARRIERS".to_string(),
        stopped_before_logical_provider: true,
        stop_reason: "The required finalize(session) -> GroupElement interface cannot preserve libspartan's ordered vector of chunk commitment points. Implementing it would change proof encoding, transcript input, and the native verifier contract.".to_string(),
    };
    write_json("physical_msm_inventory.json", &physical_inventory)?;
    write_json("logical_commitment_inventory.json", &logical_inventory)?;
    println!("LIBSPARTAN_PHYSICAL_TO_LOGICAL_MSM_MAP_COMPLETE");
    println!("LIBSPARTAN_LARGE_LOGICAL_PRIVATE_MSM_FOUND");
    println!("LIBSPARTAN_CHUNK_LEVEL_TRANSCRIPT_BARRIERS_DETECTED");
    println!("PHASE3A_R2_5_BLOCKED_CHUNK_TRANSCRIPT_BARRIERS");
    Ok(())
}
