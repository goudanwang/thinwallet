#![allow(non_snake_case)]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(clippy::assertions_on_result_states)]

extern crate byteorder;
extern crate core;
extern crate curve25519_dalek;
extern crate digest;
extern crate merlin;
extern crate rand;
extern crate sha3;

#[cfg(feature = "multicore")]
extern crate rayon;

mod commitments;
mod dense_mlpoly;
mod errors;
mod group;
mod math;
/// Phase V3A allocation-level memory instrumentation.
pub mod memory_trace;

/// Explicit budgets and capacity accounting for the Phase V3B prover path.
pub mod memory_budget;

/// Deterministic retain/spill/recompute planning for Phase V3B.
pub mod budget_planner;

/// Session-bound multi-object stores used by the Phase V3B prover.
pub mod multi_state_store;
mod nizk;
pub mod pbmo_commitment;
mod product_tree;
pub mod prover_msm;
mod r1csinstance;
mod r1csproof;
mod random;
#[doc(hidden)]
pub mod remote_eval;
mod scalar;
mod secure_temp;
mod sparse_mlpoly;
/// Bounded-memory state stores used by the fixed Phase V3A path.
pub mod state_store;
pub mod streaming_sumcheck_fold;
mod sumcheck;
mod timer;
mod transcript;
mod unipoly;

use core::cmp::max;
use errors::{ProofVerifyError, R1CSError};
use hmac::{Hmac, Mac};
use merlin::Transcript;
use r1csinstance::{
  R1CSCommitment, R1CSCommitmentGens, R1CSDecommitment, R1CSEvalProof, R1CSInstance,
};
use r1csproof::{R1CSGens, R1CSProof};
use rand::rngs::OsRng;
use rand::RngCore;
use random::{RandomTape, RandomTapeAudit};
use scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
#[cfg(feature = "thinwallet-experiment")]
use std::time::Instant;
use timer::Timer;
use transcript::{AppendToTranscript, ProofTranscript};

const SPLIT_PROTOCOL_VERSION: &[u8] = b"thinwallet/spartan/split/v1";

#[derive(Clone, Serialize, Deserialize)]
struct TranscriptReplayData {
  protocol_identifier: Vec<u8>,
  commitment_digest: [u8; 32],
  public_inputs_digest: [u8; 32],
  sat_proof_digest: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
struct EvalTailRequest {
  circuit_id: [u8; 32],
  invocation_id: [u8; 32],
  public_inputs: Vec<Scalar>,
  r1cs_sat_proof: Vec<u8>,
  transcript_replay_data: TranscriptReplayData,
  rx: Vec<Scalar>,
  ry: Vec<Scalar>,
  inst_evals: (Scalar, Scalar, Scalar),
  binding_digest: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
struct EvalTailResponse {
  circuit_id: [u8; 32],
  invocation_id: [u8; 32],
  request_binding_digest: [u8; 32],
  inst_evals: (Scalar, Scalar, Scalar),
  r1cs_eval_proof: Vec<u8>,
  binding_metadata: [u8; 32],
}

#[derive(Debug)]
enum SplitExecutionError {
  CircuitBinding,
  InvocationBinding,
  RequestBinding,
  TranscriptReplay,
  ProofEncoding,
  EvalVerification,
  ResponseBinding,
  SessionConsumed,
}

enum ProverRandomnessPlan {
  LegacyShared(RandomTape),
  Split {
    sat_random_tape: RandomTape,
    eval_root: [u8; 32],
    circuit_id: [u8; 32],
    invocation_id: [u8; 32],
    transcript_base: Transcript,
  },
}

impl ProverRandomnessPlan {
  #[cfg(feature = "thinwallet-experiment")]
  fn record_trace_preamble(&self) {
    match self {
      Self::LegacyShared(tape) => {
        thinwallet_instrumentation::record_trace_preamble_spartan(&[tape.root_label()]);
      }
      Self::Split {
        sat_random_tape, ..
      } => {
        thinwallet_instrumentation::record_trace_preamble_spartan(&[
          sat_random_tape.root_label(),
          "eval_proof",
        ]);
      }
    }
    thinwallet_instrumentation::record_trace_event(
      "materialize_relation",
      &["pp", "circ"],
      &["R_raw"],
      None,
      &[],
      false,
    );
    thinwallet_instrumentation::record_trace_event(
      "build_instance",
      &["R_raw"],
      &["inst"],
      None,
      &[],
      false,
    );
  }

  fn sat_random_tape(&mut self) -> &mut RandomTape {
    match self {
      Self::LegacyShared(tape) => tape,
      Self::Split {
        sat_random_tape, ..
      } => sat_random_tape,
    }
  }

  fn seal_sat_frontier(&mut self) -> RandomTapeAudit {
    match self {
      Self::LegacyShared(tape) => tape.audit(),
      Self::Split {
        sat_random_tape, ..
      } => {
        sat_random_tape.seal_frontier();
        sat_random_tape.audit()
      }
    }
  }
}

#[cfg(feature = "thinwallet-experiment")]
fn record_sat_randomness_audit(audit: RandomTapeAudit) {
  thinwallet_instrumentation::increment_counter("q_sat_samples", audit.scalar_samples);
  thinwallet_instrumentation::increment_counter("sat_random_bytes", audit.bytes_consumed);
  thinwallet_instrumentation::increment_counter(
    "sat_post_frontier_sample_attempts",
    audit.post_frontier_attempts,
  );
  thinwallet_instrumentation::increment_counter(
    "sat_frontier_sealed",
    u64::from(audit.frontier_sealed),
  );
  thinwallet_instrumentation::increment_counter(
    "sat_sample_coordinates_unique",
    u64::from(audit.sample_coordinates_unique),
  );
}

struct LocalSatExecutor<'a> {
  inst: &'a R1CSInstance,
  vars: Vec<Scalar>,
  inputs: &'a [Scalar],
  gens: &'a R1CSGens,
  transcript: &'a mut Transcript,
  sat_random_tape: &'a mut RandomTape,
}

impl<'a> LocalSatExecutor<'a> {
  fn execute(self) -> (R1CSProof, Vec<Scalar>, Vec<Scalar>) {
    R1CSProof::prove(
      self.inst,
      self.vars,
      self.inputs,
      self.gens,
      self.transcript,
      self.sat_random_tape,
    )
  }
}

struct LocalEvalExecutor<'a> {
  comm: &'a ComputationCommitment,
  decomm: &'a ComputationDecommitment,
  gens: &'a SNARKGens,
  transcript_base: Transcript,
  eval_root: [u8; 32],
  cached_decomm_circuit_id: [u8; 32],
  expected_circuit_id: [u8; 32],
  expected_invocation_id: [u8; 32],
  consumed: bool,
}

struct LocalAssembler<'a> {
  comm: &'a ComputationCommitment,
  gens: &'a SNARKGens,
  transcript_base: Transcript,
  expected_circuit_id: [u8; 32],
  expected_invocation_id: [u8; 32],
  consumed: bool,
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
  let mut hash = Sha256::new();
  hash.update((domain.len() as u64).to_le_bytes());
  hash.update(domain);
  for part in parts {
    hash.update((part.len() as u64).to_le_bytes());
    hash.update(part);
  }
  hash.finalize().into()
}

fn hmac_phase_seed(
  root: &[u8; 32],
  phase: &[u8],
  circuit_id: &[u8; 32],
  invocation_id: &[u8; 32],
) -> [u8; 32] {
  type HmacSha256 = Hmac<Sha256>;
  let mut mac = <HmacSha256 as Mac>::new_from_slice(root).expect("HMAC accepts 32-byte keys");
  for part in [
    SPLIT_PROTOCOL_VERSION,
    phase,
    circuit_id.as_slice(),
    invocation_id.as_slice(),
    b"spartan-0.9.0/ristretto255",
  ] {
    mac.update(&(part.len() as u64).to_le_bytes());
    mac.update(part);
  }
  mac.finalize().into_bytes().into()
}

fn decode_seed_hex(name: &str, value: &str) -> [u8; 32] {
  assert_eq!(
    value.len(),
    64,
    "{name} must contain exactly 64 hexadecimal characters"
  );
  let mut output = [0u8; 32];
  for (index, slot) in output.iter_mut().enumerate() {
    *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
      .unwrap_or_else(|_| panic!("{name} contains non-hexadecimal data"));
  }
  output
}

fn phase_root_from_environment(name: &str, fixture_phase: &[u8]) -> [u8; 32] {
  if let Ok(value) = std::env::var(name) {
    return decode_seed_hex(name, &value);
  }
  #[cfg(feature = "phase3ar2-deterministic-tests")]
  if let Ok(value) = std::env::var("THINWALLET_EXPERIMENT_PROVER_SEED") {
    let fixture_root = hash_parts(
      b"thinwallet/non-production/deterministic-fixture-root/v1",
      &[value.as_bytes()],
    );
    return hmac_phase_seed(&fixture_root, fixture_phase, &[0u8; 32], &[0u8; 32]);
  }
  let mut root = [0u8; 32];
  OsRng.fill_bytes(&mut root);
  root
}

fn circuit_identifier(comm: &ComputationCommitment) -> [u8; 32] {
  let encoded = bincode::serialize(comm).expect("computation commitment serialization");
  hash_parts(b"thinwallet/spartan/circuit-id/v1", &[&encoded])
}

fn invocation_identifier() -> [u8; 32] {
  if let Ok(value) = std::env::var("THINWALLET_LOGICAL_INVOCATION_ID_HEX") {
    if value.len() == 64 {
      let mut decoded = [0u8; 32];
      let mut valid = true;
      for (index, byte) in decoded.iter_mut().enumerate() {
        match u8::from_str_radix(&value[index * 2..index * 2 + 2], 16) {
          Ok(value) => *byte = value,
          Err(_) => {
            valid = false;
            break;
          }
        }
      }
      if valid && decoded != [0u8; 32] {
        return decoded;
      }
    }
    panic!("THINWALLET_LOGICAL_INVOCATION_ID_HEX must be a nonzero 32-byte hex value");
  }
  let session = std::env::var("THINWALLET_PROOF_SESSION_ID").ok();
  let run = std::env::var("THINWALLET_EXPERIMENT_RUN_ID").ok();
  if session.is_none() && run.is_none() {
    let mut invocation = [0u8; 32];
    OsRng.fill_bytes(&mut invocation);
    return invocation;
  }
  hash_parts(
    b"thinwallet/spartan/invocation-id/v1",
    &[
      session.as_deref().unwrap_or("").as_bytes(),
      run.as_deref().unwrap_or("").as_bytes(),
    ],
  )
}

fn prepare_randomness_plan(
  comm: &ComputationCommitment,
  transcript: &Transcript,
) -> ProverRandomnessPlan {
  if std::env::var("THINWALLET_SPARTAN_RANDOMNESS_MODE").as_deref() == Ok("legacy-shared") {
    return ProverRandomnessPlan::LegacyShared(RandomTape::new(b"proof"));
  }
  let circuit_id = circuit_identifier(comm);
  let invocation_id = invocation_identifier();
  let sat_root = phase_root_from_environment("THINWALLET_SAT_SEED_HEX", b"sat-root");
  let eval_root = phase_root_from_environment("THINWALLET_EVAL_SEED_HEX", b"eval-root");
  let sat_seed = hmac_phase_seed(&sat_root, b"sat", &circuit_id, &invocation_id);
  ProverRandomnessPlan::Split {
    sat_random_tape: RandomTape::from_phase_seed(b"sat_proof", &sat_seed),
    eval_root,
    circuit_id,
    invocation_id,
    transcript_base: transcript.clone(),
  }
}

fn eval_request_binding_digest(request: &EvalTailRequest) -> [u8; 32] {
  let encoded = bincode::serialize(&(
    request.circuit_id,
    request.invocation_id,
    &request.public_inputs,
    &request.r1cs_sat_proof,
    &request.transcript_replay_data,
    &request.rx,
    &request.ry,
    request.inst_evals,
  ))
  .expect("eval request binding serialization");
  hash_parts(b"thinwallet/spartan/eval-tail-request/v1", &[&encoded])
}

fn eval_response_binding_digest(response: &EvalTailResponse) -> [u8; 32] {
  let encoded = bincode::serialize(&(
    response.circuit_id,
    response.invocation_id,
    response.request_binding_digest,
    response.inst_evals,
    &response.r1cs_eval_proof,
  ))
  .expect("eval response binding serialization");
  hash_parts(b"thinwallet/spartan/eval-tail-response/v1", &[&encoded])
}

fn build_eval_tail_request(
  comm: &ComputationCommitment,
  inputs: &InputsAssignment,
  sat_proof: &R1CSProof,
  rx: &[Scalar],
  ry: &[Scalar],
  inst_evals: &(Scalar, Scalar, Scalar),
  circuit_id: [u8; 32],
  invocation_id: [u8; 32],
) -> EvalTailRequest {
  #[cfg(feature = "thinwallet-experiment")]
  let cpu_start = thinwallet_instrumentation::process_cpu_time_ns();
  #[cfg(feature = "thinwallet-experiment")]
  let wall_start = Instant::now();
  let sat_proof_bytes = bincode::serialize(sat_proof).expect("sat proof serialization");
  let public_input_bytes = bincode::serialize(&inputs.assignment).expect("input serialization");
  let commitment_bytes = bincode::serialize(comm).expect("commitment serialization");
  let transcript_replay_data = TranscriptReplayData {
    protocol_identifier: SPLIT_PROTOCOL_VERSION.to_vec(),
    commitment_digest: hash_parts(
      b"thinwallet/spartan/replay-commitment/v1",
      &[&commitment_bytes],
    ),
    public_inputs_digest: hash_parts(
      b"thinwallet/spartan/replay-inputs/v1",
      &[&public_input_bytes],
    ),
    sat_proof_digest: hash_parts(
      b"thinwallet/spartan/replay-sat-proof/v1",
      &[&sat_proof_bytes],
    ),
  };
  let mut request = EvalTailRequest {
    circuit_id,
    invocation_id,
    public_inputs: inputs.assignment.clone(),
    r1cs_sat_proof: sat_proof_bytes,
    transcript_replay_data,
    rx: rx.to_vec(),
    ry: ry.to_vec(),
    inst_evals: *inst_evals,
    binding_digest: [0u8; 32],
  };
  request.binding_digest = eval_request_binding_digest(&request);
  #[cfg(feature = "thinwallet-experiment")]
  {
    let encoded_size = bincode::serialized_size(&request).unwrap_or_default();
    let decomm_cached_bytes = bincode::serialized_size(comm).unwrap_or_default();
    let wall_ns = wall_start.elapsed().as_nanos() as u64;
    let cpu_ns = thinwallet_instrumentation::process_cpu_time_ns().saturating_sub(cpu_start);
    thinwallet_instrumentation::record_stage_metrics(
      "eval_request_construction",
      wall_ns,
      wall_ns,
      cpu_ns,
      cpu_ns,
      encoded_size,
    );
    thinwallet_instrumentation::increment_counter("eval_request_bytes", encoded_size);
    for (name, size) in [
      (
        "eval_request_field_circuit_id_bytes",
        bincode::serialized_size(&request.circuit_id).unwrap_or_default(),
      ),
      (
        "eval_request_field_invocation_id_bytes",
        bincode::serialized_size(&request.invocation_id).unwrap_or_default(),
      ),
      (
        "eval_request_field_public_inputs_bytes",
        bincode::serialized_size(&request.public_inputs).unwrap_or_default(),
      ),
      (
        "eval_request_field_sat_proof_bytes",
        bincode::serialized_size(&request.r1cs_sat_proof).unwrap_or_default(),
      ),
      (
        "eval_request_field_replay_data_bytes",
        bincode::serialized_size(&request.transcript_replay_data).unwrap_or_default(),
      ),
      (
        "eval_request_field_rx_bytes",
        bincode::serialized_size(&request.rx).unwrap_or_default(),
      ),
      (
        "eval_request_field_ry_bytes",
        bincode::serialized_size(&request.ry).unwrap_or_default(),
      ),
      (
        "eval_request_field_inst_evals_bytes",
        bincode::serialized_size(&request.inst_evals).unwrap_or_default(),
      ),
      (
        "eval_request_field_binding_digest_bytes",
        bincode::serialized_size(&request.binding_digest).unwrap_or_default(),
      ),
    ] {
      thinwallet_instrumentation::increment_counter(name, size);
    }
    thinwallet_instrumentation::increment_counter(
      "eval_cached_commitment_bytes",
      decomm_cached_bytes,
    );
    thinwallet_instrumentation::increment_counter("eval_request_fields", 9);
    thinwallet_instrumentation::increment_counter("eval_request_secret_forbidden_fields", 0);
    thinwallet_instrumentation::increment_counter("eval_request_unknown_fields", 0);
  }
  request
}

fn validate_request_binding(
  request: &EvalTailRequest,
  comm: &ComputationCommitment,
) -> Result<(), SplitExecutionError> {
  if request.binding_digest != eval_request_binding_digest(request) {
    return Err(SplitExecutionError::RequestBinding);
  }
  let commitment_bytes =
    bincode::serialize(comm).map_err(|_| SplitExecutionError::ProofEncoding)?;
  let public_input_bytes =
    bincode::serialize(&request.public_inputs).map_err(|_| SplitExecutionError::ProofEncoding)?;
  if request.transcript_replay_data.protocol_identifier != SPLIT_PROTOCOL_VERSION
    || request.transcript_replay_data.commitment_digest
      != hash_parts(
        b"thinwallet/spartan/replay-commitment/v1",
        &[&commitment_bytes],
      )
    || request.transcript_replay_data.public_inputs_digest
      != hash_parts(
        b"thinwallet/spartan/replay-inputs/v1",
        &[&public_input_bytes],
      )
    || request.transcript_replay_data.sat_proof_digest
      != hash_parts(
        b"thinwallet/spartan/replay-sat-proof/v1",
        &[&request.r1cs_sat_proof],
      )
  {
    return Err(SplitExecutionError::RequestBinding);
  }
  Ok(())
}

fn replay_sat_transcript(
  request: &EvalTailRequest,
  comm: &ComputationCommitment,
  gens: &SNARKGens,
  mut transcript: Transcript,
) -> Result<(R1CSProof, Transcript), SplitExecutionError> {
  let sat_proof: R1CSProof = bincode::deserialize(&request.r1cs_sat_proof)
    .map_err(|_| SplitExecutionError::ProofEncoding)?;
  transcript.append_protocol_name(SNARK::protocol_name());
  comm.comm.append_to_transcript(b"comm", &mut transcript);
  if request.public_inputs.len() != comm.comm.get_num_inputs() {
    return Err(SplitExecutionError::TranscriptReplay);
  }
  let (replayed_rx, replayed_ry) = sat_proof
    .verify(
      comm.comm.get_num_vars(),
      comm.comm.get_num_cons(),
      &request.public_inputs,
      &request.inst_evals,
      &mut transcript,
      &gens.gens_r1cs_sat,
    )
    .map_err(|_| SplitExecutionError::TranscriptReplay)?;
  if replayed_rx != request.rx || replayed_ry != request.ry {
    return Err(SplitExecutionError::TranscriptReplay);
  }
  request
    .inst_evals
    .0
    .append_to_transcript(b"Ar_claim", &mut transcript);
  request
    .inst_evals
    .1
    .append_to_transcript(b"Br_claim", &mut transcript);
  request
    .inst_evals
    .2
    .append_to_transcript(b"Cr_claim", &mut transcript);
  Ok((sat_proof, transcript))
}

impl<'a> LocalEvalExecutor<'a> {
  fn execute(&mut self, request: EvalTailRequest) -> Result<EvalTailResponse, SplitExecutionError> {
    if self.consumed {
      return Err(SplitExecutionError::SessionConsumed);
    }
    self.consumed = true;
    if request.circuit_id != self.expected_circuit_id
      || circuit_identifier(self.comm) != self.expected_circuit_id
      || self.cached_decomm_circuit_id != self.expected_circuit_id
    {
      return Err(SplitExecutionError::CircuitBinding);
    }
    if request.invocation_id != self.expected_invocation_id {
      return Err(SplitExecutionError::InvocationBinding);
    }
    validate_request_binding(&request, self.comm)?;
    #[cfg(feature = "thinwallet-experiment")]
    let replay_cpu_start = thinwallet_instrumentation::process_cpu_time_ns();
    #[cfg(feature = "thinwallet-experiment")]
    let replay_wall_start = Instant::now();
    let (_, mut transcript) =
      replay_sat_transcript(&request, self.comm, self.gens, self.transcript_base.clone())?;
    #[cfg(feature = "thinwallet-experiment")]
    {
      let wall_ns = replay_wall_start.elapsed().as_nanos() as u64;
      let cpu_ns =
        thinwallet_instrumentation::process_cpu_time_ns().saturating_sub(replay_cpu_start);
      thinwallet_instrumentation::record_stage_metrics(
        "transcript_replay",
        wall_ns,
        wall_ns,
        cpu_ns,
        cpu_ns,
        0,
      );
      thinwallet_instrumentation::increment_counter("transcript_replay_pass", 1);
    }
    let eval_seed = hmac_phase_seed(
      &self.eval_root,
      b"eval",
      &request.circuit_id,
      &request.invocation_id,
    );
    let mut eval_random_tape = RandomTape::from_phase_seed(b"eval_proof", &eval_seed);
    #[cfg(feature = "thinwallet-experiment")]
    let eval_cpu_start = thinwallet_instrumentation::process_cpu_time_ns();
    #[cfg(feature = "thinwallet-experiment")]
    let eval_wall_start = Instant::now();
    let eval_proof = R1CSEvalProof::prove(
      &self.decomm.decomm,
      &request.rx,
      &request.ry,
      &request.inst_evals,
      &self.gens.gens_r1cs_eval,
      &mut transcript,
      &mut eval_random_tape,
    );
    #[cfg(feature = "thinwallet-experiment")]
    {
      let wall_ns = eval_wall_start.elapsed().as_nanos() as u64;
      let cpu_ns = thinwallet_instrumentation::process_cpu_time_ns().saturating_sub(eval_cpu_start);
      thinwallet_instrumentation::record_stage_metrics(
        "native_eval_prove",
        wall_ns,
        wall_ns,
        cpu_ns,
        cpu_ns,
        0,
      );
    }
    let eval_proof_bytes =
      bincode::serialize(&eval_proof).map_err(|_| SplitExecutionError::ProofEncoding)?;
    let mut response = EvalTailResponse {
      circuit_id: request.circuit_id,
      invocation_id: request.invocation_id,
      request_binding_digest: request.binding_digest,
      inst_evals: request.inst_evals,
      r1cs_eval_proof: eval_proof_bytes,
      binding_metadata: [0u8; 32],
    };
    response.binding_metadata = eval_response_binding_digest(&response);
    #[cfg(feature = "thinwallet-experiment")]
    {
      let encoded_size = bincode::serialized_size(&response).unwrap_or_default();
      thinwallet_instrumentation::increment_counter("eval_response_bytes", encoded_size);
    }
    Ok(response)
  }
}

impl<'a> LocalAssembler<'a> {
  fn assemble(
    &mut self,
    request: &EvalTailRequest,
    response: EvalTailResponse,
  ) -> Result<R1CSEvalProof, SplitExecutionError> {
    if self.consumed {
      return Err(SplitExecutionError::SessionConsumed);
    }
    self.consumed = true;
    #[cfg(feature = "thinwallet-experiment")]
    let cpu_start = thinwallet_instrumentation::process_cpu_time_ns();
    #[cfg(feature = "thinwallet-experiment")]
    let wall_start = Instant::now();
    if response.circuit_id != self.expected_circuit_id
      || response.invocation_id != self.expected_invocation_id
      || response.request_binding_digest != request.binding_digest
      || response.inst_evals != request.inst_evals
      || response.binding_metadata != eval_response_binding_digest(&response)
    {
      return Err(SplitExecutionError::ResponseBinding);
    }
    validate_request_binding(request, self.comm)?;
    let (_, mut transcript) =
      replay_sat_transcript(request, self.comm, self.gens, self.transcript_base.clone())?;
    let eval_proof: R1CSEvalProof = bincode::deserialize(&response.r1cs_eval_proof)
      .map_err(|_| SplitExecutionError::ProofEncoding)?;
    eval_proof
      .verify(
        &self.comm.comm,
        &request.rx,
        &request.ry,
        &request.inst_evals,
        &self.gens.gens_r1cs_eval,
        &mut transcript,
      )
      .map_err(|_| SplitExecutionError::EvalVerification)?;
    #[cfg(feature = "thinwallet-experiment")]
    {
      let wall_ns = wall_start.elapsed().as_nanos() as u64;
      let cpu_ns = thinwallet_instrumentation::process_cpu_time_ns().saturating_sub(cpu_start);
      thinwallet_instrumentation::record_stage_metrics(
        "eval_response_validation",
        wall_ns,
        wall_ns,
        cpu_ns,
        cpu_ns,
        0,
      );
      thinwallet_instrumentation::increment_counter("native_eval_verify_pass", 1);
      thinwallet_instrumentation::increment_counter("circuit_binding_pass", 1);
      thinwallet_instrumentation::increment_counter("invocation_binding_pass", 1);
    }
    Ok(eval_proof)
  }
}

fn execute_local_eval_split(
  comm: &ComputationCommitment,
  decomm: &ComputationDecommitment,
  inputs: &InputsAssignment,
  gens: &SNARKGens,
  sat_proof: &R1CSProof,
  rx: &[Scalar],
  ry: &[Scalar],
  inst_evals: &(Scalar, Scalar, Scalar),
  transcript_base: Transcript,
  eval_root: [u8; 32],
  circuit_id: [u8; 32],
  invocation_id: [u8; 32],
) -> Result<R1CSEvalProof, SplitExecutionError> {
  if std::env::var_os("THINWALLET_REMOTE_EVAL_ENDPOINT").is_some() {
    return remote_eval::execute_remote_eval_split(
      comm,
      decomm,
      inputs,
      gens,
      sat_proof,
      rx,
      ry,
      inst_evals,
      transcript_base,
      eval_root,
      circuit_id,
      invocation_id,
    );
  }
  #[cfg(feature = "thinwallet-experiment")]
  thinwallet_instrumentation::increment_counter("local_r1cs_eval_prove_calls", 1);
  #[cfg(feature = "thinwallet-experiment")]
  thinwallet_instrumentation::increment_counter(
    "decomm_cached_bytes",
    bincode::serialized_size(decomm).unwrap_or_default(),
  );
  let request = build_eval_tail_request(
    comm,
    inputs,
    sat_proof,
    rx,
    ry,
    inst_evals,
    circuit_id,
    invocation_id,
  );
  let assembler_request = request.clone();
  let mut executor = LocalEvalExecutor {
    comm,
    decomm,
    gens,
    transcript_base: transcript_base.clone(),
    eval_root,
    cached_decomm_circuit_id: circuit_id,
    expected_circuit_id: circuit_id,
    expected_invocation_id: invocation_id,
    consumed: false,
  };
  let response = executor.execute(request)?;
  let mut assembler = LocalAssembler {
    comm,
    gens,
    transcript_base,
    expected_circuit_id: circuit_id,
    expected_invocation_id: invocation_id,
    consumed: false,
  };
  assembler.assemble(&assembler_request, response)
}

#[cfg(feature = "thinwallet-experiment")]
fn eval_child_totals() -> (u64, u64) {
  let counters = thinwallet_instrumentation::counters_snapshot();
  let wall = [
    "eval_commit_nondet_wall_ns",
    "eval_build_layered_network_wall_ns",
    "eval_layered_proof_wall_ns",
  ]
  .iter()
  .map(|name| counters.get(*name).copied().unwrap_or_default())
  .sum();
  let cpu = [
    "eval_commit_nondet_cpu_ns",
    "eval_build_layered_network_cpu_ns",
    "eval_layered_proof_cpu_ns",
  ]
  .iter()
  .map(|name| counters.get(*name).copied().unwrap_or_default())
  .sum();
  (wall, cpu)
}

/// `ComputationCommitment` holds a public preprocessed NP statement (e.g., R1CS)
#[derive(Serialize, Deserialize)]
pub struct ComputationCommitment {
  comm: R1CSCommitment,
}

/// `ComputationDecommitment` holds information to decommit `ComputationCommitment`
#[derive(Serialize, Deserialize)]
pub struct ComputationDecommitment {
  decomm: R1CSDecommitment,
}

/// `Assignment` holds an assignment of values to either the inputs or variables in an `Instance`
#[derive(Clone, Serialize, Deserialize)]
pub struct Assignment {
  assignment: Vec<Scalar>,
}

impl Assignment {
  /// Constructs a new `Assignment` from a vector
  pub fn new(assignment: &[[u8; 32]]) -> Result<Assignment, R1CSError> {
    let bytes_to_scalar = |vec: &[[u8; 32]]| -> Result<Vec<Scalar>, R1CSError> {
      let mut vec_scalar: Vec<Scalar> = Vec::new();
      for v in vec {
        let val = Scalar::from_bytes(v);
        if val.is_some().unwrap_u8() == 1 {
          vec_scalar.push(val.unwrap());
        } else {
          return Err(R1CSError::InvalidScalar);
        }
      }
      Ok(vec_scalar)
    };

    let assignment_scalar = bytes_to_scalar(assignment);

    // check for any parsing errors
    if assignment_scalar.is_err() {
      return Err(R1CSError::InvalidScalar);
    }

    Ok(Assignment {
      assignment: assignment_scalar.unwrap(),
    })
  }

  /// pads Assignment to the specified length
  fn pad(&self, len: usize) -> VarsAssignment {
    // check that the new length is higher than current length
    assert!(len > self.assignment.len());

    let padded_assignment = {
      let mut padded_assignment = self.assignment.clone();
      padded_assignment.extend(vec![Scalar::zero(); len - self.assignment.len()]);
      padded_assignment
    };

    VarsAssignment {
      assignment: padded_assignment,
    }
  }
}

/// `VarsAssignment` holds an assignment of values to variables in an `Instance`
pub type VarsAssignment = Assignment;

/// `InputsAssignment` holds an assignment of values to variables in an `Instance`
pub type InputsAssignment = Assignment;

/// `Instance` holds the description of R1CS matrices and a hash of the matrices
pub struct Instance {
  inst: R1CSInstance,
  digest: Vec<u8>,
}

impl Instance {
  /// Constructs a new `Instance` and an associated satisfying assignment
  pub fn new(
    num_cons: usize,
    num_vars: usize,
    num_inputs: usize,
    A: &[(usize, usize, [u8; 32])],
    B: &[(usize, usize, [u8; 32])],
    C: &[(usize, usize, [u8; 32])],
  ) -> Result<Instance, R1CSError> {
    let (num_vars_padded, num_cons_padded) = {
      let num_vars_padded = {
        let mut num_vars_padded = num_vars;

        // ensure that num_inputs + 1 <= num_vars
        num_vars_padded = max(num_vars_padded, num_inputs + 1);

        // ensure that num_vars_padded a power of two
        if num_vars_padded.next_power_of_two() != num_vars_padded {
          num_vars_padded = num_vars_padded.next_power_of_two();
        }
        num_vars_padded
      };

      let num_cons_padded = {
        let mut num_cons_padded = num_cons;

        // ensure that num_cons_padded is at least 2
        if num_cons_padded == 0 || num_cons_padded == 1 {
          num_cons_padded = 2;
        }

        // ensure that num_cons_padded is power of 2
        if num_cons.next_power_of_two() != num_cons {
          num_cons_padded = num_cons.next_power_of_two();
        }
        num_cons_padded
      };

      (num_vars_padded, num_cons_padded)
    };

    let bytes_to_scalar =
      |tups: &[(usize, usize, [u8; 32])]| -> Result<Vec<(usize, usize, Scalar)>, R1CSError> {
        let mut mat: Vec<(usize, usize, Scalar)> = Vec::new();
        for &(row, col, val_bytes) in tups {
          // row must be smaller than num_cons
          if row >= num_cons {
            return Err(R1CSError::InvalidIndex);
          }

          // col must be smaller than num_vars + 1 + num_inputs
          if col >= num_vars + 1 + num_inputs {
            return Err(R1CSError::InvalidIndex);
          }

          let val = Scalar::from_bytes(&val_bytes);
          if val.is_some().unwrap_u8() == 1 {
            // if col >= num_vars, it means that it is referencing a 1 or input in the satisfying
            // assignment
            if col >= num_vars {
              mat.push((row, col + num_vars_padded - num_vars, val.unwrap()));
            } else {
              mat.push((row, col, val.unwrap()));
            }
          } else {
            return Err(R1CSError::InvalidScalar);
          }
        }

        // pad with additional constraints up until num_cons_padded if the original constraints were 0 or 1
        // we do not need to pad otherwise because the dummy constraints are implicit in the sum-check protocol
        if num_cons == 0 || num_cons == 1 {
          for i in tups.len()..num_cons_padded {
            mat.push((i, num_vars, Scalar::zero()));
          }
        }

        Ok(mat)
      };

    let A_scalar = bytes_to_scalar(A);
    if A_scalar.is_err() {
      return Err(A_scalar.err().unwrap());
    }

    let B_scalar = bytes_to_scalar(B);
    if B_scalar.is_err() {
      return Err(B_scalar.err().unwrap());
    }

    let C_scalar = bytes_to_scalar(C);
    if C_scalar.is_err() {
      return Err(C_scalar.err().unwrap());
    }

    let inst = R1CSInstance::new(
      num_cons_padded,
      num_vars_padded,
      num_inputs,
      &A_scalar.unwrap(),
      &B_scalar.unwrap(),
      &C_scalar.unwrap(),
    );

    let digest = inst.get_digest();

    Ok(Instance { inst, digest })
  }

  /// Checks if a given R1CSInstance is satisfiable with a given variables and inputs assignments
  pub fn is_sat(
    &self,
    vars: &VarsAssignment,
    inputs: &InputsAssignment,
  ) -> Result<bool, R1CSError> {
    if vars.assignment.len() > self.inst.get_num_vars() {
      return Err(R1CSError::InvalidNumberOfInputs);
    }

    if inputs.assignment.len() != self.inst.get_num_inputs() {
      return Err(R1CSError::InvalidNumberOfInputs);
    }

    // we might need to pad variables
    let padded_vars = {
      let num_padded_vars = self.inst.get_num_vars();
      let num_vars = vars.assignment.len();
      if num_padded_vars > num_vars {
        vars.pad(num_padded_vars)
      } else {
        vars.clone()
      }
    };

    Ok(
      self
        .inst
        .is_sat(&padded_vars.assignment, &inputs.assignment),
    )
  }

  /// Constructs a new synthetic R1CS `Instance` and an associated satisfying assignment
  pub fn produce_synthetic_r1cs(
    num_cons: usize,
    num_vars: usize,
    num_inputs: usize,
  ) -> (Instance, VarsAssignment, InputsAssignment) {
    let (inst, vars, inputs) = R1CSInstance::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);
    let digest = inst.get_digest();
    (
      Instance { inst, digest },
      VarsAssignment { assignment: vars },
      InputsAssignment { assignment: inputs },
    )
  }
}

/// `SNARKGens` holds public parameters for producing and verifying proofs with the Spartan SNARK
#[derive(Serialize, Deserialize)]
pub struct SNARKGens {
  gens_r1cs_sat: R1CSGens,
  gens_r1cs_eval: R1CSCommitmentGens,
}

impl SNARKGens {
  /// Constructs a new `SNARKGens` given the size of the R1CS statement
  /// `num_nz_entries` specifies the maximum number of non-zero entries in any of the three R1CS matrices
  pub fn new(num_cons: usize, num_vars: usize, num_inputs: usize, num_nz_entries: usize) -> Self {
    let num_vars_padded = {
      let mut num_vars_padded = max(num_vars, num_inputs + 1);
      if num_vars_padded != num_vars_padded.next_power_of_two() {
        num_vars_padded = num_vars_padded.next_power_of_two();
      }
      num_vars_padded
    };

    let gens_r1cs_sat = R1CSGens::new(b"gens_r1cs_sat", num_cons, num_vars_padded);
    let gens_r1cs_eval = R1CSCommitmentGens::new(
      b"gens_r1cs_eval",
      num_cons,
      num_vars_padded,
      num_inputs,
      num_nz_entries,
    );
    SNARKGens {
      gens_r1cs_sat,
      gens_r1cs_eval,
    }
  }
}

/// `SNARK` holds a proof produced by Spartan SNARK
#[derive(Serialize, Deserialize, Debug)]
pub struct SNARK {
  r1cs_sat_proof: R1CSProof,
  inst_evals: (Scalar, Scalar, Scalar),
  r1cs_eval_proof: R1CSEvalProof,
}

impl SNARK {
  fn protocol_name() -> &'static [u8] {
    b"Spartan SNARK proof"
  }

  /// Returns audit-only SHA-256 digests of the native Sat and Eval proof components.
  pub fn phase_component_digests(&self) -> ([u8; 32], [u8; 32]) {
    let sat = bincode::serialize(&self.r1cs_sat_proof).expect("sat proof serialization");
    let eval = bincode::serialize(&self.r1cs_eval_proof).expect("eval proof serialization");
    (
      hash_parts(b"thinwallet/spartan/sat-proof-digest/v1", &[&sat]),
      hash_parts(b"thinwallet/spartan/eval-proof-digest/v1", &[&eval]),
    )
  }

  /// A public computation to create a commitment to an R1CS instance
  pub fn encode(
    inst: &Instance,
    gens: &SNARKGens,
  ) -> (ComputationCommitment, ComputationDecommitment) {
    let timer_encode = Timer::new("SNARK::encode");
    let (comm, decomm) = inst.inst.commit(&gens.gens_r1cs_eval);
    timer_encode.stop();
    (
      ComputationCommitment { comm },
      ComputationDecommitment { decomm },
    )
  }

  /// A method to produce a SNARK proof of the satisfiability of an R1CS instance
  pub fn prove(
    inst: &Instance,
    comm: &ComputationCommitment,
    decomm: &ComputationDecommitment,
    vars: VarsAssignment,
    inputs: &InputsAssignment,
    gens: &SNARKGens,
    transcript: &mut Transcript,
  ) -> Self {
    let timer_prove = Timer::new("SNARK::prove");

    let mut randomness_plan = prepare_randomness_plan(comm, transcript);
    #[cfg(feature = "thinwallet-experiment")]
    randomness_plan.record_trace_preamble();

    transcript.append_protocol_name(SNARK::protocol_name());
    comm.comm.append_to_transcript(b"comm", transcript);

    let (r1cs_sat_proof, rx, ry) = {
      let (proof, rx, ry) = {
        // we might need to pad variables
        let padded_vars = {
          let num_padded_vars = inst.inst.get_num_vars();
          let num_vars = vars.assignment.len();
          if num_padded_vars > num_vars {
            vars.pad(num_padded_vars)
          } else {
            vars
          }
        };

        #[cfg(feature = "thinwallet-experiment")]
        let sat_cpu_start = thinwallet_instrumentation::process_cpu_time_ns();
        #[cfg(feature = "thinwallet-experiment")]
        let sat_wall_start = Instant::now();
        let result = LocalSatExecutor {
          inst: &inst.inst,
          vars: padded_vars.assignment,
          inputs: &inputs.assignment,
          gens: &gens.gens_r1cs_sat,
          transcript,
          sat_random_tape: randomness_plan.sat_random_tape(),
        }
        .execute();
        let sat_randomness_audit = randomness_plan.seal_sat_frontier();
        #[cfg(feature = "thinwallet-experiment")]
        record_sat_randomness_audit(sat_randomness_audit);
        #[cfg(not(feature = "thinwallet-experiment"))]
        let _ = sat_randomness_audit;
        #[cfg(feature = "thinwallet-experiment")]
        let sat_wall_ns = sat_wall_start.elapsed().as_nanos() as u64;
        #[cfg(feature = "thinwallet-experiment")]
        let sat_cpu_ns =
          thinwallet_instrumentation::process_cpu_time_ns().saturating_sub(sat_cpu_start);
        #[cfg(feature = "thinwallet-experiment")]
        thinwallet_instrumentation::record_stage_metrics(
          "r1cs_sat",
          sat_wall_ns,
          sat_wall_ns,
          sat_cpu_ns,
          sat_cpu_ns,
          0,
        );
        result
      };

      let proof_encoded: Vec<u8> = bincode::serialize(&proof).unwrap();
      Timer::print(&format!("len_r1cs_sat_proof {:?}", proof_encoded.len()));
      #[cfg(feature = "thinwallet-experiment")]
      {
        thinwallet_instrumentation::increment_counter(
          "r1cs_sat_proof_bytes",
          proof_encoded.len() as u64,
        );
        thinwallet_instrumentation::increment_counter(
          "r1cs_sat_num_cons",
          inst.inst.get_num_cons() as u64,
        );
        thinwallet_instrumentation::increment_counter(
          "r1cs_sat_num_vars",
          inst.inst.get_num_vars() as u64,
        );
        thinwallet_instrumentation::increment_counter(
          "r1cs_sat_num_inputs",
          inputs.assignment.len() as u64,
        );
      }

      (proof, rx, ry)
    };

    // We send evaluations of A, B, C at r = (rx, ry) as claims
    // to enable the verifier complete the first sum-check
    let timer_eval = Timer::new("eval_sparse_polys");
    #[cfg(feature = "thinwallet-experiment")]
    let sparse_cpu_start = thinwallet_instrumentation::process_cpu_time_ns();
    #[cfg(feature = "thinwallet-experiment")]
    let sparse_wall_start = Instant::now();
    let inst_evals = {
      let (Ar, Br, Cr) = inst.inst.evaluate(&rx, &ry);
      Ar.append_to_transcript(b"Ar_claim", transcript);
      Br.append_to_transcript(b"Br_claim", transcript);
      Cr.append_to_transcript(b"Cr_claim", transcript);
      (Ar, Br, Cr)
    };
    #[cfg(feature = "thinwallet-experiment")]
    {
      thinwallet_instrumentation::record_trace_event(
        "fix_d_pub",
        &["pi_sat", "x", "pubmeta"],
        &["d_pub"],
        None,
        &["d_pub"],
        false,
      );
      thinwallet_instrumentation::record_trace_event(
        "derive_eval_point",
        &["d_pub"],
        &["rx_ry"],
        None,
        &[],
        true,
      );
    }
    #[cfg(feature = "thinwallet-experiment")]
    let sparse_wall_ns = sparse_wall_start.elapsed().as_nanos() as u64;
    #[cfg(feature = "thinwallet-experiment")]
    let sparse_cpu_ns =
      thinwallet_instrumentation::process_cpu_time_ns().saturating_sub(sparse_cpu_start);
    timer_eval.stop();
    #[cfg(feature = "thinwallet-experiment")]
    {
      let sparse_bytes = bincode::serialize(&inst_evals).unwrap().len() as u64;
      thinwallet_instrumentation::record_stage_metrics(
        "sparse_eval",
        sparse_wall_ns,
        sparse_wall_ns,
        sparse_cpu_ns,
        sparse_cpu_ns,
        sparse_bytes,
      );
      thinwallet_instrumentation::increment_counter("sparse_eval_rx_len", rx.len() as u64);
      thinwallet_instrumentation::increment_counter("sparse_eval_ry_len", ry.len() as u64);
    }

    let r1cs_eval_proof = {
      #[cfg(feature = "thinwallet-experiment")]
      let eval_children_before = eval_child_totals();
      #[cfg(feature = "thinwallet-experiment")]
      let eval_cpu_start = thinwallet_instrumentation::process_cpu_time_ns();
      #[cfg(feature = "thinwallet-experiment")]
      let eval_wall_start = Instant::now();
      let proof = match randomness_plan {
        ProverRandomnessPlan::LegacyShared(mut shared_tape) => R1CSEvalProof::prove(
          &decomm.decomm,
          &rx,
          &ry,
          &inst_evals,
          &gens.gens_r1cs_eval,
          transcript,
          &mut shared_tape,
        ),
        ProverRandomnessPlan::Split {
          eval_root,
          circuit_id,
          invocation_id,
          transcript_base,
          ..
        } => execute_local_eval_split(
          comm,
          decomm,
          inputs,
          gens,
          &r1cs_sat_proof,
          &rx,
          &ry,
          &inst_evals,
          transcript_base,
          eval_root,
          circuit_id,
          invocation_id,
        )
        .expect("local split eval execution must validate"),
      };
      #[cfg(feature = "thinwallet-experiment")]
      let eval_wall_ns = eval_wall_start.elapsed().as_nanos() as u64;
      #[cfg(feature = "thinwallet-experiment")]
      let eval_cpu_ns =
        thinwallet_instrumentation::process_cpu_time_ns().saturating_sub(eval_cpu_start);

      let proof_encoded: Vec<u8> = bincode::serialize(&proof).unwrap();
      Timer::print(&format!("len_r1cs_eval_proof {:?}", proof_encoded.len()));
      #[cfg(feature = "thinwallet-experiment")]
      {
        let eval_children_after = eval_child_totals();
        let child_wall_ns = eval_children_after.0.saturating_sub(eval_children_before.0);
        let child_cpu_ns = eval_children_after.1.saturating_sub(eval_children_before.1);
        thinwallet_instrumentation::record_stage_metrics(
          "r1cs_eval_proof",
          eval_wall_ns,
          eval_wall_ns.saturating_sub(child_wall_ns),
          eval_cpu_ns,
          eval_cpu_ns.saturating_sub(child_cpu_ns),
          proof_encoded.len() as u64,
        );
        thinwallet_instrumentation::increment_counter("uses_r1cs_eval_proof", 1);
        thinwallet_instrumentation::increment_counter("r1cs_eval_rx_len", rx.len() as u64);
        thinwallet_instrumentation::increment_counter("r1cs_eval_ry_len", ry.len() as u64);
        thinwallet_instrumentation::increment_counter("r1cs_eval_batch_size", 3);
      }
      proof
    };

    #[cfg(feature = "thinwallet-experiment")]
    {
      thinwallet_instrumentation::record_trace_event(
        "assemble_pi_eval",
        &["comm_derefs", "proof_prod_layer", "proof_hash_layer"],
        &["pi_eval"],
        None,
        &["pi_eval"],
        false,
      );
      thinwallet_instrumentation::record_trace_event(
        "assemble_proof",
        &["pi_sat", "pi_eval"],
        &["Pi"],
        None,
        &["Pi"],
        false,
      );
    }

    timer_prove.stop();
    SNARK {
      r1cs_sat_proof,
      inst_evals,
      r1cs_eval_proof,
    }
  }

  /// Prover-only ownership variant used by FS3 to release the public instance at its last use.
  pub fn prove_owned(
    inst: Instance,
    comm: &ComputationCommitment,
    decomm: &ComputationDecommitment,
    vars: VarsAssignment,
    inputs: &InputsAssignment,
    gens: &SNARKGens,
    transcript: &mut Transcript,
  ) -> Self {
    let timer_prove = Timer::new("SNARK::prove");
    let mut randomness_plan = prepare_randomness_plan(comm, transcript);
    #[cfg(feature = "thinwallet-experiment")]
    randomness_plan.record_trace_preamble();
    transcript.append_protocol_name(SNARK::protocol_name());
    comm.comm.append_to_transcript(b"comm", transcript);

    let (r1cs_sat_proof, rx, ry) = {
      let (proof, rx, ry) = {
        let padded_vars = {
          let num_padded_vars = inst.inst.get_num_vars();
          let num_vars = vars.assignment.len();
          if num_padded_vars > num_vars {
            vars.pad(num_padded_vars)
          } else {
            vars
          }
        };
        #[cfg(feature = "thinwallet-experiment")]
        let sat_cpu_start = thinwallet_instrumentation::process_cpu_time_ns();
        #[cfg(feature = "thinwallet-experiment")]
        let sat_wall_start = Instant::now();
        let result = LocalSatExecutor {
          inst: &inst.inst,
          vars: padded_vars.assignment,
          inputs: &inputs.assignment,
          gens: &gens.gens_r1cs_sat,
          transcript,
          sat_random_tape: randomness_plan.sat_random_tape(),
        }
        .execute();
        let sat_randomness_audit = randomness_plan.seal_sat_frontier();
        #[cfg(feature = "thinwallet-experiment")]
        record_sat_randomness_audit(sat_randomness_audit);
        #[cfg(not(feature = "thinwallet-experiment"))]
        let _ = sat_randomness_audit;
        #[cfg(feature = "thinwallet-experiment")]
        let sat_wall_ns = sat_wall_start.elapsed().as_nanos() as u64;
        #[cfg(feature = "thinwallet-experiment")]
        let sat_cpu_ns =
          thinwallet_instrumentation::process_cpu_time_ns().saturating_sub(sat_cpu_start);
        #[cfg(feature = "thinwallet-experiment")]
        thinwallet_instrumentation::record_stage_metrics(
          "r1cs_sat",
          sat_wall_ns,
          sat_wall_ns,
          sat_cpu_ns,
          sat_cpu_ns,
          0,
        );
        result
      };
      let proof_encoded: Vec<u8> = bincode::serialize(&proof).unwrap();
      Timer::print(&format!("len_r1cs_sat_proof {:?}", proof_encoded.len()));
      #[cfg(feature = "thinwallet-experiment")]
      {
        thinwallet_instrumentation::increment_counter(
          "r1cs_sat_proof_bytes",
          proof_encoded.len() as u64,
        );
        thinwallet_instrumentation::increment_counter(
          "r1cs_sat_num_cons",
          inst.inst.get_num_cons() as u64,
        );
        thinwallet_instrumentation::increment_counter(
          "r1cs_sat_num_vars",
          inst.inst.get_num_vars() as u64,
        );
        thinwallet_instrumentation::increment_counter(
          "r1cs_sat_num_inputs",
          inputs.assignment.len() as u64,
        );
      }
      (proof, rx, ry)
    };

    let timer_eval = Timer::new("eval_sparse_polys");
    #[cfg(feature = "thinwallet-experiment")]
    let sparse_cpu_start = thinwallet_instrumentation::process_cpu_time_ns();
    #[cfg(feature = "thinwallet-experiment")]
    let sparse_wall_start = Instant::now();
    let inst_evals = {
      let (ar, br, cr) = inst.inst.evaluate(&rx, &ry);
      ar.append_to_transcript(b"Ar_claim", transcript);
      br.append_to_transcript(b"Br_claim", transcript);
      cr.append_to_transcript(b"Cr_claim", transcript);
      (ar, br, cr)
    };
    #[cfg(feature = "thinwallet-experiment")]
    {
      thinwallet_instrumentation::record_trace_event(
        "fix_d_pub",
        &["pi_sat", "x", "pubmeta"],
        &["d_pub"],
        None,
        &["d_pub"],
        false,
      );
      thinwallet_instrumentation::record_trace_event(
        "derive_eval_point",
        &["d_pub"],
        &["rx_ry"],
        None,
        &[],
        true,
      );
    }
    #[cfg(feature = "thinwallet-experiment")]
    let sparse_wall_ns = sparse_wall_start.elapsed().as_nanos() as u64;
    #[cfg(feature = "thinwallet-experiment")]
    let sparse_cpu_ns =
      thinwallet_instrumentation::process_cpu_time_ns().saturating_sub(sparse_cpu_start);
    timer_eval.stop();
    #[cfg(feature = "thinwallet-experiment")]
    {
      let sparse_bytes = bincode::serialize(&inst_evals).unwrap().len() as u64;
      thinwallet_instrumentation::record_stage_metrics(
        "sparse_eval",
        sparse_wall_ns,
        sparse_wall_ns,
        sparse_cpu_ns,
        sparse_cpu_ns,
        sparse_bytes,
      );
      thinwallet_instrumentation::increment_counter("sparse_eval_rx_len", rx.len() as u64);
      thinwallet_instrumentation::increment_counter("sparse_eval_ry_len", ry.len() as u64);
    }
    drop(inst);

    let r1cs_eval_proof = {
      #[cfg(feature = "thinwallet-experiment")]
      let eval_children_before = eval_child_totals();
      #[cfg(feature = "thinwallet-experiment")]
      let eval_cpu_start = thinwallet_instrumentation::process_cpu_time_ns();
      #[cfg(feature = "thinwallet-experiment")]
      let eval_wall_start = Instant::now();
      let proof = match randomness_plan {
        ProverRandomnessPlan::LegacyShared(mut shared_tape) => R1CSEvalProof::prove(
          &decomm.decomm,
          &rx,
          &ry,
          &inst_evals,
          &gens.gens_r1cs_eval,
          transcript,
          &mut shared_tape,
        ),
        ProverRandomnessPlan::Split {
          eval_root,
          circuit_id,
          invocation_id,
          transcript_base,
          ..
        } => execute_local_eval_split(
          comm,
          decomm,
          inputs,
          gens,
          &r1cs_sat_proof,
          &rx,
          &ry,
          &inst_evals,
          transcript_base,
          eval_root,
          circuit_id,
          invocation_id,
        )
        .expect("local split eval execution must validate"),
      };
      #[cfg(feature = "thinwallet-experiment")]
      let eval_wall_ns = eval_wall_start.elapsed().as_nanos() as u64;
      #[cfg(feature = "thinwallet-experiment")]
      let eval_cpu_ns =
        thinwallet_instrumentation::process_cpu_time_ns().saturating_sub(eval_cpu_start);
      let proof_encoded: Vec<u8> = bincode::serialize(&proof).unwrap();
      Timer::print(&format!("len_r1cs_eval_proof {:?}", proof_encoded.len()));
      #[cfg(feature = "thinwallet-experiment")]
      {
        let eval_children_after = eval_child_totals();
        let child_wall_ns = eval_children_after.0.saturating_sub(eval_children_before.0);
        let child_cpu_ns = eval_children_after.1.saturating_sub(eval_children_before.1);
        thinwallet_instrumentation::record_stage_metrics(
          "r1cs_eval_proof",
          eval_wall_ns,
          eval_wall_ns.saturating_sub(child_wall_ns),
          eval_cpu_ns,
          eval_cpu_ns.saturating_sub(child_cpu_ns),
          proof_encoded.len() as u64,
        );
        thinwallet_instrumentation::increment_counter("uses_r1cs_eval_proof", 1);
        thinwallet_instrumentation::increment_counter("r1cs_eval_rx_len", rx.len() as u64);
        thinwallet_instrumentation::increment_counter("r1cs_eval_ry_len", ry.len() as u64);
        thinwallet_instrumentation::increment_counter("r1cs_eval_batch_size", 3);
      }
      proof
    };

    #[cfg(feature = "thinwallet-experiment")]
    {
      thinwallet_instrumentation::record_trace_event(
        "assemble_pi_eval",
        &["comm_derefs", "proof_prod_layer", "proof_hash_layer"],
        &["pi_eval"],
        None,
        &["pi_eval"],
        false,
      );
      thinwallet_instrumentation::record_trace_event(
        "assemble_proof",
        &["pi_sat", "pi_eval"],
        &["Pi"],
        None,
        &["Pi"],
        false,
      );
    }

    timer_prove.stop();
    SNARK {
      r1cs_sat_proof,
      inst_evals,
      r1cs_eval_proof,
    }
  }

  /// A method to verify the SNARK proof of the satisfiability of an R1CS instance
  pub fn verify(
    &self,
    comm: &ComputationCommitment,
    input: &InputsAssignment,
    transcript: &mut Transcript,
    gens: &SNARKGens,
  ) -> Result<(), ProofVerifyError> {
    let timer_verify = Timer::new("SNARK::verify");
    transcript.append_protocol_name(SNARK::protocol_name());

    // append a commitment to the computation to the transcript
    comm.comm.append_to_transcript(b"comm", transcript);

    let timer_sat_proof = Timer::new("verify_sat_proof");
    assert_eq!(input.assignment.len(), comm.comm.get_num_inputs());
    let (rx, ry) = self.r1cs_sat_proof.verify(
      comm.comm.get_num_vars(),
      comm.comm.get_num_cons(),
      &input.assignment,
      &self.inst_evals,
      transcript,
      &gens.gens_r1cs_sat,
    )?;
    timer_sat_proof.stop();

    let timer_eval_proof = Timer::new("verify_eval_proof");
    let (Ar, Br, Cr) = &self.inst_evals;
    Ar.append_to_transcript(b"Ar_claim", transcript);
    Br.append_to_transcript(b"Br_claim", transcript);
    Cr.append_to_transcript(b"Cr_claim", transcript);
    #[cfg(feature = "thinwallet-experiment")]
    let eval_verify_cpu_start = thinwallet_instrumentation::process_cpu_time_ns();
    #[cfg(feature = "thinwallet-experiment")]
    let eval_verify_wall_start = Instant::now();
    let eval_verify_result = self.r1cs_eval_proof.verify(
      &comm.comm,
      &rx,
      &ry,
      &self.inst_evals,
      &gens.gens_r1cs_eval,
      transcript,
    );
    #[cfg(feature = "thinwallet-experiment")]
    {
      let wall_ns = eval_verify_wall_start.elapsed().as_nanos() as u64;
      let cpu_ns =
        thinwallet_instrumentation::process_cpu_time_ns().saturating_sub(eval_verify_cpu_start);
      thinwallet_instrumentation::record_stage_metrics(
        "r1cs_eval_verify",
        wall_ns,
        wall_ns,
        cpu_ns,
        cpu_ns,
        0,
      );
    }
    eval_verify_result?;
    timer_eval_proof.stop();
    timer_verify.stop();
    Ok(())
  }
}

/// `NIZKGens` holds public parameters for producing and verifying proofs with the Spartan NIZK
pub struct NIZKGens {
  gens_r1cs_sat: R1CSGens,
}

impl NIZKGens {
  /// Constructs a new `NIZKGens` given the size of the R1CS statement
  pub fn new(num_cons: usize, num_vars: usize, num_inputs: usize) -> Self {
    let num_vars_padded = {
      let mut num_vars_padded = max(num_vars, num_inputs + 1);
      if num_vars_padded != num_vars_padded.next_power_of_two() {
        num_vars_padded = num_vars_padded.next_power_of_two();
      }
      num_vars_padded
    };

    let gens_r1cs_sat = R1CSGens::new(b"gens_r1cs_sat", num_cons, num_vars_padded);
    NIZKGens { gens_r1cs_sat }
  }
}

/// `NIZK` holds a proof produced by Spartan NIZK
#[derive(Serialize, Deserialize, Debug)]
pub struct NIZK {
  r1cs_sat_proof: R1CSProof,
  r: (Vec<Scalar>, Vec<Scalar>),
}

impl NIZK {
  fn protocol_name() -> &'static [u8] {
    b"Spartan NIZK proof"
  }

  /// A method to produce a NIZK proof of the satisfiability of an R1CS instance
  pub fn prove(
    inst: &Instance,
    vars: VarsAssignment,
    input: &InputsAssignment,
    gens: &NIZKGens,
    transcript: &mut Transcript,
  ) -> Self {
    let timer_prove = Timer::new("NIZK::prove");
    // we create a Transcript object seeded with a random Scalar
    // to aid the prover produce its randomness
    let mut random_tape = RandomTape::new(b"proof");

    transcript.append_protocol_name(NIZK::protocol_name());
    transcript.append_message(b"R1CSInstanceDigest", &inst.digest);
    transcript::audit_append_message(b"R1CSInstanceDigest", &inst.digest);

    let (r1cs_sat_proof, rx, ry) = {
      // we might need to pad variables
      let padded_vars = {
        let num_padded_vars = inst.inst.get_num_vars();
        let num_vars = vars.assignment.len();
        if num_padded_vars > num_vars {
          vars.pad(num_padded_vars)
        } else {
          vars
        }
      };

      let (proof, rx, ry) = R1CSProof::prove(
        &inst.inst,
        padded_vars.assignment,
        &input.assignment,
        &gens.gens_r1cs_sat,
        transcript,
        &mut random_tape,
      );
      let proof_encoded: Vec<u8> = bincode::serialize(&proof).unwrap();
      Timer::print(&format!("len_r1cs_sat_proof {:?}", proof_encoded.len()));
      (proof, rx, ry)
    };

    timer_prove.stop();
    NIZK {
      r1cs_sat_proof,
      r: (rx, ry),
    }
  }

  /// A method to verify a NIZK proof of the satisfiability of an R1CS instance
  pub fn verify(
    &self,
    inst: &Instance,
    input: &InputsAssignment,
    transcript: &mut Transcript,
    gens: &NIZKGens,
  ) -> Result<(), ProofVerifyError> {
    let timer_verify = Timer::new("NIZK::verify");

    transcript.append_protocol_name(NIZK::protocol_name());
    transcript.append_message(b"R1CSInstanceDigest", &inst.digest);
    transcript::audit_append_message(b"R1CSInstanceDigest", &inst.digest);

    // We send evaluations of A, B, C at r = (rx, ry) as claims
    // to enable the verifier complete the first sum-check
    let timer_eval = Timer::new("eval_sparse_polys");
    let (claimed_rx, claimed_ry) = &self.r;
    let inst_evals = inst.inst.evaluate(claimed_rx, claimed_ry);
    timer_eval.stop();

    let timer_sat_proof = Timer::new("verify_sat_proof");
    assert_eq!(input.assignment.len(), inst.inst.get_num_inputs());
    let (rx, ry) = self.r1cs_sat_proof.verify(
      inst.inst.get_num_vars(),
      inst.inst.get_num_cons(),
      &input.assignment,
      &inst_evals,
      transcript,
      &gens.gens_r1cs_sat,
    )?;

    // verify if claimed rx and ry are correct
    assert_eq!(rx, *claimed_rx);
    assert_eq!(ry, *claimed_ry);
    timer_sat_proof.stop();
    timer_verify.stop();

    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  struct SplitTestMaterial {
    inst: Instance,
    vars: VarsAssignment,
    inputs: InputsAssignment,
    gens: SNARKGens,
    comm: ComputationCommitment,
    decomm: ComputationDecommitment,
  }

  fn split_test_material(num_vars: usize) -> SplitTestMaterial {
    let num_cons = num_vars;
    let num_inputs = 10;
    let gens = SNARKGens::new(num_cons, num_vars, num_inputs, num_cons);
    let (inst, vars, inputs) = Instance::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);
    let (comm, decomm) = SNARK::encode(&inst, &gens);
    SplitTestMaterial {
      inst,
      vars,
      inputs,
      gens,
      comm,
      decomm,
    }
  }

  fn split_test_request(
    material: &SplitTestMaterial,
    sat_root: [u8; 32],
    invocation_id: [u8; 32],
  ) -> (EvalTailRequest, Transcript) {
    let transcript_base = Transcript::new(b"phase5da_test");
    let mut transcript = transcript_base.clone();
    transcript.append_protocol_name(SNARK::protocol_name());
    material
      .comm
      .comm
      .append_to_transcript(b"comm", &mut transcript);
    let circuit_id = circuit_identifier(&material.comm);
    let sat_seed = hmac_phase_seed(&sat_root, b"sat", &circuit_id, &invocation_id);
    let mut sat_random_tape = RandomTape::from_phase_seed(b"sat_proof", &sat_seed);
    let padded_vars = {
      let num_padded_vars = material.inst.inst.get_num_vars();
      if num_padded_vars > material.vars.assignment.len() {
        material.vars.clone().pad(num_padded_vars)
      } else {
        material.vars.clone()
      }
    };
    let (sat_proof, rx, ry) = LocalSatExecutor {
      inst: &material.inst.inst,
      vars: padded_vars.assignment,
      inputs: &material.inputs.assignment,
      gens: &material.gens.gens_r1cs_sat,
      transcript: &mut transcript,
      sat_random_tape: &mut sat_random_tape,
    }
    .execute();
    let inst_evals = material.inst.inst.evaluate(&rx, &ry);
    (
      build_eval_tail_request(
        &material.comm,
        &material.inputs,
        &sat_proof,
        &rx,
        &ry,
        &inst_evals,
        circuit_id,
        invocation_id,
      ),
      transcript_base,
    )
  }

  fn split_test_response(
    material: &SplitTestMaterial,
    request: EvalTailRequest,
    transcript_base: Transcript,
    eval_root: [u8; 32],
    cached_decomm_circuit_id: [u8; 32],
    expected_invocation_id: [u8; 32],
  ) -> Result<EvalTailResponse, SplitExecutionError> {
    let circuit_id = circuit_identifier(&material.comm);
    LocalEvalExecutor {
      comm: &material.comm,
      decomm: &material.decomm,
      gens: &material.gens,
      transcript_base,
      eval_root,
      cached_decomm_circuit_id,
      expected_circuit_id: circuit_id,
      expected_invocation_id,
      consumed: false,
    }
    .execute(request)
  }

  fn split_test_assemble(
    material: &SplitTestMaterial,
    request: &EvalTailRequest,
    response: EvalTailResponse,
    transcript_base: Transcript,
  ) -> Result<SNARK, SplitExecutionError> {
    let circuit_id = circuit_identifier(&material.comm);
    let mut assembler = LocalAssembler {
      comm: &material.comm,
      gens: &material.gens,
      transcript_base,
      expected_circuit_id: circuit_id,
      expected_invocation_id: request.invocation_id,
      consumed: false,
    };
    let eval_proof = assembler.assemble(request, response)?;
    let sat_proof = bincode::deserialize(&request.r1cs_sat_proof)
      .map_err(|_| SplitExecutionError::ProofEncoding)?;
    Ok(SNARK {
      r1cs_sat_proof: sat_proof,
      inst_evals: request.inst_evals,
      r1cs_eval_proof: eval_proof,
    })
  }

  fn refresh_request_binding(request: &mut EvalTailRequest) {
    request.transcript_replay_data.sat_proof_digest = hash_parts(
      b"thinwallet/spartan/replay-sat-proof/v1",
      &[&request.r1cs_sat_proof],
    );
    request.binding_digest = eval_request_binding_digest(request);
  }

  fn refresh_response_binding(response: &mut EvalTailResponse) {
    response.binding_metadata = eval_response_binding_digest(response);
  }

  #[test]
  fn phase5da_split_boundary_suite() {
    let material = split_test_material(256);
    let other_material = split_test_material(512);
    let sat_root_a = [0x11; 32];
    let sat_root_b = [0x22; 32];
    let eval_root_a = [0x33; 32];
    let eval_root_b = [0x44; 32];
    let invocation_a = [0x55; 32];
    let invocation_b = [0x66; 32];
    let circuit_id = circuit_identifier(&material.comm);

    let (request_a, transcript_a) = split_test_request(&material, sat_root_a, invocation_a);
    println!(
      "PHASE5DA request_sizes circuit={} invocation={} public_inputs={} sat_proof={} replay={} rx={} ry={} inst_evals={} binding={} total={}",
      bincode::serialized_size(&request_a.circuit_id).unwrap(),
      bincode::serialized_size(&request_a.invocation_id).unwrap(),
      bincode::serialized_size(&request_a.public_inputs).unwrap(),
      bincode::serialized_size(&request_a.r1cs_sat_proof).unwrap(),
      bincode::serialized_size(&request_a.transcript_replay_data).unwrap(),
      bincode::serialized_size(&request_a.rx).unwrap(),
      bincode::serialized_size(&request_a.ry).unwrap(),
      bincode::serialized_size(&request_a.inst_evals).unwrap(),
      bincode::serialized_size(&request_a.binding_digest).unwrap(),
      bincode::serialized_size(&request_a).unwrap(),
    );
    let response_a = split_test_response(
      &material,
      request_a.clone(),
      transcript_a.clone(),
      eval_root_a,
      circuit_id,
      invocation_a,
    )
    .unwrap();
    let proof_a = split_test_assemble(
      &material,
      &request_a,
      response_a.clone(),
      transcript_a.clone(),
    )
    .unwrap();
    let mut verifier_transcript = Transcript::new(b"phase5da_test");
    assert!(proof_a
      .verify(
        &material.comm,
        &material.inputs,
        &mut verifier_transcript,
        &material.gens,
      )
      .is_ok());
    println!("PHASE5DA native_full_verify PASS");

    let response_eval_changed = split_test_response(
      &material,
      request_a.clone(),
      transcript_a.clone(),
      eval_root_b,
      circuit_id,
      invocation_a,
    )
    .unwrap();
    assert_ne!(
      response_a.r1cs_eval_proof,
      response_eval_changed.r1cs_eval_proof
    );
    let changed_eval_proof = split_test_assemble(
      &material,
      &request_a,
      response_eval_changed,
      transcript_a.clone(),
    )
    .unwrap();
    let mut changed_eval_transcript = Transcript::new(b"phase5da_test");
    assert!(changed_eval_proof
      .verify(
        &material.comm,
        &material.inputs,
        &mut changed_eval_transcript,
        &material.gens,
      )
      .is_ok());
    println!("PHASE5DA fixed_sat_changed_eval PASS");

    let (request_sat_changed, transcript_sat_changed) =
      split_test_request(&material, sat_root_b, invocation_a);
    assert_ne!(request_a.r1cs_sat_proof, request_sat_changed.r1cs_sat_proof);
    let response_sat_changed = split_test_response(
      &material,
      request_sat_changed.clone(),
      transcript_sat_changed.clone(),
      eval_root_a,
      circuit_id,
      invocation_a,
    )
    .unwrap();
    let proof_sat_changed = split_test_assemble(
      &material,
      &request_sat_changed,
      response_sat_changed,
      transcript_sat_changed,
    )
    .unwrap();
    let mut sat_changed_transcript = Transcript::new(b"phase5da_test");
    assert!(proof_sat_changed
      .verify(
        &material.comm,
        &material.inputs,
        &mut sat_changed_transcript,
        &material.gens,
      )
      .is_ok());
    println!("PHASE5DA fixed_eval_changed_sat PASS");

    let (request_repeat, transcript_repeat) =
      split_test_request(&material, sat_root_a, invocation_a);
    let response_repeat = split_test_response(
      &material,
      request_repeat.clone(),
      transcript_repeat.clone(),
      eval_root_a,
      circuit_id,
      invocation_a,
    )
    .unwrap();
    assert_eq!(request_a.r1cs_sat_proof, request_repeat.r1cs_sat_proof);
    assert_eq!(response_a.r1cs_eval_proof, response_repeat.r1cs_eval_proof);
    println!("PHASE5DA deterministic_reproduction PASS");

    let (request_invocation_b, _) = split_test_request(&material, sat_root_a, invocation_b);
    assert_ne!(
      request_a.r1cs_sat_proof,
      request_invocation_b.r1cs_sat_proof
    );
    println!("PHASE5DA invocation_separation PASS");

    let (other_request, _) = split_test_request(&other_material, sat_root_a, invocation_a);
    assert_ne!(request_a.circuit_id, other_request.circuit_id);
    println!("PHASE5DA circuit_separation PASS");

    let sat_seed = hmac_phase_seed(&sat_root_a, b"sat", &circuit_id, &invocation_a);
    let eval_seed = hmac_phase_seed(&eval_root_a, b"eval", &circuit_id, &invocation_a);
    assert_ne!(sat_seed, eval_seed);
    assert!(!bincode::serialize(&request_a)
      .unwrap()
      .windows(eval_root_a.len())
      .any(|window| window == eval_root_a));
    println!("PHASE5DA eval_seed_leak_boundary PASS");

    let mut tampered = request_a.clone();
    tampered.circuit_id[0] ^= 1;
    refresh_request_binding(&mut tampered);
    assert!(split_test_response(
      &material,
      tampered,
      transcript_a.clone(),
      eval_root_a,
      circuit_id,
      invocation_a,
    )
    .is_err());
    println!("PHASE5DA negative_modified_circuit_id PASS");

    let mut tampered = request_a.clone();
    tampered.invocation_id[0] ^= 1;
    refresh_request_binding(&mut tampered);
    assert!(split_test_response(
      &material,
      tampered,
      transcript_a.clone(),
      eval_root_a,
      circuit_id,
      invocation_a,
    )
    .is_err());
    println!("PHASE5DA negative_modified_invocation_id PASS");

    let mut tampered = request_a.clone();
    tampered.r1cs_sat_proof[0] ^= 1;
    refresh_request_binding(&mut tampered);
    assert!(split_test_response(
      &material,
      tampered,
      transcript_a.clone(),
      eval_root_a,
      circuit_id,
      invocation_a,
    )
    .is_err());
    println!("PHASE5DA negative_modified_sat_proof PASS");

    let mut tampered = request_a.clone();
    tampered.rx[0] += Scalar::one();
    refresh_request_binding(&mut tampered);
    assert!(split_test_response(
      &material,
      tampered,
      transcript_a.clone(),
      eval_root_a,
      circuit_id,
      invocation_a,
    )
    .is_err());
    println!("PHASE5DA negative_modified_rx_ry PASS");

    let mut tampered = request_a.clone();
    tampered.transcript_replay_data.protocol_identifier.push(0);
    refresh_request_binding(&mut tampered);
    assert!(split_test_response(
      &material,
      tampered,
      transcript_a.clone(),
      eval_root_a,
      circuit_id,
      invocation_a,
    )
    .is_err());
    println!("PHASE5DA negative_modified_replay_data PASS");

    let mut tampered = request_a.clone();
    tampered.inst_evals.0 += Scalar::one();
    refresh_request_binding(&mut tampered);
    assert!(split_test_response(
      &material,
      tampered,
      transcript_a.clone(),
      eval_root_a,
      circuit_id,
      invocation_a,
    )
    .is_err());
    println!("PHASE5DA negative_modified_inst_evals PASS");

    let mut tampered_response = response_a.clone();
    tampered_response.r1cs_eval_proof[0] ^= 1;
    refresh_response_binding(&mut tampered_response);
    assert!(split_test_assemble(
      &material,
      &request_a,
      tampered_response,
      transcript_a.clone(),
    )
    .is_err());
    println!("PHASE5DA negative_modified_eval_proof PASS");

    let wrong_seed_response = split_test_response(
      &material,
      request_a.clone(),
      transcript_a.clone(),
      [0x77; 32],
      circuit_id,
      invocation_a,
    )
    .unwrap();
    assert!(split_test_assemble(
      &material,
      &request_a,
      wrong_seed_response,
      transcript_a.clone(),
    )
    .is_ok());
    println!("PHASE5DA wrong_eval_seed_valid_randomness PASS");

    let (request_b, transcript_b) = split_test_request(&material, sat_root_a, invocation_b);
    assert!(split_test_assemble(&material, &request_b, response_a.clone(), transcript_b,).is_err());
    println!("PHASE5DA negative_cross_session_response PASS");

    assert!(split_test_response(
      &material,
      request_a.clone(),
      transcript_a.clone(),
      eval_root_a,
      circuit_identifier(&other_material.comm),
      invocation_a,
    )
    .is_err());
    println!("PHASE5DA negative_other_circuit_decomm PASS");

    let mut replay_assembler = LocalAssembler {
      comm: &material.comm,
      gens: &material.gens,
      transcript_base: transcript_a.clone(),
      expected_circuit_id: circuit_id,
      expected_invocation_id: invocation_a,
      consumed: false,
    };
    assert!(replay_assembler
      .assemble(&request_a, response_a.clone())
      .is_ok());
    assert!(matches!(
      replay_assembler.assemble(&request_a, response_a),
      Err(SplitExecutionError::SessionConsumed)
    ));
    println!("PHASE5DA negative_consumed_session_replay PASS");
  }

  #[test]
  fn sat_randomness_domain_invocation_and_replay_are_explicit() {
    let root = [0x5a; 32];
    let circuit_id = [0x31; 32];
    let invocation_a = [0x41; 32];
    let invocation_b = [0x42; 32];
    let sat_a = hmac_phase_seed(&root, b"sat", &circuit_id, &invocation_a);
    let eval_a = hmac_phase_seed(&root, b"eval", &circuit_id, &invocation_a);
    let sat_b = hmac_phase_seed(&root, b"sat", &circuit_id, &invocation_b);
    assert_ne!(sat_a, eval_a, "Sat/Eval phase tags must separate seeds");
    assert_ne!(
      sat_a, sat_b,
      "invocation identifier must separate Sat seeds"
    );

    let mut first = RandomTape::from_phase_seed(b"sat_proof", &sat_a);
    let mut replay = RandomTape::from_phase_seed(b"sat_proof", &sat_a);
    let first_bytes: Vec<_> = first
      .random_vector(b"fixed_replay", 4)
      .into_iter()
      .map(|scalar| scalar.to_bytes())
      .collect();
    let replay_bytes: Vec<_> = replay
      .random_vector(b"fixed_replay", 4)
      .into_iter()
      .map(|scalar| scalar.to_bytes())
      .collect();
    assert_eq!(first_bytes, replay_bytes);
  }

  #[test]
  pub fn check_snark() {
    let num_vars = 256;
    let num_cons = num_vars;
    let num_inputs = 10;

    // produce public generators
    let gens = SNARKGens::new(num_cons, num_vars, num_inputs, num_cons);

    // produce a synthetic R1CSInstance
    let (inst, vars, inputs) = Instance::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);

    // create a commitment to R1CSInstance
    let (comm, decomm) = SNARK::encode(&inst, &gens);

    // produce a proof
    let mut prover_transcript = Transcript::new(b"example");
    let proof = SNARK::prove(
      &inst,
      &comm,
      &decomm,
      vars,
      &inputs,
      &gens,
      &mut prover_transcript,
    );

    // verify the proof
    let mut verifier_transcript = Transcript::new(b"example");
    assert!(proof
      .verify(&comm, &inputs, &mut verifier_transcript, &gens)
      .is_ok());
  }

  #[test]
  pub fn check_r1cs_invalid_index() {
    let num_cons = 4;
    let num_vars = 8;
    let num_inputs = 1;

    let zero: [u8; 32] = [
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0,
    ];

    let A = vec![(0, 0, zero)];
    let B = vec![(100, 1, zero)];
    let C = vec![(1, 1, zero)];

    let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C);
    assert!(inst.is_err());
    assert_eq!(inst.err(), Some(R1CSError::InvalidIndex));
  }

  #[test]
  pub fn check_r1cs_invalid_scalar() {
    let num_cons = 4;
    let num_vars = 8;
    let num_inputs = 1;

    let zero: [u8; 32] = [
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0,
    ];

    let larger_than_mod = [
      3, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8, 216,
      57, 51, 72, 125, 157, 41, 83, 167, 237, 115,
    ];

    let A = vec![(0, 0, zero)];
    let B = vec![(1, 1, larger_than_mod)];
    let C = vec![(1, 1, zero)];

    let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C);
    assert!(inst.is_err());
    assert_eq!(inst.err(), Some(R1CSError::InvalidScalar));
  }

  #[test]
  fn test_padded_constraints() {
    // parameters of the R1CS instance
    let num_cons = 1;
    let num_vars = 0;
    let num_inputs = 3;
    let num_non_zero_entries = 3;

    // We will encode the above constraints into three matrices, where
    // the coefficients in the matrix are in the little-endian byte order
    let mut A: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut B: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut C: Vec<(usize, usize, [u8; 32])> = Vec::new();

    // Create a^2 + b + 13
    A.push((0, num_vars + 2, Scalar::one().to_bytes())); // 1*a
    B.push((0, num_vars + 2, Scalar::one().to_bytes())); // 1*a
    C.push((0, num_vars + 1, Scalar::one().to_bytes())); // 1*z
    C.push((0, num_vars, (-Scalar::from(13u64)).to_bytes())); // -13*1
    C.push((0, num_vars + 3, (-Scalar::one()).to_bytes())); // -1*b

    // Var Assignments (Z_0 = 16 is the only output)
    let vars = vec![Scalar::zero().to_bytes(); num_vars];

    // create an InputsAssignment (a = 1, b = 2)
    let mut inputs = vec![Scalar::zero().to_bytes(); num_inputs];
    inputs[0] = Scalar::from(16u64).to_bytes();
    inputs[1] = Scalar::from(1u64).to_bytes();
    inputs[2] = Scalar::from(2u64).to_bytes();

    let assignment_inputs = InputsAssignment::new(&inputs).unwrap();
    let assignment_vars = VarsAssignment::new(&vars).unwrap();

    // Check if instance is satisfiable
    let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();
    let res = inst.is_sat(&assignment_vars, &assignment_inputs);
    assert!(res.unwrap(), "should be satisfied");

    // SNARK public params
    let gens = SNARKGens::new(num_cons, num_vars, num_inputs, num_non_zero_entries);

    // create a commitment to the R1CS instance
    let (comm, decomm) = SNARK::encode(&inst, &gens);

    // produce a SNARK
    let mut prover_transcript = Transcript::new(b"snark_example");
    let proof = SNARK::prove(
      &inst,
      &comm,
      &decomm,
      assignment_vars.clone(),
      &assignment_inputs,
      &gens,
      &mut prover_transcript,
    );

    // verify the SNARK
    let mut verifier_transcript = Transcript::new(b"snark_example");
    assert!(proof
      .verify(&comm, &assignment_inputs, &mut verifier_transcript, &gens)
      .is_ok());

    // NIZK public params
    let gens = NIZKGens::new(num_cons, num_vars, num_inputs);

    // produce a NIZK
    let mut prover_transcript = Transcript::new(b"nizk_example");
    let proof = NIZK::prove(
      &inst,
      assignment_vars,
      &assignment_inputs,
      &gens,
      &mut prover_transcript,
    );

    // verify the NIZK
    let mut verifier_transcript = Transcript::new(b"nizk_example");
    assert!(proof
      .verify(&inst, &assignment_inputs, &mut verifier_transcript, &gens)
      .is_ok());
  }
}
