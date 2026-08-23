//! Prover-only MSM integration hook used by the ThinWallet Phase 3A-R2 experiment.
//!
//! This module does not change proof objects, transcript semantics, or verifier code.

use super::group::{GroupElement, VartimeMultiscalarMul};
use super::scalar::Scalar;
use core::cell::RefCell;
use curve25519_dalek::ristretto::CompressedRistretto;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256, Sha3_512};
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// Explicit warning required for the repetition-code plumbing provider.
pub const INTEGRATION_ONLY_NOT_SECURITY_CLAIM: &str = "INTEGRATION_ONLY_NOT_SECURITY_CLAIM";

/// Provider implementation selected for one prover MSM.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum ProverMsmProviderKind {
  /// The unchanged curve25519-dalek variable-time MSM.
  Native,
  /// Canonically serialize the request and execute it in an isolated worker thread.
  PlainRemote,
  /// Exercise the repetition-code integration data path.
  RepetitionCodeIntegration,
}

/// Binding fields attached to a selected prover MSM request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProverMsmRunConfig {
  /// Provider to invoke for the selected call.
  pub provider: ProverMsmProviderKind,
  /// Stable identifier of the one call selected for replacement.
  pub selected_msm_id: String,
  /// Session identifier.
  pub session_id: String,
  /// Proof identifier.
  pub proof_id: String,
  /// Digest of the application request bound to this proof.
  pub request_digest: String,
}

/// Static and dynamic context for one prover MSM.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProverMsmContext {
  /// Stable call identifier.
  pub msm_id: String,
  /// Parent logical polynomial-commitment identifier.
  pub logical_commitment_id: String,
  /// Zero-based physical chunk index within the parent commitment.
  pub chunk_index: usize,
  /// Transcript phase that receives the resulting commitment.
  pub transcript_phase: String,
  /// SHA3-256 digest of the ordered compressed bases.
  pub basis_digest: String,
  /// Inclusive start of the generator slice used by this physical MSM.
  pub basis_start: usize,
  /// Exclusive end of the generator slice used by this physical MSM.
  pub basis_end: usize,
  /// Whether the scalar vector is witness-dependent.
  pub private_scalars: bool,
  /// Number of scalar/base pairs.
  pub scalar_count: usize,
  /// Whether the resulting blinded chunk point is separately absorbed.
  pub separately_absorbed_into_transcript: bool,
  /// Whether the point is first accumulated into one larger group element.
  pub accumulated_into_larger_commitment: bool,
}

/// Telemetry for the exactly one replaced MSM.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProverMsmCallReport {
  /// Call context.
  pub context: ProverMsmContext,
  /// SHA3-256 digest of the ordered compressed bases.
  pub basis_digest: String,
  /// Session identifier included in the provider request.
  pub session_id: String,
  /// Proof identifier included in the provider request.
  pub proof_id: String,
  /// Application request digest included in the provider request.
  pub request_digest: String,
  /// Provider marker.
  pub provider: String,
  /// Native MSM wall-clock latency.
  pub native_latency_ms: f64,
  /// Selected provider wall-clock latency.
  pub provider_latency_ms: f64,
  /// Serialized request bytes sent to the worker.
  pub upload_bytes: usize,
  /// Serialized compressed point bytes returned by the worker.
  pub download_bytes: usize,
  /// Input scalar bytes.
  pub scalar_bytes: usize,
  /// Input basis bytes.
  pub basis_bytes: usize,
  /// Native and selected provider points were byte-identical before transcript use.
  pub native_result_matches: bool,
  /// Transcript-equivalence check justified by identical pre-transcript point bytes.
  pub transcript_input_matches: bool,
  /// Integration-only warning when applicable.
  pub security_marker: Option<String>,
}

/// Report returned after a scoped prover invocation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProverMsmRunReport {
  /// Number of selected calls actually replaced.
  pub selected_call_count: usize,
  /// Selected call telemetry.
  pub calls: Vec<ProverMsmCallReport>,
}

/// Negative checks for the bound remote request envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemoteBindingNegativeTests {
  /// Honest request accepted.
  pub honest_request_accepted: bool,
  /// Replayed request rejected.
  pub replay_rejected: bool,
  /// Swapped MSM identifier rejected.
  pub swapped_msm_rejected: bool,
  /// Wrong basis digest rejected.
  pub wrong_basis_rejected: bool,
  /// Wrong session rejected.
  pub wrong_session_rejected: bool,
  /// Truncated stream rejected.
  pub truncated_stream_rejected: bool,
  /// Duplicate chunk index rejected.
  pub duplicate_chunk_rejected: bool,
}

struct ActiveRun {
  config: ProverMsmRunConfig,
  report: ProverMsmRunReport,
}

thread_local! {
  static ACTIVE_RUN: RefCell<Option<ActiveRun>> = const { RefCell::new(None) };
  static ACTIVE_AUDIT: RefCell<Option<Vec<ProverMsmContext>>> = const { RefCell::new(None) };
}

/// Trace every physical MSM reached through the dense private commitment path.
pub fn with_prover_msm_audit<T>(f: impl FnOnce() -> T) -> (T, Vec<ProverMsmContext>) {
  ACTIVE_AUDIT.with(|slot| {
    assert!(slot.borrow().is_none(), "nested prover MSM audit scopes");
    *slot.borrow_mut() = Some(Vec::new());
  });
  let output = f();
  let records = ACTIVE_AUDIT.with(|slot| slot.borrow_mut().take().unwrap());
  (output, records)
}

/// Run an unchanged prover API call with a scoped provider selection.
pub fn with_prover_msm_provider<T>(
  config: ProverMsmRunConfig,
  f: impl FnOnce() -> T,
) -> (T, ProverMsmRunReport) {
  ACTIVE_RUN.with(|slot| {
    assert!(slot.borrow().is_none(), "nested prover MSM provider scopes");
    *slot.borrow_mut() = Some(ActiveRun {
      config,
      report: ProverMsmRunReport {
        selected_call_count: 0,
        calls: Vec::new(),
      },
    });
  });
  let output = f();
  let report = ACTIVE_RUN.with(|slot| slot.borrow_mut().take().unwrap().report);
  (output, report)
}

trait ProverMsmProvider {
  fn execute(
    &self,
    context: &ProverMsmContext,
    request: &RemoteMsmRequest,
    scalars: &[Scalar],
    bases: &[GroupElement],
  ) -> Result<ProviderOutput, String>;
}

struct NativeMsmProvider;
struct PlainRemoteMsmProvider;

/// Integration plumbing only. This is not a privacy or malicious-security construction.
struct RepetitionCodeIntegrationMsmProvider;

struct ProviderOutput {
  point: GroupElement,
  upload_bytes: usize,
  download_bytes: usize,
}

#[derive(Clone, Serialize, Deserialize)]
struct ScalarChunk {
  index: usize,
  bytes: Vec<[u8; 32]>,
}

#[derive(Clone, Serialize, Deserialize)]
struct PointChunk {
  index: usize,
  bytes: Vec<[u8; 32]>,
}

#[derive(Clone, Serialize, Deserialize)]
struct RemoteMsmRequest {
  session_id: String,
  proof_id: String,
  msm_id: String,
  basis_digest: String,
  transcript_phase: String,
  private_scalars: bool,
  scalar_count: usize,
  request_digest: String,
  scalar_chunks: Vec<ScalarChunk>,
  point_chunks: Vec<PointChunk>,
  envelope_digest: String,
}

#[derive(Default)]
struct RemoteVerifierState {
  seen: HashSet<String>,
}

static REMOTE_VERIFIER_STATE: OnceLock<Mutex<RemoteVerifierState>> = OnceLock::new();

fn validate_persistent(
  request: &RemoteMsmRequest,
  expected: &RemoteMsmRequest,
) -> Result<(), String> {
  let state = REMOTE_VERIFIER_STATE.get_or_init(|| Mutex::new(RemoteVerifierState::default()));
  let mut guard = state
    .lock()
    .map_err(|_| "remote verifier state poisoned".to_string())?;
  validate_request(&mut guard, request, expected)
}

fn hex(bytes: &[u8]) -> String {
  const DIGITS: &[u8; 16] = b"0123456789abcdef";
  let mut out = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    out.push(DIGITS[(byte >> 4) as usize] as char);
    out.push(DIGITS[(byte & 0x0f) as usize] as char);
  }
  out
}

pub(crate) fn basis_digest(bases: &[GroupElement]) -> String {
  let mut hasher = Sha3_256::new();
  hasher.input(b"thinwallet/libspartan/basis/v1");
  hasher.input(&(bases.len() as u64).to_le_bytes());
  for base in bases {
    hasher.input(base.compress().as_bytes());
  }
  hex(&hasher.result())
}

fn envelope_digest(request: &RemoteMsmRequest) -> String {
  let mut clone = request.clone();
  clone.envelope_digest.clear();
  let encoded = bincode::serialize(&clone).expect("serialize remote MSM request");
  let mut hasher = Sha3_256::new();
  hasher.input(b"thinwallet/libspartan/remote-msm-envelope/v1");
  hasher.input(&encoded);
  hex(&hasher.result())
}

fn chunks_complete<T>(chunks: &[(usize, T)], expected_items: usize, lengths: &[usize]) -> bool {
  if chunks.len() != lengths.len() {
    return false;
  }
  let mut seen = HashSet::new();
  let mut total = 0usize;
  for ((index, _), length) in chunks.iter().zip(lengths) {
    if !seen.insert(*index) || *index >= chunks.len() {
      return false;
    }
    total += length;
  }
  total == expected_items && seen.len() == chunks.len()
}

fn validate_request(
  state: &mut RemoteVerifierState,
  request: &RemoteMsmRequest,
  expected: &RemoteMsmRequest,
) -> Result<(), String> {
  if request.envelope_digest != envelope_digest(request) {
    return Err("request envelope digest mismatch".to_string());
  }
  if request.session_id != expected.session_id {
    return Err("wrong session".to_string());
  }
  if request.proof_id != expected.proof_id {
    return Err("wrong proof".to_string());
  }
  if request.msm_id != expected.msm_id {
    return Err("swapped MSM".to_string());
  }
  if request.basis_digest != expected.basis_digest {
    return Err("wrong basis".to_string());
  }
  if request.transcript_phase != expected.transcript_phase
    || request.scalar_count != expected.scalar_count
    || request.request_digest != expected.request_digest
  {
    return Err("wrong request binding".to_string());
  }
  let scalar_pairs: Vec<_> = request
    .scalar_chunks
    .iter()
    .map(|chunk| (chunk.index, ()))
    .collect();
  let scalar_lengths: Vec<_> = request
    .scalar_chunks
    .iter()
    .map(|chunk| chunk.bytes.len())
    .collect();
  let point_pairs: Vec<_> = request
    .point_chunks
    .iter()
    .map(|chunk| (chunk.index, ()))
    .collect();
  let point_lengths: Vec<_> = request
    .point_chunks
    .iter()
    .map(|chunk| chunk.bytes.len())
    .collect();
  if !chunks_complete(&scalar_pairs, request.scalar_count, &scalar_lengths)
    || !chunks_complete(&point_pairs, request.scalar_count, &point_lengths)
  {
    return Err("truncated or duplicate chunk stream".to_string());
  }
  if !state.seen.insert(request.envelope_digest.clone()) {
    return Err("replayed result".to_string());
  }
  Ok(())
}

fn request_for(
  config: &ProverMsmRunConfig,
  context: &ProverMsmContext,
  scalars: &[Scalar],
  bases: &[GroupElement],
) -> RemoteMsmRequest {
  let scalar_chunks = scalars
    .chunks(256)
    .enumerate()
    .map(|(index, chunk)| ScalarChunk {
      index,
      bytes: chunk.iter().map(Scalar::to_bytes).collect(),
    })
    .collect();
  let point_chunks = bases
    .chunks(256)
    .enumerate()
    .map(|(index, chunk)| PointChunk {
      index,
      bytes: chunk
        .iter()
        .map(|point| point.compress().to_bytes())
        .collect(),
    })
    .collect();
  let mut request = RemoteMsmRequest {
    session_id: config.session_id.clone(),
    proof_id: config.proof_id.clone(),
    msm_id: context.msm_id.clone(),
    basis_digest: context.basis_digest.clone(),
    transcript_phase: context.transcript_phase.clone(),
    private_scalars: context.private_scalars,
    scalar_count: context.scalar_count,
    request_digest: config.request_digest.clone(),
    scalar_chunks,
    point_chunks,
    envelope_digest: String::new(),
  };
  request.envelope_digest = envelope_digest(&request);
  request
}

fn decode_request(request: &RemoteMsmRequest) -> Result<(Vec<Scalar>, Vec<GroupElement>), String> {
  let mut scalars = Vec::with_capacity(request.scalar_count);
  for chunk in &request.scalar_chunks {
    for bytes in &chunk.bytes {
      let scalar = Scalar::from_bytes(bytes);
      if scalar.is_none().unwrap_u8() == 1 {
        return Err("non-canonical scalar".to_string());
      }
      scalars.push(scalar.unwrap());
    }
  }
  let mut points = Vec::with_capacity(request.scalar_count);
  for chunk in &request.point_chunks {
    for bytes in &chunk.bytes {
      let point = CompressedRistretto(*bytes)
        .decompress()
        .ok_or_else(|| "invalid compressed Ristretto point".to_string())?;
      points.push(point);
    }
  }
  Ok((scalars, points))
}

fn native_msm(scalars: &[Scalar], bases: &[GroupElement]) -> GroupElement {
  GroupElement::vartime_multiscalar_mul(scalars, bases)
}

impl ProverMsmProvider for NativeMsmProvider {
  fn execute(
    &self,
    _context: &ProverMsmContext,
    _request: &RemoteMsmRequest,
    scalars: &[Scalar],
    bases: &[GroupElement],
  ) -> Result<ProviderOutput, String> {
    Ok(ProviderOutput {
      point: native_msm(scalars, bases),
      upload_bytes: 0,
      download_bytes: 0,
    })
  }
}

impl ProverMsmProvider for PlainRemoteMsmProvider {
  fn execute(
    &self,
    _context: &ProverMsmContext,
    request: &RemoteMsmRequest,
    _scalars: &[Scalar],
    _bases: &[GroupElement],
  ) -> Result<ProviderOutput, String> {
    let encoded = bincode::serialize(request).map_err(|err| err.to_string())?;
    let upload_bytes = encoded.len();
    let expected = request.clone();
    let handle = std::thread::spawn(move || -> Result<[u8; 32], String> {
      let decoded: RemoteMsmRequest =
        bincode::deserialize(&encoded).map_err(|err| err.to_string())?;
      validate_persistent(&decoded, &expected)?;
      let (scalars, bases) = decode_request(&decoded)?;
      Ok(native_msm(&scalars, &bases).compress().to_bytes())
    });
    let bytes = handle
      .join()
      .map_err(|_| "remote worker panicked".to_string())??;
    let point = CompressedRistretto(bytes)
      .decompress()
      .ok_or_else(|| "remote worker returned invalid point".to_string())?;
    Ok(ProviderOutput {
      point,
      upload_bytes,
      download_bytes: bytes.len(),
    })
  }
}

fn integration_masks(request: &RemoteMsmRequest, index: usize) -> [Scalar; 3] {
  let mut output = [Scalar::zero(); 3];
  for (lane, value) in output.iter_mut().enumerate() {
    let mut hasher = Sha3_512::new();
    hasher.input(INTEGRATION_ONLY_NOT_SECURITY_CLAIM.as_bytes());
    hasher.input(request.envelope_digest.as_bytes());
    hasher.input(&(index as u64).to_le_bytes());
    hasher.input(&(lane as u64).to_le_bytes());
    let digest = hasher.result();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    *value = Scalar::from_bytes_wide(&wide);
  }
  output
}

impl ProverMsmProvider for RepetitionCodeIntegrationMsmProvider {
  fn execute(
    &self,
    _context: &ProverMsmContext,
    request: &RemoteMsmRequest,
    scalars: &[Scalar],
    bases: &[GroupElement],
  ) -> Result<ProviderOutput, String> {
    let mut encoded_scalars = Vec::with_capacity(scalars.len() * 4);
    let mut encoded_bases = Vec::with_capacity(bases.len() * 4);
    for (index, (scalar, base)) in scalars.iter().zip(bases).enumerate() {
      let masks = integration_masks(request, index);
      encoded_scalars.extend_from_slice(&[
        masks[0],
        masks[1],
        masks[2],
        *scalar - masks[0] - masks[1] - masks[2],
      ]);
      encoded_bases.extend_from_slice(&[*base; 4]);
    }
    let encoded_request = request_for(
      &ProverMsmRunConfig {
        provider: ProverMsmProviderKind::RepetitionCodeIntegration,
        selected_msm_id: request.msm_id.clone(),
        session_id: request.session_id.clone(),
        proof_id: request.proof_id.clone(),
        request_digest: request.request_digest.clone(),
      },
      &ProverMsmContext {
        msm_id: request.msm_id.clone(),
        logical_commitment_id: request.msm_id.clone(),
        chunk_index: 0,
        transcript_phase: request.transcript_phase.clone(),
        basis_digest: basis_digest(&encoded_bases),
        basis_start: 0,
        basis_end: encoded_bases.len(),
        private_scalars: request.private_scalars,
        scalar_count: encoded_scalars.len(),
        separately_absorbed_into_transcript: false,
        accumulated_into_larger_commitment: false,
      },
      &encoded_scalars,
      &encoded_bases,
    );
    let encoded = bincode::serialize(&encoded_request).map_err(|err| err.to_string())?;
    let upload_bytes = encoded.len();
    let expected = encoded_request.clone();
    let handle = std::thread::spawn(move || -> Result<[u8; 32], String> {
      let decoded: RemoteMsmRequest =
        bincode::deserialize(&encoded).map_err(|err| err.to_string())?;
      validate_persistent(&decoded, &expected)?;
      let (scalars, bases) = decode_request(&decoded)?;
      Ok(native_msm(&scalars, &bases).compress().to_bytes())
    });
    let bytes = handle
      .join()
      .map_err(|_| "integration worker panicked".to_string())??;
    let point = CompressedRistretto(bytes)
      .decompress()
      .ok_or_else(|| "integration worker returned invalid point".to_string())?;
    Ok(ProviderOutput {
      point,
      upload_bytes,
      download_bytes: bytes.len(),
    })
  }
}

/// Execute a prover MSM, routing exactly the configured call through its provider.
pub(crate) fn prover_msm(
  context: &ProverMsmContext,
  scalars: &[Scalar],
  bases: &[GroupElement],
) -> GroupElement {
  assert_eq!(context.scalar_count, scalars.len());
  assert_eq!(scalars.len(), bases.len());
  let native_start = Instant::now();
  let native = native_msm(scalars, bases);
  let native_latency_ms = native_start.elapsed().as_secs_f64() * 1000.0;

  if context.private_scalars {
    ACTIVE_AUDIT.with(|slot| {
      if let Some(records) = slot.borrow_mut().as_mut() {
        records.push(context.clone());
      }
    });
  }

  ACTIVE_RUN.with(|slot| {
    let mut active = slot.borrow_mut();
    let Some(active) = active.as_mut() else {
      return native;
    };
    if context.msm_id != active.config.selected_msm_id || !context.private_scalars {
      return native;
    }
    active.report.selected_call_count += 1;
    assert_eq!(
      active.report.selected_call_count, 1,
      "selected more than one MSM"
    );
    let request = request_for(&active.config, context, scalars, bases);
    let provider: Box<dyn ProverMsmProvider> = match active.config.provider {
      ProverMsmProviderKind::Native => Box::new(NativeMsmProvider),
      ProverMsmProviderKind::PlainRemote => Box::new(PlainRemoteMsmProvider),
      ProverMsmProviderKind::RepetitionCodeIntegration => {
        Box::new(RepetitionCodeIntegrationMsmProvider)
      }
    };
    let provider_start = Instant::now();
    let output = provider
      .execute(context, &request, scalars, bases)
      .expect("selected prover MSM provider failed");
    let provider_latency_ms = provider_start.elapsed().as_secs_f64() * 1000.0;
    let native_result_matches = native.compress().to_bytes() == output.point.compress().to_bytes();
    assert!(
      native_result_matches,
      "provider returned a different MSM point"
    );
    active.report.calls.push(ProverMsmCallReport {
      context: context.clone(),
      basis_digest: request.basis_digest,
      session_id: request.session_id,
      proof_id: request.proof_id,
      request_digest: request.request_digest,
      provider: format!("{:?}", active.config.provider),
      native_latency_ms,
      provider_latency_ms,
      upload_bytes: output.upload_bytes,
      download_bytes: output.download_bytes,
      scalar_bytes: scalars.len() * 32,
      basis_bytes: bases.len() * 32,
      native_result_matches,
      transcript_input_matches: native_result_matches,
      security_marker: match active.config.provider {
        ProverMsmProviderKind::RepetitionCodeIntegration => {
          Some(INTEGRATION_ONLY_NOT_SECURITY_CLAIM.to_string())
        }
        _ => None,
      },
    });
    output.point
  })
}

fn sample_request() -> RemoteMsmRequest {
  let scalars = vec![Scalar::one(), Scalar::from(2u64)];
  let bases = vec![
    curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT,
    curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT
      * curve25519_dalek::scalar::Scalar::from(7u64),
  ];
  request_for(
    &ProverMsmRunConfig {
      provider: ProverMsmProviderKind::PlainRemote,
      selected_msm_id: "negative-test-msm".to_string(),
      session_id: "negative-test-session".to_string(),
      proof_id: "negative-test-proof".to_string(),
      request_digest: "negative-test-request".to_string(),
    },
    &ProverMsmContext {
      msm_id: "negative-test-msm".to_string(),
      logical_commitment_id: "negative-test-logical-commitment".to_string(),
      chunk_index: 0,
      transcript_phase: "negative-test-phase".to_string(),
      basis_digest: basis_digest(&bases),
      basis_start: 0,
      basis_end: bases.len(),
      private_scalars: true,
      scalar_count: scalars.len(),
      separately_absorbed_into_transcript: true,
      accumulated_into_larger_commitment: false,
    },
    &scalars,
    &bases,
  )
}

fn resign(request: &mut RemoteMsmRequest) {
  request.envelope_digest = envelope_digest(request);
}

/// Run binding failures against the same validation logic as the remote worker.
pub fn remote_binding_negative_tests() -> RemoteBindingNegativeTests {
  let honest = sample_request();
  let mut state = RemoteVerifierState::default();
  let honest_request_accepted = validate_request(&mut state, &honest, &honest).is_ok();
  let replay_rejected = validate_request(&mut state, &honest, &honest).is_err();

  let mut swapped = honest.clone();
  swapped.msm_id = "other-msm".to_string();
  resign(&mut swapped);
  let swapped_msm_rejected =
    validate_request(&mut RemoteVerifierState::default(), &swapped, &honest).is_err();

  let mut wrong_basis = honest.clone();
  wrong_basis.basis_digest = "wrong-basis".to_string();
  resign(&mut wrong_basis);
  let wrong_basis_rejected =
    validate_request(&mut RemoteVerifierState::default(), &wrong_basis, &honest).is_err();

  let mut wrong_session = honest.clone();
  wrong_session.session_id = "wrong-session".to_string();
  resign(&mut wrong_session);
  let wrong_session_rejected =
    validate_request(&mut RemoteVerifierState::default(), &wrong_session, &honest).is_err();

  let mut truncated = honest.clone();
  truncated.scalar_chunks[0].bytes.pop();
  resign(&mut truncated);
  let truncated_stream_rejected =
    validate_request(&mut RemoteVerifierState::default(), &truncated, &honest).is_err();

  let mut duplicate = honest.clone();
  let copy = duplicate.scalar_chunks[0].clone();
  duplicate.scalar_chunks.push(copy);
  resign(&mut duplicate);
  let duplicate_chunk_rejected =
    validate_request(&mut RemoteVerifierState::default(), &duplicate, &honest).is_err();

  RemoteBindingNegativeTests {
    honest_request_accepted,
    replay_rejected,
    swapped_msm_rejected,
    wrong_basis_rejected,
    wrong_session_rejected,
    truncated_stream_rejected,
    duplicate_chunk_rejected,
  }
}
