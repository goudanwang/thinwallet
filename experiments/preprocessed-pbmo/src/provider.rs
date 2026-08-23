use crate::field::{derive_batch_challenge, derive_mask_scalar, digest32};
use crate::secure_spool::{SecureSpool, SpoolDescriptor};
use crate::token::{Token, TokenState};
use crate::transport::{
    PbmoTransport, TransportChunk, TransportMetrics, TransportRequestHeader, CURVE_IDENTIFIER,
    INTEGRITY_HMAC_SHA256, WIRE_PROTOCOL_VERSION,
};
use crate::{GroupElement, Scalar};
use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PbmoError {
    #[error("invalid context: {0}")]
    Context(String),
    #[error("invalid stream: {0}")]
    Stream(String),
    #[error("token error: {0}")]
    Token(String),
    #[error("server integrity check failed")]
    Integrity,
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("transport error: {0}")]
    Transport(#[from] crate::transport::PbmoTransportError),
}

pub type Result<T> = std::result::Result<T, PbmoError>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PbmoContext {
    pub protocol_version: u16,
    pub session_id: String,
    pub proof_id: String,
    pub token_id: Option<[u8; 16]>,
    pub logical_commitment_id: String,
    pub basis_digest: [u8; 32],
    pub backend_revision: String,
    pub relation_shape: String,
    pub expected_chunks: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PbmoProviderKind {
    NativeLocal,
    PlainRemote,
    PreprocessedSemihonest,
    PreprocessedMalicious,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PbmoMetrics {
    pub provider: String,
    pub q: usize,
    pub m: usize,
    pub chunks: usize,
    pub upload_bytes: usize,
    pub download_bytes: usize,
    pub basis_upload_bytes: usize,
    pub client_mask_field_ops: u64,
    pub client_recovery_point_ops: u64,
    pub server_group_terms: u64,
    pub aggregate_field_ops: u64,
    pub aggregate_point_ops: u64,
    pub local_check_msm_terms: u64,
    pub server_msm_ms: f64,
    pub masking_ms: f64,
    pub recovery_ms: f64,
    pub batch_check_ms: f64,
    pub working_scalar_peak: usize,
    pub spool_bytes_written: u64,
    pub spool_bytes_read: u64,
    pub outputs_bound_before_challenge: bool,
    pub soundness_bound: Option<String>,
    pub token_final_state: Option<String>,
    pub durable_reservation_observed: bool,
    pub transport_metrics: Option<TransportMetrics>,
}

#[derive(Serialize, Deserialize)]
struct StreamFrame {
    context_digest: [u8; 32],
    row: u32,
    col_start: u32,
    col_end: u32,
    scalars: Vec<[u8; 32]>,
}

#[derive(Debug)]
struct ServerState {
    accumulators: Vec<GroupElement>,
    next_col: Vec<usize>,
}

#[derive(Debug)]
enum SessionMode {
    Native,
    Plain,
    Semi {
        token: Token,
    },
    Malicious {
        token: Token,
        spool: Box<SecureSpool>,
    },
}

pub struct PbmoSession {
    context: PbmoContext,
    q: usize,
    m: usize,
    bases: Vec<GroupElement>,
    mode: SessionMode,
    server: ServerState,
    metrics: PbmoMetrics,
    transport: Option<Box<dyn PbmoTransport>>,
    first_masked_marker_emitted: bool,
    upload_marker_emitted: bool,
    finalized: bool,
}

impl PbmoSession {
    pub fn metrics(&self) -> &PbmoMetrics {
        &self.metrics
    }

    fn is_preprocessed(&self) -> bool {
        matches!(
            self.mode,
            SessionMode::Semi { .. } | SessionMode::Malicious { .. }
        )
    }

    fn token(&self) -> Option<&Token> {
        match &self.mode {
            SessionMode::Semi { token } | SessionMode::Malicious { token, .. } => Some(token),
            _ => None,
        }
    }

    fn token_mut(&mut self) -> Option<&mut Token> {
        match &mut self.mode {
            SessionMode::Semi { token } | SessionMode::Malicious { token, .. } => Some(token),
            _ => None,
        }
    }
}

impl Drop for PbmoSession {
    fn drop(&mut self) {
        if !self.finalized {
            if let Some(transport) = self.transport.as_mut() {
                let _ = transport.abort_session("client session dropped before finalization");
            }
            if let Some(token) = self.token_mut() {
                if token.state == TokenState::Reserved {
                    token.state = TokenState::Burned;
                }
            }
            if let SessionMode::Malicious { spool, .. } = &mut self.mode {
                #[cfg(feature = "thinwallet-experiment")]
                thinwallet_instrumentation::record_artifact_remove(&spool.active_path());
                let _ = spool.remove();
            }
        }
    }
}

/// Proof-system-independent q-output MSM streaming interface.
pub trait PreprocessedPbmoProvider {
    fn begin(&mut self, context: PbmoContext, q: usize, m: usize) -> Result<PbmoSession>;

    fn push_private_row_chunk(
        &mut self,
        session: &mut PbmoSession,
        row: usize,
        col_range: Range<usize>,
        private_scalars: &[Scalar],
    ) -> Result<()>;

    fn finalize(&mut self, session: PbmoSession) -> Result<Vec<GroupElement>>;

    fn last_metrics(&self) -> Option<&PbmoMetrics>;
}

pub struct NativeLocalPbmoProvider {
    bases: Vec<GroupElement>,
    last_metrics: Option<PbmoMetrics>,
}

pub struct PlainRemotePbmoProvider {
    bases: Vec<GroupElement>,
    last_metrics: Option<PbmoMetrics>,
}

pub struct PreprocessedSemihonestPbmoProvider {
    bases: Vec<GroupElement>,
    token: Option<Token>,
    last_metrics: Option<PbmoMetrics>,
    transport: Option<Box<dyn PbmoTransport>>,
}

pub struct PreprocessedMaliciousPbmoProvider {
    bases: Vec<GroupElement>,
    token: Option<Token>,
    corruption: Option<Corruption>,
    last_metrics: Option<PbmoMetrics>,
    transport: Option<Box<dyn PbmoTransport>>,
}

#[derive(Clone, Copy, Debug)]
pub enum Corruption {
    OneOutput,
    CorrelatedOutputs,
    Reorder,
    Omit,
    Duplicate,
    AfterChallenge,
    ReplayedVector,
    CrossSessionSwap,
}

impl NativeLocalPbmoProvider {
    pub fn new(bases: Vec<GroupElement>) -> Self {
        Self {
            bases,
            last_metrics: None,
        }
    }
}

impl PlainRemotePbmoProvider {
    pub fn new(bases: Vec<GroupElement>) -> Self {
        Self {
            bases,
            last_metrics: None,
        }
    }
}

impl PreprocessedSemihonestPbmoProvider {
    pub fn new(bases: Vec<GroupElement>, token: Token) -> Self {
        Self {
            bases,
            token: Some(token),
            last_metrics: None,
            transport: None,
        }
    }

    pub fn new_with_transport(
        bases: Vec<GroupElement>,
        token: Token,
        transport: Box<dyn PbmoTransport>,
    ) -> Self {
        Self {
            bases,
            token: Some(token),
            last_metrics: None,
            transport: Some(transport),
        }
    }
}

impl PreprocessedMaliciousPbmoProvider {
    pub fn new(bases: Vec<GroupElement>, token: Token) -> Self {
        Self {
            bases,
            token: Some(token),
            corruption: None,
            last_metrics: None,
            transport: None,
        }
    }

    pub fn new_with_transport(
        bases: Vec<GroupElement>,
        token: Token,
        transport: Box<dyn PbmoTransport>,
    ) -> Self {
        Self {
            bases,
            token: Some(token),
            corruption: None,
            last_metrics: None,
            transport: Some(transport),
        }
    }

    pub fn with_corruption(mut self, corruption: Corruption) -> Self {
        self.corruption = Some(corruption);
        self
    }
}

pub fn context_binding_digest(context: &PbmoContext, q: usize, m: usize) -> Result<[u8; 32]> {
    let encoded = bincode::serialize(&(context, q, m))
        .map_err(|e| PbmoError::Serialization(e.to_string()))?;
    Ok(digest32(
        b"thinwallet/preprocessed-pbmo/stream-context/v2",
        &[&encoded],
    ))
}

fn start_session(
    context: PbmoContext,
    q: usize,
    m: usize,
    bases: &[GroupElement],
    mode: SessionMode,
    provider: &str,
    transport: Option<Box<dyn PbmoTransport>>,
) -> Result<PbmoSession> {
    if q == 0 || m == 0 || bases.len() != m || context.expected_chunks == 0 {
        return Err(PbmoError::Context("invalid dimensions".into()));
    }
    if context.basis_digest != crate::token::basis_digest(bases) {
        return Err(PbmoError::Context("wrong basis".into()));
    }
    if let SessionMode::Semi { token } | SessionMode::Malicious { token, .. } = &mode {
        let encoded_shape = format!(
            "{}:{}",
            token.binding.relation_shape.relation_id, token.binding.relation_shape.layout_version
        );
        if token.binding.basis_digest != context.basis_digest
            || token.binding.backend_revision != context.backend_revision
            || token.binding.relation_shape.logical_commitment_id != context.logical_commitment_id
            || encoded_shape != context.relation_shape
            || token.binding.q != q as u32
            || token.binding.m != m as u32
        {
            return Err(PbmoError::Token("token relation binding mismatch".into()));
        }
        if context.token_id != Some(token.token_id) || token.state != TokenState::Reserved {
            return Err(PbmoError::Token("token was not durably reserved".into()));
        }
        let reservation = token
            .reservation_binding()
            .ok_or_else(|| PbmoError::Token("missing durable reservation binding".into()))?;
        if reservation.ctx_digest != token.binding.context_digest()
            || reservation.sid != context.proof_id
            || reservation.iid != context.session_id
            || reservation.request_digest != context_binding_digest(&context, q, m)?
        {
            return Err(PbmoError::Token(
                "PBMO context differs from durable reservation".into(),
            ));
        }
    }
    let mut session = PbmoSession {
        context,
        q,
        m,
        bases: bases.to_vec(),
        mode,
        server: ServerState {
            accumulators: vec![GroupElement::identity(); q],
            next_col: vec![0; q],
        },
        metrics: PbmoMetrics {
            provider: provider.into(),
            q,
            m,
            basis_upload_bytes: 0,
            ..PbmoMetrics::default()
        },
        transport,
        first_masked_marker_emitted: false,
        upload_marker_emitted: false,
        finalized: false,
    };
    #[cfg(feature = "thinwallet-experiment")]
    match &session.mode {
        SessionMode::Native => {
            thinwallet_instrumentation::increment_counter("native_commitment_calls", 1);
            thinwallet_instrumentation::increment_counter("native_commitment_rows", q as u64);
        }
        SessionMode::Semi { .. } | SessionMode::Malicious { .. } => {
            thinwallet_instrumentation::increment_counter("pbmo_sessions_started", 1);
        }
        SessionMode::Plain => {}
    }
    session.metrics.durable_reservation_observed = session.token().is_some();
    if let Some(transport) = session.transport.as_mut() {
        #[cfg(feature = "thinwallet-experiment")]
        let _upload_phase = thinwallet_instrumentation::PhaseGuard::begin("pbmo_upload");
        let session_digest = context_binding_digest(&session.context, q, m)?;
        transport.reserve_session(session_digest)?;
        transport.send_request_header(&TransportRequestHeader {
            protocol_version: WIRE_PROTOCOL_VERSION,
            backend_revision: session.context.backend_revision.clone(),
            curve_identifier: CURVE_IDENTIFIER.into(),
            basis_digest: session.context.basis_digest,
            q: q as u32,
            m: m as u32,
            output_count: q as u32,
            token_session_digest: session_digest,
            workload_identifier: session.context.relation_shape.clone(),
            expected_scalar_count: (q * m) as u64,
            request_byte_length: (q * m * 32) as u64,
            integrity_mode: INTEGRITY_HMAC_SHA256.into(),
            nonce_challenge_context: digest32(
                b"thinwallet/pbmo-transport/nonce-context/v1",
                &[
                    session.context.session_id.as_bytes(),
                    session.context.proof_id.as_bytes(),
                ],
            ),
            expected_chunk_count: session.context.expected_chunks,
        })?;
    }
    Ok(session)
}

fn push_chunk(
    session: &mut PbmoSession,
    row: usize,
    col_range: Range<usize>,
    private_scalars: &[Scalar],
) -> Result<()> {
    if row >= session.q
        || col_range.start != session.server.next_col[row]
        || col_range.end > session.m
        || col_range.end - col_range.start != private_scalars.len()
    {
        return Err(PbmoError::Stream(
            "out-of-order or malformed row chunk".into(),
        ));
    }
    let start = Instant::now();
    if !session.first_masked_marker_emitted {
        emit_phase_marker("BEFORE_FIRST_MASKED_BYTE", session.metrics.chunks as u64)?;
        session.first_masked_marker_emitted = true;
    }
    let mut wire_scalars = Vec::with_capacity(private_scalars.len());
    if session.is_preprocessed() {
        #[cfg(feature = "thinwallet-experiment")]
        let _mask_phase = thinwallet_instrumentation::PhaseGuard::begin("pbmo_mask_generation");
        let token = session.token().unwrap();
        let meta = token.binding.domain_metadata(token.token_id);
        for (offset, scalar) in private_scalars.iter().enumerate() {
            let col = col_range.start + offset;
            wire_scalars
                .push(*scalar + derive_mask_scalar(token.seed(), &meta, row as u32, col as u32, 0));
        }
        session.metrics.client_mask_field_ops += private_scalars.len() as u64;
    } else {
        wire_scalars.extend_from_slice(private_scalars);
    }
    session.metrics.masking_ms += start.elapsed().as_secs_f64() * 1000.0;
    session.metrics.working_scalar_peak =
        session.metrics.working_scalar_peak.max(wire_scalars.len());

    if let SessionMode::Malicious { spool, .. } = &mut session.mode {
        #[cfg(feature = "thinwallet-experiment")]
        let _spool_phase = thinwallet_instrumentation::PhaseGuard::begin("pbmo_request_spool");
        #[cfg(feature = "thinwallet-experiment")]
        thinwallet_instrumentation::register_temp_artifact(
            &spool.active_path(),
            "pbmo_request_spool",
        );
        let encoded: Vec<[u8; 32]> = wire_scalars.iter().map(Scalar::to_bytes).collect();
        spool.append(&encoded)?;
        session.metrics.spool_bytes_written += (encoded.len() * 32) as u64;
        #[cfg(feature = "thinwallet-experiment")]
        thinwallet_instrumentation::record_artifact_write(
            &spool.active_path(),
            (wire_scalars.len() * 32) as u64,
        );
    }

    let frame = StreamFrame {
        context_digest: context_binding_digest(&session.context, session.q, session.m)?,
        row: row as u32,
        col_start: col_range.start as u32,
        col_end: col_range.end as u32,
        scalars: wire_scalars.iter().map(Scalar::to_bytes).collect(),
    };
    if session.transport.is_none() && !matches!(session.mode, SessionMode::Native) {
        let encoded =
            bincode::serialize(&frame).map_err(|e| PbmoError::Serialization(e.to_string()))?;
        session.metrics.upload_bytes += encoded.len();
        let decoded: StreamFrame =
            bincode::deserialize(&encoded).map_err(|e| PbmoError::Serialization(e.to_string()))?;
        if decoded.context_digest != context_binding_digest(&session.context, session.q, session.m)?
            || decoded.row as usize != row
            || decoded.col_start as usize != col_range.start
            || decoded.col_end as usize != col_range.end
        {
            return Err(PbmoError::Stream("frame binding mismatch".into()));
        }
    }
    if let Some(transport) = session.transport.as_mut() {
        #[cfg(feature = "thinwallet-experiment")]
        let _upload_phase = thinwallet_instrumentation::PhaseGuard::begin("pbmo_upload");
        transport.send_masked_chunk(&TransportChunk {
            chunk_index: session.metrics.chunks as u32,
            total_chunks: session.context.expected_chunks,
            row: row as u32,
            col_start: col_range.start as u32,
            col_end: col_range.end as u32,
            scalars: frame.scalars,
        })?;
    } else {
        let server_start = Instant::now();
        #[cfg(feature = "thinwallet-experiment")]
        let native_row_cpu_start = thinwallet_instrumentation::process_cpu_time_ns();
        let chunk_point =
            GroupElement::vartime_multiscalar_mul(&wire_scalars, &session.bases[col_range.clone()]);
        #[cfg(feature = "thinwallet-experiment")]
        if matches!(session.mode, SessionMode::Native) {
            thinwallet_instrumentation::record_native_row_msm_physical_call(
                "preprocessed_pbmo.provider.push_chunk.native_local",
                row,
                col_range.start,
                col_range.end,
                wire_scalars.len(),
                server_start.elapsed().as_nanos() as u64,
                thinwallet_instrumentation::process_cpu_time_ns()
                    .saturating_sub(native_row_cpu_start),
                session.q,
                session.m,
            );
            if col_range.end == session.m {
                thinwallet_instrumentation::record_native_row_msm_logical_row(session.m);
            }
        }
        session.server.accumulators[row] += chunk_point;
        session.metrics.server_msm_ms += server_start.elapsed().as_secs_f64() * 1000.0;
    }
    session.metrics.server_group_terms += wire_scalars.len() as u64;
    session.server.next_col[row] = col_range.end;
    #[cfg(feature = "thinwallet-experiment")]
    if session.is_preprocessed() && col_range.end == session.m {
        thinwallet_instrumentation::increment_counter("pbmo_rows_uploaded", 1);
    }
    session.metrics.chunks += 1;
    let completed_scalars = session.server.next_col.iter().sum::<usize>();
    let upload_percent = std::env::var("THINWALLET_MARKER_UPLOAD_PERCENT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(50);
    if !session.upload_marker_emitted
        && completed_scalars.saturating_mul(100) >= session.q * session.m * upload_percent
    {
        emit_phase_marker("DURING_UPLOAD", completed_scalars as u64)?;
        session.upload_marker_emitted = true;
    }
    Ok(())
}

fn emit_phase_marker(name: &str, progress: u64) -> Result<()> {
    let Some(path) = std::env::var_os("THINWALLET_PHASE_MARKER_PATH") else {
        return Ok(());
    };
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let (rss_kib, hwm_kib) = self_memory_kib();
    writeln!(
        file,
        "{name}\t{progress}\t{}\t{}",
        rss_kib.map_or_else(|| "null".into(), |value| value.to_string()),
        hwm_kib.map_or_else(|| "null".into(), |value| value.to_string())
    )?;
    file.sync_all()?;
    if std::env::var("THINWALLET_KILL_AT_MARKER").as_deref() == Ok(name) {
        let pause_ms = std::env::var("THINWALLET_MARKER_PAUSE_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(15_000);
        std::thread::sleep(std::time::Duration::from_millis(pause_ms));
    }
    Ok(())
}

fn self_memory_kib() -> (Option<u64>, Option<u64>) {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return (None, None);
    };
    let value = |name: &str| {
        status.lines().find_map(|line| {
            let rest = line.strip_prefix(name)?;
            rest.split_whitespace().next()?.parse::<u64>().ok()
        })
    };
    (value("VmRSS:"), value("VmHWM:"))
}

fn output_digest(context: &PbmoContext, outputs: &[GroupElement]) -> Result<[u8; 32]> {
    let context_bytes =
        bincode::serialize(context).map_err(|e| PbmoError::Serialization(e.to_string()))?;
    let points: Vec<_> = outputs
        .iter()
        .flat_map(|p| p.compress().to_bytes())
        .collect();
    Ok(digest32(
        b"thinwallet/preprocessed-pbmo/ordered-outputs/v2",
        &[&context_bytes, &points],
    ))
}

fn finish(
    mut session: PbmoSession,
    corruption: Option<Corruption>,
) -> Result<(Vec<GroupElement>, PbmoMetrics)> {
    if session.server.next_col.iter().any(|col| *col != session.m) {
        if let Some(token) = session.token_mut() {
            token.state = TokenState::Burned;
        }
        return Err(PbmoError::Stream("omitted row data".into()));
    }
    let mut outputs = if let Some(transport) = session.transport.as_mut() {
        emit_phase_marker("AFTER_UPLOAD", session.metrics.chunks as u64)?;
        transport.finish_request()?;
        emit_phase_marker("WAITING_FOR_RESPONSE", session.metrics.chunks as u64)?;
        #[cfg(feature = "thinwallet-experiment")]
        let wait_phase = thinwallet_instrumentation::PhaseGuard::begin("pbmo_server_wait");
        let response = transport.receive_response()?;
        #[cfg(feature = "thinwallet-experiment")]
        drop(wait_phase);
        emit_phase_marker("AFTER_RESPONSE", response.points.len() as u64)?;
        if response.points.len() != session.q {
            return Err(PbmoError::Stream(
                "transport returned wrong output count".into(),
            ));
        }
        let transport_metrics = transport.metrics().clone();
        session.metrics.upload_bytes = transport_metrics.request_bytes as usize;
        session.metrics.download_bytes = transport_metrics.response_bytes as usize;
        session.metrics.server_msm_ms = response.server_msm_ms;
        session.metrics.transport_metrics = Some(transport_metrics);
        #[cfg(feature = "thinwallet-experiment")]
        {
            thinwallet_instrumentation::add_network_bytes(
                session.metrics.upload_bytes as u64,
                session.metrics.download_bytes as u64,
            );
            thinwallet_instrumentation::increment_counter(
                "pbmo_server_outputs_received",
                response.points.len() as u64,
            );
        }
        response.points
    } else {
        session.server.accumulators.clone()
    };
    match corruption {
        Some(Corruption::OneOutput) => outputs[0] += session.bases[0],
        Some(Corruption::CorrelatedOutputs) if outputs.len() > 1 => {
            outputs[0] += session.bases[0];
            outputs[1] -= session.bases[0];
        }
        Some(Corruption::Reorder) if outputs.len() > 1 => outputs.swap(0, 1),
        Some(Corruption::Omit) => {
            outputs.pop();
        }
        Some(Corruption::Duplicate) if outputs.len() > 1 => outputs[1] = outputs[0],
        Some(Corruption::ReplayedVector) => outputs.fill(GroupElement::identity()),
        Some(Corruption::CrossSessionSwap) => outputs[0] += session.bases[0],
        _ => {}
    }
    if !matches!(session.mode, SessionMode::Native) && session.transport.is_none() {
        session.metrics.download_bytes = outputs.len() * 32;
    }

    if matches!(session.mode, SessionMode::Malicious { .. }) {
        #[cfg(feature = "thinwallet-experiment")]
        let _aggregate_phase =
            thinwallet_instrumentation::PhaseGuard::begin("pbmo_aggregate_check");
        #[cfg(feature = "thinwallet-experiment")]
        thinwallet_instrumentation::increment_counter("aggregate_checks_executed", 1);
        let check_start = Instant::now();
        if outputs.len() != session.q {
            if let Some(token) = session.token_mut() {
                token.state = TokenState::Burned;
            }
            return Err(PbmoError::Integrity);
        }
        let digest = output_digest(&session.context, &outputs)?;
        session.metrics.outputs_bound_before_challenge = true;
        let transcript = bincode::serialize(&session.context)
            .map_err(|e| PbmoError::Serialization(e.to_string()))?;
        let token_id = session.token().unwrap().token_id;
        let rho: Vec<_> = (0..session.q)
            .map(|row| derive_batch_challenge(&transcript, &token_id, &digest, row as u32))
            .collect();
        let y_rho = GroupElement::vartime_multiscalar_mul(&rho, &outputs);
        session.metrics.aggregate_point_ops = session.q as u64;

        let _spool_path = match &session.mode {
            SessionMode::Malicious { spool, .. } => spool.active_path(),
            _ => unreachable!(),
        };
        let mut spool_reader = match &mut session.mode {
            SessionMode::Malicious { spool, .. } => spool.seal_and_open_verified()?,
            _ => unreachable!(),
        };
        let mut a = vec![Scalar::ZERO; session.m];
        let mut raw = [0u8; 32];
        for rho_j in rho.iter().take(session.q) {
            for a_i in a.iter_mut().take(session.m) {
                spool_reader.read_exact(&mut raw)?;
                session.metrics.spool_bytes_read += 32;
                let value = Option::<Scalar>::from(Scalar::from_canonical_bytes(raw))
                    .ok_or_else(|| PbmoError::Stream("non-canonical spool scalar".into()))?;
                *a_i += rho_j * value;
                session.metrics.aggregate_field_ops += 2;
            }
        }
        let t = GroupElement::vartime_multiscalar_mul(&a, &session.bases);
        session.metrics.local_check_msm_terms = session.m as u64;
        if matches!(corruption, Some(Corruption::AfterChallenge)) {
            outputs[0] += session.bases[0];
        }
        if t != y_rho || matches!(corruption, Some(Corruption::AfterChallenge)) {
            if let Some(token) = session.token_mut() {
                token.state = TokenState::Burned;
            }
            #[cfg(feature = "thinwallet-experiment")]
            thinwallet_instrumentation::record_artifact_remove(&_spool_path);
            if let SessionMode::Malicious { spool, .. } = &mut session.mode {
                let _ = spool.remove();
            }
            return Err(PbmoError::Integrity);
        }
        session.metrics.batch_check_ms = check_start.elapsed().as_secs_f64() * 1000.0;
        #[cfg(feature = "thinwallet-experiment")]
        thinwallet_instrumentation::increment_counter("aggregate_checks_passed", 1);
        session.metrics.soundness_bound = Some("<= 1 / |Fr| for a fixed nonzero ordered output error vector in the post-commitment random-challenge model".into());
        #[cfg(feature = "thinwallet-experiment")]
        thinwallet_instrumentation::record_artifact_remove(&_spool_path);
        if let SessionMode::Malicious { spool, .. } = &mut session.mode {
            spool.remove()?;
        }
    }

    if session.is_preprocessed() {
        #[cfg(feature = "thinwallet-experiment")]
        let _recover_phase = thinwallet_instrumentation::PhaseGuard::begin("pbmo_recover");
        emit_phase_marker("DURING_CORRECTION", session.q as u64)?;
        let recovery_start = Instant::now();
        let corrections = session.token().unwrap().correction_points.clone();
        for (output, correction) in outputs.iter_mut().zip(corrections) {
            *output -= correction;
        }
        session.metrics.client_recovery_point_ops = session.q as u64;
        session.metrics.recovery_ms = recovery_start.elapsed().as_secs_f64() * 1000.0;
        if let Some(token) = session.token_mut() {
            token.state = TokenState::Spent;
        }
        session.metrics.token_final_state = Some("SPENT".into());
    }
    #[cfg(feature = "thinwallet-experiment")]
    if session.is_preprocessed() {
        thinwallet_instrumentation::increment_counter("pbmo_sessions_completed", 1);
    }
    session.finalized = true;
    Ok((outputs, session.metrics.clone()))
}

fn spool_path(context: &PbmoContext) -> PathBuf {
    static NEXT_SPOOL: AtomicU64 = AtomicU64::new(1);
    let digest = digest32(
        b"thinwallet/preprocessed-pbmo/spool-name/v2",
        &[context.session_id.as_bytes(), context.proof_id.as_bytes()],
    );
    let name: String = digest[..12].iter().map(|b| format!("{b:02x}")).collect();
    let sequence = NEXT_SPOOL.fetch_add(1, Ordering::Relaxed);
    let root = std::env::var_os("THINWALLET_EXPERIMENT_TEMP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    root.join(format!("pbmo-{name}-{sequence}.spool"))
}

macro_rules! impl_provider {
    ($ty:ty) => {
        fn push_private_row_chunk(
            &mut self,
            session: &mut PbmoSession,
            row: usize,
            col_range: Range<usize>,
            private_scalars: &[Scalar],
        ) -> Result<()> {
            push_chunk(session, row, col_range, private_scalars)
        }
    };
}

impl PreprocessedPbmoProvider for NativeLocalPbmoProvider {
    fn begin(&mut self, context: PbmoContext, q: usize, m: usize) -> Result<PbmoSession> {
        start_session(
            context,
            q,
            m,
            &self.bases,
            SessionMode::Native,
            "native-local",
            None,
        )
    }
    impl_provider!(NativeLocalPbmoProvider);
    fn finalize(&mut self, session: PbmoSession) -> Result<Vec<GroupElement>> {
        let (points, metrics) = finish(session, None)?;
        self.last_metrics = Some(metrics);
        Ok(points)
    }
    fn last_metrics(&self) -> Option<&PbmoMetrics> {
        self.last_metrics.as_ref()
    }
}

impl PreprocessedPbmoProvider for PlainRemotePbmoProvider {
    fn begin(&mut self, context: PbmoContext, q: usize, m: usize) -> Result<PbmoSession> {
        start_session(
            context,
            q,
            m,
            &self.bases,
            SessionMode::Plain,
            "plain-remote",
            None,
        )
    }
    impl_provider!(PlainRemotePbmoProvider);
    fn finalize(&mut self, session: PbmoSession) -> Result<Vec<GroupElement>> {
        let (points, metrics) = finish(session, None)?;
        self.last_metrics = Some(metrics);
        Ok(points)
    }
    fn last_metrics(&self) -> Option<&PbmoMetrics> {
        self.last_metrics.as_ref()
    }
}

impl PreprocessedPbmoProvider for PreprocessedSemihonestPbmoProvider {
    fn begin(&mut self, context: PbmoContext, q: usize, m: usize) -> Result<PbmoSession> {
        let token = self
            .token
            .take()
            .ok_or_else(|| PbmoError::Token("token already consumed".into()))?;
        start_session(
            context,
            q,
            m,
            &self.bases,
            SessionMode::Semi { token },
            "preprocessed-semihonest",
            self.transport.take(),
        )
    }
    impl_provider!(PreprocessedSemihonestPbmoProvider);
    fn finalize(&mut self, session: PbmoSession) -> Result<Vec<GroupElement>> {
        let (points, metrics) = finish(session, None)?;
        self.last_metrics = Some(metrics);
        Ok(points)
    }
    fn last_metrics(&self) -> Option<&PbmoMetrics> {
        self.last_metrics.as_ref()
    }
}

impl PreprocessedPbmoProvider for PreprocessedMaliciousPbmoProvider {
    fn begin(&mut self, context: PbmoContext, q: usize, m: usize) -> Result<PbmoSession> {
        let token = self
            .token
            .take()
            .ok_or_else(|| PbmoError::Token("token already consumed".into()))?;
        let path = spool_path(&context);
        let descriptor = SpoolDescriptor {
            invocation_id: context.session_id.clone(),
            object_id: context.proof_id.clone(),
            context_digest: context_binding_digest(&context, q, m)?,
            logical_element_count: q
                .checked_mul(m)
                .ok_or_else(|| PbmoError::Context("PBMO spool element count overflow".into()))?
                as u64,
        };
        let spool = Box::new(SecureSpool::create(&path, descriptor)?);
        start_session(
            context,
            q,
            m,
            &self.bases,
            SessionMode::Malicious { token, spool },
            "preprocessed-malicious",
            self.transport.take(),
        )
    }
    impl_provider!(PreprocessedMaliciousPbmoProvider);
    fn finalize(&mut self, session: PbmoSession) -> Result<Vec<GroupElement>> {
        let (points, metrics) = finish(session, self.corruption)?;
        self.last_metrics = Some(metrics);
        Ok(points)
    }
    fn last_metrics(&self) -> Option<&PbmoMetrics> {
        self.last_metrics.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::{basis_digest, RelationShape, TokenBinding};
    use crate::{BACKEND_REVISION, PROTOCOL_VERSION};
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    fn fixture(q: usize, m: usize) -> (Vec<GroupElement>, Vec<Vec<Scalar>>, Token, PbmoContext) {
        let bases: Vec<_> = (1..=m)
            .map(|i| Scalar::from(i as u64) * RISTRETTO_BASEPOINT_POINT)
            .collect();
        let rows: Vec<Vec<_>> = (0..q)
            .map(|j| {
                (0..m)
                    .map(|i| Scalar::from((j * m + i + 1) as u64))
                    .collect()
            })
            .collect();
        let binding = TokenBinding {
            basis_digest: basis_digest(&bases),
            backend_revision: BACKEND_REVISION.into(),
            relation_shape: RelationShape {
                relation_id: "test".into(),
                logical_commitment_id: "witness".into(),
                layout_version: "v1".into(),
            },
            q: q as u32,
            m: m as u32,
        };
        let mut token =
            Token::generate_with_material(binding.clone(), &bases, [3; 16], [7; 32]).unwrap();
        let context = PbmoContext {
            protocol_version: PROTOCOL_VERSION,
            session_id: "session-a".into(),
            proof_id: "proof-a".into(),
            token_id: Some(token.token_id),
            logical_commitment_id: "witness".into(),
            basis_digest: binding.basis_digest,
            backend_revision: BACKEND_REVISION.into(),
            relation_shape: "test:v1".into(),
            expected_chunks: (q * 2) as u32,
        };
        token.set_test_reservation(
            crate::ReservationBinding {
                ctx_digest: binding.context_digest(),
                sid: context.proof_id.clone(),
                iid: context.session_id.clone(),
                request_digest: context_binding_digest(&context, q, m).unwrap(),
            },
            1,
        );
        (bases, rows, token, context)
    }

    fn run(
        provider: &mut dyn PreprocessedPbmoProvider,
        context: PbmoContext,
        rows: &[Vec<Scalar>],
    ) -> Result<Vec<GroupElement>> {
        let q = rows.len();
        let m = rows[0].len();
        let mut session = provider.begin(context, q, m)?;
        for (row, scalars) in rows.iter().enumerate() {
            let mid = m / 2;
            provider.push_private_row_chunk(&mut session, row, 0..mid, &scalars[..mid])?;
            provider.push_private_row_chunk(&mut session, row, mid..m, &scalars[mid..])?;
        }
        provider.finalize(session)
    }

    #[test]
    fn all_honest_providers_match() {
        let (bases, rows, token, context) = fixture(8, 16);
        let mut native = NativeLocalPbmoProvider::new(bases.clone());
        let expected = run(&mut native, context.clone(), &rows).unwrap();
        let mut plain = PlainRemotePbmoProvider::new(bases.clone());
        assert_eq!(run(&mut plain, context.clone(), &rows).unwrap(), expected);
        let mut semi = PreprocessedSemihonestPbmoProvider::new(bases.clone(), token.clone());
        assert_eq!(run(&mut semi, context.clone(), &rows).unwrap(), expected);
        let mut malicious = PreprocessedMaliciousPbmoProvider::new(bases, token);
        assert_eq!(run(&mut malicious, context, &rows).unwrap(), expected);
    }

    #[test]
    fn malicious_corruptions_are_rejected() {
        for corruption in [
            Corruption::OneOutput,
            Corruption::CorrelatedOutputs,
            Corruption::Reorder,
            Corruption::Omit,
            Corruption::Duplicate,
            Corruption::AfterChallenge,
            Corruption::ReplayedVector,
            Corruption::CrossSessionSwap,
        ] {
            let (bases, rows, token, context) = fixture(4, 8);
            let mut provider =
                PreprocessedMaliciousPbmoProvider::new(bases, token).with_corruption(corruption);
            assert!(
                run(&mut provider, context, &rows).is_err(),
                "accepted {corruption:?}"
            );
        }
    }

    #[test]
    fn token_reuse_is_rejected() {
        let (bases, rows, token, context) = fixture(4, 8);
        let mut provider = PreprocessedSemihonestPbmoProvider::new(bases, token);
        assert!(run(&mut provider, context.clone(), &rows).is_ok());
        assert!(run(&mut provider, context, &rows).is_err());
    }

    #[test]
    fn stream_context_binds_session_and_proof() {
        let (_, _, _, context) = fixture(4, 8);
        let digest = context_binding_digest(&context, 4, 8).unwrap();
        let mut wrong = context.clone();
        wrong.session_id.push_str("-wrong");
        assert_ne!(digest, context_binding_digest(&wrong, 4, 8).unwrap());
        wrong = context.clone();
        wrong.proof_id.push_str("-wrong");
        assert_ne!(digest, context_binding_digest(&wrong, 4, 8).unwrap());
    }
}
