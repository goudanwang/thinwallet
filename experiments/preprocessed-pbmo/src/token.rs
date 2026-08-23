use crate::field::{derive_mask_scalar, derive_mask_scalar_profiled, digest32, DomainMetadata};
use crate::{GroupElement, BACKEND_REVISION, PROTOCOL_VERSION};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use fs2::FileExt;
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const MAGIC: &[u8; 8] = b"PBMOTOK2";
const MAX_METADATA: usize = 16 * 1024;
const MAX_POINTS: usize = 1 << 20;
const LIFECYCLE_FORMAT_VERSION: u16 = 3;
const MAX_LIFECYCLE_RECORDS: usize = 1 << 20;
const MAX_BINDING_TEXT: usize = 4096;
static SNAPSHOT_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("token authentication failed")]
    Authentication,
    #[error("malformed token: {0}")]
    Malformed(String),
    #[error("token binding mismatch: {0}")]
    Binding(String),
    #[error("invalid lifecycle transition from {0:?} to {1:?}")]
    InvalidTransition(TokenState, TokenState),
    #[error("duplicate token id")]
    DuplicateToken,
    #[error("token not available")]
    NotAvailable,
    #[error("journal authentication failed")]
    JournalAuthentication,
    #[error("monotonic state unavailable: {0}")]
    Monotonic(String),
    #[error("stale lifecycle generation")]
    StaleGeneration,
}

pub type Result<T> = std::result::Result<T, TokenError>;

/// Public relation dimensions and commitment layout bound into a token.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelationShape {
    pub relation_id: String,
    pub logical_commitment_id: String,
    pub layout_version: String,
}

/// Complete public binding for one token family.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TokenBinding {
    pub basis_digest: [u8; 32],
    pub backend_revision: String,
    pub relation_shape: RelationShape,
    pub q: u32,
    pub m: u32,
}

impl TokenBinding {
    pub fn context_digest(&self) -> [u8; 32] {
        let encoded = bincode::serialize(&(PROTOCOL_VERSION, self))
            .expect("TokenBinding serialization is infallible");
        digest32(
            b"thinwallet/preprocessed-pbmo/lifecycle-context/v3",
            &[&encoded],
        )
    }

    pub fn domain_metadata(&self, token_id: [u8; 16]) -> DomainMetadata {
        DomainMetadata {
            token_id,
            basis_digest: self.basis_digest,
            backend_revision: self.backend_revision.clone(),
            logical_commitment_id: self.relation_shape.logical_commitment_id.clone(),
            relation_shape: format!(
                "{}:{}",
                self.relation_shape.relation_id, self.relation_shape.layout_version
            ),
            q: self.q,
            m: self.m,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReservationBinding {
    pub ctx_digest: [u8; 32],
    pub sid: String,
    pub iid: String,
    pub request_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TokenState {
    Available = 0,
    Reserved = 1,
    Spent = 2,
    Burned = 3,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TokenHeader {
    protocol_version: u16,
    token_id: [u8; 16],
    binding: TokenBinding,
    creation_epoch: u64,
    state: TokenState,
    journal_reference: [u8; 32],
    key_id: String,
}

/// Decrypted in-memory token. The seed is never serialized in cleartext.
#[derive(Clone, Debug)]
pub struct Token {
    pub token_id: [u8; 16],
    pub binding: TokenBinding,
    pub creation_epoch: u64,
    pub state: TokenState,
    pub journal_reference: [u8; 32],
    pub correction_points: Vec<GroupElement>,
    seed: [u8; 32],
    key_id: String,
    reservation_binding: Option<ReservationBinding>,
    record_generation: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TokenGenerationProfile {
    pub prf_expansion_ns: u64,
    pub field_reduction_ns: u64,
    pub correction_msm_total_ns: u64,
    pub correction_msm_per_row_ns: Vec<u64>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TokenEncodingProfile {
    pub correction_encoding_ns: u64,
    pub metadata_encoding_ns: u64,
    pub token_encryption_ns: u64,
}

impl Token {
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub fn reservation_binding(&self) -> Option<&ReservationBinding> {
        self.reservation_binding.as_ref()
    }

    pub fn record_generation(&self) -> u64 {
        self.record_generation
    }

    #[cfg(test)]
    pub(crate) fn set_test_reservation(&mut self, binding: ReservationBinding, generation: u64) {
        self.state = TokenState::Reserved;
        self.reservation_binding = Some(binding);
        self.record_generation = generation;
    }

    pub fn generate<R: RngCore + CryptoRng>(
        binding: TokenBinding,
        bases: &[GroupElement],
        rng: &mut R,
    ) -> Result<Self> {
        if binding.backend_revision != BACKEND_REVISION {
            return Err(TokenError::Binding("backend revision".into()));
        }
        if binding.q == 0 || binding.m == 0 || bases.len() != binding.m as usize {
            return Err(TokenError::Binding("invalid dimensions or basis".into()));
        }
        let mut token_id = [0u8; 16];
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut token_id);
        rng.fill_bytes(&mut seed);
        Self::generate_with_material(binding, bases, token_id, seed)
    }

    pub fn generate_with_material(
        binding: TokenBinding,
        bases: &[GroupElement],
        token_id: [u8; 16],
        seed: [u8; 32],
    ) -> Result<Self> {
        if binding.q == 0 || binding.m == 0 || bases.len() != binding.m as usize {
            return Err(TokenError::Binding("invalid dimensions or basis".into()));
        }
        let meta = binding.domain_metadata(token_id);
        let mut correction_points = Vec::with_capacity(binding.q as usize);
        for row in 0..binding.q {
            let scalars: Vec<_> = (0..binding.m)
                .map(|col| derive_mask_scalar(&seed, &meta, row, col, 0))
                .collect();
            correction_points.push(GroupElement::vartime_multiscalar_mul(&scalars, bases));
        }
        Ok(Self {
            token_id,
            binding,
            creation_epoch: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            state: TokenState::Available,
            journal_reference: [0; 32],
            correction_points,
            seed,
            key_id: "software-test-key-v1".into(),
            reservation_binding: None,
            record_generation: 0,
        })
    }

    pub fn generate_with_material_profiled(
        binding: TokenBinding,
        bases: &[GroupElement],
        token_id: [u8; 16],
        seed: [u8; 32],
    ) -> Result<(Self, TokenGenerationProfile)> {
        if binding.q == 0 || binding.m == 0 || bases.len() != binding.m as usize {
            return Err(TokenError::Binding("invalid dimensions or basis".into()));
        }
        let meta = binding.domain_metadata(token_id);
        let mut correction_points = Vec::with_capacity(binding.q as usize);
        let mut profile = TokenGenerationProfile::default();
        for row in 0..binding.q {
            // Only one row is live. No q*m mask matrix is materialized.
            let scalars: Vec<_> = (0..binding.m)
                .map(|col| {
                    let (scalar, prf_ns, reduction_ns) =
                        derive_mask_scalar_profiled(&seed, &meta, row, col, 0);
                    profile.prf_expansion_ns = profile.prf_expansion_ns.saturating_add(prf_ns);
                    profile.field_reduction_ns =
                        profile.field_reduction_ns.saturating_add(reduction_ns);
                    scalar
                })
                .collect();
            let msm_started = Instant::now();
            correction_points.push(GroupElement::vartime_multiscalar_mul(&scalars, bases));
            let msm_ns = msm_started.elapsed().as_nanos() as u64;
            profile.correction_msm_total_ns =
                profile.correction_msm_total_ns.saturating_add(msm_ns);
            profile.correction_msm_per_row_ns.push(msm_ns);
        }
        Ok((
            Self {
                token_id,
                binding,
                creation_epoch: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                state: TokenState::Available,
                journal_reference: [0; 32],
                correction_points,
                seed,
                key_id: "software-test-key-v1".into(),
                reservation_binding: None,
                record_generation: 0,
            },
            profile,
        ))
    }

    pub fn validate_binding(&self, expected: &TokenBinding) -> Result<()> {
        if &self.binding != expected {
            return Err(TokenError::Binding("token metadata differs".into()));
        }
        Ok(())
    }

    fn header(&self) -> TokenHeader {
        TokenHeader {
            protocol_version: PROTOCOL_VERSION,
            token_id: self.token_id,
            binding: self.binding.clone(),
            creation_epoch: self.creation_epoch,
            state: self.state,
            journal_reference: self.journal_reference,
            key_id: self.key_id.clone(),
        }
    }

    fn aad(header_bytes: &[u8], point_bytes: &[[u8; 32]]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(header_bytes.len() + point_bytes.len() * 32 + 16);
        aad.extend_from_slice(MAGIC);
        aad.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        aad.extend_from_slice(header_bytes);
        aad.extend_from_slice(&(point_bytes.len() as u32).to_le_bytes());
        for point in point_bytes {
            aad.extend_from_slice(point);
        }
        aad
    }

    pub fn encode<R: RngCore + CryptoRng>(
        &self,
        keys: &dyn TokenStoreKeyProvider,
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        let header_bytes = bincode::serialize(&self.header())
            .map_err(|e| TokenError::Serialization(e.to_string()))?;
        if header_bytes.len() > MAX_METADATA {
            return Err(TokenError::Malformed("metadata too large".into()));
        }
        let point_bytes: Vec<_> = self
            .correction_points
            .iter()
            .map(|point| point.compress().to_bytes())
            .collect();
        let aad = Self::aad(&header_bytes, &point_bytes);
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);
        let key = keys.key(&self.key_id)?;
        let cipher = XChaCha20Poly1305::new((&key).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &self.seed,
                    aad: &aad,
                },
            )
            .map_err(|_| TokenError::Authentication)?;
        let mut out = aad;
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn encode_profiled<R: RngCore + CryptoRng>(
        &self,
        keys: &dyn TokenStoreKeyProvider,
        rng: &mut R,
    ) -> Result<(Vec<u8>, TokenEncodingProfile)> {
        let metadata_started = Instant::now();
        let header_bytes = bincode::serialize(&self.header())
            .map_err(|e| TokenError::Serialization(e.to_string()))?;
        let metadata_encoding_ns = metadata_started.elapsed().as_nanos() as u64;
        if header_bytes.len() > MAX_METADATA {
            return Err(TokenError::Malformed("metadata too large".into()));
        }
        let correction_started = Instant::now();
        let point_bytes: Vec<_> = self
            .correction_points
            .iter()
            .map(|point| point.compress().to_bytes())
            .collect();
        let correction_encoding_ns = correction_started.elapsed().as_nanos() as u64;
        let aad = Self::aad(&header_bytes, &point_bytes);
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);
        let key = keys.key(&self.key_id)?;
        let cipher = XChaCha20Poly1305::new((&key).into());
        let encryption_started = Instant::now();
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &self.seed,
                    aad: &aad,
                },
            )
            .map_err(|_| TokenError::Authentication)?;
        let token_encryption_ns = encryption_started.elapsed().as_nanos() as u64;
        let mut out = aad;
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&ciphertext);
        Ok((
            out,
            TokenEncodingProfile {
                correction_encoding_ns,
                metadata_encoding_ns,
                token_encryption_ns,
            },
        ))
    }

    pub fn decode(bytes: &[u8], keys: &dyn TokenStoreKeyProvider) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != MAGIC {
            return Err(TokenError::Malformed("bad magic".into()));
        }
        let header_len = cursor.u32()? as usize;
        if header_len > MAX_METADATA {
            return Err(TokenError::Malformed("metadata too large".into()));
        }
        let header_bytes = cursor.take(header_len)?.to_vec();
        let header: TokenHeader = bincode::deserialize(&header_bytes)
            .map_err(|e| TokenError::Serialization(e.to_string()))?;
        if header.protocol_version != PROTOCOL_VERSION {
            return Err(TokenError::Binding("protocol version".into()));
        }
        let point_count = cursor.u32()? as usize;
        if point_count > MAX_POINTS || point_count != header.binding.q as usize {
            return Err(TokenError::Malformed("wrong point count".into()));
        }
        let mut point_bytes = Vec::with_capacity(point_count);
        let mut correction_points = Vec::with_capacity(point_count);
        for _ in 0..point_count {
            let raw: [u8; 32] = cursor.take(32)?.try_into().unwrap();
            let point = CompressedRistretto(raw)
                .decompress()
                .ok_or_else(|| TokenError::Malformed("non-canonical Ristretto point".into()))?;
            point_bytes.push(raw);
            correction_points.push(point);
        }
        let aad_end = cursor.position;
        let nonce: [u8; 24] = cursor.take(24)?.try_into().unwrap();
        let ciphertext_len = cursor.u32()? as usize;
        let ciphertext = cursor.take(ciphertext_len)?;
        if cursor.position != bytes.len() {
            return Err(TokenError::Malformed("trailing data".into()));
        }
        let aad = &bytes[..aad_end];
        if aad != Self::aad(&header_bytes, &point_bytes) {
            return Err(TokenError::Malformed("non-canonical encoding".into()));
        }
        let key = keys.key(&header.key_id)?;
        let cipher = XChaCha20Poly1305::new((&key).into());
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| TokenError::Authentication)?;
        let seed: [u8; 32] = plaintext
            .try_into()
            .map_err(|_| TokenError::Malformed("seed length".into()))?;
        Ok(Self {
            token_id: header.token_id,
            binding: header.binding,
            creation_epoch: header.creation_epoch,
            state: header.state,
            journal_reference: header.journal_reference,
            correction_points,
            seed,
            key_id: header.key_id,
            reservation_binding: None,
            record_generation: 0,
        })
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| TokenError::Malformed("length overflow".into()))?;
        if end > self.bytes.len() {
            return Err(TokenError::Malformed("truncated token".into()));
        }
        let out = &self.bytes[self.position..end];
        self.position = end;
        Ok(out)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
}

pub trait TokenStoreKeyProvider: Send + Sync {
    fn key(&self, key_id: &str) -> Result<[u8; 32]>;
}

#[derive(Clone)]
pub struct SoftwareTokenStoreKeyProvider {
    key_id: String,
    key: [u8; 32],
}

impl SoftwareTokenStoreKeyProvider {
    pub fn new(key_id: impl Into<String>, key: [u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            key,
        }
    }
}

impl TokenStoreKeyProvider for SoftwareTokenStoreKeyProvider {
    fn key(&self, key_id: &str) -> Result<[u8; 32]> {
        if key_id != self.key_id {
            return Err(TokenError::Authentication);
        }
        Ok(self.key)
    }
}

pub trait MonotonicStateProvider: Send + Sync {
    fn observe(&self, journal_sequence: u64) -> Result<()>;
    fn security_classification(&self) -> &'static str;
}

#[derive(Default)]
pub struct SoftwareCrashConsistentProvider;

impl MonotonicStateProvider for SoftwareCrashConsistentProvider {
    fn observe(&self, _journal_sequence: u64) -> Result<()> {
        Ok(())
    }

    fn security_classification(&self) -> &'static str {
        "SOFTWARE_ONLY_SNAPSHOT_ROLLBACK_NOT_PREVENTED"
    }
}

/// Interface only; no hardware implementation is fabricated in Phase V2.
pub trait HardwareMonotonicProvider: MonotonicStateProvider {}
/// Interface only; no external witness service is fabricated in Phase V2.
pub trait ExternalWitnessProvider: MonotonicStateProvider {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CrashPoint {
    BeforeReservation,
    AfterJournalAppend,
    AfterFsync,
    AfterFirstChunk,
    MidwayUpload,
    AfterServerResponse,
    DuringProofAssembly,
    DuringFinalization,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct JournalState {
    pub sequence: u64,
    pub token_states: HashMap<[u8; 16], TokenState>,
    pub head_hash: [u8; 32],
}

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LifecycleRecord {
    pub format_version: u16,
    pub store_generation: u64,
    pub tid: [u8; 16],
    pub ctx_digest: [u8; 32],
    pub state: TokenState,
    pub sid: String,
    pub iid: String,
    pub request_digest: [u8; 32],
}

#[derive(Clone, Debug, Serialize)]
pub struct LifecycleInspection {
    pub store_generation: u64,
    pub records: Vec<LifecycleRecord>,
}

impl LifecycleRecord {
    fn reservation_binding(&self) -> Option<ReservationBinding> {
        (self.state != TokenState::Available).then(|| ReservationBinding {
            ctx_digest: self.ctx_digest,
            sid: self.sid.clone(),
            iid: self.iid.clone(),
            request_digest: self.request_digest,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LifecycleSnapshot {
    format_version: u16,
    store_generation: u64,
    records: Vec<LifecycleRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AuthenticatedLifecycleSnapshot {
    snapshot: LifecycleSnapshot,
    tag: [u8; 32],
}

fn lifecycle_tag(key: &[u8; 32], snapshot_bytes: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key size");
    mac.update(b"thinwallet/preprocessed-pbmo/lifecycle-snapshot/v3");
    mac.update(snapshot_bytes);
    mac.finalize().into_bytes().into()
}

pub struct TokenStore {
    root: PathBuf,
    keys: Box<dyn TokenStoreKeyProvider>,
    monotonic: Box<dyn MonotonicStateProvider>,
    journal_key: [u8; 32],
    state: JournalState,
    records: HashMap<[u8; 16], LifecycleRecord>,
}

static TOKEN_DURABLE_SYNC_NS: AtomicU64 = AtomicU64::new(0);
static TOKEN_DURABLE_SYNC_CALLS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct TokenDurabilityMetrics {
    pub sync_calls: u64,
    pub sync_time_ns: u64,
}

pub fn reset_token_durability_metrics() {
    TOKEN_DURABLE_SYNC_NS.store(0, Ordering::Relaxed);
    TOKEN_DURABLE_SYNC_CALLS.store(0, Ordering::Relaxed);
}

pub fn token_durability_metrics() -> TokenDurabilityMetrics {
    TokenDurabilityMetrics {
        sync_calls: TOKEN_DURABLE_SYNC_CALLS.load(Ordering::Relaxed),
        sync_time_ns: TOKEN_DURABLE_SYNC_NS.load(Ordering::Relaxed),
    }
}

fn measured_sync_all(file: &File) -> std::io::Result<()> {
    let started = Instant::now();
    file.sync_all()?;
    TOKEN_DURABLE_SYNC_NS.fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
    TOKEN_DURABLE_SYNC_CALLS.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

impl TokenStore {
    pub fn inspect_committed_records(
        root: impl AsRef<Path>,
        journal_key: [u8; 32],
    ) -> Result<LifecycleInspection> {
        let store = Self {
            root: root.as_ref().to_path_buf(),
            keys: Box::new(SoftwareTokenStoreKeyProvider::new(
                "lifecycle-inspection-only",
                [0; 32],
            )),
            monotonic: Box::new(SoftwareCrashConsistentProvider),
            journal_key,
            state: JournalState::default(),
            records: HashMap::new(),
        };
        let lock = store.acquire_exclusive_lock()?;
        let snapshot = store.load_snapshot()?;
        let inspection = LifecycleInspection {
            store_generation: snapshot.store_generation,
            records: snapshot.records,
        };
        store.release_lock(lock)?;
        Ok(inspection)
    }

    pub fn open(
        root: impl AsRef<Path>,
        keys: Box<dyn TokenStoreKeyProvider>,
        monotonic: Box<dyn MonotonicStateProvider>,
        journal_key: [u8; 32],
    ) -> Result<Self> {
        fs::create_dir_all(root.as_ref().join("tokens"))?;
        let mut store = Self {
            root: root.as_ref().to_path_buf(),
            keys,
            monotonic,
            journal_key,
            state: JournalState::default(),
            records: HashMap::new(),
        };
        let lock = store.acquire_exclusive_lock()?;
        let mut snapshot = store.load_snapshot()?;
        store.validate_available_token_files(&snapshot)?;
        if snapshot
            .records
            .iter()
            .any(|record| record.state == TokenState::Reserved)
        {
            let generation = Self::next_generation(snapshot.store_generation)?;
            for record in &mut snapshot.records {
                if record.state == TokenState::Reserved {
                    record.state = TokenState::Burned;
                    record.store_generation = generation;
                }
            }
            snapshot.store_generation = generation;
            store.commit_snapshot(&snapshot)?;
        }
        store.install_snapshot(snapshot)?;
        store.release_lock(lock)?;
        Ok(store)
    }

    fn journal_path(&self) -> PathBuf {
        self.root.join("lifecycle.journal")
    }

    fn lock_path(&self) -> PathBuf {
        self.root.join("lifecycle.lock")
    }

    fn token_path(&self, token_id: &[u8; 16]) -> PathBuf {
        self.root
            .join("tokens")
            .join(format!("{}.pbmo", hex(token_id)))
    }

    fn acquire_exclusive_lock(&self) -> Result<File> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(self.lock_path())?;
        file.lock_exclusive()?;
        Ok(file)
    }

    fn release_lock(&self, lock: File) -> Result<()> {
        FileExt::unlock(&lock)?;
        Ok(())
    }

    fn empty_snapshot() -> LifecycleSnapshot {
        LifecycleSnapshot {
            format_version: LIFECYCLE_FORMAT_VERSION,
            store_generation: 0,
            records: Vec::new(),
        }
    }

    fn next_generation(current: u64) -> Result<u64> {
        current
            .checked_add(1)
            .ok_or_else(|| TokenError::Malformed("lifecycle generation exhausted".into()))
    }

    fn validate_snapshot(&self, snapshot: &LifecycleSnapshot) -> Result<()> {
        if snapshot.format_version != LIFECYCLE_FORMAT_VERSION {
            return Err(TokenError::Malformed(
                "unknown lifecycle format version".into(),
            ));
        }
        if snapshot.records.len() > MAX_LIFECYCLE_RECORDS {
            return Err(TokenError::Malformed("too many lifecycle records".into()));
        }
        let mut previous = None;
        for record in &snapshot.records {
            if record.format_version != LIFECYCLE_FORMAT_VERSION
                || record.store_generation == 0
                || record.store_generation > snapshot.store_generation
                || record.ctx_digest == [0; 32]
                || record.sid.len() > MAX_BINDING_TEXT
                || record.iid.len() > MAX_BINDING_TEXT
            {
                return Err(TokenError::Malformed("invalid lifecycle record".into()));
            }
            if previous.is_some_and(|tid| tid >= record.tid) {
                return Err(TokenError::DuplicateToken);
            }
            previous = Some(record.tid);
            let empty_binding =
                record.sid.is_empty() && record.iid.is_empty() && record.request_digest == [0; 32];
            if (record.state == TokenState::Available) != empty_binding {
                return Err(TokenError::Malformed(
                    "non-canonical lifecycle reservation binding".into(),
                ));
            }
        }
        if snapshot.records.is_empty() && snapshot.store_generation != 0 {
            return Err(TokenError::Malformed(
                "empty snapshot has generation".into(),
            ));
        }
        Ok(())
    }

    fn load_snapshot(&self) -> Result<LifecycleSnapshot> {
        let path = self.journal_path();
        if !path.exists() {
            return Ok(Self::empty_snapshot());
        }
        let bytes = fs::read(path)?;
        let envelope: AuthenticatedLifecycleSnapshot =
            bincode::deserialize(&bytes).map_err(|_| {
                TokenError::Malformed("unsupported or malformed lifecycle store".into())
            })?;
        let canonical = bincode::serialize(&envelope)
            .map_err(|error| TokenError::Serialization(error.to_string()))?;
        if canonical != bytes {
            return Err(TokenError::Malformed(
                "non-canonical lifecycle encoding".into(),
            ));
        }
        let snapshot_bytes = bincode::serialize(&envelope.snapshot)
            .map_err(|error| TokenError::Serialization(error.to_string()))?;
        if lifecycle_tag(&self.journal_key, &snapshot_bytes) != envelope.tag {
            return Err(TokenError::JournalAuthentication);
        }
        self.validate_snapshot(&envelope.snapshot)?;
        self.monotonic.observe(envelope.snapshot.store_generation)?;
        Ok(envelope.snapshot)
    }

    fn snapshot_head(snapshot: &LifecycleSnapshot) -> Result<[u8; 32]> {
        let bytes = bincode::serialize(snapshot)
            .map_err(|error| TokenError::Serialization(error.to_string()))?;
        Ok(digest32(
            b"thinwallet/preprocessed-pbmo/lifecycle-head/v3",
            &[&bytes],
        ))
    }

    fn commit_snapshot(&self, snapshot: &LifecycleSnapshot) -> Result<()> {
        self.validate_snapshot(snapshot)?;
        let snapshot_bytes = bincode::serialize(snapshot)
            .map_err(|error| TokenError::Serialization(error.to_string()))?;
        let envelope = AuthenticatedLifecycleSnapshot {
            snapshot: snapshot.clone(),
            tag: lifecycle_tag(&self.journal_key, &snapshot_bytes),
        };
        let bytes = bincode::serialize(&envelope)
            .map_err(|error| TokenError::Serialization(error.to_string()))?;
        let counter = SNAPSHOT_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp = self.root.join(format!(
            ".lifecycle.{}.{}.{}.tmp",
            std::process::id(),
            stamp,
            counter
        ));
        let mut file = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
        if let Err(error) = (|| -> std::io::Result<()> {
            file.write_all(&bytes)?;
            measured_sync_all(&file)?;
            drop(file);
            fs::rename(&tmp, self.journal_path())?;
            measured_sync_all(&File::open(&self.root)?)?;
            Ok(())
        })() {
            let _ = fs::remove_file(&tmp);
            return Err(error.into());
        }
        self.monotonic.observe(snapshot.store_generation)?;
        Ok(())
    }

    fn install_snapshot(&mut self, snapshot: LifecycleSnapshot) -> Result<()> {
        let head_hash = Self::snapshot_head(&snapshot)?;
        self.state = JournalState {
            sequence: snapshot.store_generation,
            token_states: snapshot
                .records
                .iter()
                .map(|record| (record.tid, record.state))
                .collect(),
            head_hash,
        };
        self.records = snapshot
            .records
            .into_iter()
            .map(|record| (record.tid, record))
            .collect();
        Ok(())
    }

    fn validate_available_token_files(&self, snapshot: &LifecycleSnapshot) -> Result<()> {
        for record in &snapshot.records {
            if record.state == TokenState::Available {
                let bytes = fs::read(self.token_path(&record.tid))?;
                let token = Token::decode(&bytes, self.keys.as_ref())?;
                if token.state != TokenState::Available
                    || token.binding.context_digest() != record.ctx_digest
                {
                    return Err(TokenError::Binding(
                        "available token file differs from lifecycle record".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn insert<R: RngCore + CryptoRng>(&mut self, token: &Token, rng: &mut R) -> Result<()> {
        let lock = self.acquire_exclusive_lock()?;
        let mut snapshot = self.load_snapshot()?;
        if snapshot
            .records
            .iter()
            .any(|record| record.tid == token.token_id)
            || self.token_path(&token.token_id).exists()
        {
            return Err(TokenError::DuplicateToken);
        }
        let mut token = token.clone();
        token.state = TokenState::Available;
        token.reservation_binding = None;
        let generation = Self::next_generation(snapshot.store_generation)?;
        token.record_generation = generation;
        self.persist_token(&token, rng)?;
        snapshot.store_generation = generation;
        snapshot.records.push(LifecycleRecord {
            format_version: LIFECYCLE_FORMAT_VERSION,
            store_generation: generation,
            tid: token.token_id,
            ctx_digest: token.binding.context_digest(),
            state: TokenState::Available,
            sid: String::new(),
            iid: String::new(),
            request_digest: [0; 32],
        });
        snapshot.records.sort_by_key(|record| record.tid);
        self.commit_snapshot(&snapshot)?;
        self.install_snapshot(snapshot)?;
        self.release_lock(lock)?;
        Ok(())
    }

    pub fn load(&self, token_id: &[u8; 16], expected: &TokenBinding) -> Result<Token> {
        let bytes = fs::read(self.token_path(token_id))?;
        let mut token = Token::decode(&bytes, self.keys.as_ref())?;
        token.validate_binding(expected)?;
        let record = self.records.get(token_id).ok_or(TokenError::NotAvailable)?;
        if record.ctx_digest != expected.context_digest() {
            return Err(TokenError::Binding("lifecycle context digest".into()));
        }
        token.state = record.state;
        token.reservation_binding = record.reservation_binding();
        token.record_generation = record.store_generation;
        Ok(token)
    }

    pub fn reserve<R: RngCore + CryptoRng>(
        &mut self,
        token_id: &[u8; 16],
        expected: &TokenBinding,
        ctx_digest: [u8; 32],
        sid: &str,
        iid: &str,
        request_digest: [u8; 32],
        rng: &mut R,
    ) -> Result<Token> {
        if sid.is_empty()
            || iid.is_empty()
            || sid.len() > MAX_BINDING_TEXT
            || iid.len() > MAX_BINDING_TEXT
            || request_digest == [0; 32]
            || ctx_digest != expected.context_digest()
        {
            return Err(TokenError::Binding("invalid reservation binding".into()));
        }
        let lock = self.acquire_exclusive_lock()?;
        let mut snapshot = self.load_snapshot()?;
        if snapshot
            .records
            .iter()
            .any(|record| record.state != TokenState::Available && record.iid == iid)
        {
            return Err(TokenError::Binding("repeated invocation id".into()));
        }
        let position = snapshot
            .records
            .iter()
            .position(|record| &record.tid == token_id)
            .ok_or(TokenError::NotAvailable)?;
        if snapshot.records[position].state != TokenState::Available {
            return Err(TokenError::NotAvailable);
        }
        if snapshot.records[position].ctx_digest != ctx_digest {
            return Err(TokenError::Binding("reservation context digest".into()));
        }
        let bytes = fs::read(self.token_path(token_id))?;
        let mut token = Token::decode(&bytes, self.keys.as_ref())?;
        token.validate_binding(expected)?;
        let generation = Self::next_generation(snapshot.store_generation)?;
        snapshot.store_generation = generation;
        let record = &mut snapshot.records[position];
        record.store_generation = generation;
        record.state = TokenState::Reserved;
        record.sid = sid.into();
        record.iid = iid.into();
        record.request_digest = request_digest;
        self.commit_snapshot(&snapshot)?;
        let head_hash = Self::snapshot_head(&snapshot)?;
        token.state = TokenState::Reserved;
        token.journal_reference = head_hash;
        token.reservation_binding = Some(ReservationBinding {
            ctx_digest,
            sid: sid.into(),
            iid: iid.into(),
            request_digest,
        });
        token.record_generation = generation;
        self.install_snapshot(snapshot)?;
        self.persist_token(&token, rng)?;
        self.release_lock(lock)?;
        Ok(token)
    }

    fn mark_terminal<R: RngCore + CryptoRng>(
        &mut self,
        token_id: &[u8; 16],
        binding: &ReservationBinding,
        expected_generation: u64,
        target: TokenState,
        rng: &mut R,
    ) -> Result<TokenState> {
        if !matches!(target, TokenState::Spent | TokenState::Burned) {
            return Err(TokenError::Malformed("non-terminal target".into()));
        }
        let lock = self.acquire_exclusive_lock()?;
        let mut snapshot = self.load_snapshot()?;
        let position = snapshot
            .records
            .iter()
            .position(|record| &record.tid == token_id)
            .ok_or(TokenError::NotAvailable)?;
        let record = &snapshot.records[position];
        if record.store_generation != expected_generation {
            return Err(TokenError::StaleGeneration);
        }
        if record.state != TokenState::Reserved {
            return Err(TokenError::InvalidTransition(record.state, target));
        }
        if record.ctx_digest != binding.ctx_digest
            || record.sid != binding.sid
            || record.iid != binding.iid
            || record.request_digest != binding.request_digest
        {
            return Err(TokenError::Binding("terminal reservation binding".into()));
        }
        let generation = Self::next_generation(snapshot.store_generation)?;
        snapshot.store_generation = generation;
        snapshot.records[position].store_generation = generation;
        snapshot.records[position].state = target;
        self.commit_snapshot(&snapshot)?;
        let head_hash = Self::snapshot_head(&snapshot)?;
        self.install_snapshot(snapshot)?;
        let path = self.token_path(token_id);
        if path.exists() {
            let bytes = fs::read(&path)?;
            let mut token = Token::decode(&bytes, self.keys.as_ref())?;
            token.state = target;
            token.journal_reference = head_hash;
            token.reservation_binding = Some(binding.clone());
            token.record_generation = generation;
            self.persist_token(&token, rng)?;
        }
        self.release_lock(lock)?;
        Ok(target)
    }

    pub fn mark_spent<R: RngCore + CryptoRng>(
        &mut self,
        token_id: &[u8; 16],
        binding: &ReservationBinding,
        expected_generation: u64,
        rng: &mut R,
    ) -> Result<TokenState> {
        self.mark_terminal(
            token_id,
            binding,
            expected_generation,
            TokenState::Spent,
            rng,
        )
    }

    pub fn mark_burned<R: RngCore + CryptoRng>(
        &mut self,
        token_id: &[u8; 16],
        binding: &ReservationBinding,
        expected_generation: u64,
        rng: &mut R,
    ) -> Result<TokenState> {
        self.mark_terminal(
            token_id,
            binding,
            expected_generation,
            TokenState::Burned,
            rng,
        )
    }

    pub fn state(&self, token_id: &[u8; 16]) -> Option<TokenState> {
        self.state.token_states.get(token_id).copied()
    }

    pub fn record(&self, token_id: &[u8; 16]) -> Option<&LifecycleRecord> {
        self.records.get(token_id)
    }

    pub fn journal_state(&self) -> &JournalState {
        &self.state
    }

    pub fn rollback_classification(&self) -> &'static str {
        self.monotonic.security_classification()
    }

    fn persist_token<R: RngCore + CryptoRng>(&self, token: &Token, rng: &mut R) -> Result<()> {
        let bytes = token.encode(self.keys.as_ref(), rng)?;
        let path = self.token_path(&token.token_id);
        let counter = SNAPSHOT_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_extension(format!("{}.{}.tmp", std::process::id(), counter));
        let mut file = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
        file.write_all(&bytes)?;
        measured_sync_all(&file)?;
        drop(file);
        fs::rename(&tmp, &path)?;
        if let Some(parent) = path.parent() {
            measured_sync_all(&File::open(parent)?)?;
        }
        Ok(())
    }

    fn recover_reserved(&mut self) -> Result<()> {
        let lock = self.acquire_exclusive_lock()?;
        let mut snapshot = self.load_snapshot()?;
        if snapshot
            .records
            .iter()
            .any(|record| record.state == TokenState::Reserved)
        {
            let generation = Self::next_generation(snapshot.store_generation)?;
            for record in &mut snapshot.records {
                if record.state == TokenState::Reserved {
                    record.state = TokenState::Burned;
                    record.store_generation = generation;
                }
            }
            snapshot.store_generation = generation;
            self.commit_snapshot(&snapshot)?;
        }
        self.install_snapshot(snapshot)?;
        self.release_lock(lock)?;
        Ok(())
    }
}

pub struct TokenLifecycle<'a> {
    store: &'a mut TokenStore,
}

impl<'a> TokenLifecycle<'a> {
    pub fn new(store: &'a mut TokenStore) -> Self {
        Self { store }
    }

    pub fn recover_after_crash(&mut self) -> Result<()> {
        self.store.recover_reserved()
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    out
}

pub fn basis_digest(bases: &[GroupElement]) -> [u8; 32] {
    let encoded: Vec<_> = bases.iter().flat_map(|p| p.compress().to_bytes()).collect();
    digest32(b"thinwallet/preprocessed-pbmo/basis/v2", &[&encoded])
}

pub fn detect_duplicate_ids(tokens: &[Token]) -> Result<()> {
    let mut ids = HashSet::new();
    for token in tokens {
        if !ids.insert(token.token_id) {
            return Err(TokenError::DuplicateToken);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Scalar;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use tempfile::tempdir;

    fn binding(q: u32, m: u32) -> (TokenBinding, Vec<GroupElement>) {
        let bases: Vec<_> = (1..=m)
            .map(|i| Scalar::from(i as u64) * RISTRETTO_BASEPOINT_POINT)
            .collect();
        (
            TokenBinding {
                basis_digest: basis_digest(&bases),
                backend_revision: BACKEND_REVISION.into(),
                relation_shape: RelationShape {
                    relation_id: "test-relation".into(),
                    logical_commitment_id: "private-witness".into(),
                    layout_version: "fragmented-v1".into(),
                },
                q,
                m,
            },
            bases,
        )
    }

    fn keys() -> SoftwareTokenStoreKeyProvider {
        SoftwareTokenStoreKeyProvider::new("software-test-key-v1", [9; 32])
    }

    fn reserve<R: RngCore + CryptoRng>(
        store: &mut TokenStore,
        token: &Token,
        binding: &TokenBinding,
        label: u8,
        rng: &mut R,
    ) -> Token {
        store
            .reserve(
                &token.token_id,
                binding,
                binding.context_digest(),
                &format!("sid-{label}"),
                &format!("iid-{label}"),
                [label; 32],
                rng,
            )
            .unwrap()
    }

    #[test]
    fn format_roundtrip_and_tamper_rejection() {
        let (binding, bases) = binding(4, 8);
        let token =
            Token::generate_with_material(binding.clone(), &bases, [1; 16], [2; 32]).unwrap();
        let mut rng = StdRng::seed_from_u64(4);
        let encoded = token.encode(&keys(), &mut rng).unwrap();
        let decoded = Token::decode(&encoded, &keys()).unwrap();
        assert_eq!(decoded.token_id, token.token_id);
        assert_eq!(decoded.correction_points, token.correction_points);

        for index in [12usize, encoded.len() / 2, encoded.len() - 1] {
            let mut modified = encoded.clone();
            modified[index] ^= 1;
            assert!(Token::decode(&modified, &keys()).is_err());
        }
        assert!(Token::decode(&encoded[..encoded.len() - 1], &keys()).is_err());
        assert!(Token::decode(
            &encoded,
            &SoftwareTokenStoreKeyProvider::new("software-test-key-v1", [8; 32])
        )
        .is_err());
        let mut wrong = binding;
        wrong.m += 1;
        assert!(decoded.validate_binding(&wrong).is_err());
    }

    #[test]
    fn lifecycle_is_one_way_and_recovery_burns_reserved() {
        let dir = tempdir().unwrap();
        let (binding, bases) = binding(2, 4);
        let token =
            Token::generate_with_material(binding.clone(), &bases, [3; 16], [4; 32]).unwrap();
        let mut rng = StdRng::seed_from_u64(9);
        {
            let mut store = TokenStore::open(
                dir.path(),
                Box::new(keys()),
                Box::new(SoftwareCrashConsistentProvider),
                [7; 32],
            )
            .unwrap();
            store.insert(&token, &mut rng).unwrap();
            reserve(&mut store, &token, &binding, 1, &mut rng);
            assert_eq!(store.state(&token.token_id), Some(TokenState::Reserved));
        }
        let store = TokenStore::open(
            dir.path(),
            Box::new(keys()),
            Box::new(SoftwareCrashConsistentProvider),
            [7; 32],
        )
        .unwrap();
        assert_eq!(store.state(&token.token_id), Some(TokenState::Burned));
        assert_eq!(
            store.rollback_classification(),
            "SOFTWARE_ONLY_SNAPSHOT_ROLLBACK_NOT_PREVENTED"
        );
    }

    #[test]
    fn duplicate_ids_rejected() {
        let (binding, bases) = binding(2, 4);
        let token = Token::generate_with_material(binding, &bases, [5; 16], [6; 32]).unwrap();
        assert!(detect_duplicate_ids(&[token.clone(), token]).is_err());
    }

    #[test]
    fn journal_only_rollback_fails_closed_against_latest_token_file() {
        let dir = tempdir().unwrap();
        let (binding, bases) = binding(2, 4);
        let token =
            Token::generate_with_material(binding.clone(), &bases, [8; 16], [9; 32]).unwrap();
        let mut rng = StdRng::seed_from_u64(11);
        let available_snapshot;
        {
            let mut store = TokenStore::open(
                dir.path(),
                Box::new(keys()),
                Box::new(SoftwareCrashConsistentProvider),
                [7; 32],
            )
            .unwrap();
            store.insert(&token, &mut rng).unwrap();
            available_snapshot = fs::read(store.journal_path()).unwrap();
            let reserved = reserve(&mut store, &token, &binding, 2, &mut rng);
            store
                .mark_spent(
                    &token.token_id,
                    reserved.reservation_binding().unwrap(),
                    reserved.record_generation(),
                    &mut rng,
                )
                .unwrap();
        }
        fs::write(dir.path().join("lifecycle.journal"), available_snapshot).unwrap();
        assert!(TokenStore::open(
            dir.path(),
            Box::new(keys()),
            Box::new(SoftwareCrashConsistentProvider),
            [7; 32],
        )
        .is_err());
    }

    #[test]
    fn malformed_lifecycle_snapshots_fail_closed() {
        let dir = tempdir().unwrap();
        let store = TokenStore::open(
            dir.path(),
            Box::new(keys()),
            Box::new(SoftwareCrashConsistentProvider),
            [7; 32],
        )
        .unwrap();
        let record = LifecycleRecord {
            format_version: LIFECYCLE_FORMAT_VERSION,
            store_generation: 1,
            tid: [1; 16],
            ctx_digest: [2; 32],
            state: TokenState::Available,
            sid: String::new(),
            iid: String::new(),
            request_digest: [0; 32],
        };

        let mut unknown_version = LifecycleSnapshot {
            format_version: LIFECYCLE_FORMAT_VERSION + 1,
            store_generation: 1,
            records: vec![record.clone()],
        };
        assert!(store.validate_snapshot(&unknown_version).is_err());

        unknown_version.format_version = LIFECYCLE_FORMAT_VERSION;
        unknown_version.records.push(record.clone());
        assert!(matches!(
            store.validate_snapshot(&unknown_version),
            Err(TokenError::DuplicateToken)
        ));

        let mut malformed_binding = record;
        malformed_binding.sid = "sid-on-available".into();
        let malformed_binding = LifecycleSnapshot {
            format_version: LIFECYCLE_FORMAT_VERSION,
            store_generation: 1,
            records: vec![malformed_binding],
        };
        assert!(store.validate_snapshot(&malformed_binding).is_err());
    }
}
