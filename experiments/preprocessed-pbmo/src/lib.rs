//! One-time preprocessed private batched multi-output MSM prototype.
//!
//! This crate is proof-system independent and targets Ristretto255. It is an
//! experimental implementation, not a production-security claim.

mod field;
mod provider;
mod secure_spool;
mod token;
mod transport;

pub use field::{derive_batch_challenge, derive_mask_scalar, DomainMetadata};
pub use provider::{
    context_binding_digest, Corruption, NativeLocalPbmoProvider, PbmoContext, PbmoMetrics,
    PbmoProviderKind, PbmoSession, PlainRemotePbmoProvider, PreprocessedMaliciousPbmoProvider,
    PreprocessedPbmoProvider, PreprocessedSemihonestPbmoProvider,
};
pub use token::{
    basis_digest, detect_duplicate_ids, reset_token_durability_metrics, token_durability_metrics,
    CrashPoint, ExternalWitnessProvider, HardwareMonotonicProvider, JournalState,
    LifecycleInspection, LifecycleRecord, MonotonicStateProvider, RelationShape,
    ReservationBinding, SoftwareCrashConsistentProvider, SoftwareTokenStoreKeyProvider, Token,
    TokenBinding, TokenDurabilityMetrics, TokenEncodingProfile, TokenGenerationProfile,
    TokenLifecycle, TokenState, TokenStore, TokenStoreKeyProvider,
};
pub use transport::{
    handle_tcp_connection, run_transport_rejection_suite, LoopbackTransport, PbmoTransport,
    PbmoTransportError, ServerConnectionMetrics, TcpTransport, TransportChunk, TransportMetrics,
    TransportRequestHeader, TransportResponse, CURVE_IDENTIFIER, INTEGRITY_HMAC_SHA256,
    WIRE_PROTOCOL_VERSION,
};

pub use curve25519_dalek::ristretto::RistrettoPoint as GroupElement;
pub use curve25519_dalek::scalar::Scalar;

/// Frozen backend revision used for token relation binding.
pub const BACKEND_REVISION: &str = "libspartan-0.9.0/curve25519-dalek-4.1.3";
/// Binary protocol version.
pub const PROTOCOL_VERSION: u16 = 2;
