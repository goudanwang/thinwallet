// Rust interface mirror for Phase 2C dense streaming RAA.
// Executable implementation: dense_raa_streaming.py.

pub trait DenseRaaStreaming<Fr> {
    fn stream_beta(
        &mut self,
        manifest_digest: &[u8],
        nonce: &[u8],
        check_round: u32,
    ) -> Result<(), String>;
}

