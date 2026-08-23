// Rust interface mirror for Phase 2A. See raa_encoder_streaming.py.

pub trait StreamingRaaEncoder<Fr> {
    fn begin(chunk_size: usize) -> Result<Self, String>
    where
        Self: Sized;

    fn next_mask_chunk(&mut self) -> Result<Option<(usize, Vec<Fr>)>, String>;
}

