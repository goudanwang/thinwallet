// Rust interface mirror for Phase 2A. See ciphertext_stream.py.

pub struct CiphertextChunk<Fr> {
    pub offset: usize,
    pub values: Vec<Fr>,
}

