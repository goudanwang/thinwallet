// Rust interface mirror for Phase 2A. See streaming_encrypt.py.

pub trait WitnessChunkSource<Fr> {
    fn next_chunk(&mut self, chunk_size: usize) -> Result<Option<(usize, Vec<Fr>)>, String>;
}

pub trait CiphertextSink<Fr> {
    fn append_chunk(&mut self, offset: usize, values: Vec<Fr>) -> Result<(), String>;
}

