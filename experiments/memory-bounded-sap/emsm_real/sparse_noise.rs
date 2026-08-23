// Rust interface mirror for Phase 2A. See sparse_noise.py for executable code.

pub struct SparseNoiseEntry<Fr> {
    pub index: usize,
    pub value: Fr,
}

pub struct SparseNoise<Fr> {
    pub code_len_n: usize,
    pub entries: Vec<SparseNoiseEntry<Fr>>,
    pub session_id: String,
}

