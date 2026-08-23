// Rust interface mirror for Phase 2B H0 h-file format.
// Executable implementation: h_file_format.py.

pub const H0_MAGIC: &[u8; 8] = b"H0HFILE1";

pub struct H0FileHeader {
    pub backend_id: String,
    pub curve_id: String,
    pub n: usize,
    pub code_len_n: usize,
    pub parameter_version: String,
    pub element_byte_len: usize,
    pub root_digest: String,
    pub complete_file_digest: String,
}

