// Rust interface mirror for Phase 2B H0 manifest.

pub struct HManifest {
    pub parameter_version: String,
    pub curve_id: String,
    pub vector_length: usize,
    pub root_digest: String,
    pub complete_file_digest: String,
}

