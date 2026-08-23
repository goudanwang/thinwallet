// Rust interface mirror for Phase 2C dense RAA external store.

pub struct DenseRaaExternalStoreMetrics {
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub passes: u64,
    pub temporary_storage: u64,
}

