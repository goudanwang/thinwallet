// Rust interface mirror for Phase 2A. See raa_external_store.py.

pub struct ExternalStoreMetrics {
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub number_of_passes: u64,
    pub random_reads: u64,
    pub sequential_reads: u64,
    pub temporary_storage: u64,
}

