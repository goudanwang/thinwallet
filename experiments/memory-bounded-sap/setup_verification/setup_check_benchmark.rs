// Rust benchmark-plan mirror. Measured results are JSON outputs.

pub struct SetupCheckBenchmarkRecord {
    pub n: usize,
    pub peak_rss_mb: f64,
    pub temporary_disk_bytes: u64,
    pub field_operations: u64,
    pub group_operations: u64,
}

