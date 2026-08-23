// Rust benchmark-plan mirror. Measured Phase 2B results are JSON outputs.

pub struct H0BenchmarkProfile {
    pub random_read_latency_ms: f64,
    pub sequential_bandwidth_mb_s: f64,
    pub page_size: usize,
    pub cache_size: usize,
    pub fsync_latency_ms: f64,
}

