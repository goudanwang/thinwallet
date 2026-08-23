// Rust interface mirror for Phase 2A.
// Executable source of truth for this phase is raa_parameters.py.
// This file records the requested Rust-shaped boundary without claiming a
// production Rust EMSM implementation.

pub struct EmsmParameters {
    pub security_bits: usize,
    pub input_len_n: usize,
    pub code_len_n: usize,
    pub code_rate: f64,
    pub relative_distance_target: f64,
    pub noise_weight_t: usize,
    pub malicious_mode: bool,
    pub curve_id: &'static str,
    pub field_id: &'static str,
    pub parameter_version: &'static str,
}

