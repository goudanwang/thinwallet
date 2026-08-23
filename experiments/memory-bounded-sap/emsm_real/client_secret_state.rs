// Rust interface mirror for Phase 2A. See client_secret_state.py.

pub struct ClientSecretState {
    pub session_id: String,
    pub used: bool,
}

