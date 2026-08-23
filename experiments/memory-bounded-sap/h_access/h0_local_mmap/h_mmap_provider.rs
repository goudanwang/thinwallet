// Rust interface mirror for Phase 2B H0 provider.

pub trait HEntryProvider {
    type Entry;

    fn begin_session(&mut self, request_digest: &[u8]) -> Result<(), String>;
    fn fetch_entries(&mut self, indices: &[usize]) -> Result<Vec<Self::Entry>, String>;
    fn finish_session(&mut self) -> Result<(), String>;
}

