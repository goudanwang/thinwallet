use super::scalar::Scalar;
use super::transcript::{ProofTranscript, WIDE_SAMPLE_BYTES};
use merlin::Transcript;
#[cfg(not(feature = "phase3ar2-deterministic-tests"))]
use rand::rngs::OsRng;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RandomTapeAudit {
  pub(crate) scalar_samples: u64,
  pub(crate) bytes_consumed: u64,
  pub(crate) post_frontier_attempts: u64,
  pub(crate) frontier_sealed: bool,
  pub(crate) sample_coordinates_unique: bool,
}

pub struct RandomTape {
  tape: Transcript,
  root_label: &'static str,
  scalar_samples: u64,
  bytes_consumed: u64,
  post_frontier_attempts: u64,
  frontier_sealed: bool,
  label_ordinals: HashMap<Vec<u8>, u64>,
  sample_coordinates: HashSet<(Vec<u8>, u64)>,
}

impl RandomTape {
  pub fn new(name: &'static [u8]) -> Self {
    let tape = {
      #[cfg(not(feature = "phase3ar2-deterministic-tests"))]
      let mut csprng: OsRng = OsRng;
      let mut tape = Transcript::new(name);
      #[cfg(not(feature = "phase3ar2-deterministic-tests"))]
      tape.append_scalar(b"init_randomness", &Scalar::random(&mut csprng));
      #[cfg(feature = "phase3ar2-deterministic-tests")]
      {
        let seed = std::env::var("THINWALLET_EXPERIMENT_PROVER_SEED")
          .ok()
          .and_then(|value| value.parse::<u64>().ok())
          .unwrap_or(0x3a52_02d2_u64);
        tape.append_scalar(b"init_randomness", &Scalar::from(seed));
      }
      tape
    };
    Self::from_transcript(tape, std::str::from_utf8(name).unwrap_or("unknown_root"))
  }

  pub(crate) fn from_phase_seed(name: &'static [u8], seed: &[u8; 32]) -> Self {
    let mut tape = Transcript::new(name);
    tape.append_message(b"phase_seed_v1", seed);
    Self::from_transcript(tape, std::str::from_utf8(name).unwrap_or("unknown_root"))
  }

  pub fn root_label(&self) -> &'static str {
    self.root_label
  }

  pub fn random_scalar(&mut self, label: &'static [u8]) -> Scalar {
    if self.frontier_sealed {
      self.post_frontier_attempts = self.post_frontier_attempts.saturating_add(1);
      panic!("random tape sample requested after frontier sealing");
    }
    let ordinal = self.label_ordinals.entry(label.to_vec()).or_insert(0);
    let coordinate = (label.to_vec(), *ordinal);
    assert!(
      self.sample_coordinates.insert(coordinate),
      "random tape label/counter coordinate reused"
    );
    *ordinal = ordinal.saturating_add(1);
    self.scalar_samples = self.scalar_samples.saturating_add(1);
    self.bytes_consumed = self.bytes_consumed.saturating_add(WIDE_SAMPLE_BYTES as u64);
    self.tape.challenge_scalar(label)
  }

  pub fn random_vector(&mut self, label: &'static [u8], len: usize) -> Vec<Scalar> {
    (0..len).map(|_| self.random_scalar(label)).collect()
  }

  pub(crate) fn seal_frontier(&mut self) {
    self.frontier_sealed = true;
    #[cfg(feature = "thinwallet-experiment")]
    thinwallet_instrumentation::record_trace_seal(self.root_label);
  }

  pub(crate) fn audit(&self) -> RandomTapeAudit {
    RandomTapeAudit {
      scalar_samples: self.scalar_samples,
      bytes_consumed: self.bytes_consumed,
      post_frontier_attempts: self.post_frontier_attempts,
      frontier_sealed: self.frontier_sealed,
      sample_coordinates_unique: self.sample_coordinates.len() == self.scalar_samples as usize,
    }
  }

  fn from_transcript(tape: Transcript, root_label: &'static str) -> Self {
    Self {
      tape,
      root_label,
      scalar_samples: 0,
      bytes_consumed: 0,
      post_frontier_attempts: 0,
      frontier_sealed: false,
      label_ordinals: HashMap::new(),
      sample_coordinates: HashSet::new(),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn random_vector_counts_each_wide_sample_once() {
    let mut tape = RandomTape::from_phase_seed(b"sat_test", &[7; 32]);
    assert_eq!(tape.random_vector(b"vector", 5).len(), 5);
    let audit = tape.audit();
    assert_eq!(audit.scalar_samples, 5);
    assert_eq!(audit.bytes_consumed, 5 * WIDE_SAMPLE_BYTES as u64);
    assert!(audit.sample_coordinates_unique);
  }

  #[test]
  fn every_sample_consumes_exactly_64_bytes_and_coordinates_do_not_repeat() {
    let mut tape = RandomTape::from_phase_seed(b"sat_test", &[8; 32]);
    let _ = tape.random_scalar(b"same_label");
    let _ = tape.random_scalar(b"same_label");
    let audit = tape.audit();
    assert_eq!(audit.scalar_samples, 2);
    assert_eq!(audit.bytes_consumed / audit.scalar_samples, 64);
    assert!(audit.sample_coordinates_unique);
  }

  #[test]
  fn sealed_sat_tape_rejects_later_samples() {
    let mut tape = RandomTape::from_phase_seed(b"sat_test", &[9; 32]);
    let _ = tape.random_scalar(b"before");
    tape.seal_frontier();
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let _ = tape.random_scalar(b"after");
    }));
    assert!(rejected.is_err());
    let audit = tape.audit();
    assert_eq!(audit.scalar_samples, 1);
    assert_eq!(audit.post_frontier_attempts, 1);
    assert!(audit.frontier_sealed);
  }
}
