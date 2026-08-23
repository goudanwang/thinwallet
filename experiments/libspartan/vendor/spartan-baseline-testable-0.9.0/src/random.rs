use super::scalar::Scalar;
use super::transcript::ProofTranscript;
use merlin::Transcript;
#[cfg(not(feature = "phase3ar2-deterministic-tests"))]
use rand::rngs::OsRng;

pub struct RandomTape {
  tape: Transcript,
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
    Self { tape }
  }

  pub fn random_scalar(&mut self, label: &'static [u8]) -> Scalar {
    self.tape.challenge_scalar(label)
  }

  pub fn random_vector(&mut self, label: &'static [u8], len: usize) -> Vec<Scalar> {
    self.tape.challenge_vector(label, len)
  }
}
