use super::group::CompressedGroup;
use super::scalar::Scalar;
use merlin::Transcript;

pub(crate) const WIDE_SAMPLE_BYTES: usize = 64;

pub(crate) fn audit_append_message(label: &[u8], value: &[u8]) {
  #[cfg(feature = "thinwallet-experiment")]
  thinwallet_instrumentation::record_transcript_event("append_message", label, Some(value));
}

pub trait ProofTranscript {
  fn append_protocol_name(&mut self, protocol_name: &'static [u8]);
  fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar);
  fn append_point(&mut self, label: &'static [u8], point: &CompressedGroup);
  fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
  fn challenge_vector(&mut self, label: &'static [u8], len: usize) -> Vec<Scalar>;
}

impl ProofTranscript for Transcript {
  fn append_protocol_name(&mut self, protocol_name: &'static [u8]) {
    self.append_message(b"protocol-name", protocol_name);
    audit_append_message(b"protocol-name", protocol_name);
  }

  fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
    let bytes = scalar.to_bytes();
    self.append_message(label, &bytes);
    #[cfg(feature = "thinwallet-experiment")]
    thinwallet_instrumentation::record_transcript_event("append_scalar", label, Some(&bytes));
  }

  fn append_point(&mut self, label: &'static [u8], point: &CompressedGroup) {
    self.append_message(label, point.as_bytes());
    #[cfg(feature = "thinwallet-experiment")]
    thinwallet_instrumentation::record_transcript_event(
      "append_point",
      label,
      Some(point.as_bytes()),
    );
  }

  fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
    let mut buf = [0u8; WIDE_SAMPLE_BYTES];
    self.challenge_bytes(label, &mut buf);
    let scalar = Scalar::from_bytes_wide(&buf);
    #[cfg(feature = "thinwallet-experiment")]
    thinwallet_instrumentation::record_transcript_event("challenge_scalar", label, None);
    scalar
  }

  fn challenge_vector(&mut self, label: &'static [u8], len: usize) -> Vec<Scalar> {
    (0..len)
      .map(|_i| self.challenge_scalar(label))
      .collect::<Vec<Scalar>>()
  }
}

pub trait AppendToTranscript {
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript);
}

impl AppendToTranscript for Scalar {
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
    transcript.append_scalar(label, self);
  }
}

impl AppendToTranscript for [Scalar] {
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
    transcript.append_message(label, b"begin_append_vector");
    audit_append_message(label, b"begin_append_vector");
    for item in self {
      transcript.append_scalar(label, item);
    }
    transcript.append_message(label, b"end_append_vector");
    audit_append_message(label, b"end_append_vector");
  }
}

impl AppendToTranscript for CompressedGroup {
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
    transcript.append_point(label, self);
  }
}
