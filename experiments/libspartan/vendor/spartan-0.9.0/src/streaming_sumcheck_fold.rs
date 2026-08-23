//! Bounded-memory external folds for canonical scalar state objects.
#![allow(missing_docs)]

use super::multi_state_store::{
  MultiObjectFileBackedStateStore, ProverStateStore, StateObjectDescriptor, VerifiedRangeReader,
};
pub use super::scalar::Scalar as StreamingScalar;
use std::io;

type Scalar = StreamingScalar;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamingPolynomial {
  pub object_id: String,
  pub scalar_count: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StreamingFoldStats {
  pub read_bytes: u64,
  pub write_bytes: u64,
  pub input_chunks: u64,
  pub output_chunks: u64,
  pub peak_buffer_bytes: usize,
}

pub(crate) struct StreamingPolynomialReader {
  inner: VerifiedRangeReader,
}

fn decode_scalars(bytes: &[u8]) -> io::Result<Vec<Scalar>> {
  if bytes.len() % 32 != 0 {
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "unaligned canonical scalar stream",
    ));
  }
  bytes
    .chunks_exact(32)
    .map(|encoded| {
      let mut canonical = [0u8; 32];
      canonical.copy_from_slice(encoded);
      Option::<Scalar>::from(Scalar::from_bytes(&canonical))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-canonical scalar encoding"))
    })
    .collect()
}

fn encode_scalars(values: &[Scalar]) -> Vec<u8> {
  values.iter().flat_map(|value| value.to_bytes()).collect()
}

fn descriptor(
  store: &MultiObjectFileBackedStateStore,
  object_id: &str,
  operator_id: &str,
  scalar_count: usize,
) -> StateObjectDescriptor {
  store.descriptor(object_id, operator_id, "Scalar", scalar_count as u64)
}

fn chunk_scalars(store: &MultiObjectFileBackedStateStore) -> usize {
  (store.maximum_chunk_bytes() / 32).max(1)
}

fn challenge_tag(challenge: &Scalar) -> String {
  challenge
    .to_bytes()
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect()
}

fn read_range(
  store: &mut MultiObjectFileBackedStateStore,
  object_id: &str,
  scalar_offset: usize,
  scalar_count: usize,
) -> io::Result<Vec<Scalar>> {
  let bytes = store.range_read(object_id, (scalar_offset * 32) as u64, scalar_count * 32)?;
  decode_scalars(&bytes)
}

impl StreamingPolynomial {
  pub(crate) fn existing(object_id: impl Into<String>, scalar_count: usize) -> Self {
    Self {
      object_id: object_id.into(),
      scalar_count,
    }
  }

  pub(crate) fn preferred_chunk_scalars(store: &MultiObjectFileBackedStateStore) -> usize {
    chunk_scalars(store)
  }

  pub(crate) fn read_segment(
    &self,
    store: &mut MultiObjectFileBackedStateStore,
    scalar_offset: usize,
    scalar_count: usize,
  ) -> io::Result<Vec<Scalar>> {
    let end = scalar_offset
      .checked_add(scalar_count)
      .filter(|end| *end <= self.scalar_count)
      .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "segment outside table"))?;
    debug_assert!(end <= self.scalar_count);
    read_range(store, &self.object_id, scalar_offset, scalar_count)
  }

  pub(crate) fn open_reader(
    &self,
    store: &MultiObjectFileBackedStateStore,
  ) -> io::Result<StreamingPolynomialReader> {
    Ok(StreamingPolynomialReader {
      inner: store.open_verified_range_reader(&self.object_id)?,
    })
  }

  pub(crate) fn read_segment_from(
    &self,
    store: &mut MultiObjectFileBackedStateStore,
    reader: &mut StreamingPolynomialReader,
    scalar_offset: usize,
    scalar_count: usize,
  ) -> io::Result<Vec<Scalar>> {
    scalar_offset
      .checked_add(scalar_count)
      .filter(|end| *end <= self.scalar_count)
      .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "segment outside table"))?;
    let bytes = store.read_verified_range(
      &mut reader.inner,
      (scalar_offset * 32) as u64,
      scalar_count * 32,
    )?;
    decode_scalars(&bytes)
  }

  pub fn write(
    store: &mut MultiObjectFileBackedStateStore,
    object_id: impl Into<String>,
    operator_id: &str,
    values: &[Scalar],
  ) -> io::Result<Self> {
    let object_id = object_id.into();
    store.create_object(descriptor(store, &object_id, operator_id, values.len()))?;
    let width = chunk_scalars(store);
    for (chunk_index, chunk) in values.chunks(width).enumerate() {
      store.append_chunk(&object_id, chunk_index as u64, &encode_scalars(chunk))?;
    }
    store.seal_object(&object_id)?;
    Ok(Self {
      object_id,
      scalar_count: values.len(),
    })
  }

  pub(crate) fn write_generated<F>(
    store: &mut MultiObjectFileBackedStateStore,
    object_id: impl Into<String>,
    operator_id: &str,
    scalar_count: usize,
    mut source: F,
  ) -> io::Result<Self>
  where
    F: FnMut(usize, usize) -> io::Result<Vec<Scalar>>,
  {
    let object_id = object_id.into();
    store.create_object(descriptor(store, &object_id, operator_id, scalar_count))?;
    let width = chunk_scalars(store);
    for (chunk_index, start) in (0..scalar_count).step_by(width).enumerate() {
      let count = width.min(scalar_count - start);
      let values = source(start, count)?;
      if values.len() != count {
        return Err(io::Error::new(
          io::ErrorKind::InvalidData,
          "generated scalar chunk has the wrong length",
        ));
      }
      store.append_chunk(&object_id, chunk_index as u64, &encode_scalars(&values))?;
    }
    store.seal_object(&object_id)?;
    Ok(Self {
      object_id,
      scalar_count,
    })
  }

  pub fn read_all(&self, store: &mut MultiObjectFileBackedStateStore) -> io::Result<Vec<Scalar>> {
    read_range(store, &self.object_id, 0, self.scalar_count)
  }

  pub fn read_scalar(&self, store: &mut MultiObjectFileBackedStateStore) -> io::Result<Scalar> {
    if self.scalar_count != 1 {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "streaming polynomial is not fully folded",
      ));
    }
    Ok(read_range(store, &self.object_id, 0, 1)?[0])
  }

  /// Folds the top multilinear variable, matching `DensePolynomial::bound_poly_var_top`.
  pub fn fold_top(
    &mut self,
    store: &mut MultiObjectFileBackedStateStore,
    next_object_id: impl Into<String>,
    challenge: &Scalar,
    round: usize,
  ) -> io::Result<StreamingFoldStats> {
    if self.scalar_count < 2 || !self.scalar_count.is_power_of_two() {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "top fold requires a non-constant power-of-two table",
      ));
    }
    let next_object_id = next_object_id.into();
    let next_count = self.scalar_count / 2;
    store.create_object(descriptor(
      store,
      &next_object_id,
      &format!(
        "StreamingSumcheckFold/top/round-{round}/challenge-{}",
        challenge_tag(challenge)
      ),
      next_count,
    ))?;
    let width = chunk_scalars(store);
    let mut stats = StreamingFoldStats::default();
    let mut reader = self.open_reader(store)?;
    for (chunk_index, start) in (0..next_count).step_by(width).enumerate() {
      let count = width.min(next_count - start);
      let low = self.read_segment_from(store, &mut reader, start, count)?;
      let high = self.read_segment_from(store, &mut reader, next_count + start, count)?;
      let output = low
        .iter()
        .zip(high.iter())
        .map(|(low, high)| *low + challenge * (*high - *low))
        .collect::<Vec<_>>();
      let encoded = encode_scalars(&output);
      store.append_chunk(&next_object_id, chunk_index as u64, &encoded)?;
      stats.read_bytes += (count * 64) as u64;
      stats.write_bytes += encoded.len() as u64;
      stats.input_chunks += 2;
      stats.output_chunks += 1;
      stats.peak_buffer_bytes = stats
        .peak_buffer_bytes
        .max((low.capacity() + high.capacity() + output.capacity()) * 32 + encoded.capacity());
    }
    store.seal_object(&next_object_id)?;
    store.delete_object(&self.object_id)?;
    self.object_id = next_object_id;
    self.scalar_count = next_count;
    Ok(stats)
  }

  /// Implements the standard adjacent-pair fold `T[2i] + r(T[2i+1]-T[2i])`.
  pub fn fold_adjacent(
    &mut self,
    store: &mut MultiObjectFileBackedStateStore,
    next_object_id: impl Into<String>,
    challenge: &Scalar,
    round: usize,
  ) -> io::Result<StreamingFoldStats> {
    if self.scalar_count < 2 || !self.scalar_count.is_power_of_two() {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "adjacent fold requires a non-constant power-of-two table",
      ));
    }
    let next_object_id = next_object_id.into();
    let next_count = self.scalar_count / 2;
    store.create_object(descriptor(
      store,
      &next_object_id,
      &format!(
        "StreamingSumcheckFold/adjacent/round-{round}/challenge-{}",
        challenge_tag(challenge)
      ),
      next_count,
    ))?;
    let width = chunk_scalars(store);
    let mut stats = StreamingFoldStats::default();
    let mut reader = self.open_reader(store)?;
    for (chunk_index, start) in (0..next_count).step_by(width).enumerate() {
      let count = width.min(next_count - start);
      let input = self.read_segment_from(store, &mut reader, start * 2, count * 2)?;
      let output = input
        .chunks_exact(2)
        .map(|pair| pair[0] + challenge * (pair[1] - pair[0]))
        .collect::<Vec<_>>();
      let encoded = encode_scalars(&output);
      store.append_chunk(&next_object_id, chunk_index as u64, &encoded)?;
      stats.read_bytes += (count * 64) as u64;
      stats.write_bytes += encoded.len() as u64;
      stats.input_chunks += 1;
      stats.output_chunks += 1;
      stats.peak_buffer_bytes = stats
        .peak_buffer_bytes
        .max((input.capacity() + output.capacity()) * 32 + encoded.capacity());
    }
    store.seal_object(&next_object_id)?;
    store.delete_object(&self.object_id)?;
    self.object_id = next_object_id;
    self.scalar_count = next_count;
    Ok(stats)
  }
}
