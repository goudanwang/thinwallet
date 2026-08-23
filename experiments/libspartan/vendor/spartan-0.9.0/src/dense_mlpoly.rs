#![allow(clippy::too_many_arguments)]
use super::commitments::{Commitments, MultiCommitGens};
use super::errors::ProofVerifyError;
use super::group::{CompressedGroup, GroupElement, VartimeMultiscalarMul};
use super::math::Math;
use super::nizk::{DotProductProofGens, DotProductProofLog};
use super::pbmo_commitment::maybe_commit_private_rows;
use super::prover_msm::{basis_digest, prover_msm, ProverMsmContext};
use super::random::RandomTape;
use super::scalar::Scalar;
use super::state_store::{FileBackedStateStore, ProverStateStore, StateStoreConfig};
use super::transcript::{audit_append_message, AppendToTranscript, ProofTranscript};
use core::ops::Index;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[cfg(feature = "multicore")]
use rayon::prelude::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct DensePolynomial {
  num_vars: usize, // the number of variables in the multilinear polynomial
  len: usize,
  Z: Vec<Scalar>, // evaluations of the polynomial in all the 2^num_vars Boolean inputs
}

/// File-backed dense polynomial used by the single fixed Phase V3A strategy.
pub(crate) struct FileBackedDensePolynomial {
  num_vars: usize,
  len: usize,
  component: String,
  store: Mutex<FileBackedStateStore>,
}

static EXTERNAL_POLY_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Serialize, Deserialize)]
pub struct PolyCommitmentGens {
  pub gens: DotProductProofGens,
}

impl PolyCommitmentGens {
  // the number of variables in the multilinear polynomial
  pub fn new(num_vars: usize, label: &'static [u8]) -> PolyCommitmentGens {
    let (_left, right) = EqPolynomial::compute_factored_lens(num_vars);
    let gens = DotProductProofGens::new(right.pow2(), label);
    PolyCommitmentGens { gens }
  }
}

pub struct PolyCommitmentBlinds {
  blinds: Vec<Scalar>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolyCommitment {
  C: Vec<CompressedGroup>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConstPolyCommitment {
  C: CompressedGroup,
}

pub struct EqPolynomial {
  r: Vec<Scalar>,
}

impl EqPolynomial {
  pub fn new(r: Vec<Scalar>) -> Self {
    EqPolynomial { r }
  }

  pub fn evaluate(&self, rx: &[Scalar]) -> Scalar {
    assert_eq!(self.r.len(), rx.len());
    (0..rx.len())
      .map(|i| self.r[i] * rx[i] + (Scalar::one() - self.r[i]) * (Scalar::one() - rx[i]))
      .product()
  }

  pub fn evals(&self) -> Vec<Scalar> {
    let ell = self.r.len();

    let mut evals: Vec<Scalar> = vec![Scalar::one(); ell.pow2()];
    let mut size = 1;
    for j in 0..ell {
      // in each iteration, we double the size of chis
      size *= 2;
      for i in (0..size).rev().step_by(2) {
        // copy each element from the prior iteration twice
        let scalar = evals[i / 2];
        evals[i] = scalar * self.r[j];
        evals[i - 1] = scalar - evals[i];
      }
    }
    evals
  }

  pub fn compute_factored_lens(ell: usize) -> (usize, usize) {
    (ell / 2, ell - ell / 2)
  }

  pub fn compute_factored_evals(&self) -> (Vec<Scalar>, Vec<Scalar>) {
    let ell = self.r.len();
    let (left_num_vars, _right_num_vars) = EqPolynomial::compute_factored_lens(ell);

    let L = EqPolynomial::new(self.r[..left_num_vars].to_vec()).evals();
    let R = EqPolynomial::new(self.r[left_num_vars..ell].to_vec()).evals();

    (L, R)
  }
}

pub struct IdentityPolynomial {
  size_point: usize,
}

impl IdentityPolynomial {
  pub fn new(size_point: usize) -> Self {
    IdentityPolynomial { size_point }
  }

  pub fn evaluate(&self, r: &[Scalar]) -> Scalar {
    let len = r.len();
    assert_eq!(len, self.size_point);
    (0..len)
      .map(|i| Scalar::from((len - i - 1).pow2() as u64) * r[i])
      .sum()
  }
}

impl DensePolynomial {
  fn audit_private_commitment(unblinded: &[GroupElement], blinded: &[CompressedGroup]) {
    #[cfg(feature = "thinwallet-experiment")]
    {
      let call_id = thinwallet_instrumentation::next_commitment_call_id();
      for (index, point) in unblinded.iter().enumerate() {
        thinwallet_instrumentation::record_commitment(
          call_id,
          index,
          unblinded.len(),
          point.compress().as_bytes(),
          false,
        );
      }
      for (index, point) in blinded.iter().enumerate() {
        thinwallet_instrumentation::record_commitment(
          call_id,
          index,
          blinded.len(),
          point.as_bytes(),
          true,
        );
      }
    }
  }

  pub fn new(Z: Vec<Scalar>) -> Self {
    DensePolynomial {
      num_vars: Z.len().log_2(),
      len: Z.len(),
      Z,
    }
  }

  pub fn get_num_vars(&self) -> usize {
    self.num_vars
  }

  pub fn len(&self) -> usize {
    self.len
  }

  pub fn clone(&self) -> DensePolynomial {
    DensePolynomial::new(self.Z[0..self.len].to_vec())
  }

  pub fn split(&self, idx: usize) -> (DensePolynomial, DensePolynomial) {
    assert!(idx < self.len());
    (
      DensePolynomial::new(self.Z[..idx].to_vec()),
      DensePolynomial::new(self.Z[idx..2 * idx].to_vec()),
    )
  }

  #[cfg(feature = "multicore")]
  fn commit_inner(
    &self,
    blinds: &[Scalar],
    gens: &MultiCommitGens,
    private_scalars: bool,
  ) -> PolyCommitment {
    let L_size = blinds.len();
    let R_size = self.Z.len() / L_size;
    assert_eq!(L_size * R_size, self.Z.len());
    if private_scalars {
      if let Some(points) = maybe_commit_private_rows(&self.Z, L_size, R_size, &gens.G) {
        #[cfg(feature = "thinwallet-experiment")]
        let _blinding_phase = thinwallet_instrumentation::PhaseGuard::begin("native_blinding");
        let C = points
          .iter()
          .zip(blinds)
          .map(|(point, blind)| (*point + *blind * gens.h).compress())
          .collect::<Vec<_>>();
        Self::audit_private_commitment(&points, &C);
        return PolyCommitment { C };
      }
    }
    #[cfg(feature = "thinwallet-experiment")]
    let _local_msm_phase = thinwallet_instrumentation::PhaseGuard::begin("commitment_local_msm");
    let points = (0..L_size)
      .into_par_iter()
      .map(|i| {
        let scalars = &self.Z[R_size * i..R_size * (i + 1)];
        let context = ProverMsmContext {
          msm_id: format!("dense_mlpoly.private_commit.0.chunk.{i}"),
          logical_commitment_id: "dense_mlpoly.private_commit.0".to_string(),
          chunk_index: i,
          transcript_phase: "r1cs_witness_commitment".to_string(),
          basis_digest: basis_digest(&gens.G),
          basis_start: 0,
          basis_end: scalars.len(),
          private_scalars,
          scalar_count: scalars.len(),
          separately_absorbed_into_transcript: true,
          accumulated_into_larger_commitment: false,
        };
        prover_msm(&context, scalars, &gens.G)
      })
      .collect::<Vec<_>>();
    #[cfg(feature = "thinwallet-experiment")]
    drop(_local_msm_phase);
    #[cfg(feature = "thinwallet-experiment")]
    if private_scalars {
      thinwallet_instrumentation::increment_counter("native_commitment_calls", 1);
      thinwallet_instrumentation::increment_counter("native_commitment_rows", L_size as u64);
    }
    #[cfg(feature = "thinwallet-experiment")]
    let _blinding_phase = thinwallet_instrumentation::PhaseGuard::begin("native_blinding");
    let C = points
      .iter()
      .zip(blinds)
      .map(|(point, blind)| (*point + *blind * gens.h).compress())
      .collect::<Vec<_>>();
    if private_scalars {
      Self::audit_private_commitment(&points, &C);
    }
    PolyCommitment { C }
  }

  #[cfg(not(feature = "multicore"))]
  fn commit_inner(
    &self,
    blinds: &[Scalar],
    gens: &MultiCommitGens,
    private_scalars: bool,
  ) -> PolyCommitment {
    let L_size = blinds.len();
    let R_size = self.Z.len() / L_size;
    assert_eq!(L_size * R_size, self.Z.len());
    if private_scalars {
      if let Some(points) = maybe_commit_private_rows(&self.Z, L_size, R_size, &gens.G) {
        #[cfg(feature = "thinwallet-experiment")]
        let _blinding_phase = thinwallet_instrumentation::PhaseGuard::begin("native_blinding");
        let C = points
          .iter()
          .zip(blinds)
          .map(|(point, blind)| (*point + *blind * gens.h).compress())
          .collect::<Vec<_>>();
        Self::audit_private_commitment(&points, &C);
        return PolyCommitment { C };
      }
    }
    #[cfg(feature = "thinwallet-experiment")]
    let _local_msm_phase = thinwallet_instrumentation::PhaseGuard::begin("commitment_local_msm");
    let points = (0..L_size)
      .map(|i| {
        let scalars = &self.Z[R_size * i..R_size * (i + 1)];
        let context = ProverMsmContext {
          msm_id: format!("dense_mlpoly.private_commit.0.chunk.{i}"),
          logical_commitment_id: "dense_mlpoly.private_commit.0".to_string(),
          chunk_index: i,
          transcript_phase: "r1cs_witness_commitment".to_string(),
          basis_digest: basis_digest(&gens.G),
          basis_start: 0,
          basis_end: scalars.len(),
          private_scalars,
          scalar_count: scalars.len(),
          separately_absorbed_into_transcript: true,
          accumulated_into_larger_commitment: false,
        };
        prover_msm(&context, scalars, &gens.G)
      })
      .collect::<Vec<_>>();
    #[cfg(feature = "thinwallet-experiment")]
    drop(_local_msm_phase);
    #[cfg(feature = "thinwallet-experiment")]
    if private_scalars {
      thinwallet_instrumentation::increment_counter("native_commitment_calls", 1);
      thinwallet_instrumentation::increment_counter("native_commitment_rows", L_size as u64);
    }
    #[cfg(feature = "thinwallet-experiment")]
    let _blinding_phase = thinwallet_instrumentation::PhaseGuard::begin("native_blinding");
    let C = points
      .iter()
      .zip(blinds)
      .map(|(point, blind)| (*point + *blind * gens.h).compress())
      .collect::<Vec<_>>();
    if private_scalars {
      Self::audit_private_commitment(&points, &C);
    }
    PolyCommitment { C }
  }

  pub fn commit(
    &self,
    gens: &PolyCommitmentGens,
    random_tape: Option<&mut RandomTape>,
  ) -> (PolyCommitment, PolyCommitmentBlinds) {
    #[cfg(feature = "thinwallet-experiment")]
    let _prepare_phase = thinwallet_instrumentation::PhaseGuard::begin("commitment_prepare");
    let n = self.Z.len();
    let ell = self.get_num_vars();
    assert_eq!(n, ell.pow2());

    let (left_num_vars, right_num_vars) = EqPolynomial::compute_factored_lens(ell);
    let L_size = left_num_vars.pow2();
    let R_size = right_num_vars.pow2();
    assert_eq!(L_size * R_size, n);

    let private_scalars = random_tape.is_some();
    let blinds = if let Some(t) = random_tape {
      let trace_root = t.root_label();
      let blinds = t.random_vector(b"poly_blinds", L_size);
      #[cfg(feature = "thinwallet-experiment")]
      thinwallet_instrumentation::record_trace_event(
        "sample_poly_blinds",
        &[],
        &["blinds_vars"],
        Some(trace_root),
        &[],
        false,
      );
      PolyCommitmentBlinds { blinds }
    } else {
      PolyCommitmentBlinds {
        blinds: vec![Scalar::zero(); L_size],
      }
    };

    let commitment = self.commit_inner(&blinds.blinds, &gens.gens.gens_n, private_scalars);
    #[cfg(feature = "thinwallet-experiment")]
    if private_scalars {
      thinwallet_instrumentation::record_trace_event(
        "native_blinding",
        &["row_points", "blinds_vars", "H"],
        &["comm_vars"],
        None,
        &["comm_vars"],
        false,
      );
    }
    (commitment, blinds)
  }

  pub fn bound(&self, L: &[Scalar]) -> Vec<Scalar> {
    let (left_num_vars, right_num_vars) = EqPolynomial::compute_factored_lens(self.get_num_vars());
    let L_size = left_num_vars.pow2();
    let R_size = right_num_vars.pow2();
    (0..R_size)
      .map(|i| (0..L_size).map(|j| L[j] * self.Z[j * R_size + i]).sum())
      .collect()
  }

  pub fn bound_poly_var_top(&mut self, r: &Scalar) {
    let n = self.len() / 2;
    for i in 0..n {
      self.Z[i] = self.Z[i] + r * (self.Z[i + n] - self.Z[i]);
    }
    self.Z.truncate(n); // Resize the vector Z to the new length
    self.num_vars -= 1;
    self.len = n;
  }

  pub fn bound_poly_var_bot(&mut self, r: &Scalar) {
    let n = self.len() / 2;
    for i in 0..n {
      self.Z[i] = self.Z[2 * i] + r * (self.Z[2 * i + 1] - self.Z[2 * i]);
    }
    self.Z.truncate(n); // Resize the vector Z to the new length
    self.num_vars -= 1;
    self.len = n;
  }

  // returns Z(r) in O(n) time
  pub fn evaluate(&self, r: &[Scalar]) -> Scalar {
    // r must have a value for each variable
    assert_eq!(r.len(), self.get_num_vars());
    let chis = EqPolynomial::new(r.to_vec()).evals();
    assert_eq!(chis.len(), self.Z.len());
    DotProductProofLog::compute_dotproduct(&self.Z, &chis)
  }

  fn vec(&self) -> &Vec<Scalar> {
    &self.Z
  }

  pub(crate) fn values(&self) -> &[Scalar] {
    &self.Z
  }

  pub fn extend(&mut self, other: &DensePolynomial) {
    // TODO: allow extension even when some vars are bound
    assert_eq!(self.Z.len(), self.len);
    let other_vec = other.vec();
    assert_eq!(other_vec.len(), self.len);
    self.Z.extend(other_vec);
    self.num_vars += 1;
    self.len *= 2;
    assert_eq!(self.Z.len(), self.len);
  }

  pub fn merge<'a, I>(polys: I) -> DensePolynomial
  where
    I: IntoIterator<Item = &'a DensePolynomial>,
  {
    let mut Z: Vec<Scalar> = Vec::new();
    for poly in polys.into_iter() {
      Z.extend(poly.vec());
    }

    // pad the polynomial with zero polynomial at the end
    Z.resize(Z.len().next_power_of_two(), Scalar::zero());

    DensePolynomial::new(Z)
  }

  pub fn from_usize(Z: &[usize]) -> Self {
    DensePolynomial::new(
      (0..Z.len())
        .map(|i| Scalar::from(Z[i] as u64))
        .collect::<Vec<Scalar>>(),
    )
  }
}

impl FileBackedDensePolynomial {
  pub(crate) fn len(&self) -> usize {
    self.len
  }

  pub(crate) fn commit_scalar_iter_plain<I>(
    scalars: I,
    logical_len: usize,
    gens: &PolyCommitmentGens,
  ) -> io::Result<(PolyCommitment, PolyCommitmentBlinds)>
  where
    I: IntoIterator<Item = Scalar>,
  {
    if logical_len == 0 {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "empty scalar iterator",
      ));
    }
    let padded_len = logical_len.next_power_of_two();
    let num_vars = padded_len.log_2();
    let (left_num_vars, right_num_vars) = EqPolynomial::compute_factored_lens(num_vars);
    let left_size = left_num_vars.pow2();
    let right_size = right_num_vars.pow2();
    let mut row = Vec::with_capacity(right_size);
    let mut points = Vec::with_capacity(left_size);
    let mut count = 0usize;
    for scalar in scalars
      .into_iter()
      .chain((logical_len..padded_len).map(|_| Scalar::zero()))
    {
      if count >= padded_len {
        return Err(io::Error::new(
          io::ErrorKind::InvalidData,
          "too many scalars",
        ));
      }
      row.push(scalar);
      count += 1;
      if row.len() == right_size {
        let row_index = points.len();
        let context = ProverMsmContext {
          msm_id: format!("dense_mlpoly.private_commit.0.chunk.{row_index}"),
          logical_commitment_id: "dense_mlpoly.private_commit.0".to_string(),
          chunk_index: row_index,
          transcript_phase: "r1cs_witness_commitment".to_string(),
          basis_digest: basis_digest(&gens.gens.gens_n.G),
          basis_start: 0,
          basis_end: row.len(),
          private_scalars: false,
          scalar_count: row.len(),
          separately_absorbed_into_transcript: true,
          accumulated_into_larger_commitment: false,
        };
        points.push(prover_msm(&context, &row, &gens.gens.gens_n.G).compress());
        row.fill(Scalar::zero());
        row.clear();
      }
    }
    if count != padded_len || !row.is_empty() || points.len() != left_size {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid polynomial shape",
      ));
    }
    Ok((
      PolyCommitment { C: points },
      PolyCommitmentBlinds {
        blinds: vec![Scalar::zero(); left_size],
      },
    ))
  }

  pub(crate) fn from_polynomials<'a, I>(polys: I) -> io::Result<Self>
  where
    I: IntoIterator<Item = &'a DensePolynomial>,
  {
    Self::from_polynomials_named(polys, "comb_ops")
  }

  pub(crate) fn from_polynomials_named<'a, I>(polys: I, component: &str) -> io::Result<Self>
  where
    I: IntoIterator<Item = &'a DensePolynomial>,
  {
    let id = EXTERNAL_POLY_ID.fetch_add(1, Ordering::Relaxed);
    let session_id = std::env::var("V3A_STATE_SESSION")
      .unwrap_or_else(|_| format!("v3a-process-{}", std::process::id()));
    let root = std::env::var_os("V3A_STATE_DIR")
      .map(std::path::PathBuf::from)
      .unwrap_or_else(std::env::temp_dir);
    let chunk_size = std::env::var("V3A_STATE_CHUNK_BYTES")
      .ok()
      .and_then(|value| value.parse::<usize>().ok())
      .filter(|value| *value >= 32 && *value % 32 == 0)
      .unwrap_or(128 * 1024);
    let mut key_hasher = Sha256::new();
    key_hasher.update(b"thinwallet-v3a-temporary-metadata-key");
    key_hasher.update(session_id.as_bytes());
    key_hasher.update(std::process::id().to_le_bytes());
    let metadata_key: [u8; 32] = key_hasher.finalize().into();
    let safe_component = component.replace(|ch: char| !ch.is_ascii_alphanumeric(), "-");
    let path = root.join(format!(
      "{safe_component}-{}-{id}.scalars",
      std::process::id()
    ));
    let mut store = FileBackedStateStore::create(StateStoreConfig {
      path,
      session_id,
      metadata_key,
      chunk_size,
      durable: std::env::var("LIBSPARTAN_EPHEMERAL_STATE").as_deref() != Ok("1"),
    })?;

    let mut scalar_count = 0usize;
    let mut chunk = Vec::with_capacity(chunk_size);
    let mut chunk_index = 0u64;
    for poly in polys {
      for scalar in poly.values() {
        chunk.extend_from_slice(&scalar.to_bytes());
        scalar_count += 1;
        if chunk.len() == chunk_size {
          store.write_chunk(chunk_index, &chunk)?;
          chunk.fill(0);
          chunk.clear();
          chunk_index += 1;
        }
      }
    }
    let padded_len = scalar_count.next_power_of_two();
    for _ in scalar_count..padded_len {
      chunk.extend_from_slice(&Scalar::zero().to_bytes());
      if chunk.len() == chunk_size {
        store.write_chunk(chunk_index, &chunk)?;
        chunk.fill(0);
        chunk.clear();
        chunk_index += 1;
      }
    }
    if !chunk.is_empty() {
      store.write_chunk(chunk_index, &chunk)?;
      chunk.fill(0);
    }
    store.release_cache()?;

    Ok(Self {
      num_vars: padded_len.log_2(),
      len: padded_len,
      component: component.to_owned(),
      store: Mutex::new(store),
    })
  }

  pub(crate) fn from_scalar_iter_named<I>(scalars: I, component: &str) -> io::Result<Self>
  where
    I: IntoIterator<Item = Scalar>,
  {
    let id = EXTERNAL_POLY_ID.fetch_add(1, Ordering::Relaxed);
    let session_id = std::env::var("V3A_STATE_SESSION")
      .unwrap_or_else(|_| format!("v3a-process-{}", std::process::id()));
    let root = std::env::var_os("V3A_STATE_DIR")
      .map(std::path::PathBuf::from)
      .unwrap_or_else(std::env::temp_dir);
    let chunk_size = std::env::var("V3A_STATE_CHUNK_BYTES")
      .ok()
      .and_then(|value| value.parse::<usize>().ok())
      .filter(|value| *value >= 32 && *value % 32 == 0)
      .unwrap_or(128 * 1024);
    let mut key_hasher = Sha256::new();
    key_hasher.update(b"thinwallet-v3a-temporary-metadata-key");
    key_hasher.update(session_id.as_bytes());
    key_hasher.update(std::process::id().to_le_bytes());
    let metadata_key: [u8; 32] = key_hasher.finalize().into();
    let safe_component = component.replace(|ch: char| !ch.is_ascii_alphanumeric(), "-");
    let path = root.join(format!(
      "{safe_component}-{}-{id}.scalars",
      std::process::id()
    ));
    let mut store = FileBackedStateStore::create(StateStoreConfig {
      path,
      session_id,
      metadata_key,
      chunk_size,
      durable: std::env::var("LIBSPARTAN_EPHEMERAL_STATE").as_deref() != Ok("1"),
    })?;

    let mut scalar_count = 0usize;
    let mut chunk = Vec::with_capacity(chunk_size);
    let mut chunk_index = 0u64;
    for scalar in scalars {
      chunk.extend_from_slice(&scalar.to_bytes());
      scalar_count += 1;
      if chunk.len() == chunk_size {
        store.write_chunk(chunk_index, &chunk)?;
        chunk.fill(0);
        chunk.clear();
        chunk_index += 1;
      }
    }
    if scalar_count == 0 {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "empty scalar iterator",
      ));
    }
    let padded_len = scalar_count.next_power_of_two();
    for _ in scalar_count..padded_len {
      chunk.extend_from_slice(&Scalar::zero().to_bytes());
      if chunk.len() == chunk_size {
        store.write_chunk(chunk_index, &chunk)?;
        chunk.fill(0);
        chunk.clear();
        chunk_index += 1;
      }
    }
    if !chunk.is_empty() {
      store.write_chunk(chunk_index, &chunk)?;
      chunk.fill(0);
    }
    store.release_cache()?;

    Ok(Self {
      num_vars: padded_len.log_2(),
      len: padded_len,
      component: component.to_owned(),
      store: Mutex::new(store),
    })
  }

  pub(crate) fn scan_scalars(
    &self,
    visitor: &mut dyn FnMut(usize, Scalar) -> io::Result<()>,
  ) -> io::Result<()> {
    let mut scalar_index = 0usize;
    self
      .store
      .lock()
      .unwrap()
      .sequential_scan(&mut |_chunk_index, bytes| {
        if bytes.len() % 32 != 0 {
          return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unaligned scalar chunk",
          ));
        }
        for encoded in bytes.chunks_exact(32) {
          let mut canonical = [0u8; 32];
          canonical.copy_from_slice(encoded);
          let scalar = Option::<Scalar>::from(Scalar::from_bytes(&canonical)).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "non-canonical scalar encoding")
          })?;
          visitor(scalar_index, scalar)?;
          scalar_index += 1;
        }
        Ok(())
      })?;
    if scalar_index != self.len {
      return Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "scalar count mismatch",
      ));
    }
    Ok(())
  }

  pub(crate) fn read_scalar_range(&self, start: usize, length: usize) -> io::Result<Vec<Scalar>> {
    let end = start
      .checked_add(length)
      .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "scalar range overflow"))?;
    if end > self.len {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "scalar range outside polynomial",
      ));
    }
    let mut output = Vec::with_capacity(length);
    self.scan_scalars(&mut |index, scalar| {
      if index >= start && index < end {
        output.push(scalar);
      }
      Ok(())
    })?;
    if output.len() != length {
      return Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "scalar range length mismatch",
      ));
    }
    Ok(output)
  }

  pub(crate) fn evaluate_scalar_range(
    &self,
    start: usize,
    length: usize,
    point: &[Scalar],
  ) -> io::Result<Scalar> {
    if length != 1usize << point.len() || start.saturating_add(length) > self.len {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "scalar evaluation range shape mismatch",
      ));
    }
    let weights = EqPolynomial::new(point.to_vec()).evals();
    let end = start + length;
    let mut evaluation = Scalar::zero();
    let mut seen = 0usize;
    self.scan_scalars(&mut |index, scalar| {
      if index >= start && index < end {
        evaluation += scalar * weights[index - start];
        seen += 1;
      }
      Ok(())
    })?;
    if seen != length {
      return Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "scalar evaluation range length mismatch",
      ));
    }
    Ok(evaluation)
  }

  pub(crate) fn commit_plain(
    &self,
    gens: &PolyCommitmentGens,
  ) -> io::Result<(PolyCommitment, PolyCommitmentBlinds)> {
    let (left_num_vars, right_num_vars) = EqPolynomial::compute_factored_lens(self.num_vars);
    let left_size = left_num_vars.pow2();
    let right_size = right_num_vars.pow2();
    let mut row = Vec::with_capacity(right_size);
    let mut points = Vec::with_capacity(left_size);
    self.scan_scalars(&mut |_index, scalar| {
      row.push(scalar);
      if row.len() == right_size {
        let row_index = points.len();
        let context = ProverMsmContext {
          msm_id: format!("dense_mlpoly.private_commit.0.chunk.{row_index}"),
          logical_commitment_id: "dense_mlpoly.private_commit.0".to_string(),
          chunk_index: row_index,
          transcript_phase: "r1cs_witness_commitment".to_string(),
          basis_digest: basis_digest(&gens.gens.gens_n.G),
          basis_start: 0,
          basis_end: row.len(),
          private_scalars: false,
          scalar_count: row.len(),
          separately_absorbed_into_transcript: true,
          accumulated_into_larger_commitment: false,
        };
        points.push(prover_msm(&context, &row, &gens.gens.gens_n.G).compress());
        row.fill(Scalar::zero());
        row.clear();
      }
      Ok(())
    })?;
    if !row.is_empty() || points.len() != left_size {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid polynomial shape",
      ));
    }
    Ok((
      PolyCommitment { C: points },
      PolyCommitmentBlinds {
        blinds: vec![Scalar::zero(); left_size],
      },
    ))
  }

  fn bound(&self, left: &[Scalar]) -> io::Result<Vec<Scalar>> {
    let (left_num_vars, right_num_vars) = EqPolynomial::compute_factored_lens(self.num_vars);
    let left_size = left_num_vars.pow2();
    let right_size = right_num_vars.pow2();
    if left.len() != left_size {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "left factor length mismatch",
      ));
    }
    let mut result = vec![Scalar::zero(); right_size];
    self.scan_scalars(&mut |index, scalar| {
      let row = index / right_size;
      let column = index % right_size;
      result[column] += left[row] * scalar;
      Ok(())
    })?;
    Ok(result)
  }

  pub(crate) fn bound_at(&self, point: &[Scalar]) -> io::Result<Vec<Scalar>> {
    if point.len() != self.num_vars {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "polynomial binding point mismatch",
      ));
    }
    let (left, _right) = EqPolynomial::new(point.to_vec()).compute_factored_evals();
    self.bound(&left)
  }

  #[cfg(debug_assertions)]
  pub(crate) fn evaluate(&self, r: &[Scalar]) -> io::Result<Scalar> {
    if r.len() != self.num_vars {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "evaluation point mismatch",
      ));
    }
    let (left, right) = EqPolynomial::new(r.to_vec()).compute_factored_evals();
    let bound = self.bound(&left)?;
    Ok(DotProductProofLog::compute_dotproduct(&bound, &right))
  }
}

impl Drop for FileBackedDensePolynomial {
  fn drop(&mut self) {
    if let Ok(store) = self.store.get_mut() {
      let stats = store.stats();
      if let Some(path) = std::env::var_os("V3A_STATE_REPORT_PATH") {
        if let Ok(mut file) = std::fs::OpenOptions::new()
          .create(true)
          .append(true)
          .open(path)
        {
          let _ = writeln!(
            file,
            "{{\"component\":\"{}\",\"bytes_read\":{},\"bytes_written\":{},\"temporary_storage_peak_bytes\":{},\"full_state_passes\":{}}}",
            self.component, stats.bytes_read, stats.bytes_written, stats.peak_bytes, stats.full_scans
          );
        }
      }
    }
  }
}

impl Index<usize> for DensePolynomial {
  type Output = Scalar;

  #[inline(always)]
  fn index(&self, _index: usize) -> &Scalar {
    &(self.Z[_index])
  }
}

impl AppendToTranscript for PolyCommitment {
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
    transcript.append_message(label, b"poly_commitment_begin");
    audit_append_message(label, b"poly_commitment_begin");
    for i in 0..self.C.len() {
      transcript.append_point(b"poly_commitment_share", &self.C[i]);
    }
    transcript.append_message(label, b"poly_commitment_end");
    audit_append_message(label, b"poly_commitment_end");
  }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolyEvalProof {
  proof: DotProductProofLog,
}

impl PolyEvalProof {
  fn protocol_name() -> &'static [u8] {
    b"polynomial evaluation proof"
  }

  pub fn prove(
    poly: &DensePolynomial,
    blinds_opt: Option<&PolyCommitmentBlinds>,
    r: &[Scalar],                  // point at which the polynomial is evaluated
    Zr: &Scalar,                   // evaluation of \widetilde{Z}(r)
    blind_Zr_opt: Option<&Scalar>, // specifies a blind for Zr
    gens: &PolyCommitmentGens,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape,
  ) -> (PolyEvalProof, CompressedGroup) {
    transcript.append_protocol_name(PolyEvalProof::protocol_name());

    // assert vectors are of the right size
    assert_eq!(poly.get_num_vars(), r.len());

    let (left_num_vars, right_num_vars) = EqPolynomial::compute_factored_lens(r.len());
    let L_size = left_num_vars.pow2();
    let R_size = right_num_vars.pow2();

    let default_blinds = PolyCommitmentBlinds {
      blinds: vec![Scalar::zero(); L_size],
    };
    let blinds = blinds_opt.map_or(&default_blinds, |p| p);

    assert_eq!(blinds.blinds.len(), L_size);

    let zero = Scalar::zero();
    let blind_Zr = blind_Zr_opt.map_or(&zero, |p| p);

    // compute the L and R vectors
    let eq = EqPolynomial::new(r.to_vec());
    let (L, R) = eq.compute_factored_evals();
    assert_eq!(L.len(), L_size);
    assert_eq!(R.len(), R_size);

    // compute the vector underneath L*Z and the L*blinds
    // compute vector-matrix product between L and Z viewed as a matrix
    let LZ = poly.bound(&L);
    let LZ_blind: Scalar = (0..L.len()).map(|i| blinds.blinds[i] * L[i]).sum();

    // a dot product proof of size R_size
    let (proof, _C_LR, C_Zr_prime) = DotProductProofLog::prove(
      &gens.gens,
      transcript,
      random_tape,
      &LZ,
      &LZ_blind,
      &R,
      Zr,
      blind_Zr,
    );

    (PolyEvalProof { proof }, C_Zr_prime)
  }

  pub(crate) fn prove_file_backed_plain(
    poly: &FileBackedDensePolynomial,
    r: &[Scalar],
    zr: &Scalar,
    gens: &PolyCommitmentGens,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape,
  ) -> io::Result<(PolyEvalProof, CompressedGroup)> {
    transcript.append_protocol_name(PolyEvalProof::protocol_name());
    if poly.num_vars != r.len() {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "evaluation point mismatch",
      ));
    }
    let (left, right) = EqPolynomial::new(r.to_vec()).compute_factored_evals();
    let lz = poly.bound(&left)?;
    let zero = Scalar::zero();
    let (proof, _commitment, evaluated_commitment) = DotProductProofLog::prove(
      &gens.gens,
      transcript,
      random_tape,
      &lz,
      &zero,
      &right,
      zr,
      &zero,
    );
    Ok((PolyEvalProof { proof }, evaluated_commitment))
  }

  pub(crate) fn prove_prebound_plain(
    num_vars: usize,
    r: &[Scalar],
    zr: &Scalar,
    lz: &[Scalar],
    gens: &PolyCommitmentGens,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape,
  ) -> io::Result<(PolyEvalProof, CompressedGroup)> {
    transcript.append_protocol_name(PolyEvalProof::protocol_name());
    if num_vars != r.len() {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "evaluation point mismatch",
      ));
    }
    let (_left, right) = EqPolynomial::new(r.to_vec()).compute_factored_evals();
    if lz.len() != right.len() {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "prebound vector length mismatch",
      ));
    }
    let zero = Scalar::zero();
    let (proof, _commitment, evaluated_commitment) = DotProductProofLog::prove(
      &gens.gens,
      transcript,
      random_tape,
      lz,
      &zero,
      &right,
      zr,
      &zero,
    );
    Ok((PolyEvalProof { proof }, evaluated_commitment))
  }

  pub fn verify(
    &self,
    gens: &PolyCommitmentGens,
    transcript: &mut Transcript,
    r: &[Scalar],           // point at which the polynomial is evaluated
    C_Zr: &CompressedGroup, // commitment to \widetilde{Z}(r)
    comm: &PolyCommitment,
  ) -> Result<(), ProofVerifyError> {
    transcript.append_protocol_name(PolyEvalProof::protocol_name());

    // compute L and R
    let eq = EqPolynomial::new(r.to_vec());
    let (L, R) = eq.compute_factored_evals();

    // compute a weighted sum of commitments and L
    let C_decompressed = comm.C.iter().map(|pt| pt.decompress().unwrap());

    let C_LZ = GroupElement::vartime_multiscalar_mul(&L, C_decompressed).compress();

    self
      .proof
      .verify(R.len(), &gens.gens, transcript, &R, &C_LZ, C_Zr)
  }

  pub fn verify_plain(
    &self,
    gens: &PolyCommitmentGens,
    transcript: &mut Transcript,
    r: &[Scalar], // point at which the polynomial is evaluated
    Zr: &Scalar,  // evaluation \widetilde{Z}(r)
    comm: &PolyCommitment,
  ) -> Result<(), ProofVerifyError> {
    // compute a commitment to Zr with a blind of zero
    let C_Zr = Zr.commit(&Scalar::zero(), &gens.gens.gens_1).compress();

    self.verify(gens, transcript, r, &C_Zr, comm)
  }
}

#[cfg(test)]
mod tests {
  use super::super::scalar::ScalarFromPrimitives;
  use super::*;
  use rand::rngs::OsRng;

  fn evaluate_with_LR(Z: &[Scalar], r: &[Scalar]) -> Scalar {
    let eq = EqPolynomial::new(r.to_vec());
    let (L, R) = eq.compute_factored_evals();

    let ell = r.len();
    // ensure ell is even
    assert!(ell % 2 == 0);
    // compute n = 2^\ell
    let n = ell.pow2();
    // compute m = sqrt(n) = 2^{\ell/2}
    let m = (n as f64).sqrt() as usize;

    // compute vector-matrix product between L and Z viewed as a matrix
    let LZ = (0..m)
      .map(|i| (0..m).map(|j| L[j] * Z[j * m + i]).sum())
      .collect::<Vec<Scalar>>();

    // compute dot product between LZ and R
    DotProductProofLog::compute_dotproduct(&LZ, &R)
  }

  #[test]
  fn check_polynomial_evaluation() {
    // Z = [1, 2, 1, 4]
    let Z = vec![
      Scalar::one(),
      (2_usize).to_scalar(),
      (1_usize).to_scalar(),
      (4_usize).to_scalar(),
    ];

    // r = [4,3]
    let r = vec![(4_usize).to_scalar(), (3_usize).to_scalar()];

    let eval_with_LR = evaluate_with_LR(&Z, &r);
    let poly = DensePolynomial::new(Z);

    let eval = poly.evaluate(&r);
    assert_eq!(eval, (28_usize).to_scalar());
    assert_eq!(eval_with_LR, eval);
  }

  pub fn compute_factored_chis_at_r(r: &[Scalar]) -> (Vec<Scalar>, Vec<Scalar>) {
    let mut L: Vec<Scalar> = Vec::new();
    let mut R: Vec<Scalar> = Vec::new();

    let ell = r.len();
    assert!(ell % 2 == 0); // ensure ell is even
    let n = ell.pow2();
    let m = (n as f64).sqrt() as usize;

    // compute row vector L
    for i in 0..m {
      let mut chi_i = Scalar::one();
      for j in 0..ell / 2 {
        let bit_j = ((m * i) & (1 << (r.len() - j - 1))) > 0;
        if bit_j {
          chi_i *= r[j];
        } else {
          chi_i *= Scalar::one() - r[j];
        }
      }
      L.push(chi_i);
    }

    // compute column vector R
    for i in 0..m {
      let mut chi_i = Scalar::one();
      for j in ell / 2..ell {
        let bit_j = (i & (1 << (r.len() - j - 1))) > 0;
        if bit_j {
          chi_i *= r[j];
        } else {
          chi_i *= Scalar::one() - r[j];
        }
      }
      R.push(chi_i);
    }
    (L, R)
  }

  pub fn compute_chis_at_r(r: &[Scalar]) -> Vec<Scalar> {
    let ell = r.len();
    let n = ell.pow2();
    let mut chis: Vec<Scalar> = Vec::new();
    for i in 0..n {
      let mut chi_i = Scalar::one();
      for j in 0..r.len() {
        let bit_j = (i & (1 << (r.len() - j - 1))) > 0;
        if bit_j {
          chi_i *= r[j];
        } else {
          chi_i *= Scalar::one() - r[j];
        }
      }
      chis.push(chi_i);
    }
    chis
  }

  pub fn compute_outerproduct(L: Vec<Scalar>, R: Vec<Scalar>) -> Vec<Scalar> {
    assert_eq!(L.len(), R.len());
    (0..L.len())
      .map(|i| (0..R.len()).map(|j| L[i] * R[j]).collect::<Vec<Scalar>>())
      .collect::<Vec<Vec<Scalar>>>()
      .into_iter()
      .flatten()
      .collect::<Vec<Scalar>>()
  }

  #[test]
  fn check_memoized_chis() {
    let mut csprng: OsRng = OsRng;

    let s = 10;
    let mut r: Vec<Scalar> = Vec::new();
    for _i in 0..s {
      r.push(Scalar::random(&mut csprng));
    }
    let chis = tests::compute_chis_at_r(&r);
    let chis_m = EqPolynomial::new(r).evals();
    assert_eq!(chis, chis_m);
  }

  #[test]
  fn check_factored_chis() {
    let mut csprng: OsRng = OsRng;

    let s = 10;
    let mut r: Vec<Scalar> = Vec::new();
    for _i in 0..s {
      r.push(Scalar::random(&mut csprng));
    }
    let chis = EqPolynomial::new(r.clone()).evals();
    let (L, R) = EqPolynomial::new(r).compute_factored_evals();
    let O = compute_outerproduct(L, R);
    assert_eq!(chis, O);
  }

  #[test]
  fn check_memoized_factored_chis() {
    let mut csprng: OsRng = OsRng;

    let s = 10;
    let mut r: Vec<Scalar> = Vec::new();
    for _i in 0..s {
      r.push(Scalar::random(&mut csprng));
    }
    let (L, R) = tests::compute_factored_chis_at_r(&r);
    let eq = EqPolynomial::new(r);
    let (L2, R2) = eq.compute_factored_evals();
    assert_eq!(L, L2);
    assert_eq!(R, R2);
  }

  #[test]
  fn check_polynomial_commit() {
    let Z = vec![
      (1_usize).to_scalar(),
      (2_usize).to_scalar(),
      (1_usize).to_scalar(),
      (4_usize).to_scalar(),
    ];
    let poly = DensePolynomial::new(Z);

    // r = [4,3]
    let r = vec![(4_usize).to_scalar(), (3_usize).to_scalar()];
    let eval = poly.evaluate(&r);
    assert_eq!(eval, (28_usize).to_scalar());

    let gens = PolyCommitmentGens::new(poly.get_num_vars(), b"test-two");
    let (poly_commitment, blinds) = poly.commit(&gens, None);

    let mut random_tape = RandomTape::new(b"proof");
    let mut prover_transcript = Transcript::new(b"example");
    let (proof, C_Zr) = PolyEvalProof::prove(
      &poly,
      Some(&blinds),
      &r,
      &eval,
      None,
      &gens,
      &mut prover_transcript,
      &mut random_tape,
    );

    let mut verifier_transcript = Transcript::new(b"example");
    assert!(proof
      .verify(&gens, &mut verifier_transcript, &r, &C_Zr, &poly_commitment)
      .is_ok());
  }
}
