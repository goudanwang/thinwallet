#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::needless_range_loop)]
use super::dense_mlpoly::{DensePolynomial, FileBackedDensePolynomial};
use super::dense_mlpoly::{
  EqPolynomial, IdentityPolynomial, PolyCommitment, PolyCommitmentGens, PolyEvalProof,
};
use super::errors::ProofVerifyError;
use super::math::Math;
use super::memory_budget::{BudgetAccountedArena, ProverMemoryBudget};
use super::multi_state_store::{
  MultiObjectFileBackedStateStore, MultiObjectStoreConfig, ProverStateStore, StateDurability,
};
use super::nizk::DotProductProofLog;
use super::product_tree::{DotProductCircuit, ProductCircuit, ProductCircuitEvalProofBatched};
use super::random::RandomTape;
use super::scalar::Scalar;
use super::timer::Timer;
use super::transcript::{audit_append_message, AppendToTranscript, ProofTranscript};
use core::cmp::Ordering;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::Instant;

use crate::memory_trace::{self, AllocationClass};

const SPARSE_DENSE_VECS: AllocationClass = AllocationClass {
  source_file: "src/sparse_mlpoly.rs",
  function: "SparseMatPolynomial::sparse_to_dense_vecs",
  component: "sparse polynomial structures",
  element_type: "usize/Scalar",
  privacy: "public",
  replayable: true,
  streamable: true,
};
const ADDRESS_TIMESTAMPS: AllocationClass = AllocationClass {
  source_file: "src/sparse_mlpoly.rs",
  function: "AddrTimestamps::new",
  component: "sparse polynomial structures",
  element_type: "usize/Scalar",
  privacy: "public",
  replayable: true,
  streamable: true,
};
const ADDRESS_AUDIT_USIZE: AllocationClass = AllocationClass {
  source_file: "src/sparse_mlpoly.rs",
  function: "AddrTimestamps::new:audit_ts_usize",
  component: "sparse polynomial structures",
  element_type: "usize",
  privacy: "public",
  replayable: true,
  streamable: true,
};
const ADDRESS_READ_USIZE: AllocationClass = AllocationClass {
  source_file: "src/sparse_mlpoly.rs",
  function: "AddrTimestamps::new:read_ts_usize",
  component: "sparse polynomial structures",
  element_type: "usize",
  privacy: "public",
  replayable: true,
  streamable: true,
};
const ADDRESS_OPS_SCALAR: AllocationClass = AllocationClass {
  source_file: "src/sparse_mlpoly.rs",
  function: "AddrTimestamps::new:ops_addr_scalar",
  component: "dense multilinear polynomials",
  element_type: "Scalar",
  privacy: "public",
  replayable: true,
  streamable: true,
};
const ADDRESS_READ_SCALAR: AllocationClass = AllocationClass {
  source_file: "src/sparse_mlpoly.rs",
  function: "AddrTimestamps::new:read_ts_scalar",
  component: "dense multilinear polynomials",
  element_type: "Scalar",
  privacy: "public",
  replayable: true,
  streamable: true,
};
const ADDRESS_AUDIT_SCALAR: AllocationClass = AllocationClass {
  source_file: "src/sparse_mlpoly.rs",
  function: "AddrTimestamps::new:audit_ts_scalar",
  component: "dense multilinear polynomials",
  element_type: "Scalar",
  privacy: "public",
  replayable: true,
  streamable: true,
};
const COMBINED_OPS: AllocationClass = AllocationClass {
  source_file: "src/sparse_mlpoly.rs",
  function: "SparseMatPolynomial::multi_sparse_to_dense_rep:comb_ops",
  component: "dense multilinear polynomials",
  element_type: "Scalar",
  privacy: "public",
  replayable: true,
  streamable: true,
};
const COMBINED_MEM: AllocationClass = AllocationClass {
  source_file: "src/sparse_mlpoly.rs",
  function: "SparseMatPolynomial::multi_sparse_to_dense_rep:comb_mem",
  component: "dense multilinear polynomials",
  element_type: "Scalar",
  privacy: "public",
  replayable: true,
  streamable: true,
};
const SPARSE_EVAL_PROOF: AllocationClass = AllocationClass {
  source_file: "src/sparse_mlpoly.rs",
  function: "SparseMatPolyEvalProof::prove",
  component: "Sumcheck folded tables",
  element_type: "Scalar/ProductCircuit",
  privacy: "public",
  replayable: true,
  streamable: true,
};

static ACTIVE_PRODUCT_BUILD_NS: AtomicU64 = AtomicU64::new(0);
static CHECKPOINT_RECOMPUTE_NS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Serialize, Deserialize)]
pub struct SparseMatEntry {
  row: usize,
  col: usize,
  val: Scalar,
}

impl SparseMatEntry {
  pub fn new(row: usize, col: usize, val: Scalar) -> Self {
    SparseMatEntry { row, col, val }
  }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SparseMatPolynomial {
  num_vars_x: usize,
  num_vars_y: usize,
  M: Vec<SparseMatEntry>,
}

pub struct Derefs {
  row_ops_val: Vec<DensePolynomial>,
  col_ops_val: Vec<DensePolynomial>,
  comb: DensePolynomial,
  fs6_row_mem: Vec<Scalar>,
  fs6_col_mem: Vec<Scalar>,
  fs6_table_count: usize,
  fs6_table_len: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DerefsCommitment {
  comm_ops_val: PolyCommitment,
}

impl Derefs {
  pub fn new(row_ops_val: Vec<DensePolynomial>, col_ops_val: Vec<DensePolynomial>) -> Self {
    assert_eq!(row_ops_val.len(), col_ops_val.len());

    // combine all polynomials into a single polynomial (used below to produce a single commitment)
    let comb = DensePolynomial::merge(row_ops_val.iter().chain(col_ops_val.iter()));

    Derefs {
      row_ops_val,
      col_ops_val,
      comb,
      fs6_row_mem: Vec::new(),
      fs6_col_mem: Vec::new(),
      fs6_table_count: 0,
      fs6_table_len: 0,
    }
  }

  fn new_fs6(
    row: &AddrTimestamps,
    col: &AddrTimestamps,
    row_mem_val: &[Scalar],
    col_mem_val: &[Scalar],
  ) -> Self {
    assert_eq!(row.ops_addr_usize.len(), col.ops_addr_usize.len());
    let table_count = row.ops_addr_usize.len();
    let table_len = row.num_ops();
    Self {
      row_ops_val: Vec::new(),
      col_ops_val: Vec::new(),
      comb: DensePolynomial::new(vec![Scalar::zero()]),
      fs6_row_mem: row_mem_val.to_vec(),
      fs6_col_mem: col_mem_val.to_vec(),
      fs6_table_count: table_count,
      fs6_table_len: table_len,
    }
  }

  fn is_fs6(&self) -> bool {
    self.fs6_table_count != 0
  }

  fn value(&self, row_side: bool, table: usize, item: usize, addresses: &AddrTimestamps) -> Scalar {
    if !self.is_fs6() {
      return if row_side {
        self.row_ops_val[table][item]
      } else {
        self.col_ops_val[table][item]
      };
    }
    let address = addresses.ops_addr_usize[table][item] as usize;
    if row_side {
      self.fs6_row_mem[address]
    } else {
      self.fs6_col_mem[address]
    }
  }

  fn materialize_table(
    &self,
    row_side: bool,
    table: usize,
    addresses: &AddrTimestamps,
  ) -> Vec<Scalar> {
    let len = if self.is_fs6() {
      self.fs6_table_len
    } else if row_side {
      self.row_ops_val[table].len()
    } else {
      self.col_ops_val[table].len()
    };
    (0..len)
      .map(|item| self.value(row_side, table, item, addresses))
      .collect()
  }

  fn materialize_table_range(
    &self,
    row_side: bool,
    table: usize,
    addresses: &AddrTimestamps,
    start: usize,
    length: usize,
  ) -> Vec<Scalar> {
    (start..start + length)
      .map(|item| self.value(row_side, table, item, addresses))
      .collect()
  }

  fn table_count(&self) -> usize {
    if self.is_fs6() {
      self.fs6_table_count
    } else {
      self.row_ops_val.len()
    }
  }

  fn evaluate_side_streaming(
    &self,
    row_side: bool,
    addresses: &AddrTimestamps,
    point: &[Scalar],
  ) -> Vec<Scalar> {
    assert_eq!(self.fs6_table_len, 1usize << point.len());
    let mut evaluations = vec![Scalar::zero(); self.table_count()];
    for item in 0..self.fs6_table_len {
      let weight = AddrTimestamps::equality_weight(point, item);
      for (table, evaluation) in evaluations.iter_mut().enumerate() {
        *evaluation += self.value(row_side, table, item, addresses) * weight;
      }
    }
    evaluations
  }

  fn fs6_bound_comb(
    &self,
    dense: &MultiSparseMatPolynomialAsDense,
    point: &[Scalar],
  ) -> Vec<Scalar> {
    let scalars = dense
      .row
      .ops_addr_usize
      .iter()
      .flat_map(|addresses| addresses.iter())
      .map(|address| self.fs6_row_mem[*address as usize])
      .chain(
        dense
          .col
          .ops_addr_usize
          .iter()
          .flat_map(|addresses| addresses.iter())
          .map(|address| self.fs6_col_mem[*address as usize]),
      );
    MultiSparseMatPolynomialAsDense::bound_scalar_iter(scalars, point)
  }

  pub fn commit(
    &self,
    dense: &MultiSparseMatPolynomialAsDense,
    gens: &PolyCommitmentGens,
  ) -> DerefsCommitment {
    let (comm_ops_val, _blinds) = if self.is_fs6() {
      let scalars = dense
        .row
        .ops_addr_usize
        .iter()
        .flat_map(|addresses| addresses.iter())
        .map(|address| self.fs6_row_mem[*address as usize])
        .chain(
          dense
            .col
            .ops_addr_usize
            .iter()
            .flat_map(|addresses| addresses.iter())
            .map(|address| self.fs6_col_mem[*address as usize]),
        );
      FileBackedDensePolynomial::commit_scalar_iter_plain(
        scalars,
        2 * self.table_count() * self.fs6_table_len,
        gens,
      )
      .expect("failed to commit bounded dereference source")
    } else {
      self.comb.commit(gens, None)
    };
    DerefsCommitment { comm_ops_val }
  }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DerefsEvalProof {
  proof_derefs: PolyEvalProof,
}

impl DerefsEvalProof {
  fn protocol_name() -> &'static [u8] {
    b"Derefs evaluation proof"
  }

  fn prove_single(
    derefs: &Derefs,
    dense: &MultiSparseMatPolynomialAsDense,
    r: &[Scalar],
    evals: Vec<Scalar>,
    gens: &PolyCommitmentGens,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape,
  ) -> PolyEvalProof {
    let joint_num_vars = if derefs.is_fs6() {
      (2 * derefs.table_count() * derefs.fs6_table_len)
        .next_power_of_two()
        .log_2()
    } else {
      derefs.comb.get_num_vars()
    };
    assert_eq!(joint_num_vars, r.len() + evals.len().log_2());

    // append the claimed evaluations to transcript
    evals.append_to_transcript(b"evals_ops_val", transcript);

    // n-to-1 reduction
    let (r_joint, eval_joint) = {
      let challenges =
        transcript.challenge_vector(b"challenge_combine_n_to_one", evals.len().log_2());
      let mut poly_evals = DensePolynomial::new(evals);
      for i in (0..challenges.len()).rev() {
        poly_evals.bound_poly_var_bot(&challenges[i]);
      }
      assert_eq!(poly_evals.len(), 1);
      let joint_claim_eval = poly_evals[0];
      let mut r_joint = challenges;
      r_joint.extend(r);

      if !derefs.is_fs6() {
        debug_assert_eq!(derefs.comb.evaluate(&r_joint), joint_claim_eval);
      }
      (r_joint, joint_claim_eval)
    };
    // decommit the joint polynomial at r_joint
    eval_joint.append_to_transcript(b"joint_claim_eval", transcript);
    let (proof_derefs, _comm_derefs_eval) = if derefs.is_fs6() {
      let prebound = derefs.fs6_bound_comb(dense, &r_joint);
      PolyEvalProof::prove_prebound_plain(
        joint_num_vars,
        &r_joint,
        &eval_joint,
        &prebound,
        gens,
        transcript,
        random_tape,
      )
      .expect("source-fused dereference opening failed")
    } else {
      PolyEvalProof::prove(
        &derefs.comb,
        None,
        &r_joint,
        &eval_joint,
        None,
        gens,
        transcript,
        random_tape,
      )
    };

    proof_derefs
  }

  // evalues both polynomials at r and produces a joint proof of opening
  pub fn prove(
    derefs: &Derefs,
    dense: &MultiSparseMatPolynomialAsDense,
    eval_row_ops_val_vec: &[Scalar],
    eval_col_ops_val_vec: &[Scalar],
    r: &[Scalar],
    gens: &PolyCommitmentGens,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape,
  ) -> Self {
    transcript.append_protocol_name(DerefsEvalProof::protocol_name());

    let evals = {
      let mut evals = eval_row_ops_val_vec.to_owned();
      evals.extend(eval_col_ops_val_vec);
      evals.resize(evals.len().next_power_of_two(), Scalar::zero());
      evals
    };
    let proof_derefs =
      DerefsEvalProof::prove_single(derefs, dense, r, evals, gens, transcript, random_tape);

    DerefsEvalProof { proof_derefs }
  }

  fn verify_single(
    proof: &PolyEvalProof,
    comm: &PolyCommitment,
    r: &[Scalar],
    evals: Vec<Scalar>,
    gens: &PolyCommitmentGens,
    transcript: &mut Transcript,
  ) -> Result<(), ProofVerifyError> {
    // append the claimed evaluations to transcript
    evals.append_to_transcript(b"evals_ops_val", transcript);

    // n-to-1 reduction
    let challenges =
      transcript.challenge_vector(b"challenge_combine_n_to_one", evals.len().log_2());
    let mut poly_evals = DensePolynomial::new(evals);
    for i in (0..challenges.len()).rev() {
      poly_evals.bound_poly_var_bot(&challenges[i]);
    }
    assert_eq!(poly_evals.len(), 1);
    let joint_claim_eval = poly_evals[0];
    let mut r_joint = challenges;
    r_joint.extend(r);

    // decommit the joint polynomial at r_joint
    joint_claim_eval.append_to_transcript(b"joint_claim_eval", transcript);

    proof.verify_plain(gens, transcript, &r_joint, &joint_claim_eval, comm)
  }

  // verify evaluations of both polynomials at r
  pub fn verify(
    &self,
    r: &[Scalar],
    eval_row_ops_val_vec: &[Scalar],
    eval_col_ops_val_vec: &[Scalar],
    gens: &PolyCommitmentGens,
    comm: &DerefsCommitment,
    transcript: &mut Transcript,
  ) -> Result<(), ProofVerifyError> {
    transcript.append_protocol_name(DerefsEvalProof::protocol_name());
    let mut evals = eval_row_ops_val_vec.to_owned();
    evals.extend(eval_col_ops_val_vec);
    evals.resize(evals.len().next_power_of_two(), Scalar::zero());

    DerefsEvalProof::verify_single(
      &self.proof_derefs,
      &comm.comm_ops_val,
      r,
      evals,
      gens,
      transcript,
    )
  }
}

impl AppendToTranscript for DerefsCommitment {
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
    transcript.append_message(b"derefs_commitment", b"begin_derefs_commitment");
    audit_append_message(b"derefs_commitment", b"begin_derefs_commitment");
    self.comm_ops_val.append_to_transcript(label, transcript);
    transcript.append_message(b"derefs_commitment", b"end_derefs_commitment");
    audit_append_message(b"derefs_commitment", b"end_derefs_commitment");
  }
}

#[derive(Serialize, Deserialize)]
struct TranscriptRecomputeCheckpoint {
  layer_identifier: String,
  polynomial_identifier: String,
  source_object_digest: [u8; 32],
  table_dimensions: (usize, usize),
  canonical_reconstruction_version: String,
}

#[derive(Serialize, Deserialize)]
struct AddrTimestamps {
  ops_addr_usize: Vec<Vec<u32>>,
  read_ts_usize: Vec<Vec<u32>>,
  audit_ts_usize: Vec<u32>,
  ops_addr: Vec<DensePolynomial>,
  read_ts: Vec<DensePolynomial>,
  audit_ts: DensePolynomial,
  checkpoint: TranscriptRecomputeCheckpoint,
}

impl AddrTimestamps {
  pub fn new(num_cells: usize, num_ops: usize, ops_addr: Vec<Vec<usize>>) -> Self {
    let _memory_scope = memory_trace::scope(&ADDRESS_TIMESTAMPS);
    for item in ops_addr.iter() {
      assert_eq!(item.len(), num_ops);
    }

    assert!(num_cells <= u32::MAX as usize && num_ops <= u32::MAX as usize);
    let ops_addr = ops_addr
      .into_iter()
      .map(|table| {
        table
          .into_iter()
          .map(|value| u32::try_from(value).expect("sparse address exceeds u32"))
          .collect::<Vec<_>>()
      })
      .collect::<Vec<_>>();
    let mut audit_ts = {
      let _memory_scope = memory_trace::scope(&ADDRESS_AUDIT_USIZE);
      vec![0u32; num_cells]
    };
    let fs5 = std::env::var("LIBSPARTAN_TRANSCRIPT_RECOMPUTE").as_deref() == Ok("1");
    let mut ops_addr_vec: Vec<DensePolynomial> = Vec::new();
    let mut read_ts_vec: Vec<DensePolynomial> = Vec::new();
    let mut read_ts_usize_vec: Vec<Vec<u32>> = Vec::new();
    for ops_addr_inst in ops_addr.iter() {
      let mut read_ts = {
        let _memory_scope = memory_trace::scope(&ADDRESS_READ_USIZE);
        vec![0u32; num_ops]
      };

      // since read timestamps are trustworthy, we can simply increment the r-ts to obtain a w-ts
      // this is sufficient to ensure that the write-set, consisting of (addr, val, ts) tuples, is a set
      for i in 0..num_ops {
        let addr = ops_addr_inst[i] as usize;
        assert!(addr < num_cells);
        let r_ts = audit_ts[addr];
        read_ts[i] = r_ts;

        let w_ts = r_ts + 1;
        audit_ts[addr] = w_ts;
      }

      if !fs5 {
        let ops_addr_scalar = {
          let _memory_scope = memory_trace::scope(&ADDRESS_OPS_SCALAR);
          DensePolynomial::new(
            ops_addr_inst
              .iter()
              .map(|value| Scalar::from(*value as u64))
              .collect(),
          )
        };
        ops_addr_vec.push(ops_addr_scalar);
        let read_ts_scalar = {
          let _memory_scope = memory_trace::scope(&ADDRESS_READ_SCALAR);
          DensePolynomial::new(
            read_ts
              .iter()
              .map(|value| Scalar::from(*value as u64))
              .collect(),
          )
        };
        read_ts_vec.push(read_ts_scalar);
      }
      if fs5 {
        read_ts_usize_vec.push(read_ts);
      }
    }

    let source_object_digest = Self::source_digest(&ops_addr, &read_ts_usize_vec, &audit_ts);

    AddrTimestamps {
      ops_addr: ops_addr_vec,
      ops_addr_usize: ops_addr,
      read_ts_usize: read_ts_usize_vec,
      audit_ts_usize: if fs5 { audit_ts.clone() } else { Vec::new() },
      read_ts: read_ts_vec,
      audit_ts: if fs5 {
        DensePolynomial::new(vec![Scalar::zero()])
      } else {
        let _memory_scope = memory_trace::scope(&ADDRESS_AUDIT_SCALAR);
        DensePolynomial::new(
          audit_ts
            .iter()
            .map(|value| Scalar::from(*value as u64))
            .collect(),
        )
      },
      checkpoint: TranscriptRecomputeCheckpoint {
        layer_identifier: "sparse-memory-consistency".to_owned(),
        polynomial_identifier: "address-and-timestamp-tables".to_owned(),
        source_object_digest,
        table_dimensions: (num_cells, num_ops),
        canonical_reconstruction_version: "fs5-usize-to-ristretto-scalar-v1".to_owned(),
      },
    }
  }

  fn source_digest(ops_addr: &[Vec<u32>], read_ts: &[Vec<u32>], audit_ts: &[u32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"thinwallet-fs5-address-timestamp-checkpoint-v1");
    for tables in [ops_addr, read_ts] {
      hasher.update((tables.len() as u64).to_le_bytes());
      for table in tables {
        hasher.update((table.len() as u64).to_le_bytes());
        for value in table {
          hasher.update((*value as u64).to_le_bytes());
        }
      }
    }
    hasher.update((audit_ts.len() as u64).to_le_bytes());
    for value in audit_ts {
      hasher.update((*value as u64).to_le_bytes());
    }
    hasher.finalize().into()
  }

  fn validate_checkpoint(&self) -> bool {
    self.checkpoint.canonical_reconstruction_version == "fs5-usize-to-ristretto-scalar-v1"
      && self.checkpoint.table_dimensions == (self.num_mem_cells(), self.ops_addr_usize[0].len())
      && self.checkpoint.source_object_digest
        == Self::source_digest(
          &self.ops_addr_usize,
          &self.read_ts_usize,
          &self.audit_ts_usize,
        )
  }

  fn evaluate_usize(table: &[u32], point: &[Scalar]) -> Scalar {
    let weights = EqPolynomial::new(point.to_vec()).evals();
    Self::evaluate_usize_with_weights(table, &weights)
  }

  fn evaluate_usize_with_weights(table: &[u32], weights: &[Scalar]) -> Scalar {
    assert_eq!(table.len(), weights.len());
    table
      .iter()
      .zip(weights.iter())
      .map(|(value, weight)| Scalar::from(*value as u64) * weight)
      .sum()
  }

  fn equality_weight(point: &[Scalar], index: usize) -> Scalar {
    point
      .iter()
      .enumerate()
      .fold(Scalar::one(), |weight, (bit, challenge)| {
        let shift = point.len() - bit - 1;
        if (index >> shift) & 1 == 1 {
          weight * challenge
        } else {
          weight * (Scalar::one() - challenge)
        }
      })
  }

  fn evaluate_usize_streaming(table: &[u32], point: &[Scalar]) -> Scalar {
    assert_eq!(table.len(), 1usize << point.len());
    table
      .iter()
      .enumerate()
      .map(|(index, value)| Scalar::from(*value as u64) * Self::equality_weight(point, index))
      .sum()
  }

  fn evaluate_usize_tables_streaming(tables: &[Vec<u32>], point: &[Scalar]) -> Vec<Scalar> {
    assert!(!tables.is_empty());
    assert!(tables
      .iter()
      .all(|table| table.len() == 1usize << point.len()));
    let mut evaluations = vec![Scalar::zero(); tables.len()];
    for item in 0..tables[0].len() {
      let weight = Self::equality_weight(point, item);
      for (table, evaluation) in tables.iter().zip(evaluations.iter_mut()) {
        *evaluation += Scalar::from(table[item] as u64) * weight;
      }
    }
    evaluations
  }

  fn num_ops(&self) -> usize {
    self.ops_addr_usize[0].len()
  }

  fn num_mem_cells(&self) -> usize {
    if self.audit_ts_usize.is_empty() {
      self.audit_ts.len()
    } else {
      self.audit_ts_usize.len()
    }
  }

  fn deref_mem(addr: &[u32], mem_val: &[Scalar]) -> DensePolynomial {
    DensePolynomial::new(
      (0..addr.len())
        .map(|i| {
          let a = addr[i] as usize;
          mem_val[a]
        })
        .collect::<Vec<Scalar>>(),
    )
  }

  pub fn deref(&self, mem_val: &[Scalar]) -> Vec<DensePolynomial> {
    (0..self.ops_addr_usize.len())
      .map(|i| AddrTimestamps::deref_mem(&self.ops_addr_usize[i], mem_val))
      .collect::<Vec<DensePolynomial>>()
  }
}

#[derive(Serialize, Deserialize)]
pub struct MultiSparseMatPolynomialAsDense {
  batch_size: usize,
  val: Vec<DensePolynomial>,
  #[serde(skip)]
  val_external_offset: Option<usize>,
  #[serde(skip)]
  val_table_len: usize,
  row: AddrTimestamps,
  col: AddrTimestamps,
  comb_ops: DensePolynomial,
  #[serde(skip)]
  comb_ops_external: Option<FileBackedDensePolynomial>,
  comb_mem: DensePolynomial,
  #[serde(skip)]
  comb_mem_external: Option<FileBackedDensePolynomial>,
  #[serde(skip)]
  comb_source_fused: bool,
}

#[derive(Serialize, Deserialize)]
struct RemoteExternalDenseState {
  val_external_offset: Option<usize>,
  val_table_len: usize,
  comb_ops: Option<Vec<Scalar>>,
  comb_mem: Option<Vec<Scalar>>,
  comb_source_fused: bool,
}

impl MultiSparseMatPolynomialAsDense {
  pub(crate) fn export_remote_external_state(&self) -> io::Result<Vec<u8>> {
    let read = |poly: &Option<FileBackedDensePolynomial>| -> io::Result<Option<Vec<Scalar>>> {
      poly
        .as_ref()
        .map(|value| value.read_scalar_range(0, value.len()))
        .transpose()
    };
    bincode::serialize(&RemoteExternalDenseState {
      val_external_offset: self.val_external_offset,
      val_table_len: self.val_table_len,
      comb_ops: read(&self.comb_ops_external)?,
      comb_mem: read(&self.comb_mem_external)?,
      comb_source_fused: self.comb_source_fused,
    })
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
  }

  pub(crate) fn import_remote_external_state(&mut self, bytes: &[u8]) -> io::Result<()> {
    let state: RemoteExternalDenseState = bincode::deserialize(bytes)
      .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let canonical = bincode::serialize(&state)
      .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if canonical != bytes {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "non-canonical remote external state",
      ));
    }
    self.val_external_offset = state.val_external_offset;
    self.val_table_len = state.val_table_len;
    self.comb_ops_external = state
      .comb_ops
      .map(|values| FileBackedDensePolynomial::from_scalar_iter_named(values, "remote-comb-ops"))
      .transpose()?;
    self.comb_mem_external = state
      .comb_mem
      .map(|values| FileBackedDensePolynomial::from_scalar_iter_named(values, "remote-comb-mem"))
      .transpose()?;
    self.comb_source_fused = state.comb_source_fused;
    Ok(())
  }
}

#[derive(Serialize, Deserialize)]
pub struct SparseMatPolyCommitmentGens {
  gens_ops: PolyCommitmentGens,
  gens_mem: PolyCommitmentGens,
  gens_derefs: PolyCommitmentGens,
}

impl SparseMatPolyCommitmentGens {
  pub fn new(
    label: &'static [u8],
    num_vars_x: usize,
    num_vars_y: usize,
    num_nz_entries: usize,
    batch_size: usize,
  ) -> SparseMatPolyCommitmentGens {
    let num_vars_ops =
      num_nz_entries.next_power_of_two().log_2() + (batch_size * 5).next_power_of_two().log_2();
    let num_vars_mem = if num_vars_x > num_vars_y {
      num_vars_x
    } else {
      num_vars_y
    } + 1;
    let num_vars_derefs =
      num_nz_entries.next_power_of_two().log_2() + (batch_size * 2).next_power_of_two().log_2();

    let gens_ops = PolyCommitmentGens::new(num_vars_ops, label);
    let gens_mem = PolyCommitmentGens::new(num_vars_mem, label);
    let gens_derefs = PolyCommitmentGens::new(num_vars_derefs, label);
    SparseMatPolyCommitmentGens {
      gens_ops,
      gens_mem,
      gens_derefs,
    }
  }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SparseMatPolyCommitment {
  batch_size: usize,
  num_ops: usize,
  num_mem_cells: usize,
  comm_comb_ops: PolyCommitment,
  comm_comb_mem: PolyCommitment,
}

impl AppendToTranscript for SparseMatPolyCommitment {
  fn append_to_transcript(&self, _label: &'static [u8], transcript: &mut Transcript) {
    transcript.append_u64(b"batch_size", self.batch_size as u64);
    transcript.append_u64(b"num_ops", self.num_ops as u64);
    transcript.append_u64(b"num_mem_cells", self.num_mem_cells as u64);
    self
      .comm_comb_ops
      .append_to_transcript(b"comm_comb_ops", transcript);
    self
      .comm_comb_mem
      .append_to_transcript(b"comm_comb_mem", transcript);
  }
}

impl SparseMatPolynomial {
  pub fn new(num_vars_x: usize, num_vars_y: usize, M: Vec<SparseMatEntry>) -> Self {
    Self {
      num_vars_x,
      num_vars_y,
      M,
    }
  }

  pub fn get_num_nz_entries(&self) -> usize {
    self.M.len().next_power_of_two()
  }

  fn sparse_to_dense_vecs(&self, N: usize) -> (Vec<usize>, Vec<usize>, Vec<Scalar>) {
    let _memory_scope = memory_trace::scope(&SPARSE_DENSE_VECS);
    assert!(N >= self.get_num_nz_entries());
    let mut ops_row: Vec<usize> = vec![0; N];
    let mut ops_col: Vec<usize> = vec![0; N];
    let mut val: Vec<Scalar> = vec![Scalar::zero(); N];

    for i in 0..self.M.len() {
      ops_row[i] = self.M[i].row;
      ops_col[i] = self.M[i].col;
      val[i] = self.M[i].val;
    }
    (ops_row, ops_col, val)
  }

  fn sparse_to_dense_addresses(&self, N: usize) -> (Vec<usize>, Vec<usize>) {
    let _memory_scope = memory_trace::scope(&SPARSE_DENSE_VECS);
    assert!(N >= self.get_num_nz_entries());
    let mut ops_row = vec![0; N];
    let mut ops_col = vec![0; N];
    for (index, entry) in self.M.iter().enumerate() {
      ops_row[index] = entry.row;
      ops_col[index] = entry.col;
    }
    (ops_row, ops_col)
  }

  fn multi_sparse_to_dense_rep(
    sparse_polys: &[&SparseMatPolynomial],
  ) -> MultiSparseMatPolynomialAsDense {
    assert!(!sparse_polys.is_empty());
    for i in 1..sparse_polys.len() {
      assert_eq!(sparse_polys[i].num_vars_x, sparse_polys[0].num_vars_x);
      assert_eq!(sparse_polys[i].num_vars_y, sparse_polys[0].num_vars_y);
    }

    let N = sparse_polys
      .iter()
      .map(|sparse_poly| sparse_poly.get_num_nz_entries())
      .max()
      .unwrap();

    let fs7 = std::env::var("LIBSPARTAN_CREDENTIAL_STREAMING").as_deref() == Ok("1");
    let mut ops_row_vec: Vec<Vec<usize>> = Vec::new();
    let mut ops_col_vec: Vec<Vec<usize>> = Vec::new();
    let mut val_vec: Vec<DensePolynomial> = Vec::new();
    for poly in sparse_polys {
      let (ops_row, ops_col, value) = if fs7 {
        let (row, col) = poly.sparse_to_dense_addresses(N);
        (row, col, None)
      } else {
        let (row, col, value) = poly.sparse_to_dense_vecs(N);
        (row, col, Some(value))
      };
      ops_row_vec.push(ops_row);
      ops_col_vec.push(ops_col);
      val_vec.push(DensePolynomial::new(
        value.unwrap_or_else(|| vec![Scalar::zero()]),
      ));
    }

    let any_poly = &sparse_polys[0];

    let num_mem_cells = if any_poly.num_vars_x > any_poly.num_vars_y {
      any_poly.num_vars_x.pow2()
    } else {
      any_poly.num_vars_y.pow2()
    };

    let row = AddrTimestamps::new(num_mem_cells, N, ops_row_vec);
    let col = AddrTimestamps::new(num_mem_cells, N, ops_col_vec);

    // combine polynomials into a single polynomial for commitment purposes
    let stream_comb_ops = std::env::var("LIBSPARTAN_FIXED_STREAMING").as_deref() == Ok("1");
    let fs5 = std::env::var("LIBSPARTAN_TRANSCRIPT_RECOMPUTE").as_deref() == Ok("1");
    let (comb_ops, comb_ops_external) = if stream_comb_ops {
      let _memory_scope = memory_trace::scope(&COMBINED_OPS);
      let external = if fs5 {
        let prefix = row
          .ops_addr_usize
          .iter()
          .flat_map(|table| table.iter())
          .map(|value| Scalar::from(*value as u64))
          .chain(
            row
              .read_ts_usize
              .iter()
              .flat_map(|table| table.iter())
              .map(|value| Scalar::from(*value as u64)),
          )
          .chain(
            col
              .ops_addr_usize
              .iter()
              .flat_map(|table| table.iter())
              .map(|value| Scalar::from(*value as u64)),
          )
          .chain(
            col
              .read_ts_usize
              .iter()
              .flat_map(|table| table.iter())
              .map(|value| Scalar::from(*value as u64)),
          );
        let values = sparse_polys.iter().flat_map(|poly| {
          poly
            .M
            .iter()
            .map(|entry| entry.val)
            .chain((poly.M.len()..N).map(|_| Scalar::zero()))
        });
        let scalars: Box<dyn Iterator<Item = Scalar> + '_> = if fs7 {
          Box::new(prefix.chain(values))
        } else {
          Box::new(
            prefix.chain(
              val_vec
                .iter()
                .flat_map(|poly| poly.values().iter().copied()),
            ),
          )
        };
        FileBackedDensePolynomial::from_scalar_iter_named(scalars, "comb_ops")
      } else {
        FileBackedDensePolynomial::from_polynomials(
          row
            .ops_addr
            .iter()
            .chain(row.read_ts.iter())
            .chain(col.ops_addr.iter())
            .chain(col.read_ts.iter())
            .chain(val_vec.iter()),
        )
      }
      .expect("failed to create file-backed comb_ops state");
      (DensePolynomial::new(vec![Scalar::zero()]), Some(external))
    } else {
      let _memory_scope = memory_trace::scope(&COMBINED_OPS);
      (
        DensePolynomial::merge(
          row
            .ops_addr
            .iter()
            .chain(row.read_ts.iter())
            .chain(col.ops_addr.iter())
            .chain(col.read_ts.iter())
            .chain(val_vec.iter()),
        ),
        None,
      )
    };
    let stream_comb_mem = std::env::var("LIBSPARTAN_MULTI_TARGET_STREAMING").as_deref() == Ok("1");
    let (comb_mem, comb_mem_external) = if stream_comb_mem {
      let _memory_scope = memory_trace::scope(&COMBINED_MEM);
      let external = if fs5 {
        let scalars = row
          .audit_ts_usize
          .iter()
          .chain(col.audit_ts_usize.iter())
          .map(|value| Scalar::from(*value as u64));
        FileBackedDensePolynomial::from_scalar_iter_named(scalars, "comb_mem")
      } else {
        FileBackedDensePolynomial::from_polynomials_named(
          [&row.audit_ts, &col.audit_ts],
          "comb_mem",
        )
      }
      .expect("failed to create file-backed comb_mem state");
      (DensePolynomial::new(vec![Scalar::zero()]), Some(external))
    } else {
      let mut combined = {
        let _memory_scope = memory_trace::scope(&COMBINED_MEM);
        row.audit_ts.clone()
      };
      {
        let _memory_scope = memory_trace::scope(&COMBINED_MEM);
        combined.extend(&col.audit_ts);
      }
      (combined, None)
    };

    MultiSparseMatPolynomialAsDense {
      batch_size: sparse_polys.len(),
      row,
      col,
      val: val_vec,
      val_external_offset: fs7.then_some(12 * N),
      val_table_len: if fs7 { N } else { 0 },
      comb_ops,
      comb_ops_external,
      comb_mem,
      comb_mem_external,
      comb_source_fused: false,
    }
  }

  fn evaluate_with_tables(&self, eval_table_rx: &[Scalar], eval_table_ry: &[Scalar]) -> Scalar {
    assert_eq!(self.num_vars_x.pow2(), eval_table_rx.len());
    assert_eq!(self.num_vars_y.pow2(), eval_table_ry.len());

    self
      .M
      .iter()
      .map(|SparseMatEntry { row, col, val }| eval_table_rx[*row] * eval_table_ry[*col] * val)
      .sum()
  }

  pub fn multi_evaluate(
    polys: &[&SparseMatPolynomial],
    rx: &[Scalar],
    ry: &[Scalar],
  ) -> Vec<Scalar> {
    let eval_table_rx = EqPolynomial::new(rx.to_vec()).evals();
    let eval_table_ry = EqPolynomial::new(ry.to_vec()).evals();

    polys
      .iter()
      .map(|poly| poly.evaluate_with_tables(&eval_table_rx, &eval_table_ry))
      .collect::<Vec<Scalar>>()
  }

  pub fn multiply_vec(&self, num_rows: usize, num_cols: usize, z: &[Scalar]) -> Vec<Scalar> {
    assert_eq!(z.len(), num_cols);

    self.M.iter().fold(
      vec![Scalar::zero(); num_rows],
      |mut Mz, SparseMatEntry { row, col, val }| {
        Mz[*row] += val * z[*col];
        Mz
      },
    )
  }

  pub fn compute_eval_table_sparse(
    &self,
    rx: &[Scalar],
    num_rows: usize,
    num_cols: usize,
  ) -> Vec<Scalar> {
    assert_eq!(rx.len(), num_rows);

    self.M.iter().fold(
      vec![Scalar::zero(); num_cols],
      |mut M_evals, SparseMatEntry { row, col, val }| {
        M_evals[*col] += rx[*row] * val;
        M_evals
      },
    )
  }

  pub fn multi_commit(
    sparse_polys: &[&SparseMatPolynomial],
    gens: &SparseMatPolyCommitmentGens,
  ) -> (SparseMatPolyCommitment, MultiSparseMatPolynomialAsDense) {
    let batch_size = sparse_polys.len();
    let mut dense = SparseMatPolynomial::multi_sparse_to_dense_rep(sparse_polys);

    let (comm_comb_ops, _blinds_comb_ops) = if let Some(external) = &dense.comb_ops_external {
      external
        .commit_plain(&gens.gens_ops)
        .expect("failed to commit file-backed comb_ops state")
    } else {
      dense.comb_ops.commit(&gens.gens_ops, None)
    };
    let (comm_comb_mem, _blinds_comb_mem) = if let Some(external) = &dense.comb_mem_external {
      external
        .commit_plain(&gens.gens_mem)
        .expect("failed to commit file-backed comb_mem state")
    } else {
      dense.comb_mem.commit(&gens.gens_mem, None)
    };
    if std::env::var("LIBSPARTAN_STREAMING_DEREFERENCE").as_deref() == Ok("1") {
      if dense.val_external_offset.is_none() {
        dense.comb_ops_external = None;
        dense.comb_mem_external = None;
      }
      dense.comb_source_fused = dense.val_external_offset.is_none();
    }

    (
      SparseMatPolyCommitment {
        batch_size,
        num_mem_cells: dense.row.num_mem_cells(),
        num_ops: dense.row.num_ops(),
        comm_comb_ops,
        comm_comb_mem,
      },
      dense,
    )
  }
}

impl MultiSparseMatPolynomialAsDense {
  fn bound_scalar_iter<I>(scalars: I, point: &[Scalar]) -> Vec<Scalar>
  where
    I: IntoIterator<Item = Scalar>,
  {
    let (left, right) = EqPolynomial::new(point.to_vec()).compute_factored_evals();
    let mut bound = vec![Scalar::zero(); right.len()];
    let mut count = 0usize;
    for (index, scalar) in scalars.into_iter().enumerate() {
      assert!(index < left.len() * right.len());
      bound[index % right.len()] += left[index / right.len()] * scalar;
      count = index + 1;
    }
    assert!(count <= left.len() * right.len());
    bound
  }

  fn fs6_bound_comb_ops(&self, point: &[Scalar]) -> Vec<Scalar> {
    let prefix = self
      .row
      .ops_addr_usize
      .iter()
      .flat_map(|table| table.iter())
      .map(|value| Scalar::from(*value as u64))
      .chain(
        self
          .row
          .read_ts_usize
          .iter()
          .flat_map(|table| table.iter())
          .map(|value| Scalar::from(*value as u64)),
      )
      .chain(
        self
          .col
          .ops_addr_usize
          .iter()
          .flat_map(|table| table.iter())
          .map(|value| Scalar::from(*value as u64)),
      )
      .chain(
        self
          .col
          .read_ts_usize
          .iter()
          .flat_map(|table| table.iter())
          .map(|value| Scalar::from(*value as u64)),
      );
    let Some(_external_offset) = self.val_external_offset else {
      return Self::bound_scalar_iter(
        prefix.chain(
          self
            .val
            .iter()
            .flat_map(|poly| poly.values().iter().copied()),
        ),
        point,
      );
    };

    self
      .comb_ops_external
      .as_ref()
      .expect("FS7 combined operation source missing")
      .bound_at(point)
      .expect("failed to bind FS7 combined operation source")
  }

  fn val_table_len(&self) -> usize {
    if self.val_external_offset.is_some() {
      self.val_table_len
    } else {
      self.val.first().map_or(0, DensePolynomial::len)
    }
  }

  fn val_range(&self, table: usize, start: usize, length: usize) -> Vec<Scalar> {
    if let Some(offset) = self.val_external_offset {
      let external = self
        .comb_ops_external
        .as_ref()
        .expect("FS7 combined operation source missing");
      return external
        .read_scalar_range(offset + table * self.val_table_len + start, length)
        .expect("failed to read FS7 matrix-value range");
    }
    self.val[table].values()[start..start + length].to_vec()
  }

  fn evaluate_val(&self, table: usize, point: &[Scalar]) -> Scalar {
    if let Some(offset) = self.val_external_offset {
      let external = self
        .comb_ops_external
        .as_ref()
        .expect("FS7 combined operation source missing");
      return external
        .evaluate_scalar_range(
          offset + table * self.val_table_len,
          self.val_table_len,
          point,
        )
        .expect("failed to evaluate FS7 matrix-value table");
    }
    self.val[table].evaluate(point)
  }

  fn fs6_bound_comb_mem(&self, point: &[Scalar]) -> Vec<Scalar> {
    let scalars = self
      .row
      .audit_ts_usize
      .iter()
      .chain(self.col.audit_ts_usize.iter())
      .map(|value| Scalar::from(*value as u64));
    Self::bound_scalar_iter(scalars, point)
  }

  pub fn deref(&self, row_mem_val: &[Scalar], col_mem_val: &[Scalar]) -> Derefs {
    if std::env::var("LIBSPARTAN_STREAMING_DEREFERENCE").as_deref() == Ok("1") {
      return Derefs::new_fs6(&self.row, &self.col, row_mem_val, col_mem_val);
    }
    let row_ops_val = self.row.deref(row_mem_val);
    let col_ops_val = self.col.deref(col_mem_val);

    Derefs::new(row_ops_val, col_ops_val)
  }
}

#[derive(Debug)]
struct ProductLayer {
  init: ProductCircuit,
  read_vec: Vec<ProductCircuit>,
  write_vec: Vec<ProductCircuit>,
  audit: ProductCircuit,
}

#[derive(Debug)]
struct Layers {
  prod_layer: ProductLayer,
}

impl Layers {
  fn new_external_streaming(
    eval_table: &[Scalar],
    addr_timestamps: &AddrTimestamps,
    derefs: &Derefs,
    row_side: bool,
    r_mem_check: &(Scalar, Scalar),
    store: &mut MultiObjectFileBackedStateStore,
    arena: &BudgetAccountedArena,
    object_prefix: &str,
  ) -> std::io::Result<Self> {
    let build_started = Instant::now();
    let fs5 = std::env::var("LIBSPARTAN_TRANSCRIPT_RECOMPUTE").as_deref() == Ok("1");
    if fs5 && !addr_timestamps.validate_checkpoint() {
      return Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "address/timestamp recomputation checkpoint mismatch",
      ));
    }
    let (r_hash, r_multiset_check) = r_mem_check;
    let r_hash_sqr = r_hash * r_hash;
    let hash_func = |addr: &Scalar, val: &Scalar, ts: &Scalar| -> Scalar {
      ts * r_hash_sqr + val * r_hash + addr
    };

    let init = DensePolynomial::new(
      (0..eval_table.len())
        .map(|index| {
          hash_func(
            &Scalar::from(index as u64),
            &eval_table[index],
            &Scalar::zero(),
          ) - r_multiset_check
        })
        .collect(),
    );
    let prod_init =
      ProductCircuit::new_external(&init, &format!("{object_prefix}.init"), store, arena)?;
    drop(init);

    let mut prod_read_vec = Vec::with_capacity(addr_timestamps.ops_addr_usize.len());
    for index in 0..addr_timestamps.ops_addr_usize.len() {
      let recompute_started = Instant::now();
      let read = DensePolynomial::new(
        (0..addr_timestamps.ops_addr_usize[index].len())
          .map(|item| {
            let (addr, read_ts) = if fs5 {
              (
                Scalar::from(addr_timestamps.ops_addr_usize[index][item] as u64),
                Scalar::from(addr_timestamps.read_ts_usize[index][item] as u64),
              )
            } else {
              (
                addr_timestamps.ops_addr[index][item],
                addr_timestamps.read_ts[index][item],
              )
            };
            hash_func(
              &addr,
              &derefs.value(row_side, index, item, addr_timestamps),
              &read_ts,
            ) - r_multiset_check
          })
          .collect(),
      );
      if fs5 {
        CHECKPOINT_RECOMPUTE_NS.fetch_add(
          recompute_started.elapsed().as_nanos() as u64,
          AtomicOrdering::Relaxed,
        );
      }
      prod_read_vec.push(ProductCircuit::new_external(
        &read,
        &format!("{object_prefix}.read-{index}"),
        store,
        arena,
      )?);
      drop(read);
    }

    let mut prod_write_vec = Vec::with_capacity(addr_timestamps.ops_addr_usize.len());
    for index in 0..addr_timestamps.ops_addr_usize.len() {
      let recompute_started = Instant::now();
      let write = DensePolynomial::new(
        (0..addr_timestamps.ops_addr_usize[index].len())
          .map(|item| {
            let (addr, read_ts) = if fs5 {
              (
                Scalar::from(addr_timestamps.ops_addr_usize[index][item] as u64),
                Scalar::from(addr_timestamps.read_ts_usize[index][item] as u64),
              )
            } else {
              (
                addr_timestamps.ops_addr[index][item],
                addr_timestamps.read_ts[index][item],
              )
            };
            hash_func(
              &addr,
              &derefs.value(row_side, index, item, addr_timestamps),
              &(read_ts + Scalar::one()),
            ) - r_multiset_check
          })
          .collect(),
      );
      if fs5 {
        CHECKPOINT_RECOMPUTE_NS.fetch_add(
          recompute_started.elapsed().as_nanos() as u64,
          AtomicOrdering::Relaxed,
        );
      }
      prod_write_vec.push(ProductCircuit::new_external(
        &write,
        &format!("{object_prefix}.write-{index}"),
        store,
        arena,
      )?);
      drop(write);
    }

    let recompute_started = Instant::now();
    let audit = DensePolynomial::new(
      (0..eval_table.len())
        .map(|index| {
          let audit_ts = if fs5 {
            Scalar::from(addr_timestamps.audit_ts_usize[index] as u64)
          } else {
            addr_timestamps.audit_ts[index]
          };
          hash_func(&Scalar::from(index as u64), &eval_table[index], &audit_ts) - r_multiset_check
        })
        .collect(),
    );
    if fs5 {
      CHECKPOINT_RECOMPUTE_NS.fetch_add(
        recompute_started.elapsed().as_nanos() as u64,
        AtomicOrdering::Relaxed,
      );
    }
    let prod_audit =
      ProductCircuit::new_external(&audit, &format!("{object_prefix}.audit"), store, arena)?;
    drop(audit);

    let hashed_writes: Scalar = prod_write_vec
      .iter()
      .map(ProductCircuit::evaluate)
      .product();
    let hashed_write_set = prod_init.evaluate() * hashed_writes;
    let hashed_reads: Scalar = prod_read_vec.iter().map(ProductCircuit::evaluate).product();
    let hashed_read_set = hashed_reads * prod_audit.evaluate();
    debug_assert_eq!(hashed_read_set, hashed_write_set);

    ACTIVE_PRODUCT_BUILD_NS.fetch_add(
      build_started.elapsed().as_nanos() as u64,
      AtomicOrdering::Relaxed,
    );
    Ok(Self {
      prod_layer: ProductLayer {
        init: prod_init,
        read_vec: prod_read_vec,
        write_vec: prod_write_vec,
        audit: prod_audit,
      },
    })
  }

  fn build_hash_layer(
    eval_table: &[Scalar],
    addrs_vec: &[DensePolynomial],
    derefs_vec: &[DensePolynomial],
    read_ts_vec: &[DensePolynomial],
    audit_ts: &DensePolynomial,
    r_mem_check: &(Scalar, Scalar),
  ) -> (
    DensePolynomial,
    Vec<DensePolynomial>,
    Vec<DensePolynomial>,
    DensePolynomial,
  ) {
    let (r_hash, r_multiset_check) = r_mem_check;

    //hash(addr, val, ts) = ts * r_hash_sqr + val * r_hash + addr
    let r_hash_sqr = r_hash * r_hash;
    let hash_func = |addr: &Scalar, val: &Scalar, ts: &Scalar| -> Scalar {
      ts * r_hash_sqr + val * r_hash + addr
    };

    // hash init and audit that does not depend on #instances
    let num_mem_cells = eval_table.len();
    let poly_init_hashed = DensePolynomial::new(
      (0..num_mem_cells)
        .map(|i| {
          // at init time, addr is given by i, init value is given by eval_table, and ts = 0
          hash_func(&Scalar::from(i as u64), &eval_table[i], &Scalar::zero()) - r_multiset_check
        })
        .collect::<Vec<Scalar>>(),
    );
    let poly_audit_hashed = DensePolynomial::new(
      (0..num_mem_cells)
        .map(|i| {
          // at audit time, addr is given by i, value is given by eval_table, and ts is given by audit_ts
          hash_func(&Scalar::from(i as u64), &eval_table[i], &audit_ts[i]) - r_multiset_check
        })
        .collect::<Vec<Scalar>>(),
    );

    // hash read and write that depends on #instances
    let mut poly_read_hashed_vec: Vec<DensePolynomial> = Vec::new();
    let mut poly_write_hashed_vec: Vec<DensePolynomial> = Vec::new();
    for i in 0..addrs_vec.len() {
      let (addrs, derefs, read_ts) = (&addrs_vec[i], &derefs_vec[i], &read_ts_vec[i]);
      assert_eq!(addrs.len(), derefs.len());
      assert_eq!(addrs.len(), read_ts.len());
      let num_ops = addrs.len();
      let poly_read_hashed = DensePolynomial::new(
        (0..num_ops)
          .map(|i| {
            // at read time, addr is given by addrs, value is given by derefs, and ts is given by read_ts
            hash_func(&addrs[i], &derefs[i], &read_ts[i]) - r_multiset_check
          })
          .collect::<Vec<Scalar>>(),
      );
      poly_read_hashed_vec.push(poly_read_hashed);

      let poly_write_hashed = DensePolynomial::new(
        (0..num_ops)
          .map(|i| {
            // at write time, addr is given by addrs, value is given by derefs, and ts is given by write_ts = read_ts + 1
            hash_func(&addrs[i], &derefs[i], &(read_ts[i] + Scalar::one())) - r_multiset_check
          })
          .collect::<Vec<Scalar>>(),
      );
      poly_write_hashed_vec.push(poly_write_hashed);
    }

    (
      poly_init_hashed,
      poly_read_hashed_vec,
      poly_write_hashed_vec,
      poly_audit_hashed,
    )
  }

  pub fn new(
    eval_table: &[Scalar],
    addr_timestamps: &AddrTimestamps,
    derefs: &Derefs,
    row_side: bool,
    r_mem_check: &(Scalar, Scalar),
    mut store: Option<&mut MultiObjectFileBackedStateStore>,
    arena: Option<&BudgetAccountedArena>,
    object_prefix: &str,
  ) -> std::io::Result<Self> {
    let fs4 = std::env::var("LIBSPARTAN_ACTIVE_STATE_STREAMING").as_deref() == Ok("1");
    if fs4 {
      return Layers::new_external_streaming(
        eval_table,
        addr_timestamps,
        derefs,
        row_side,
        r_mem_check,
        store.as_deref_mut().expect("FS4 state store missing"),
        arena.expect("FS4 arena missing"),
        object_prefix,
      );
    }

    let (poly_init_hashed, poly_read_hashed_vec, poly_write_hashed_vec, poly_audit_hashed) =
      Layers::build_hash_layer(
        eval_table,
        &addr_timestamps.ops_addr,
        if row_side {
          &derefs.row_ops_val
        } else {
          &derefs.col_ops_val
        },
        &addr_timestamps.read_ts,
        &addr_timestamps.audit_ts,
        r_mem_check,
      );

    let prod_init = if let Some(external) = store.as_deref_mut() {
      ProductCircuit::new_external(
        &poly_init_hashed,
        &format!("{object_prefix}.init"),
        external,
        arena.expect("FS3 arena missing"),
      )?
    } else {
      ProductCircuit::new(&poly_init_hashed)
    };
    let mut prod_read_vec = Vec::with_capacity(poly_read_hashed_vec.len());
    for (index, polynomial) in poly_read_hashed_vec.iter().enumerate() {
      prod_read_vec.push(if let Some(external) = store.as_deref_mut() {
        ProductCircuit::new_external(
          polynomial,
          &format!("{object_prefix}.read-{index}"),
          external,
          arena.expect("FS3 arena missing"),
        )?
      } else {
        ProductCircuit::new(polynomial)
      });
    }
    let mut prod_write_vec = Vec::with_capacity(poly_write_hashed_vec.len());
    for (index, polynomial) in poly_write_hashed_vec.iter().enumerate() {
      prod_write_vec.push(if let Some(external) = store.as_deref_mut() {
        ProductCircuit::new_external(
          polynomial,
          &format!("{object_prefix}.write-{index}"),
          external,
          arena.expect("FS3 arena missing"),
        )?
      } else {
        ProductCircuit::new(polynomial)
      });
    }
    let prod_audit = if let Some(external) = store.as_deref_mut() {
      ProductCircuit::new_external(
        &poly_audit_hashed,
        &format!("{object_prefix}.audit"),
        external,
        arena.expect("FS3 arena missing"),
      )?
    } else {
      ProductCircuit::new(&poly_audit_hashed)
    };

    // subset audit check
    let hashed_writes: Scalar = (0..prod_write_vec.len())
      .map(|i| prod_write_vec[i].evaluate())
      .product();
    let hashed_write_set: Scalar = prod_init.evaluate() * hashed_writes;

    let hashed_reads: Scalar = (0..prod_read_vec.len())
      .map(|i| prod_read_vec[i].evaluate())
      .product();
    let hashed_read_set: Scalar = hashed_reads * prod_audit.evaluate();

    //assert_eq!(hashed_read_set, hashed_write_set);
    debug_assert_eq!(hashed_read_set, hashed_write_set);

    Ok(Layers {
      prod_layer: ProductLayer {
        init: prod_init,
        read_vec: prod_read_vec,
        write_vec: prod_write_vec,
        audit: prod_audit,
      },
    })
  }
}

#[derive(Debug)]
struct PolyEvalNetwork {
  row_layers: Layers,
  col_layers: Layers,
}

impl PolyEvalNetwork {
  pub fn new(
    dense: &MultiSparseMatPolynomialAsDense,
    derefs: &Derefs,
    mem_rx: &[Scalar],
    mem_ry: &[Scalar],
    r_mem_check: &(Scalar, Scalar),
    mut store: Option<&mut MultiObjectFileBackedStateStore>,
    arena: Option<&BudgetAccountedArena>,
  ) -> std::io::Result<Self> {
    let row_layers = Layers::new(
      mem_rx,
      &dense.row,
      derefs,
      true,
      r_mem_check,
      store.as_deref_mut(),
      arena,
      "row-product",
    )?;
    let col_layers = Layers::new(
      mem_ry,
      &dense.col,
      derefs,
      false,
      r_mem_check,
      store.as_deref_mut(),
      arena,
      "col-product",
    )?;

    Ok(PolyEvalNetwork {
      row_layers,
      col_layers,
    })
  }
}

#[derive(Debug, Serialize, Deserialize)]
struct HashLayerProof {
  eval_row: (Vec<Scalar>, Vec<Scalar>, Scalar),
  eval_col: (Vec<Scalar>, Vec<Scalar>, Scalar),
  eval_val: Vec<Scalar>,
  eval_derefs: (Vec<Scalar>, Vec<Scalar>),
  proof_ops: PolyEvalProof,
  proof_mem: PolyEvalProof,
  proof_derefs: DerefsEvalProof,
}

impl HashLayerProof {
  fn protocol_name() -> &'static [u8] {
    b"Sparse polynomial hash layer proof"
  }

  fn prove_helper(
    rand: (&Vec<Scalar>, &Vec<Scalar>),
    addr_timestamps: &AddrTimestamps,
  ) -> (Vec<Scalar>, Vec<Scalar>, Scalar) {
    let (rand_mem, rand_ops) = rand;
    let fs5 = std::env::var("LIBSPARTAN_TRANSCRIPT_RECOMPUTE").as_deref() == Ok("1");
    if fs5 {
      let recompute_started = Instant::now();
      assert!(
        addr_timestamps.validate_checkpoint(),
        "address/timestamp recomputation checkpoint mismatch"
      );
      let fs6 = std::env::var("LIBSPARTAN_STREAMING_DEREFERENCE").as_deref() == Ok("1");
      let (eval_ops_addr_vec, eval_read_ts_vec, eval_audit_ts) = if fs6 {
        (
          AddrTimestamps::evaluate_usize_tables_streaming(
            &addr_timestamps.ops_addr_usize,
            rand_ops,
          ),
          AddrTimestamps::evaluate_usize_tables_streaming(&addr_timestamps.read_ts_usize, rand_ops),
          AddrTimestamps::evaluate_usize_streaming(&addr_timestamps.audit_ts_usize, rand_mem),
        )
      } else {
        let ops_weights = EqPolynomial::new(rand_ops.to_vec()).evals();
        let eval_ops_addr_vec = addr_timestamps
          .ops_addr_usize
          .iter()
          .map(|table| AddrTimestamps::evaluate_usize_with_weights(table, &ops_weights))
          .collect();
        let eval_read_ts_vec = addr_timestamps
          .read_ts_usize
          .iter()
          .map(|table| AddrTimestamps::evaluate_usize_with_weights(table, &ops_weights))
          .collect();
        drop(ops_weights);
        let mem_weights = EqPolynomial::new(rand_mem.to_vec()).evals();
        let eval_audit_ts = AddrTimestamps::evaluate_usize_with_weights(
          &addr_timestamps.audit_ts_usize,
          &mem_weights,
        );
        (eval_ops_addr_vec, eval_read_ts_vec, eval_audit_ts)
      };
      CHECKPOINT_RECOMPUTE_NS.fetch_add(
        recompute_started.elapsed().as_nanos() as u64,
        AtomicOrdering::Relaxed,
      );
      return (eval_ops_addr_vec, eval_read_ts_vec, eval_audit_ts);
    }

    // decommit ops-addr at rand_ops
    let eval_ops_addr_vec = addr_timestamps
      .ops_addr
      .iter()
      .map(|addr| addr.evaluate(rand_ops))
      .collect();

    // decommit read_ts at rand_ops
    let eval_read_ts_vec = addr_timestamps
      .read_ts
      .iter()
      .map(|addr| addr.evaluate(rand_ops))
      .collect();

    // decommit audit-ts at rand_mem
    let eval_audit_ts = addr_timestamps.audit_ts.evaluate(rand_mem);

    (eval_ops_addr_vec, eval_read_ts_vec, eval_audit_ts)
  }

  fn prove(
    rand: (&Vec<Scalar>, &Vec<Scalar>),
    dense: &MultiSparseMatPolynomialAsDense,
    derefs: &Derefs,
    gens: &SparseMatPolyCommitmentGens,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape,
  ) -> Self {
    transcript.append_protocol_name(HashLayerProof::protocol_name());

    let (rand_mem, rand_ops) = rand;

    // decommit derefs at rand_ops
    let fs6 = std::env::var("LIBSPARTAN_STREAMING_DEREFERENCE").as_deref() == Ok("1");
    let query_weights = (!fs6).then(|| EqPolynomial::new(rand_ops.to_vec()).evals());
    let eval_row_ops_val = if fs6 {
      derefs.evaluate_side_streaming(true, &dense.row, rand_ops)
    } else {
      (0..derefs.table_count())
        .map(|index| {
          DotProductProofLog::compute_dotproduct(
            derefs.row_ops_val[index].values(),
            query_weights.as_ref().unwrap(),
          )
        })
        .collect()
    };
    let eval_col_ops_val = if fs6 {
      derefs.evaluate_side_streaming(false, &dense.col, rand_ops)
    } else {
      (0..derefs.table_count())
        .map(|index| {
          DotProductProofLog::compute_dotproduct(
            derefs.col_ops_val[index].values(),
            query_weights.as_ref().unwrap(),
          )
        })
        .collect()
    };
    drop(query_weights);
    let proof_derefs = DerefsEvalProof::prove(
      derefs,
      dense,
      &eval_row_ops_val,
      &eval_col_ops_val,
      rand_ops,
      &gens.gens_derefs,
      transcript,
      random_tape,
    );
    let eval_derefs = (eval_row_ops_val, eval_col_ops_val);

    // evaluate row_addr, row_read-ts, col_addr, col_read-ts, val at rand_ops
    // evaluate row_audit_ts and col_audit_ts at rand_mem
    let (eval_row_addr_vec, eval_row_read_ts_vec, eval_row_audit_ts) =
      HashLayerProof::prove_helper((rand_mem, rand_ops), &dense.row);
    let (eval_col_addr_vec, eval_col_read_ts_vec, eval_col_audit_ts) =
      HashLayerProof::prove_helper((rand_mem, rand_ops), &dense.col);
    let eval_val_vec = (0..dense.val.len())
      .map(|i| dense.evaluate_val(i, rand_ops))
      .collect::<Vec<Scalar>>();

    // form a single decommitment using comm_comb_ops
    let mut evals_ops: Vec<Scalar> = Vec::new();
    evals_ops.extend(&eval_row_addr_vec);
    evals_ops.extend(&eval_row_read_ts_vec);
    evals_ops.extend(&eval_col_addr_vec);
    evals_ops.extend(&eval_col_read_ts_vec);
    evals_ops.extend(&eval_val_vec);
    evals_ops.resize(evals_ops.len().next_power_of_two(), Scalar::zero());
    evals_ops.append_to_transcript(b"claim_evals_ops", transcript);
    let challenges_ops =
      transcript.challenge_vector(b"challenge_combine_n_to_one", evals_ops.len().log_2());

    let mut poly_evals_ops = DensePolynomial::new(evals_ops);
    for i in (0..challenges_ops.len()).rev() {
      poly_evals_ops.bound_poly_var_bot(&challenges_ops[i]);
    }
    assert_eq!(poly_evals_ops.len(), 1);
    let joint_claim_eval_ops = poly_evals_ops[0];
    let mut r_joint_ops = challenges_ops;
    r_joint_ops.extend(rand_ops);
    #[cfg(debug_assertions)]
    {
      if !dense.comb_source_fused {
        let external_ops_eval = dense.comb_ops_external.as_ref().map(|external| {
          external
            .evaluate(&r_joint_ops)
            .expect("file-backed evaluation failed")
        });
        debug_assert_eq!(
          external_ops_eval.unwrap_or_else(|| dense.comb_ops.evaluate(&r_joint_ops)),
          joint_claim_eval_ops
        );
      }
    }
    joint_claim_eval_ops.append_to_transcript(b"joint_claim_eval_ops", transcript);
    let (proof_ops, _comm_ops_eval) = if dense.comb_source_fused {
      let prebound = dense.fs6_bound_comb_ops(&r_joint_ops);
      PolyEvalProof::prove_prebound_plain(
        r_joint_ops.len(),
        &r_joint_ops,
        &joint_claim_eval_ops,
        &prebound,
        &gens.gens_ops,
        transcript,
        random_tape,
      )
      .expect("source-fused comb_ops evaluation proof failed")
    } else if let Some(external) = &dense.comb_ops_external {
      PolyEvalProof::prove_file_backed_plain(
        external,
        &r_joint_ops,
        &joint_claim_eval_ops,
        &gens.gens_ops,
        transcript,
        random_tape,
      )
      .expect("file-backed evaluation proof failed")
    } else {
      PolyEvalProof::prove(
        &dense.comb_ops,
        None,
        &r_joint_ops,
        &joint_claim_eval_ops,
        None,
        &gens.gens_ops,
        transcript,
        random_tape,
      )
    };

    // form a single decommitment using comb_comb_mem at rand_mem
    let evals_mem: Vec<Scalar> = vec![eval_row_audit_ts, eval_col_audit_ts];
    evals_mem.append_to_transcript(b"claim_evals_mem", transcript);
    let challenges_mem =
      transcript.challenge_vector(b"challenge_combine_two_to_one", evals_mem.len().log_2());

    let mut poly_evals_mem = DensePolynomial::new(evals_mem);
    for i in (0..challenges_mem.len()).rev() {
      poly_evals_mem.bound_poly_var_bot(&challenges_mem[i]);
    }
    assert_eq!(poly_evals_mem.len(), 1);
    let joint_claim_eval_mem = poly_evals_mem[0];
    let mut r_joint_mem = challenges_mem;
    r_joint_mem.extend(rand_mem);
    #[cfg(debug_assertions)]
    {
      if !dense.comb_source_fused {
        let external_mem_eval = dense.comb_mem_external.as_ref().map(|external| {
          external
            .evaluate(&r_joint_mem)
            .expect("file-backed comb_mem evaluation failed")
        });
        debug_assert_eq!(
          external_mem_eval.unwrap_or_else(|| dense.comb_mem.evaluate(&r_joint_mem)),
          joint_claim_eval_mem
        );
      }
    }
    joint_claim_eval_mem.append_to_transcript(b"joint_claim_eval_mem", transcript);
    let (proof_mem, _comm_mem_eval) = if dense.comb_source_fused {
      let prebound = dense.fs6_bound_comb_mem(&r_joint_mem);
      PolyEvalProof::prove_prebound_plain(
        r_joint_mem.len(),
        &r_joint_mem,
        &joint_claim_eval_mem,
        &prebound,
        &gens.gens_mem,
        transcript,
        random_tape,
      )
      .expect("source-fused comb_mem evaluation proof failed")
    } else if let Some(external) = &dense.comb_mem_external {
      PolyEvalProof::prove_file_backed_plain(
        external,
        &r_joint_mem,
        &joint_claim_eval_mem,
        &gens.gens_mem,
        transcript,
        random_tape,
      )
      .expect("file-backed comb_mem evaluation proof failed")
    } else {
      PolyEvalProof::prove(
        &dense.comb_mem,
        None,
        &r_joint_mem,
        &joint_claim_eval_mem,
        None,
        &gens.gens_mem,
        transcript,
        random_tape,
      )
    };

    HashLayerProof {
      eval_row: (eval_row_addr_vec, eval_row_read_ts_vec, eval_row_audit_ts),
      eval_col: (eval_col_addr_vec, eval_col_read_ts_vec, eval_col_audit_ts),
      eval_val: eval_val_vec,
      eval_derefs,
      proof_ops,
      proof_mem,
      proof_derefs,
    }
  }

  fn verify_helper(
    rand: &(&Vec<Scalar>, &Vec<Scalar>),
    claims: &(Scalar, Vec<Scalar>, Vec<Scalar>, Scalar),
    eval_ops_val: &[Scalar],
    eval_ops_addr: &[Scalar],
    eval_read_ts: &[Scalar],
    eval_audit_ts: &Scalar,
    r: &[Scalar],
    r_hash: &Scalar,
    r_multiset_check: &Scalar,
  ) -> Result<(), ProofVerifyError> {
    let r_hash_sqr = r_hash * r_hash;
    let hash_func = |addr: &Scalar, val: &Scalar, ts: &Scalar| -> Scalar {
      ts * r_hash_sqr + val * r_hash + addr
    };

    let (rand_mem, _rand_ops) = rand;
    let (claim_init, claim_read, claim_write, claim_audit) = claims;

    // init
    let eval_init_addr = IdentityPolynomial::new(rand_mem.len()).evaluate(rand_mem);
    let eval_init_val = EqPolynomial::new(r.to_vec()).evaluate(rand_mem);
    let hash_init_at_rand_mem =
      hash_func(&eval_init_addr, &eval_init_val, &Scalar::zero()) - r_multiset_check; // verify the claim_last of init chunk
    assert_eq!(&hash_init_at_rand_mem, claim_init);

    // read
    for i in 0..eval_ops_addr.len() {
      let hash_read_at_rand_ops =
        hash_func(&eval_ops_addr[i], &eval_ops_val[i], &eval_read_ts[i]) - r_multiset_check; // verify the claim_last of init chunk
      assert_eq!(&hash_read_at_rand_ops, &claim_read[i]);
    }

    // write: shares addr, val component; only decommit write_ts
    for i in 0..eval_ops_addr.len() {
      let eval_write_ts = eval_read_ts[i] + Scalar::one();
      let hash_write_at_rand_ops =
        hash_func(&eval_ops_addr[i], &eval_ops_val[i], &eval_write_ts) - r_multiset_check; // verify the claim_last of init chunk
      assert_eq!(&hash_write_at_rand_ops, &claim_write[i]);
    }

    // audit: shares addr and val with init
    let eval_audit_addr = eval_init_addr;
    let eval_audit_val = eval_init_val;
    let hash_audit_at_rand_mem =
      hash_func(&eval_audit_addr, &eval_audit_val, eval_audit_ts) - r_multiset_check;
    assert_eq!(&hash_audit_at_rand_mem, claim_audit); // verify the last step of the sum-check for audit

    Ok(())
  }

  fn verify(
    &self,
    rand: (&Vec<Scalar>, &Vec<Scalar>),
    claims_row: &(Scalar, Vec<Scalar>, Vec<Scalar>, Scalar),
    claims_col: &(Scalar, Vec<Scalar>, Vec<Scalar>, Scalar),
    claims_dotp: &[Scalar],
    comm: &SparseMatPolyCommitment,
    gens: &SparseMatPolyCommitmentGens,
    comm_derefs: &DerefsCommitment,
    rx: &[Scalar],
    ry: &[Scalar],
    r_hash: &Scalar,
    r_multiset_check: &Scalar,
    transcript: &mut Transcript,
  ) -> Result<(), ProofVerifyError> {
    let timer = Timer::new("verify_hash_proof");
    transcript.append_protocol_name(HashLayerProof::protocol_name());

    let (rand_mem, rand_ops) = rand;

    // verify derefs at rand_ops
    let (eval_row_ops_val, eval_col_ops_val) = &self.eval_derefs;
    assert_eq!(eval_row_ops_val.len(), eval_col_ops_val.len());
    self.proof_derefs.verify(
      rand_ops,
      eval_row_ops_val,
      eval_col_ops_val,
      &gens.gens_derefs,
      comm_derefs,
      transcript,
    )?;

    // verify the decommitments used in evaluation sum-check
    let eval_val_vec = &self.eval_val;
    assert_eq!(claims_dotp.len(), 3 * eval_row_ops_val.len());
    for i in 0..claims_dotp.len() / 3 {
      let claim_row_ops_val = claims_dotp[3 * i];
      let claim_col_ops_val = claims_dotp[3 * i + 1];
      let claim_val = claims_dotp[3 * i + 2];

      assert_eq!(claim_row_ops_val, eval_row_ops_val[i]);
      assert_eq!(claim_col_ops_val, eval_col_ops_val[i]);
      assert_eq!(claim_val, eval_val_vec[i]);
    }

    // verify addr-timestamps using comm_comb_ops at rand_ops
    let (eval_row_addr_vec, eval_row_read_ts_vec, eval_row_audit_ts) = &self.eval_row;
    let (eval_col_addr_vec, eval_col_read_ts_vec, eval_col_audit_ts) = &self.eval_col;

    let mut evals_ops: Vec<Scalar> = Vec::new();
    evals_ops.extend(eval_row_addr_vec);
    evals_ops.extend(eval_row_read_ts_vec);
    evals_ops.extend(eval_col_addr_vec);
    evals_ops.extend(eval_col_read_ts_vec);
    evals_ops.extend(eval_val_vec);
    evals_ops.resize(evals_ops.len().next_power_of_two(), Scalar::zero());
    evals_ops.append_to_transcript(b"claim_evals_ops", transcript);
    let challenges_ops =
      transcript.challenge_vector(b"challenge_combine_n_to_one", evals_ops.len().log_2());

    let mut poly_evals_ops = DensePolynomial::new(evals_ops);
    for i in (0..challenges_ops.len()).rev() {
      poly_evals_ops.bound_poly_var_bot(&challenges_ops[i]);
    }
    assert_eq!(poly_evals_ops.len(), 1);
    let joint_claim_eval_ops = poly_evals_ops[0];
    let mut r_joint_ops = challenges_ops;
    r_joint_ops.extend(rand_ops);
    joint_claim_eval_ops.append_to_transcript(b"joint_claim_eval_ops", transcript);
    self.proof_ops.verify_plain(
      &gens.gens_ops,
      transcript,
      &r_joint_ops,
      &joint_claim_eval_ops,
      &comm.comm_comb_ops,
    )?;

    // verify proof-mem using comm_comb_mem at rand_mem
    // form a single decommitment using comb_comb_mem at rand_mem
    let evals_mem: Vec<Scalar> = vec![*eval_row_audit_ts, *eval_col_audit_ts];
    evals_mem.append_to_transcript(b"claim_evals_mem", transcript);
    let challenges_mem =
      transcript.challenge_vector(b"challenge_combine_two_to_one", evals_mem.len().log_2());

    let mut poly_evals_mem = DensePolynomial::new(evals_mem);
    for i in (0..challenges_mem.len()).rev() {
      poly_evals_mem.bound_poly_var_bot(&challenges_mem[i]);
    }
    assert_eq!(poly_evals_mem.len(), 1);
    let joint_claim_eval_mem = poly_evals_mem[0];
    let mut r_joint_mem = challenges_mem;
    r_joint_mem.extend(rand_mem);
    joint_claim_eval_mem.append_to_transcript(b"joint_claim_eval_mem", transcript);
    self.proof_mem.verify_plain(
      &gens.gens_mem,
      transcript,
      &r_joint_mem,
      &joint_claim_eval_mem,
      &comm.comm_comb_mem,
    )?;

    // verify the claims from the product layer
    let (eval_ops_addr, eval_read_ts, eval_audit_ts) = &self.eval_row;
    HashLayerProof::verify_helper(
      &(rand_mem, rand_ops),
      claims_row,
      eval_row_ops_val,
      eval_ops_addr,
      eval_read_ts,
      eval_audit_ts,
      rx,
      r_hash,
      r_multiset_check,
    )?;

    let (eval_ops_addr, eval_read_ts, eval_audit_ts) = &self.eval_col;
    HashLayerProof::verify_helper(
      &(rand_mem, rand_ops),
      claims_col,
      eval_col_ops_val,
      eval_ops_addr,
      eval_read_ts,
      eval_audit_ts,
      ry,
      r_hash,
      r_multiset_check,
    )?;

    timer.stop();
    Ok(())
  }
}

#[derive(Debug, Serialize, Deserialize)]
struct ProductLayerProof {
  eval_row: (Scalar, Vec<Scalar>, Vec<Scalar>, Scalar),
  eval_col: (Scalar, Vec<Scalar>, Vec<Scalar>, Scalar),
  eval_val: (Vec<Scalar>, Vec<Scalar>),
  proof_mem: ProductCircuitEvalProofBatched,
  proof_ops: ProductCircuitEvalProofBatched,
}

impl ProductLayerProof {
  fn protocol_name() -> &'static [u8] {
    b"Sparse polynomial product layer proof"
  }

  pub fn prove(
    row_prod_layer: &mut ProductLayer,
    col_prod_layer: &mut ProductLayer,
    dense: &MultiSparseMatPolynomialAsDense,
    derefs: &Derefs,
    eval: &[Scalar],
    mut store: Option<&mut MultiObjectFileBackedStateStore>,
    arena: Option<&BudgetAccountedArena>,
    transcript: &mut Transcript,
  ) -> (Self, Vec<Scalar>, Vec<Scalar>) {
    transcript.append_protocol_name(ProductLayerProof::protocol_name());

    let row_eval_init = row_prod_layer.init.evaluate();
    let row_eval_audit = row_prod_layer.audit.evaluate();
    let row_eval_read = (0..row_prod_layer.read_vec.len())
      .map(|i| row_prod_layer.read_vec[i].evaluate())
      .collect::<Vec<Scalar>>();
    let row_eval_write = (0..row_prod_layer.write_vec.len())
      .map(|i| row_prod_layer.write_vec[i].evaluate())
      .collect::<Vec<Scalar>>();

    // subset check
    let ws: Scalar = (0..row_eval_write.len())
      .map(|i| row_eval_write[i])
      .product();
    let rs: Scalar = (0..row_eval_read.len()).map(|i| row_eval_read[i]).product();
    assert_eq!(row_eval_init * ws, rs * row_eval_audit);

    row_eval_init.append_to_transcript(b"claim_row_eval_init", transcript);
    row_eval_read.append_to_transcript(b"claim_row_eval_read", transcript);
    row_eval_write.append_to_transcript(b"claim_row_eval_write", transcript);
    row_eval_audit.append_to_transcript(b"claim_row_eval_audit", transcript);

    let col_eval_init = col_prod_layer.init.evaluate();
    let col_eval_audit = col_prod_layer.audit.evaluate();
    let col_eval_read: Vec<Scalar> = (0..col_prod_layer.read_vec.len())
      .map(|i| col_prod_layer.read_vec[i].evaluate())
      .collect();
    let col_eval_write: Vec<Scalar> = (0..col_prod_layer.write_vec.len())
      .map(|i| col_prod_layer.write_vec[i].evaluate())
      .collect();

    // subset check
    let ws: Scalar = (0..col_eval_write.len())
      .map(|i| col_eval_write[i])
      .product();
    let rs: Scalar = (0..col_eval_read.len()).map(|i| col_eval_read[i]).product();
    assert_eq!(col_eval_init * ws, rs * col_eval_audit);

    col_eval_init.append_to_transcript(b"claim_col_eval_init", transcript);
    col_eval_read.append_to_transcript(b"claim_col_eval_read", transcript);
    col_eval_write.append_to_transcript(b"claim_col_eval_write", transcript);
    col_eval_audit.append_to_transcript(b"claim_col_eval_audit", transcript);

    // prepare dotproduct circuit for batching then with ops-related product circuits
    assert_eq!(eval.len(), derefs.table_count());
    assert_eq!(eval.len(), dense.val.len());
    let mut dotp_circuit_left_vec: Vec<DotProductCircuit> = Vec::new();
    let mut dotp_circuit_right_vec: Vec<DotProductCircuit> = Vec::new();
    let mut eval_dotp_left_vec: Vec<Scalar> = Vec::new();
    let mut eval_dotp_right_vec: Vec<Scalar> = Vec::new();
    let fs4 = std::env::var("LIBSPARTAN_ACTIVE_STATE_STREAMING").as_deref() == Ok("1");
    for i in 0..derefs.table_count() {
      let fs7 = dense.val_external_offset.is_some();
      if fs4 && fs7 {
        let length = dense.val_table_len();
        let half = length / 2;
        let external = store.as_deref_mut().expect("FS4 state store missing");
        let build_half = |start: usize,
                          suffix: &str,
                          external: &mut MultiObjectFileBackedStateStore|
         -> DotProductCircuit {
          DotProductCircuit::new_external_from_chunk_sources(
            half,
            |offset, count| {
              Ok(derefs.materialize_table_range(true, i, &dense.row, start + offset, count))
            },
            |offset, count| {
              Ok(derefs.materialize_table_range(false, i, &dense.col, start + offset, count))
            },
            |offset, count| Ok(dense.val_range(i, start + offset, count)),
            &format!("fs4-dotp-{i}.{suffix}"),
            external,
          )
          .expect("FS7 dot-product externalization failed")
        };
        let dotp_circuit_left = build_half(0, "low", external);
        let dotp_circuit_right = build_half(half, "high", external);
        let eval_dotp_left = dotp_circuit_left.evaluate();
        let eval_dotp_right = dotp_circuit_right.evaluate();
        eval_dotp_left.append_to_transcript(b"claim_eval_dotp_left", transcript);
        eval_dotp_right.append_to_transcript(b"claim_eval_dotp_right", transcript);
        assert_eq!(eval_dotp_left + eval_dotp_right, eval[i]);
        eval_dotp_left_vec.push(eval_dotp_left);
        eval_dotp_right_vec.push(eval_dotp_right);
        dotp_circuit_left_vec.push(dotp_circuit_left);
        dotp_circuit_right_vec.push(dotp_circuit_right);
        continue;
      }
      let row_values: Cow<'_, [Scalar]> = if derefs.is_fs6() {
        Cow::Owned(derefs.materialize_table(true, i, &dense.row))
      } else {
        Cow::Borrowed(derefs.row_ops_val[i].values())
      };
      let col_values: Cow<'_, [Scalar]> = if derefs.is_fs6() {
        Cow::Owned(derefs.materialize_table(false, i, &dense.col))
      } else {
        Cow::Borrowed(derefs.col_ops_val[i].values())
      };
      let (dotp_circuit_left, dotp_circuit_right) = if fs4 {
        let length = row_values.len();
        let half = length / 2;
        let external = store.as_deref_mut().expect("FS4 state store missing");
        (
          DotProductCircuit::new_external_from_slices(
            &row_values[..half],
            &col_values[..half],
            &dense.val[i].values()[..half],
            &format!("fs4-dotp-{i}.low"),
            external,
          )
          .expect("FS4 low dot-product externalization failed"),
          DotProductCircuit::new_external_from_slices(
            &row_values[half..],
            &col_values[half..],
            &dense.val[i].values()[half..],
            &format!("fs4-dotp-{i}.high"),
            external,
          )
          .expect("FS4 high dot-product externalization failed"),
        )
      } else {
        // evaluate sparse polynomial evaluation using two dotp checks
        let left = DensePolynomial::new(row_values.to_vec());
        let right = DensePolynomial::new(col_values.to_vec());
        let weights = dense.val[i].clone();
        let mut dotp_circuit = DotProductCircuit::new(left, right, weights);
        dotp_circuit.split()
      };

      let (eval_dotp_left, eval_dotp_right) =
        (dotp_circuit_left.evaluate(), dotp_circuit_right.evaluate());

      eval_dotp_left.append_to_transcript(b"claim_eval_dotp_left", transcript);
      eval_dotp_right.append_to_transcript(b"claim_eval_dotp_right", transcript);
      assert_eq!(eval_dotp_left + eval_dotp_right, eval[i]);
      eval_dotp_left_vec.push(eval_dotp_left);
      eval_dotp_right_vec.push(eval_dotp_right);

      dotp_circuit_left_vec.push(dotp_circuit_left);
      dotp_circuit_right_vec.push(dotp_circuit_right);
    }

    // The number of operations into the memory encoded by rx and ry are always the same (by design)
    // So we can produce a batched product proof for all of them at the same time.
    // prove the correctness of claim_row_eval_read, claim_row_eval_write, claim_col_eval_read, and claim_col_eval_write
    // TODO: we currently only produce proofs for 3 batched sparse polynomial evaluations
    assert_eq!(row_prod_layer.read_vec.len(), 3);
    let (row_read_A, row_read_B, row_read_C) = {
      let (vec_A, vec_BC) = row_prod_layer.read_vec.split_at_mut(1);
      let (vec_B, vec_C) = vec_BC.split_at_mut(1);
      (vec_A, vec_B, vec_C)
    };

    let (row_write_A, row_write_B, row_write_C) = {
      let (vec_A, vec_BC) = row_prod_layer.write_vec.split_at_mut(1);
      let (vec_B, vec_C) = vec_BC.split_at_mut(1);
      (vec_A, vec_B, vec_C)
    };

    let (col_read_A, col_read_B, col_read_C) = {
      let (vec_A, vec_BC) = col_prod_layer.read_vec.split_at_mut(1);
      let (vec_B, vec_C) = vec_BC.split_at_mut(1);
      (vec_A, vec_B, vec_C)
    };

    let (col_write_A, col_write_B, col_write_C) = {
      let (vec_A, vec_BC) = col_prod_layer.write_vec.split_at_mut(1);
      let (vec_B, vec_C) = vec_BC.split_at_mut(1);
      (vec_A, vec_B, vec_C)
    };

    let (dotp_left_A, dotp_left_B, dotp_left_C) = {
      let (vec_A, vec_BC) = dotp_circuit_left_vec.split_at_mut(1);
      let (vec_B, vec_C) = vec_BC.split_at_mut(1);
      (vec_A, vec_B, vec_C)
    };

    let (dotp_right_A, dotp_right_B, dotp_right_C) = {
      let (vec_A, vec_BC) = dotp_circuit_right_vec.split_at_mut(1);
      let (vec_B, vec_C) = vec_BC.split_at_mut(1);
      (vec_A, vec_B, vec_C)
    };

    let mut ops_product_circuits: [&mut ProductCircuit; 12] = [
      &mut row_read_A[0],
      &mut row_read_B[0],
      &mut row_read_C[0],
      &mut row_write_A[0],
      &mut row_write_B[0],
      &mut row_write_C[0],
      &mut col_read_A[0],
      &mut col_read_B[0],
      &mut col_read_C[0],
      &mut col_write_A[0],
      &mut col_write_B[0],
      &mut col_write_C[0],
    ];
    let mut ops_dot_product_circuits: [&mut DotProductCircuit; 6] = [
      &mut dotp_left_A[0],
      &mut dotp_right_A[0],
      &mut dotp_left_B[0],
      &mut dotp_right_B[0],
      &mut dotp_left_C[0],
      &mut dotp_right_C[0],
    ];
    let (proof_ops, rand_ops) = if let Some(external) = store.as_deref_mut() {
      ProductCircuitEvalProofBatched::prove_external(
        &mut ops_product_circuits,
        &mut ops_dot_product_circuits,
        external,
        arena.expect("FS3 arena missing"),
        transcript,
      )
      .expect("FS3 product-ops streaming failed")
    } else {
      ProductCircuitEvalProofBatched::prove(
        &mut ops_product_circuits,
        &mut ops_dot_product_circuits,
        transcript,
      )
    };

    // produce a batched proof of memory-related product circuits
    let mut memory_product_circuits: [&mut ProductCircuit; 4] = [
      &mut row_prod_layer.init,
      &mut row_prod_layer.audit,
      &mut col_prod_layer.init,
      &mut col_prod_layer.audit,
    ];
    let (proof_mem, rand_mem) = if let Some(external) = store.as_deref_mut() {
      ProductCircuitEvalProofBatched::prove_external(
        &mut memory_product_circuits,
        &mut [],
        external,
        arena.expect("FS3 arena missing"),
        transcript,
      )
      .expect("FS3 product-memory streaming failed")
    } else {
      ProductCircuitEvalProofBatched::prove(&mut memory_product_circuits, &mut [], transcript)
    };

    let product_layer_proof = ProductLayerProof {
      eval_row: (row_eval_init, row_eval_read, row_eval_write, row_eval_audit),
      eval_col: (col_eval_init, col_eval_read, col_eval_write, col_eval_audit),
      eval_val: (eval_dotp_left_vec, eval_dotp_right_vec),
      proof_mem,
      proof_ops,
    };

    let product_layer_proof_encoded: Vec<u8> = bincode::serialize(&product_layer_proof).unwrap();
    let msg = format!(
      "len_product_layer_proof {:?}",
      product_layer_proof_encoded.len()
    );
    Timer::print(&msg);

    (product_layer_proof, rand_mem, rand_ops)
  }

  pub fn verify(
    &self,
    num_ops: usize,
    num_cells: usize,
    eval: &[Scalar],
    transcript: &mut Transcript,
  ) -> Result<
    (
      Vec<Scalar>,
      Vec<Scalar>,
      Vec<Scalar>,
      Vec<Scalar>,
      Vec<Scalar>,
    ),
    ProofVerifyError,
  > {
    transcript.append_protocol_name(ProductLayerProof::protocol_name());

    let timer = Timer::new("verify_prod_proof");
    let num_instances = eval.len();

    // subset check
    let (row_eval_init, row_eval_read, row_eval_write, row_eval_audit) = &self.eval_row;
    assert_eq!(row_eval_write.len(), num_instances);
    assert_eq!(row_eval_read.len(), num_instances);
    let ws: Scalar = row_eval_write.iter().product();
    let rs: Scalar = row_eval_read.iter().product();
    assert_eq!(row_eval_init * ws, rs * row_eval_audit);

    row_eval_init.append_to_transcript(b"claim_row_eval_init", transcript);
    row_eval_read.append_to_transcript(b"claim_row_eval_read", transcript);
    row_eval_write.append_to_transcript(b"claim_row_eval_write", transcript);
    row_eval_audit.append_to_transcript(b"claim_row_eval_audit", transcript);

    // subset check
    let (col_eval_init, col_eval_read, col_eval_write, col_eval_audit) = &self.eval_col;
    assert_eq!(col_eval_write.len(), num_instances);
    assert_eq!(col_eval_read.len(), num_instances);
    let ws: Scalar = col_eval_write.iter().product();
    let rs: Scalar = col_eval_read.iter().product();
    assert_eq!(col_eval_init * ws, rs * col_eval_audit);

    col_eval_init.append_to_transcript(b"claim_col_eval_init", transcript);
    col_eval_read.append_to_transcript(b"claim_col_eval_read", transcript);
    col_eval_write.append_to_transcript(b"claim_col_eval_write", transcript);
    col_eval_audit.append_to_transcript(b"claim_col_eval_audit", transcript);

    // verify the evaluation of the sparse polynomial
    let (eval_dotp_left, eval_dotp_right) = &self.eval_val;
    assert_eq!(eval_dotp_left.len(), eval_dotp_right.len());
    assert_eq!(eval_dotp_left.len(), num_instances);
    let mut claims_dotp_circuit: Vec<Scalar> = Vec::new();
    for i in 0..num_instances {
      assert_eq!(eval_dotp_left[i] + eval_dotp_right[i], eval[i]);
      eval_dotp_left[i].append_to_transcript(b"claim_eval_dotp_left", transcript);
      eval_dotp_right[i].append_to_transcript(b"claim_eval_dotp_right", transcript);

      claims_dotp_circuit.push(eval_dotp_left[i]);
      claims_dotp_circuit.push(eval_dotp_right[i]);
    }

    // verify the correctness of claim_row_eval_read, claim_row_eval_write, claim_col_eval_read, and claim_col_eval_write
    let mut claims_prod_circuit: Vec<Scalar> = Vec::new();
    claims_prod_circuit.extend(row_eval_read);
    claims_prod_circuit.extend(row_eval_write);
    claims_prod_circuit.extend(col_eval_read);
    claims_prod_circuit.extend(col_eval_write);

    let (claims_ops, claims_dotp, rand_ops) = self.proof_ops.verify(
      &claims_prod_circuit,
      &claims_dotp_circuit,
      num_ops,
      transcript,
    );
    // verify the correctness of claim_row_eval_init and claim_row_eval_audit
    let (claims_mem, _claims_mem_dotp, rand_mem) = self.proof_mem.verify(
      &[
        *row_eval_init,
        *row_eval_audit,
        *col_eval_init,
        *col_eval_audit,
      ],
      &Vec::new(),
      num_cells,
      transcript,
    );
    timer.stop();

    Ok((claims_mem, rand_mem, claims_ops, claims_dotp, rand_ops))
  }
}

#[derive(Debug, Serialize, Deserialize)]
struct PolyEvalNetworkProof {
  proof_prod_layer: ProductLayerProof,
  proof_hash_layer: HashLayerProof,
}

impl PolyEvalNetworkProof {
  fn protocol_name() -> &'static [u8] {
    b"Sparse polynomial evaluation proof"
  }

  pub fn prove(
    network: &mut PolyEvalNetwork,
    dense: &MultiSparseMatPolynomialAsDense,
    derefs: &Derefs,
    evals: &[Scalar],
    gens: &SparseMatPolyCommitmentGens,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape,
    mut store: Option<&mut MultiObjectFileBackedStateStore>,
    arena: Option<&BudgetAccountedArena>,
  ) -> Self {
    transcript.append_protocol_name(PolyEvalNetworkProof::protocol_name());

    let (proof_prod_layer, rand_mem, rand_ops) = ProductLayerProof::prove(
      &mut network.row_layers.prod_layer,
      &mut network.col_layers.prod_layer,
      dense,
      derefs,
      evals,
      store.as_deref_mut(),
      arena,
      transcript,
    );
    #[cfg(feature = "thinwallet-experiment")]
    thinwallet_instrumentation::record_trace_event(
      "product_layer_proof",
      &["inst", "comm_derefs"],
      &["proof_prod_layer", "rand_mem", "rand_ops"],
      None,
      &["proof_prod_layer"],
      false,
    );

    // proof of hash layer for row and col
    let proof_hash_layer = HashLayerProof::prove(
      (&rand_mem, &rand_ops),
      dense,
      derefs,
      gens,
      transcript,
      random_tape,
    );
    #[cfg(feature = "thinwallet-experiment")]
    thinwallet_instrumentation::record_trace_event(
      "hash_layer_proof",
      &["inst", "rand_mem", "rand_ops"],
      &["proof_hash_layer"],
      Some(random_tape.root_label()),
      &["proof_hash_layer"],
      false,
    );

    PolyEvalNetworkProof {
      proof_prod_layer,
      proof_hash_layer,
    }
  }

  pub fn verify(
    &self,
    comm: &SparseMatPolyCommitment,
    comm_derefs: &DerefsCommitment,
    evals: &[Scalar],
    gens: &SparseMatPolyCommitmentGens,
    rx: &[Scalar],
    ry: &[Scalar],
    r_mem_check: &(Scalar, Scalar),
    nz: usize,
    transcript: &mut Transcript,
  ) -> Result<(), ProofVerifyError> {
    let timer = Timer::new("verify_polyeval_proof");
    transcript.append_protocol_name(PolyEvalNetworkProof::protocol_name());

    let num_instances = evals.len();
    let (r_hash, r_multiset_check) = r_mem_check;

    let num_ops = nz.next_power_of_two();
    let num_cells = rx.len().pow2();
    assert_eq!(rx.len(), ry.len());

    let (claims_mem, rand_mem, mut claims_ops, claims_dotp, rand_ops) = self
      .proof_prod_layer
      .verify(num_ops, num_cells, evals, transcript)?;
    assert_eq!(claims_mem.len(), 4);
    assert_eq!(claims_ops.len(), 4 * num_instances);
    assert_eq!(claims_dotp.len(), 3 * num_instances);

    let (claims_ops_row, claims_ops_col) = claims_ops.split_at_mut(2 * num_instances);
    let (claims_ops_row_read, claims_ops_row_write) = claims_ops_row.split_at_mut(num_instances);
    let (claims_ops_col_read, claims_ops_col_write) = claims_ops_col.split_at_mut(num_instances);

    // verify the proof of hash layer
    self.proof_hash_layer.verify(
      (&rand_mem, &rand_ops),
      &(
        claims_mem[0],
        claims_ops_row_read.to_vec(),
        claims_ops_row_write.to_vec(),
        claims_mem[1],
      ),
      &(
        claims_mem[2],
        claims_ops_col_read.to_vec(),
        claims_ops_col_write.to_vec(),
        claims_mem[3],
      ),
      &claims_dotp,
      comm,
      gens,
      comm_derefs,
      rx,
      ry,
      r_hash,
      r_multiset_check,
      transcript,
    )?;
    timer.stop();

    Ok(())
  }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SparseMatPolyEvalProof {
  comm_derefs: DerefsCommitment,
  poly_eval_network_proof: PolyEvalNetworkProof,
}

impl SparseMatPolyEvalProof {
  fn protocol_name() -> &'static [u8] {
    b"Sparse polynomial evaluation proof"
  }

  fn equalize(rx: &[Scalar], ry: &[Scalar]) -> (Vec<Scalar>, Vec<Scalar>) {
    match rx.len().cmp(&ry.len()) {
      Ordering::Less => {
        let diff = ry.len() - rx.len();
        let mut rx_ext = vec![Scalar::zero(); diff];
        rx_ext.extend(rx);
        (rx_ext, ry.to_vec())
      }
      Ordering::Greater => {
        let diff = rx.len() - ry.len();
        let mut ry_ext = vec![Scalar::zero(); diff];
        ry_ext.extend(ry);
        (rx.to_vec(), ry_ext)
      }
      Ordering::Equal => (rx.to_vec(), ry.to_vec()),
    }
  }

  pub fn prove(
    dense: &MultiSparseMatPolynomialAsDense,
    rx: &[Scalar], // point at which the polynomial is evaluated
    ry: &[Scalar],
    evals: &[Scalar], // a vector evaluation of \widetilde{M}(r = (rx,ry)) for each M
    gens: &SparseMatPolyCommitmentGens,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape,
  ) -> SparseMatPolyEvalProof {
    let _memory_scope = memory_trace::scope(&SPARSE_EVAL_PROOF);
    ACTIVE_PRODUCT_BUILD_NS.store(0, AtomicOrdering::Relaxed);
    CHECKPOINT_RECOMPUTE_NS.store(0, AtomicOrdering::Relaxed);
    super::sumcheck::reset_active_sumcheck_streaming_ns();
    transcript.append_protocol_name(SparseMatPolyEvalProof::protocol_name());

    // ensure there is one eval for each polynomial in dense
    assert_eq!(evals.len(), dense.batch_size);

    let (mem_rx, mem_ry) = {
      // equalize the lengths of rx and ry
      let (rx_ext, ry_ext) = SparseMatPolyEvalProof::equalize(rx, ry);
      let poly_rx = EqPolynomial::new(rx_ext).evals();
      let poly_ry = EqPolynomial::new(ry_ext).evals();
      (poly_rx, poly_ry)
    };

    let derefs = dense.deref(&mem_rx, &mem_ry);

    // commit to non-deterministic choices of the prover
    let timer_commit = Timer::new("commit_nondet_witness");
    #[cfg(feature = "thinwallet-experiment")]
    let commit_cpu_start = thinwallet_instrumentation::process_cpu_time_ns();
    #[cfg(feature = "thinwallet-experiment")]
    let commit_wall_start = Instant::now();
    let comm_derefs = {
      let comm = derefs.commit(dense, &gens.gens_derefs);
      comm.append_to_transcript(b"comm_poly_row_col_ops_val", transcript);
      comm
    };
    #[cfg(feature = "thinwallet-experiment")]
    thinwallet_instrumentation::record_trace_event(
      "derefs_commit",
      &["inst", "rx_ry"],
      &["comm_derefs"],
      None,
      &["comm_derefs"],
      false,
    );
    #[cfg(feature = "thinwallet-experiment")]
    {
      let wall_ns = commit_wall_start.elapsed().as_nanos() as u64;
      let cpu_ns =
        thinwallet_instrumentation::process_cpu_time_ns().saturating_sub(commit_cpu_start);
      thinwallet_instrumentation::record_stage_metrics(
        "eval_commit_nondet",
        wall_ns,
        wall_ns,
        cpu_ns,
        cpu_ns,
        0,
      );
    }
    timer_commit.stop();

    let fs3 = std::env::var("LIBSPARTAN_MULTI_TARGET_STREAMING").as_deref() == Ok("1");
    let budget = if fs3 {
      Some(ProverMemoryBudget::from_env().expect("invalid FS3 prover memory budget"))
    } else {
      None
    };
    let arena = budget
      .as_ref()
      .map(|value| BudgetAccountedArena::new(value.usable_prover_bytes().unwrap()));
    let mut state_store = budget.as_ref().map(|value| {
      let proof_session = std::env::var("V3B_STATE_SESSION")
        .unwrap_or_else(|_| format!("fs3-{}", std::process::id()));
      let mut hasher = Sha256::new();
      hasher.update(b"thinwallet-v3b-state-metadata-key");
      hasher.update(proof_session.as_bytes());
      let metadata_key: [u8; 32] = hasher.finalize().into();
      MultiObjectFileBackedStateStore::create(MultiObjectStoreConfig {
        root: PathBuf::from(
          std::env::var("V3B_STATE_DIR").unwrap_or_else(|_| "target/v3b-state".to_owned()),
        ),
        proof_session,
        backend_revision: "libspartan-0.9.0-thinwallet-v3b".to_owned(),
        metadata_key,
        maximum_chunk_bytes: value.maximum_chunk_bytes,
        maximum_temporary_storage_bytes: value.maximum_temporary_storage_bytes,
        durability: if std::env::var("LIBSPARTAN_EPHEMERAL_STATE").as_deref() == Ok("1") {
          StateDurability::EphemeralCorrectnessOnly
        } else {
          StateDurability::SecurityCriticalDurable
        },
      })
      .expect("failed to create FS3 multi-object state store")
    });

    let poly_eval_network_proof = {
      // produce a random element from the transcript for hash function
      let r_mem_check = transcript.challenge_vector(b"challenge_r_hash", 2);

      // build a network to evaluate the sparse polynomial
      let timer_build_network = Timer::new("build_layered_network");
      #[cfg(feature = "thinwallet-experiment")]
      let build_cpu_start = thinwallet_instrumentation::process_cpu_time_ns();
      #[cfg(feature = "thinwallet-experiment")]
      let build_wall_start = Instant::now();
      let mut net = PolyEvalNetwork::new(
        dense,
        &derefs,
        &mem_rx,
        &mem_ry,
        &(r_mem_check[0], r_mem_check[1]),
        state_store.as_mut(),
        arena.as_ref(),
      )
      .expect("failed to build FS3 layered network");
      #[cfg(feature = "thinwallet-experiment")]
      {
        let wall_ns = build_wall_start.elapsed().as_nanos() as u64;
        let cpu_ns =
          thinwallet_instrumentation::process_cpu_time_ns().saturating_sub(build_cpu_start);
        thinwallet_instrumentation::record_stage_metrics(
          "eval_build_layered_network",
          wall_ns,
          wall_ns,
          cpu_ns,
          cpu_ns,
          0,
        );
      }
      timer_build_network.stop();

      // The equality tables are consumed while constructing the active hash
      // layers. Keeping them alive across every subsequent Sumcheck round adds
      // two full dense tables without any transcript or verifier dependency.
      drop(mem_rx);
      drop(mem_ry);

      let timer_eval_network = Timer::new("evalproof_layered_network");
      #[cfg(feature = "thinwallet-experiment")]
      let layered_cpu_start = thinwallet_instrumentation::process_cpu_time_ns();
      #[cfg(feature = "thinwallet-experiment")]
      let layered_wall_start = Instant::now();
      let poly_eval_network_proof = PolyEvalNetworkProof::prove(
        &mut net,
        dense,
        &derefs,
        evals,
        gens,
        transcript,
        random_tape,
        state_store.as_mut(),
        arena.as_ref(),
      );
      #[cfg(feature = "thinwallet-experiment")]
      {
        let wall_ns = layered_wall_start.elapsed().as_nanos() as u64;
        let cpu_ns =
          thinwallet_instrumentation::process_cpu_time_ns().saturating_sub(layered_cpu_start);
        thinwallet_instrumentation::record_stage_metrics(
          "eval_layered_proof",
          wall_ns,
          wall_ns,
          cpu_ns,
          cpu_ns,
          0,
        );
      }
      timer_eval_network.stop();

      poly_eval_network_proof
    };

    if let Some(store) = state_store.as_mut() {
      store
        .abort_session_cleanup()
        .expect("failed to clean FS3 multi-object state");
      if let Some(path) = std::env::var_os("V3B_STATE_REPORT_PATH") {
        let stats = store.stats();
        let arena_peak = arena
          .as_ref()
          .map(BudgetAccountedArena::peak_bytes)
          .unwrap_or(0);
        let arena_current = arena
          .as_ref()
          .map(BudgetAccountedArena::current_bytes)
          .unwrap_or(0);
        let report = serde_json::json!({
          "schema_version": "thinwallet-phase5f-b-state-store-v1",
          "backend": std::env::var("THINWALLET_EVAL_STORE").ok(),
          "state_root": std::env::var("V3B_STATE_DIR").ok(),
          "bytes_read": stats.bytes_read,
          "bytes_written": stats.bytes_written,
          "full_scans": stats.full_scans,
          "replay_scans": stats.replay_scans,
          "range_reads": stats.range_reads,
          "temporary_storage_peak_bytes": stats.temporary_storage_peak_bytes,
          "accounted_arena_peak_bytes": arena_peak,
          "accounted_arena_current_bytes": arena_current,
          "state_read_time_ns": stats.read_time_ns,
          "state_write_time_ns": stats.write_time_ns,
          "state_fsync_time_ns": stats.fsync_time_ns,
          "state_fsync_calls": stats.fsync_calls,
          "state_skipped_fsync_calls": stats.skipped_fsync_calls,
          "state_cleanup_time_ns": stats.cleanup_time_ns,
          "objects_created": stats.objects_created,
          "objects_deleted": stats.objects_deleted,
          "append_calls": stats.append_calls,
          "seal_calls": stats.seal_calls,
          "seek_calls": stats.seek_calls,
          "data_write_calls": stats.data_write_calls,
          "metadata_write_calls": stats.metadata_write_calls,
          "sync_data_calls": stats.sync_data_calls,
          "largest_read_bytes": stats.largest_read_bytes,
          "largest_write_bytes": stats.largest_write_bytes,
          "range_read_bytes": stats.range_read_bytes,
          "average_range_read_bytes": if stats.range_reads > 0 { Some(stats.range_read_bytes / stats.range_reads) } else { None },
          "average_write_bytes": if stats.data_write_calls > 0 { Some(stats.bytes_written / stats.data_write_calls) } else { None },
          "active_sumcheck_streaming_time_ns": super::sumcheck::active_sumcheck_streaming_ns(),
          "active_product_build_time_ns": ACTIVE_PRODUCT_BUILD_NS.load(AtomicOrdering::Relaxed),
          "checkpoint_recompute_time_ns": CHECKPOINT_RECOMPUTE_NS.load(AtomicOrdering::Relaxed),
        });
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap())
          .expect("failed to write FS3 state report");
      }
    }

    SparseMatPolyEvalProof {
      comm_derefs,
      poly_eval_network_proof,
    }
  }

  pub fn verify(
    &self,
    comm: &SparseMatPolyCommitment,
    rx: &[Scalar], // point at which the polynomial is evaluated
    ry: &[Scalar],
    evals: &[Scalar], // evaluation of \widetilde{M}(r = (rx,ry))
    gens: &SparseMatPolyCommitmentGens,
    transcript: &mut Transcript,
  ) -> Result<(), ProofVerifyError> {
    transcript.append_protocol_name(SparseMatPolyEvalProof::protocol_name());

    // equalize the lengths of rx and ry
    let (rx_ext, ry_ext) = SparseMatPolyEvalProof::equalize(rx, ry);

    let (nz, num_mem_cells) = (comm.num_ops, comm.num_mem_cells);
    assert_eq!(rx_ext.len().pow2(), num_mem_cells);

    // add claims to transcript and obtain challenges for randomized mem-check circuit
    self
      .comm_derefs
      .append_to_transcript(b"comm_poly_row_col_ops_val", transcript);

    // produce a random element from the transcript for hash function
    let r_mem_check = transcript.challenge_vector(b"challenge_r_hash", 2);

    self.poly_eval_network_proof.verify(
      comm,
      &self.comm_derefs,
      evals,
      gens,
      &rx_ext,
      &ry_ext,
      &(r_mem_check[0], r_mem_check[1]),
      nz,
      transcript,
    )
  }
}

pub struct SparsePolyEntry {
  idx: usize,
  val: Scalar,
}

impl SparsePolyEntry {
  pub fn new(idx: usize, val: Scalar) -> Self {
    SparsePolyEntry { idx, val }
  }
}

pub struct SparsePolynomial {
  num_vars: usize,
  Z: Vec<SparsePolyEntry>,
}

impl SparsePolynomial {
  pub fn new(num_vars: usize, Z: Vec<SparsePolyEntry>) -> Self {
    SparsePolynomial { num_vars, Z }
  }

  fn compute_chi(a: &[bool], r: &[Scalar]) -> Scalar {
    assert_eq!(a.len(), r.len());
    a.iter().zip(r.iter()).fold(Scalar::one(), |sum, (a, r)| {
      sum * if *a { *r } else { Scalar::one() - r }
    })
  }

  // Takes O(n log n). TODO: do this in O(n) where n is the number of entries in Z
  pub fn evaluate(&self, r: &[Scalar]) -> Scalar {
    assert_eq!(self.num_vars, r.len());

    (0..self.Z.len())
      .map(|i| {
        let bits = self.Z[i].idx.get_bits(r.len());
        SparsePolynomial::compute_chi(&bits, r) * self.Z[i].val
      })
      .sum()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use rand::rngs::OsRng;
  use rand::RngCore;
  #[test]
  fn check_sparse_polyeval_proof() {
    let mut csprng: OsRng = OsRng;

    let num_nz_entries: usize = 256;
    let num_rows: usize = 256;
    let num_cols: usize = 256;
    let num_vars_x: usize = num_rows.log_2();
    let num_vars_y: usize = num_cols.log_2();

    let M = (0..num_nz_entries)
      .map(|_i| {
        SparseMatEntry::new(
          (csprng.next_u64() % (num_rows as u64)) as usize,
          (csprng.next_u64() % (num_cols as u64)) as usize,
          Scalar::random(&mut csprng),
        )
      })
      .collect();

    let poly_M = SparseMatPolynomial::new(num_vars_x, num_vars_y, M);
    let gens = SparseMatPolyCommitmentGens::new(
      b"gens_sparse_poly",
      num_vars_x,
      num_vars_y,
      num_nz_entries,
      3,
    );

    // commitment
    let (poly_comm, dense) = SparseMatPolynomial::multi_commit(&[&poly_M, &poly_M, &poly_M], &gens);

    // evaluation
    let rx: Vec<Scalar> = (0..num_vars_x)
      .map(|_i| Scalar::random(&mut csprng))
      .collect::<Vec<Scalar>>();
    let ry: Vec<Scalar> = (0..num_vars_y)
      .map(|_i| Scalar::random(&mut csprng))
      .collect::<Vec<Scalar>>();
    let eval = SparseMatPolynomial::multi_evaluate(&[&poly_M], &rx, &ry);
    let evals = vec![eval[0], eval[0], eval[0]];

    let mut random_tape = RandomTape::new(b"proof");
    let mut prover_transcript = Transcript::new(b"example");
    let proof = SparseMatPolyEvalProof::prove(
      &dense,
      &rx,
      &ry,
      &evals,
      &gens,
      &mut prover_transcript,
      &mut random_tape,
    );

    let mut verifier_transcript = Transcript::new(b"example");
    assert!(proof
      .verify(
        &poly_comm,
        &rx,
        &ry,
        &evals,
        &gens,
        &mut verifier_transcript,
      )
      .is_ok());
  }

  #[test]
  fn checkpoint_detects_modified_reconstruction_source() {
    let mut timestamps = AddrTimestamps::new(4, 4, vec![vec![0, 1, 1, 3]]);
    timestamps.checkpoint.source_object_digest = AddrTimestamps::source_digest(
      &timestamps.ops_addr_usize,
      &timestamps.read_ts_usize,
      &timestamps.audit_ts_usize,
    );
    assert!(timestamps.validate_checkpoint());
    let point = vec![Scalar::from(2u64), Scalar::from(3u64)];
    let compact = AddrTimestamps::evaluate_usize(&timestamps.ops_addr_usize[0], &point);
    let dense = DensePolynomial::new(
      timestamps.ops_addr_usize[0]
        .iter()
        .map(|value| Scalar::from(*value as u64))
        .collect(),
    )
    .evaluate(&point);
    assert_eq!(compact, dense);
    timestamps.ops_addr_usize[0][0] ^= 1;
    assert!(!timestamps.validate_checkpoint());
  }

  #[test]
  fn chunkless_query_weights_match_dense_evaluation() {
    let tables = vec![
      (0u32..16).collect::<Vec<_>>(),
      (0u32..16).map(|value| value * 3 + 1).collect::<Vec<_>>(),
    ];
    let point = vec![
      Scalar::from(2u64),
      Scalar::from(3u64),
      Scalar::from(5u64),
      Scalar::from(7u64),
    ];
    let streamed = AddrTimestamps::evaluate_usize_tables_streaming(&tables, &point);
    for (table, evaluation) in tables.iter().zip(streamed) {
      assert_eq!(
        DensePolynomial::new(
          table
            .iter()
            .map(|value| Scalar::from(*value as u64))
            .collect(),
        )
        .evaluate(&point),
        evaluation
      );
    }
  }

  #[test]
  fn source_fused_prebound_matches_dense_bound() {
    let values = (0u64..64).map(Scalar::from).collect::<Vec<_>>();
    let point = vec![
      Scalar::from(2u64),
      Scalar::from(3u64),
      Scalar::from(5u64),
      Scalar::from(7u64),
      Scalar::from(11u64),
      Scalar::from(13u64),
    ];
    let (left, _right) = EqPolynomial::new(point.clone()).compute_factored_evals();
    let expected = DensePolynomial::new(values.clone()).bound(&left);
    let actual = MultiSparseMatPolynomialAsDense::bound_scalar_iter(values, &point);
    assert_eq!(actual, expected);
  }
}
