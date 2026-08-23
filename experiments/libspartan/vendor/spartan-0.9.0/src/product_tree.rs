#![allow(dead_code)]
use super::dense_mlpoly::DensePolynomial;
use super::dense_mlpoly::EqPolynomial;
use super::math::Math;
use super::memory_budget::{BudgetAccountedArena, BudgetReservation};
use super::multi_state_store::{MultiObjectFileBackedStateStore, ProverStateStore};
use super::scalar::Scalar;
use super::streaming_sumcheck_fold::StreamingPolynomial;
use super::sumcheck::SumcheckInstanceProof;
use super::transcript::ProofTranscript;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::io;

#[derive(Debug)]
pub struct ProductCircuit {
  left_vec: Vec<DensePolynomial>,
  right_vec: Vec<DensePolynomial>,
  external_layers: Vec<(String, String)>,
  external_layer_lengths: Vec<usize>,
  external_eval: Option<Scalar>,
}

impl ProductCircuit {
  fn compute_layer(
    inp_left: &DensePolynomial,
    inp_right: &DensePolynomial,
  ) -> (DensePolynomial, DensePolynomial) {
    let len = inp_left.len() + inp_right.len();
    let outp_left = (0..len / 4)
      .map(|i| inp_left[i] * inp_right[i])
      .collect::<Vec<Scalar>>();
    let outp_right = (len / 4..len / 2)
      .map(|i| inp_left[i] * inp_right[i])
      .collect::<Vec<Scalar>>();

    (
      DensePolynomial::new(outp_left),
      DensePolynomial::new(outp_right),
    )
  }

  pub fn new(poly: &DensePolynomial) -> Self {
    let mut left_vec: Vec<DensePolynomial> = Vec::new();
    let mut right_vec: Vec<DensePolynomial> = Vec::new();

    let num_layers = poly.len().log_2();
    let (outp_left, outp_right) = poly.split(poly.len() / 2);

    left_vec.push(outp_left);
    right_vec.push(outp_right);

    for i in 0..num_layers - 1 {
      let (outp_left, outp_right) = ProductCircuit::compute_layer(&left_vec[i], &right_vec[i]);
      left_vec.push(outp_left);
      right_vec.push(outp_right);
    }

    ProductCircuit {
      left_vec,
      right_vec,
      external_layers: Vec::new(),
      external_layer_lengths: Vec::new(),
      external_eval: None,
    }
  }

  pub(crate) fn new_external(
    poly: &DensePolynomial,
    object_prefix: &str,
    store: &mut MultiObjectFileBackedStateStore,
    arena: &BudgetAccountedArena,
  ) -> io::Result<Self> {
    let _construction_reservation = arena.reserve(poly.len() * 32 * 3 / 2)?;
    let num_layers = poly.len().log_2();
    let (mut left, mut right) = poly.split(poly.len() / 2);
    let mut external_layers = Vec::with_capacity(num_layers);
    let mut external_layer_lengths = Vec::with_capacity(num_layers);
    let mut external_eval = None;

    for layer_id in 0..num_layers {
      let left_id = format!("{object_prefix}.layer-{layer_id}.left");
      let right_id = format!("{object_prefix}.layer-{layer_id}.right");
      write_dense_object(store, &left_id, &left)?;
      write_dense_object(store, &right_id, &right)?;
      external_layer_lengths.push(left.len());
      external_layers.push((left_id, right_id));
      if layer_id + 1 == num_layers {
        external_eval = Some(left[0] * right[0]);
      } else {
        (left, right) = ProductCircuit::compute_layer(&left, &right);
      }
    }

    Ok(Self {
      left_vec: Vec::new(),
      right_vec: Vec::new(),
      external_layers,
      external_layer_lengths,
      external_eval,
    })
  }

  fn is_external(&self) -> bool {
    !self.external_layers.is_empty()
  }

  fn num_layers(&self) -> usize {
    if self.is_external() {
      self.external_layers.len()
    } else {
      self.left_vec.len()
    }
  }

  fn load_external_layer(
    &self,
    layer_id: usize,
    store: &mut MultiObjectFileBackedStateStore,
    arena: &BudgetAccountedArena,
  ) -> io::Result<(DensePolynomial, DensePolynomial, Vec<BudgetReservation>)> {
    let (left_id, right_id) = &self.external_layers[layer_id];
    let length = self.external_layer_lengths[layer_id];
    let (left, left_reservation) = read_dense_object(store, left_id, length, arena)?;
    let (right, right_reservation) = read_dense_object(store, right_id, length, arena)?;
    Ok((left, right, vec![left_reservation, right_reservation]))
  }

  fn delete_external_layer(
    &self,
    layer_id: usize,
    store: &mut MultiObjectFileBackedStateStore,
  ) -> io::Result<()> {
    let (left_id, right_id) = &self.external_layers[layer_id];
    store.delete_object(left_id)?;
    store.delete_object(right_id)
  }

  fn streaming_external_layer(
    &self,
    layer_id: usize,
  ) -> io::Result<(StreamingPolynomial, StreamingPolynomial)> {
    let (left_id, right_id) = self
      .external_layers
      .get(layer_id)
      .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing external product layer"))?;
    let length = self.external_layer_lengths[layer_id];
    Ok((
      StreamingPolynomial::existing(left_id.clone(), length),
      StreamingPolynomial::existing(right_id.clone(), length),
    ))
  }

  pub fn evaluate(&self) -> Scalar {
    if let Some(value) = self.external_eval {
      return value;
    }
    let len = self.left_vec.len();
    assert_eq!(self.left_vec[len - 1].get_num_vars(), 0);
    assert_eq!(self.right_vec[len - 1].get_num_vars(), 0);
    self.left_vec[len - 1][0] * self.right_vec[len - 1][0]
  }
}

fn write_dense_object(
  store: &mut MultiObjectFileBackedStateStore,
  object_id: &str,
  polynomial: &DensePolynomial,
) -> io::Result<()> {
  store.create_object(store.descriptor(
    object_id,
    "SumcheckFold",
    "Scalar",
    polynomial.len() as u64,
  ))?;
  let chunk_size = store.maximum_chunk_bytes();
  let mut chunk = Vec::with_capacity(chunk_size);
  let mut chunk_index = 0u64;
  for scalar in polynomial.values() {
    chunk.extend_from_slice(&scalar.to_bytes());
    if chunk.len() == chunk_size {
      store.append_chunk(object_id, chunk_index, &chunk)?;
      chunk.fill(0);
      chunk.clear();
      chunk_index += 1;
    }
  }
  if !chunk.is_empty() {
    store.append_chunk(object_id, chunk_index, &chunk)?;
    chunk.fill(0);
  }
  store.seal_object(object_id)?;
  Ok(())
}

fn read_dense_object(
  store: &mut MultiObjectFileBackedStateStore,
  object_id: &str,
  scalar_count: usize,
  arena: &BudgetAccountedArena,
) -> io::Result<(DensePolynomial, BudgetReservation)> {
  let reservation = arena.reserve(scalar_count * 32)?;
  let mut values = Vec::with_capacity(scalar_count);
  store.sequential_scan(object_id, &mut |_chunk_index, bytes| {
    if bytes.len() % 32 != 0 {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "unaligned scalar object",
      ));
    }
    for encoded in bytes.chunks_exact(32) {
      let mut canonical = [0u8; 32];
      canonical.copy_from_slice(encoded);
      let scalar = Option::<Scalar>::from(Scalar::from_bytes(&canonical))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-canonical scalar object"))?;
      values.push(scalar);
    }
    Ok(())
  })?;
  if values.len() != scalar_count {
    return Err(io::Error::new(
      io::ErrorKind::UnexpectedEof,
      "scalar object length mismatch",
    ));
  }
  Ok((DensePolynomial::new(values), reservation))
}

#[cfg(test)]
mod fs4_transition_tests {
  use super::*;
  use crate::memory_budget::ProverMemoryBudget;
  use crate::multi_state_store::{MultiObjectStoreConfig, ProverStateStore, StateDurability};
  use std::time::{SystemTime, UNIX_EPOCH};

  #[test]
  fn injected_product_transition_failure_cleans_session_state() {
    let nonce = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap()
      .as_nanos();
    let root = std::env::temp_dir().join(format!(
      "thinwallet-v3c-product-failure-{}-{nonce}",
      std::process::id()
    ));
    let session = "product-failure".to_owned();
    let session_root = root.join(&session);
    let mut store = MultiObjectFileBackedStateStore::create(MultiObjectStoreConfig {
      root,
      proof_session: session,
      backend_revision: "libspartan-0.9.0-thinwallet-v3c".to_owned(),
      metadata_key: [0x5a; 32],
      maximum_chunk_bytes: 64,
      maximum_temporary_storage_bytes: 160,
      durability: StateDurability::SecurityCriticalDurable,
    })
    .unwrap();
    let budget = ProverMemoryBudget {
      hard_limit_bytes: 1024 * 1024,
      reserved_runtime_bytes: 0,
      maximum_chunk_bytes: 64,
      maximum_inflight_network_bytes: 0,
      maximum_file_cache_bytes: 0,
      maximum_temporary_storage_bytes: 160,
    };
    let arena = BudgetAccountedArena::new(budget.usable_prover_bytes().unwrap());
    let polynomial = DensePolynomial::new((0..16).map(Scalar::from).collect());
    let error =
      ProductCircuit::new_external(&polynomial, "injected", &mut store, &arena).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
    store.abort_session_cleanup().unwrap();
    assert!(!session_root.exists());
  }
}

pub struct DotProductCircuit {
  left: DensePolynomial,
  right: DensePolynomial,
  weight: DensePolynomial,
  external: Option<ExternalDotProductCircuit>,
}

#[derive(Debug)]
struct ExternalDotProductCircuit {
  left: StreamingPolynomial,
  right: StreamingPolynomial,
  weight: StreamingPolynomial,
  eval: Scalar,
}

impl DotProductCircuit {
  pub fn new(left: DensePolynomial, right: DensePolynomial, weight: DensePolynomial) -> Self {
    assert_eq!(left.len(), right.len());
    assert_eq!(left.len(), weight.len());
    DotProductCircuit {
      left,
      right,
      weight,
      external: None,
    }
  }

  pub(crate) fn new_external_from_slices(
    left_values: &[Scalar],
    right_values: &[Scalar],
    weight_values: &[Scalar],
    object_prefix: &str,
    store: &mut MultiObjectFileBackedStateStore,
  ) -> io::Result<Self> {
    if left_values.len() != right_values.len() || left_values.len() != weight_values.len() {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "dot-product input length mismatch",
      ));
    }
    let eval = left_values
      .iter()
      .zip(right_values)
      .zip(weight_values)
      .map(|((left, right), weight)| left * right * weight)
      .sum();
    let left = StreamingPolynomial::write(
      store,
      format!("{object_prefix}.left"),
      "FS4DotProductInput",
      left_values,
    )?;
    let right = StreamingPolynomial::write(
      store,
      format!("{object_prefix}.right"),
      "FS4DotProductInput",
      right_values,
    )?;
    let weight = StreamingPolynomial::write(
      store,
      format!("{object_prefix}.weight"),
      "FS4DotProductInput",
      weight_values,
    )?;
    Ok(Self {
      left: DensePolynomial::new(vec![Scalar::zero()]),
      right: DensePolynomial::new(vec![Scalar::zero()]),
      weight: DensePolynomial::new(vec![Scalar::zero()]),
      external: Some(ExternalDotProductCircuit {
        left,
        right,
        weight,
        eval,
      }),
    })
  }

  pub(crate) fn new_external_from_chunk_sources<FL, FR, FW>(
    scalar_count: usize,
    mut left_source: FL,
    mut right_source: FR,
    mut weight_source: FW,
    object_prefix: &str,
    store: &mut MultiObjectFileBackedStateStore,
  ) -> io::Result<Self>
  where
    FL: FnMut(usize, usize) -> io::Result<Vec<Scalar>>,
    FR: FnMut(usize, usize) -> io::Result<Vec<Scalar>>,
    FW: FnMut(usize, usize) -> io::Result<Vec<Scalar>>,
  {
    let left = StreamingPolynomial::write_generated(
      store,
      format!("{object_prefix}.left"),
      "FS7CredentialDotProductInput",
      scalar_count,
      &mut left_source,
    )?;
    let right = StreamingPolynomial::write_generated(
      store,
      format!("{object_prefix}.right"),
      "FS7CredentialDotProductInput",
      scalar_count,
      &mut right_source,
    )?;
    let weight = StreamingPolynomial::write_generated(
      store,
      format!("{object_prefix}.weight"),
      "FS7CredentialDotProductInput",
      scalar_count,
      &mut weight_source,
    )?;

    let width = StreamingPolynomial::preferred_chunk_scalars(store);
    let mut left_reader = left.open_reader(store)?;
    let mut right_reader = right.open_reader(store)?;
    let mut weight_reader = weight.open_reader(store)?;
    let mut eval = Scalar::zero();
    for start in (0..scalar_count).step_by(width) {
      let count = width.min(scalar_count - start);
      let left_values = left.read_segment_from(store, &mut left_reader, start, count)?;
      let right_values = right.read_segment_from(store, &mut right_reader, start, count)?;
      let weight_values = weight.read_segment_from(store, &mut weight_reader, start, count)?;
      eval += left_values
        .iter()
        .zip(&right_values)
        .zip(&weight_values)
        .map(|((left, right), weight)| left * right * weight)
        .sum::<Scalar>();
    }

    Ok(Self {
      left: DensePolynomial::new(vec![Scalar::zero()]),
      right: DensePolynomial::new(vec![Scalar::zero()]),
      weight: DensePolynomial::new(vec![Scalar::zero()]),
      external: Some(ExternalDotProductCircuit {
        left,
        right,
        weight,
        eval,
      }),
    })
  }

  pub fn evaluate(&self) -> Scalar {
    if let Some(external) = &self.external {
      return external.eval;
    }
    (0..self.left.len())
      .map(|i| self.left[i] * self.right[i] * self.weight[i])
      .sum()
  }

  pub fn split(&mut self) -> (DotProductCircuit, DotProductCircuit) {
    assert!(self.external.is_none());
    let idx = self.left.len() / 2;
    assert_eq!(idx * 2, self.left.len());
    let (l1, l2) = self.left.split(idx);
    let (r1, r2) = self.right.split(idx);
    let (w1, w2) = self.weight.split(idx);
    (
      DotProductCircuit {
        left: l1,
        right: r1,
        weight: w1,
        external: None,
      },
      DotProductCircuit {
        left: l2,
        right: r2,
        weight: w2,
        external: None,
      },
    )
  }

  fn externalize(
    &mut self,
    object_prefix: &str,
    store: &mut MultiObjectFileBackedStateStore,
  ) -> io::Result<()> {
    if self.external.is_some() {
      return Ok(());
    }
    let eval = self.evaluate();
    let left = StreamingPolynomial::write(
      store,
      format!("{object_prefix}.left"),
      "FS4DotProductInput",
      self.left.values(),
    )?;
    let right = StreamingPolynomial::write(
      store,
      format!("{object_prefix}.right"),
      "FS4DotProductInput",
      self.right.values(),
    )?;
    let weight = StreamingPolynomial::write(
      store,
      format!("{object_prefix}.weight"),
      "FS4DotProductInput",
      self.weight.values(),
    )?;
    self.left = DensePolynomial::new(vec![Scalar::zero()]);
    self.right = DensePolynomial::new(vec![Scalar::zero()]);
    self.weight = DensePolynomial::new(vec![Scalar::zero()]);
    self.external = Some(ExternalDotProductCircuit {
      left,
      right,
      weight,
      eval,
    });
    Ok(())
  }

  fn streaming_polynomials(
    &self,
  ) -> io::Result<(
    StreamingPolynomial,
    StreamingPolynomial,
    StreamingPolynomial,
  )> {
    let external = self
      .external
      .as_ref()
      .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "dot product is not external"))?;
    Ok((
      external.left.clone(),
      external.right.clone(),
      external.weight.clone(),
    ))
  }
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct LayerProof {
  pub proof: SumcheckInstanceProof,
  pub claims: Vec<Scalar>,
}

#[allow(dead_code)]
impl LayerProof {
  pub fn verify(
    &self,
    claim: Scalar,
    num_rounds: usize,
    degree_bound: usize,
    transcript: &mut Transcript,
  ) -> (Scalar, Vec<Scalar>) {
    self
      .proof
      .verify(claim, num_rounds, degree_bound, transcript)
      .unwrap()
  }
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct LayerProofBatched {
  pub proof: SumcheckInstanceProof,
  pub claims_prod_left: Vec<Scalar>,
  pub claims_prod_right: Vec<Scalar>,
}

#[allow(dead_code)]
impl LayerProofBatched {
  pub fn verify(
    &self,
    claim: Scalar,
    num_rounds: usize,
    degree_bound: usize,
    transcript: &mut Transcript,
  ) -> (Scalar, Vec<Scalar>) {
    self
      .proof
      .verify(claim, num_rounds, degree_bound, transcript)
      .unwrap()
  }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProductCircuitEvalProof {
  proof: Vec<LayerProof>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProductCircuitEvalProofBatched {
  proof: Vec<LayerProofBatched>,
  claims_dotp: (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>),
}

impl ProductCircuitEvalProof {
  #![allow(dead_code)]
  pub fn prove(
    circuit: &mut ProductCircuit,
    transcript: &mut Transcript,
  ) -> (Self, Scalar, Vec<Scalar>) {
    let mut proof: Vec<LayerProof> = Vec::new();
    let num_layers = circuit.left_vec.len();

    let mut claim = circuit.evaluate();
    let mut rand = Vec::new();
    for layer_id in (0..num_layers).rev() {
      let len = circuit.left_vec[layer_id].len() + circuit.right_vec[layer_id].len();

      let mut poly_C = DensePolynomial::new(EqPolynomial::new(rand.clone()).evals());
      assert_eq!(poly_C.len(), len / 2);

      let num_rounds_prod = poly_C.len().log_2();
      let comb_func_prod = |poly_A_comp: &Scalar,
                            poly_B_comp: &Scalar,
                            poly_C_comp: &Scalar|
       -> Scalar { poly_A_comp * poly_B_comp * poly_C_comp };
      let (proof_prod, rand_prod, claims_prod) = SumcheckInstanceProof::prove_cubic(
        &claim,
        num_rounds_prod,
        &mut circuit.left_vec[layer_id],
        &mut circuit.right_vec[layer_id],
        &mut poly_C,
        comb_func_prod,
        transcript,
      );

      transcript.append_scalar(b"claim_prod_left", &claims_prod[0]);
      transcript.append_scalar(b"claim_prod_right", &claims_prod[1]);

      // produce a random challenge
      let r_layer = transcript.challenge_scalar(b"challenge_r_layer");
      claim = claims_prod[0] + r_layer * (claims_prod[1] - claims_prod[0]);

      let mut ext = vec![r_layer];
      ext.extend(rand_prod);
      rand = ext;

      proof.push(LayerProof {
        proof: proof_prod,
        claims: claims_prod[0..claims_prod.len() - 1].to_vec(),
      });
    }

    (ProductCircuitEvalProof { proof }, claim, rand)
  }

  pub fn verify(
    &self,
    eval: Scalar,
    len: usize,
    transcript: &mut Transcript,
  ) -> (Scalar, Vec<Scalar>) {
    let num_layers = len.log_2();
    let mut claim = eval;
    let mut rand: Vec<Scalar> = Vec::new();
    //let mut num_rounds = 0;
    assert_eq!(self.proof.len(), num_layers);
    for (num_rounds, i) in (0..num_layers).enumerate() {
      let (claim_last, rand_prod) = self.proof[i].verify(claim, num_rounds, 3, transcript);

      let claims_prod = &self.proof[i].claims;
      transcript.append_scalar(b"claim_prod_left", &claims_prod[0]);
      transcript.append_scalar(b"claim_prod_right", &claims_prod[1]);

      assert_eq!(rand.len(), rand_prod.len());
      let eq: Scalar = (0..rand.len())
        .map(|i| {
          rand[i] * rand_prod[i] + (Scalar::one() - rand[i]) * (Scalar::one() - rand_prod[i])
        })
        .product();
      assert_eq!(claims_prod[0] * claims_prod[1] * eq, claim_last);

      // produce a random challenge
      let r_layer = transcript.challenge_scalar(b"challenge_r_layer");
      claim = (Scalar::one() - r_layer) * claims_prod[0] + r_layer * claims_prod[1];
      let mut ext = vec![r_layer];
      ext.extend(rand_prod);
      rand = ext;
    }

    (claim, rand)
  }
}

impl ProductCircuitEvalProofBatched {
  pub fn prove(
    prod_circuit_vec: &mut [&mut ProductCircuit],
    dotp_circuit_vec: &mut [&mut DotProductCircuit],
    transcript: &mut Transcript,
  ) -> (Self, Vec<Scalar>) {
    assert!(!prod_circuit_vec.is_empty());

    let mut claims_dotp_final = (Vec::new(), Vec::new(), Vec::new());

    let mut proof_layers: Vec<LayerProofBatched> = Vec::new();
    let num_layers = prod_circuit_vec[0].left_vec.len();
    let mut claims_to_verify = (0..prod_circuit_vec.len())
      .map(|i| prod_circuit_vec[i].evaluate())
      .collect::<Vec<Scalar>>();
    let mut rand = Vec::new();
    for layer_id in (0..num_layers).rev() {
      // prepare paralell instance that share poly_C first
      let len = prod_circuit_vec[0].left_vec[layer_id].len()
        + prod_circuit_vec[0].right_vec[layer_id].len();

      let mut poly_C_par = DensePolynomial::new(EqPolynomial::new(rand.clone()).evals());
      assert_eq!(poly_C_par.len(), len / 2);

      let num_rounds_prod = poly_C_par.len().log_2();
      let comb_func_prod = |poly_A_comp: &Scalar,
                            poly_B_comp: &Scalar,
                            poly_C_comp: &Scalar|
       -> Scalar { poly_A_comp * poly_B_comp * poly_C_comp };

      let mut poly_A_batched_par: Vec<&mut DensePolynomial> = Vec::new();
      let mut poly_B_batched_par: Vec<&mut DensePolynomial> = Vec::new();
      for prod_circuit in prod_circuit_vec.iter_mut() {
        poly_A_batched_par.push(&mut prod_circuit.left_vec[layer_id]);
        poly_B_batched_par.push(&mut prod_circuit.right_vec[layer_id])
      }
      let poly_vec_par = (
        &mut poly_A_batched_par,
        &mut poly_B_batched_par,
        &mut poly_C_par,
      );

      // prepare sequential instances that don't share poly_C
      let mut poly_A_batched_seq: Vec<&mut DensePolynomial> = Vec::new();
      let mut poly_B_batched_seq: Vec<&mut DensePolynomial> = Vec::new();
      let mut poly_C_batched_seq: Vec<&mut DensePolynomial> = Vec::new();
      if layer_id == 0 && !dotp_circuit_vec.is_empty() {
        // add additional claims
        for item in dotp_circuit_vec.iter() {
          claims_to_verify.push(item.evaluate());
          assert_eq!(len / 2, item.left.len());
          assert_eq!(len / 2, item.right.len());
          assert_eq!(len / 2, item.weight.len());
        }

        for dotp_circuit in dotp_circuit_vec.iter_mut() {
          poly_A_batched_seq.push(&mut dotp_circuit.left);
          poly_B_batched_seq.push(&mut dotp_circuit.right);
          poly_C_batched_seq.push(&mut dotp_circuit.weight);
        }
      }
      let poly_vec_seq = (
        &mut poly_A_batched_seq,
        &mut poly_B_batched_seq,
        &mut poly_C_batched_seq,
      );

      // produce a fresh set of coeffs and a joint claim
      let coeff_vec =
        transcript.challenge_vector(b"rand_coeffs_next_layer", claims_to_verify.len());
      let claim = (0..claims_to_verify.len())
        .map(|i| claims_to_verify[i] * coeff_vec[i])
        .sum();

      let (proof, rand_prod, claims_prod, claims_dotp) = SumcheckInstanceProof::prove_cubic_batched(
        &claim,
        num_rounds_prod,
        poly_vec_par,
        poly_vec_seq,
        &coeff_vec,
        comb_func_prod,
        transcript,
      );

      let (claims_prod_left, claims_prod_right, _claims_eq) = claims_prod;
      for i in 0..prod_circuit_vec.len() {
        transcript.append_scalar(b"claim_prod_left", &claims_prod_left[i]);
        transcript.append_scalar(b"claim_prod_right", &claims_prod_right[i]);
      }

      if layer_id == 0 && !dotp_circuit_vec.is_empty() {
        let (claims_dotp_left, claims_dotp_right, claims_dotp_weight) = claims_dotp;
        for i in 0..dotp_circuit_vec.len() {
          transcript.append_scalar(b"claim_dotp_left", &claims_dotp_left[i]);
          transcript.append_scalar(b"claim_dotp_right", &claims_dotp_right[i]);
          transcript.append_scalar(b"claim_dotp_weight", &claims_dotp_weight[i]);
        }
        claims_dotp_final = (claims_dotp_left, claims_dotp_right, claims_dotp_weight);
      }

      // produce a random challenge to condense two claims into a single claim
      let r_layer = transcript.challenge_scalar(b"challenge_r_layer");

      claims_to_verify = (0..prod_circuit_vec.len())
        .map(|i| claims_prod_left[i] + r_layer * (claims_prod_right[i] - claims_prod_left[i]))
        .collect::<Vec<Scalar>>();

      let mut ext = vec![r_layer];
      ext.extend(rand_prod);
      rand = ext;

      proof_layers.push(LayerProofBatched {
        proof,
        claims_prod_left,
        claims_prod_right,
      });
    }

    (
      ProductCircuitEvalProofBatched {
        proof: proof_layers,
        claims_dotp: claims_dotp_final,
      },
      rand,
    )
  }

  pub(crate) fn prove_external(
    prod_circuit_vec: &mut [&mut ProductCircuit],
    dotp_circuit_vec: &mut [&mut DotProductCircuit],
    store: &mut MultiObjectFileBackedStateStore,
    arena: &BudgetAccountedArena,
    transcript: &mut Transcript,
  ) -> io::Result<(Self, Vec<Scalar>)> {
    if std::env::var("LIBSPARTAN_ACTIVE_STATE_STREAMING").as_deref() == Ok("1") {
      return Self::prove_external_active(prod_circuit_vec, dotp_circuit_vec, store, transcript);
    }
    assert!(!prod_circuit_vec.is_empty());
    assert!(prod_circuit_vec.iter().all(|circuit| circuit.is_external()));

    let mut claims_dotp_final = (Vec::new(), Vec::new(), Vec::new());
    let mut proof_layers: Vec<LayerProofBatched> = Vec::new();
    let num_layers = prod_circuit_vec[0].num_layers();
    let mut claims_to_verify = prod_circuit_vec
      .iter()
      .map(|circuit| circuit.evaluate())
      .collect::<Vec<Scalar>>();
    let mut rand = Vec::new();

    for layer_id in (0..num_layers).rev() {
      let mut loaded_layers = prod_circuit_vec
        .iter()
        .map(|circuit| circuit.load_external_layer(layer_id, store, arena))
        .collect::<io::Result<Vec<_>>>()?;
      let len = loaded_layers[0].0.len() + loaded_layers[0].1.len();
      let mut poly_C_par = DensePolynomial::new(EqPolynomial::new(rand.clone()).evals());
      assert_eq!(poly_C_par.len(), len / 2);
      let num_rounds_prod = poly_C_par.len().log_2();
      let comb_func_prod = |poly_A_comp: &Scalar,
                            poly_B_comp: &Scalar,
                            poly_C_comp: &Scalar|
       -> Scalar { poly_A_comp * poly_B_comp * poly_C_comp };

      let mut poly_A_batched_par: Vec<&mut DensePolynomial> = Vec::new();
      let mut poly_B_batched_par: Vec<&mut DensePolynomial> = Vec::new();
      for (left, right, _) in loaded_layers.iter_mut() {
        poly_A_batched_par.push(left);
        poly_B_batched_par.push(right);
      }
      let poly_vec_par = (
        &mut poly_A_batched_par,
        &mut poly_B_batched_par,
        &mut poly_C_par,
      );

      let mut poly_A_batched_seq: Vec<&mut DensePolynomial> = Vec::new();
      let mut poly_B_batched_seq: Vec<&mut DensePolynomial> = Vec::new();
      let mut poly_C_batched_seq: Vec<&mut DensePolynomial> = Vec::new();
      if layer_id == 0 && !dotp_circuit_vec.is_empty() {
        for item in dotp_circuit_vec.iter() {
          claims_to_verify.push(item.evaluate());
          assert_eq!(len / 2, item.left.len());
          assert_eq!(len / 2, item.right.len());
          assert_eq!(len / 2, item.weight.len());
        }
        for dotp_circuit in dotp_circuit_vec.iter_mut() {
          poly_A_batched_seq.push(&mut dotp_circuit.left);
          poly_B_batched_seq.push(&mut dotp_circuit.right);
          poly_C_batched_seq.push(&mut dotp_circuit.weight);
        }
      }
      let poly_vec_seq = (
        &mut poly_A_batched_seq,
        &mut poly_B_batched_seq,
        &mut poly_C_batched_seq,
      );

      let coeff_vec =
        transcript.challenge_vector(b"rand_coeffs_next_layer", claims_to_verify.len());
      let claim = (0..claims_to_verify.len())
        .map(|i| claims_to_verify[i] * coeff_vec[i])
        .sum();
      let (proof, rand_prod, claims_prod, claims_dotp) = SumcheckInstanceProof::prove_cubic_batched(
        &claim,
        num_rounds_prod,
        poly_vec_par,
        poly_vec_seq,
        &coeff_vec,
        comb_func_prod,
        transcript,
      );

      let (claims_prod_left, claims_prod_right, _claims_eq) = claims_prod;
      for i in 0..prod_circuit_vec.len() {
        transcript.append_scalar(b"claim_prod_left", &claims_prod_left[i]);
        transcript.append_scalar(b"claim_prod_right", &claims_prod_right[i]);
      }
      if layer_id == 0 && !dotp_circuit_vec.is_empty() {
        let (claims_dotp_left, claims_dotp_right, claims_dotp_weight) = claims_dotp;
        for i in 0..dotp_circuit_vec.len() {
          transcript.append_scalar(b"claim_dotp_left", &claims_dotp_left[i]);
          transcript.append_scalar(b"claim_dotp_right", &claims_dotp_right[i]);
          transcript.append_scalar(b"claim_dotp_weight", &claims_dotp_weight[i]);
        }
        claims_dotp_final = (claims_dotp_left, claims_dotp_right, claims_dotp_weight);
      }

      let r_layer = transcript.challenge_scalar(b"challenge_r_layer");
      claims_to_verify = (0..prod_circuit_vec.len())
        .map(|i| claims_prod_left[i] + r_layer * (claims_prod_right[i] - claims_prod_left[i]))
        .collect::<Vec<Scalar>>();
      let mut ext = vec![r_layer];
      ext.extend(rand_prod);
      rand = ext;
      proof_layers.push(LayerProofBatched {
        proof,
        claims_prod_left,
        claims_prod_right,
      });

      drop(loaded_layers);
      for circuit in prod_circuit_vec.iter() {
        circuit.delete_external_layer(layer_id, store)?;
      }
    }

    Ok((
      ProductCircuitEvalProofBatched {
        proof: proof_layers,
        claims_dotp: claims_dotp_final,
      },
      rand,
    ))
  }

  fn prove_external_active(
    prod_circuit_vec: &mut [&mut ProductCircuit],
    dotp_circuit_vec: &mut [&mut DotProductCircuit],
    store: &mut MultiObjectFileBackedStateStore,
    transcript: &mut Transcript,
  ) -> io::Result<(Self, Vec<Scalar>)> {
    assert!(!prod_circuit_vec.is_empty());
    assert!(prod_circuit_vec.iter().all(|circuit| circuit.is_external()));

    let batch_prefix = format!("{}.fs4-active", prod_circuit_vec[0].external_layers[0].0);
    for (index, circuit) in dotp_circuit_vec.iter_mut().enumerate() {
      circuit.externalize(&format!("{batch_prefix}.dotp-{index}"), store)?;
    }

    let mut claims_dotp_final = (Vec::new(), Vec::new(), Vec::new());
    let mut proof_layers = Vec::new();
    let num_layers = prod_circuit_vec[0].num_layers();
    let mut claims_to_verify = prod_circuit_vec
      .iter()
      .map(|circuit| circuit.evaluate())
      .collect::<Vec<_>>();
    let mut rand = Vec::new();

    for layer_id in (0..num_layers).rev() {
      let mut pairs = prod_circuit_vec
        .iter()
        .map(|circuit| circuit.streaming_external_layer(layer_id))
        .collect::<io::Result<Vec<_>>>()?;
      let len = pairs[0].0.scalar_count + pairs[0].1.scalar_count;
      let mut poly_C_par = DensePolynomial::new(EqPolynomial::new(rand.clone()).evals());
      assert_eq!(poly_C_par.len(), len / 2);
      let num_rounds_prod = poly_C_par.len().log_2();
      let comb_func_prod = |poly_A_comp: &Scalar,
                            poly_B_comp: &Scalar,
                            poly_C_comp: &Scalar|
       -> Scalar { poly_A_comp * poly_B_comp * poly_C_comp };

      let mut triples = Vec::new();
      if layer_id == 0 && !dotp_circuit_vec.is_empty() {
        for item in dotp_circuit_vec.iter() {
          claims_to_verify.push(item.evaluate());
        }
        triples = dotp_circuit_vec
          .iter()
          .map(|circuit| circuit.streaming_polynomials())
          .collect::<io::Result<Vec<_>>>()?;
        for (left, right, weight) in &triples {
          assert_eq!(len / 2, left.scalar_count);
          assert_eq!(len / 2, right.scalar_count);
          assert_eq!(len / 2, weight.scalar_count);
        }
      }

      let coeff_vec =
        transcript.challenge_vector(b"rand_coeffs_next_layer", claims_to_verify.len());
      let claim = (0..claims_to_verify.len())
        .map(|i| claims_to_verify[i] * coeff_vec[i])
        .sum();
      let (proof, rand_prod, claims_prod, claims_dotp) =
        SumcheckInstanceProof::prove_cubic_batched_streaming(
          &claim,
          num_rounds_prod,
          &mut pairs,
          &mut poly_C_par,
          &mut triples,
          &coeff_vec,
          &format!("{batch_prefix}.layer-{layer_id}"),
          store,
          comb_func_prod,
          transcript,
        )?;

      let (claims_prod_left, claims_prod_right, _claims_eq) = claims_prod;
      for index in 0..prod_circuit_vec.len() {
        transcript.append_scalar(b"claim_prod_left", &claims_prod_left[index]);
        transcript.append_scalar(b"claim_prod_right", &claims_prod_right[index]);
      }
      if layer_id == 0 && !dotp_circuit_vec.is_empty() {
        let (claims_dotp_left, claims_dotp_right, claims_dotp_weight) = claims_dotp;
        for index in 0..dotp_circuit_vec.len() {
          transcript.append_scalar(b"claim_dotp_left", &claims_dotp_left[index]);
          transcript.append_scalar(b"claim_dotp_right", &claims_dotp_right[index]);
          transcript.append_scalar(b"claim_dotp_weight", &claims_dotp_weight[index]);
        }
        claims_dotp_final = (claims_dotp_left, claims_dotp_right, claims_dotp_weight);
      }

      let r_layer = transcript.challenge_scalar(b"challenge_r_layer");
      claims_to_verify = (0..prod_circuit_vec.len())
        .map(|index| {
          claims_prod_left[index] + r_layer * (claims_prod_right[index] - claims_prod_left[index])
        })
        .collect();
      let mut ext = vec![r_layer];
      ext.extend(rand_prod);
      rand = ext;
      proof_layers.push(LayerProofBatched {
        proof,
        claims_prod_left,
        claims_prod_right,
      });
    }

    Ok((
      ProductCircuitEvalProofBatched {
        proof: proof_layers,
        claims_dotp: claims_dotp_final,
      },
      rand,
    ))
  }

  pub fn verify(
    &self,
    claims_prod_vec: &[Scalar],
    claims_dotp_vec: &[Scalar],
    len: usize,
    transcript: &mut Transcript,
  ) -> (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>) {
    let num_layers = len.log_2();
    let mut rand: Vec<Scalar> = Vec::new();
    //let mut num_rounds = 0;
    assert_eq!(self.proof.len(), num_layers);

    let mut claims_to_verify = claims_prod_vec.to_owned();
    let mut claims_to_verify_dotp: Vec<Scalar> = Vec::new();
    for (num_rounds, i) in (0..num_layers).enumerate() {
      if i == num_layers - 1 {
        claims_to_verify.extend(claims_dotp_vec);
      }

      // produce random coefficients, one for each instance
      let coeff_vec =
        transcript.challenge_vector(b"rand_coeffs_next_layer", claims_to_verify.len());

      // produce a joint claim
      let claim = (0..claims_to_verify.len())
        .map(|i| claims_to_verify[i] * coeff_vec[i])
        .sum();

      let (claim_last, rand_prod) = self.proof[i].verify(claim, num_rounds, 3, transcript);

      let claims_prod_left = &self.proof[i].claims_prod_left;
      let claims_prod_right = &self.proof[i].claims_prod_right;
      assert_eq!(claims_prod_left.len(), claims_prod_vec.len());
      assert_eq!(claims_prod_right.len(), claims_prod_vec.len());

      for i in 0..claims_prod_vec.len() {
        transcript.append_scalar(b"claim_prod_left", &claims_prod_left[i]);
        transcript.append_scalar(b"claim_prod_right", &claims_prod_right[i]);
      }

      assert_eq!(rand.len(), rand_prod.len());
      let eq: Scalar = (0..rand.len())
        .map(|i| {
          rand[i] * rand_prod[i] + (Scalar::one() - rand[i]) * (Scalar::one() - rand_prod[i])
        })
        .product();
      let mut claim_expected: Scalar = (0..claims_prod_vec.len())
        .map(|i| coeff_vec[i] * (claims_prod_left[i] * claims_prod_right[i] * eq))
        .sum();

      // add claims from the dotp instances
      if i == num_layers - 1 {
        let num_prod_instances = claims_prod_vec.len();
        let (claims_dotp_left, claims_dotp_right, claims_dotp_weight) = &self.claims_dotp;
        for i in 0..claims_dotp_left.len() {
          transcript.append_scalar(b"claim_dotp_left", &claims_dotp_left[i]);
          transcript.append_scalar(b"claim_dotp_right", &claims_dotp_right[i]);
          transcript.append_scalar(b"claim_dotp_weight", &claims_dotp_weight[i]);

          claim_expected += coeff_vec[i + num_prod_instances]
            * claims_dotp_left[i]
            * claims_dotp_right[i]
            * claims_dotp_weight[i];
        }
      }

      assert_eq!(claim_expected, claim_last);

      // produce a random challenge
      let r_layer = transcript.challenge_scalar(b"challenge_r_layer");

      claims_to_verify = (0..claims_prod_left.len())
        .map(|i| claims_prod_left[i] + r_layer * (claims_prod_right[i] - claims_prod_left[i]))
        .collect::<Vec<Scalar>>();

      // add claims to verify for dotp circuit
      if i == num_layers - 1 {
        let (claims_dotp_left, claims_dotp_right, claims_dotp_weight) = &self.claims_dotp;

        for i in 0..claims_dotp_vec.len() / 2 {
          // combine left claims
          let claim_left = claims_dotp_left[2 * i]
            + r_layer * (claims_dotp_left[2 * i + 1] - claims_dotp_left[2 * i]);

          let claim_right = claims_dotp_right[2 * i]
            + r_layer * (claims_dotp_right[2 * i + 1] - claims_dotp_right[2 * i]);

          let claim_weight = claims_dotp_weight[2 * i]
            + r_layer * (claims_dotp_weight[2 * i + 1] - claims_dotp_weight[2 * i]);
          claims_to_verify_dotp.push(claim_left);
          claims_to_verify_dotp.push(claim_right);
          claims_to_verify_dotp.push(claim_weight);
        }
      }

      let mut ext = vec![r_layer];
      ext.extend(rand_prod);
      rand = ext;
    }
    (claims_to_verify, claims_to_verify_dotp, rand)
  }
}
