//! Deterministic retain/spill/recompute planning over the measured V3B DAG.
#![allow(missing_docs)]

use super::memory_budget::ProverMemoryBudget;
use serde::{Deserialize, Serialize};
use std::io;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum StateStrategy {
  Retain,
  Spill,
  Recompute,
  StreamDirectly,
  FuseWithConsumer,
  CheckpointAndRecompute,
  RegenerateQueryChunks,
  FuseWithOpening,
  EphemeralNonDurableSpill,
  BufferReuse,
  ControlledThreadConfiguration,
  StreamDereference,
  FuseDereferenceOpening,
  GenerateQueryWeightsChunked,
  ReleasePhaseArena,
  ConsolidateStateScan,
  ReuseTemporaryObject,
  StreamCredentialRelation,
  ReplayCompactCredentialWitness,
  StreamMimcIntermediates,
  StreamRevocationPath,
  CompactCrossCredentialBinding,
  ExternalizeSparseR1csBuild,
  SeparateRelationProverLifetimes,
  ExternalizeMatrixValues,
  CompactSparseAddressTimestamps,
  NotSafeToExternalize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateCost {
  pub object_id: &'static str,
  pub size_bytes: u64,
  pub retain_cost_bytes: u64,
  pub spill_write_bytes: u64,
  pub spill_read_bytes: u64,
  pub recompute_work_units: u64,
  pub peak_memory_saved_bytes: u64,
  pub number_of_reuses: u32,
  pub transcript_barrier_lifetime: u32,
  pub externalizable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlannedState {
  pub object_id: String,
  pub strategy: StateStrategy,
  pub size_bytes: u64,
  pub estimated_peak_saved_bytes: u64,
  pub estimated_read_bytes: u64,
  pub estimated_write_bytes: u64,
  pub estimated_recompute_work_units: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProverMemoryPlan {
  pub relation_size: usize,
  pub usable_prover_bytes: usize,
  pub baseline_estimated_peak_bytes: u64,
  pub estimated_peak_bytes: u64,
  pub estimated_read_bytes: u64,
  pub estimated_write_bytes: u64,
  pub estimated_recompute_work_units: u64,
  pub estimated_temporary_storage_bytes: u64,
  pub reserved_runtime_bytes: u64,
  pub predicted_total_rss_bytes: u64,
  pub measured_disk_bytes_per_second: u64,
  pub measured_recompute_units_per_second: u64,
  pub network_profile: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub credential_shape: Option<CredentialPlanShape>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub predicted_relation_construction_peak_bytes: Option<u64>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub predicted_proving_peak_bytes: Option<u64>,
  pub states: Vec<PlannedState>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialPlanShape {
  pub credential_count: usize,
  pub revocation_count: usize,
  pub revocation_depth: usize,
  pub raw_constraint_count: Option<usize>,
  pub padded_constraint_count: usize,
  pub public_input_count: usize,
  pub sparse_nonzero_entry_count: usize,
  pub max_sparse_matrix_entries: usize,
  pub q: usize,
  pub m: usize,
}

pub fn state_costs(n: usize) -> Vec<StateCost> {
  let n = n as u64;
  vec![
    StateCost {
      object_id: "comb_ops",
      size_bytes: 512 * n,
      retain_cost_bytes: 512 * n,
      spill_write_bytes: 512 * n,
      spill_read_bytes: 1024 * n,
      recompute_work_units: 0,
      peak_memory_saved_bytes: 512 * n,
      number_of_reuses: 2,
      transcript_barrier_lifetime: 1,
      externalizable: true,
    },
    StateCost {
      object_id: "comb_mem",
      size_bytes: 128 * n,
      retain_cost_bytes: 128 * n,
      spill_write_bytes: 128 * n,
      spill_read_bytes: 256 * n,
      recompute_work_units: 0,
      peak_memory_saved_bytes: 128 * n,
      number_of_reuses: 2,
      transcript_barrier_lifetime: 1,
      externalizable: true,
    },
    StateCost {
      object_id: "product_circuit_inactive_layers",
      size_bytes: 2232 * n,
      retain_cost_bytes: 2232 * n,
      spill_write_bytes: 2232 * n,
      spill_read_bytes: 2232 * n,
      recompute_work_units: 0,
      peak_memory_saved_bytes: 1116 * n,
      number_of_reuses: 1,
      transcript_barrier_lifetime: 20,
      externalizable: true,
    },
    StateCost {
      object_id: "relation_and_instance_last_use",
      size_bytes: 512 * n,
      retain_cost_bytes: 512 * n,
      spill_write_bytes: 0,
      spill_read_bytes: 0,
      recompute_work_units: n,
      peak_memory_saved_bytes: 512 * n,
      number_of_reuses: 0,
      transcript_barrier_lifetime: 1,
      externalizable: true,
    },
  ]
}

/// Greedily externalizes the highest-memory candidates until the budget fits.
pub fn plan(
  n: usize,
  budget: ProverMemoryBudget,
  measured_disk_bytes_per_second: u64,
  measured_recompute_units_per_second: u64,
  network_profile: &str,
) -> io::Result<ProverMemoryPlan> {
  let usable = budget.usable_prover_bytes()? as u64;
  // Four measured V3A points support an approximately linear dominant-state model.
  let baseline = 3_868u64
    .checked_mul(n as u64)
    .and_then(|value| value.checked_add(512 * 1024))
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "plan size overflow"))?;
  let mut candidates = state_costs(n);
  candidates.sort_by(|left, right| {
    right
      .peak_memory_saved_bytes
      .cmp(&left.peak_memory_saved_bytes)
      .then_with(|| left.object_id.cmp(right.object_id))
  });
  let mut estimated_peak = baseline;
  let mut states = Vec::new();
  let mut reads = 0;
  let mut writes = 0;
  let mut recompute = 0;
  for cost in candidates {
    // FS3 conservatively externalizes every selected class at every n so the
    // executor never retains state that the emitted plan marks as spilled.
    let strategy = if cost.externalizable {
      if cost.object_id == "relation_and_instance_last_use" {
        StateStrategy::Recompute
      } else {
        StateStrategy::Spill
      }
    } else {
      StateStrategy::Retain
    };
    let saved = if strategy == StateStrategy::Retain {
      0
    } else {
      cost.peak_memory_saved_bytes
    };
    estimated_peak = estimated_peak.saturating_sub(saved);
    let read = if strategy == StateStrategy::Spill {
      cost.spill_read_bytes
    } else {
      0
    };
    let write = if strategy == StateStrategy::Spill {
      cost.spill_write_bytes
    } else {
      0
    };
    let work = if strategy == StateStrategy::Recompute {
      cost.recompute_work_units
    } else {
      0
    };
    reads += read;
    writes += write;
    recompute += work;
    states.push(PlannedState {
      object_id: cost.object_id.to_owned(),
      strategy,
      size_bytes: cost.size_bytes,
      estimated_peak_saved_bytes: saved,
      estimated_read_bytes: read,
      estimated_write_bytes: write,
      estimated_recompute_work_units: work,
    });
  }
  if estimated_peak > usable {
    return Err(io::Error::new(
      io::ErrorKind::OutOfMemory,
      format!("no plan fits: predicted {estimated_peak} > usable {usable}"),
    ));
  }
  Ok(ProverMemoryPlan {
    relation_size: n,
    usable_prover_bytes: usable as usize,
    baseline_estimated_peak_bytes: baseline,
    estimated_peak_bytes: estimated_peak,
    estimated_read_bytes: reads,
    estimated_write_bytes: writes,
    estimated_recompute_work_units: recompute,
    estimated_temporary_storage_bytes: writes,
    reserved_runtime_bytes: budget.reserved_runtime_bytes as u64,
    predicted_total_rss_bytes: estimated_peak + budget.reserved_runtime_bytes as u64,
    measured_disk_bytes_per_second,
    measured_recompute_units_per_second,
    network_profile: network_profile.to_owned(),
    credential_shape: None,
    predicted_relation_construction_peak_bytes: None,
    predicted_proving_peak_bytes: None,
    states,
  })
}

/// Plans the FS4 active-state path using the calibrated 2^18 implementation model.
pub fn plan_fs4(
  n: usize,
  budget: ProverMemoryBudget,
  measured_disk_bytes_per_second: u64,
  measured_recompute_units_per_second: u64,
  network_profile: &str,
) -> io::Result<ProverMemoryPlan> {
  let usable = budget.usable_prover_bytes()? as u64;
  let n64 = n as u64;
  // Calibrated from the first untraced 2^18 FS4 run. The fixed 8 MiB term
  // keeps the estimate conservative at smaller supported relation sizes.
  let estimated_peak = 990u64
    .checked_mul(n64)
    .and_then(|value| value.checked_add(8 * 1024 * 1024))
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "FS4 plan size overflow"))?;
  let reads = 6_272u64.saturating_mul(n64);
  let writes = 3_136u64.saturating_mul(n64);
  let temporary = 1_568u64.saturating_mul(n64);
  let states = vec![
    PlannedState {
      object_id: "fs3_externalization_targets".to_owned(),
      strategy: StateStrategy::Spill,
      size_bytes: 2_872 * n64,
      estimated_peak_saved_bytes: 2_280 * n64,
      estimated_read_bytes: 2_560 * n64,
      estimated_write_bytes: 1_920 * n64,
      estimated_recompute_work_units: n64,
    },
    PlannedState {
      object_id: "active_sumcheck_fold_tables".to_owned(),
      strategy: StateStrategy::StreamDirectly,
      size_bytes: 896 * n64,
      estimated_peak_saved_bytes: 800 * n64,
      estimated_read_bytes: 3_200 * n64,
      estimated_write_bytes: 1_024 * n64,
      estimated_recompute_work_units: 0,
    },
    PlannedState {
      object_id: "active_product_hash_layer".to_owned(),
      strategy: StateStrategy::FuseWithConsumer,
      size_bytes: 256 * n64,
      estimated_peak_saved_bytes: 224 * n64,
      estimated_read_bytes: 512 * n64,
      estimated_write_bytes: 192 * n64,
      estimated_recompute_work_units: n64,
    },
    PlannedState {
      object_id: "exact_capacity_dense_inputs".to_owned(),
      strategy: StateStrategy::Retain,
      size_bytes: 512 * n64,
      estimated_peak_saved_bytes: 0,
      estimated_read_bytes: 0,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: 0,
    },
  ];
  if estimated_peak > usable {
    return Err(io::Error::new(
      io::ErrorKind::OutOfMemory,
      format!("no FS4 plan fits: predicted {estimated_peak} > usable {usable}"),
    ));
  }
  let reserve = budget.reserved_runtime_bytes as u64;
  Ok(ProverMemoryPlan {
    relation_size: n,
    usable_prover_bytes: usable as usize,
    baseline_estimated_peak_bytes: 3_868 * n64 + 512 * 1024,
    estimated_peak_bytes: estimated_peak,
    estimated_read_bytes: reads,
    estimated_write_bytes: writes,
    estimated_recompute_work_units: 2 * n64,
    estimated_temporary_storage_bytes: temporary,
    reserved_runtime_bytes: reserve,
    predicted_total_rss_bytes: estimated_peak + reserve,
    measured_disk_bytes_per_second,
    measured_recompute_units_per_second,
    network_profile: network_profile.to_owned(),
    credential_shape: None,
    predicted_relation_construction_peak_bytes: None,
    predicted_proving_peak_bytes: None,
    states,
  })
}

/// Plans the FS5 checkpoint/recompute path. The model retains the measured
/// 111 MiB runtime reserve and removes only the scalar address/timestamp
/// duplicates that the executor actually regenerates from compact sources.
pub fn plan_fs5(
  n: usize,
  budget: ProverMemoryBudget,
  measured_disk_bytes_per_second: u64,
  measured_recompute_units_per_second: u64,
  network_profile: &str,
) -> io::Result<ProverMemoryPlan> {
  let usable = budget.usable_prover_bytes()? as u64;
  let n64 = n as u64;
  let fs4_peak = 990u64
    .checked_mul(n64)
    .and_then(|value| value.checked_add(8 * 1024 * 1024))
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "FS5 plan size overflow"))?;
  // Six operation-address, six read-timestamp, and two audit-timestamp
  // Scalar tables are replaced by compact usize checkpoints. The operation
  // address source already existed in FS4; new compact read/audit sources cost
  // 64*n bytes. The first uncapped 2^18 FS5 run measured a further 32*n bytes
  // of released allocation overlap, so the calibrated conservative saving is
  // 416*n bytes. The 111 MiB runtime reserve remains unchanged.
  let saved = 416u64.saturating_mul(n64);
  let estimated_peak = fs4_peak.saturating_sub(saved);
  // Include both V3B active-state files and the V3A comb_ops/comb_mem files.
  let reads = 7_552u64.saturating_mul(n64);
  let writes = 3_776u64.saturating_mul(n64);
  let temporary = 2_208u64.saturating_mul(n64).saturating_add(1024 * 1024);
  let states = vec![
    PlannedState {
      object_id: "address_timestamp_scalar_tables".to_owned(),
      strategy: StateStrategy::CheckpointAndRecompute,
      size_bytes: 448 * n64,
      estimated_peak_saved_bytes: saved,
      estimated_read_bytes: 0,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: 14 * n64,
    },
    PlannedState {
      object_id: "late_hash_layer_queries".to_owned(),
      strategy: StateStrategy::RegenerateQueryChunks,
      size_bytes: 64 * n64,
      estimated_peak_saved_bytes: 0,
      estimated_read_bytes: 0,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: 14 * n64,
    },
    PlannedState {
      object_id: "comb_ops_and_mem_openings".to_owned(),
      strategy: StateStrategy::FuseWithOpening,
      size_bytes: 640 * n64,
      estimated_peak_saved_bytes: 0,
      estimated_read_bytes: 1_280 * n64,
      estimated_write_bytes: 640 * n64,
      estimated_recompute_work_units: 0,
    },
    PlannedState {
      object_id: "prover_spill_durability".to_owned(),
      strategy: StateStrategy::EphemeralNonDurableSpill,
      size_bytes: temporary,
      estimated_peak_saved_bytes: 0,
      estimated_read_bytes: 0,
      estimated_write_bytes: writes,
      estimated_recompute_work_units: 0,
    },
    PlannedState {
      object_id: "active_fold_buffers".to_owned(),
      strategy: StateStrategy::BufferReuse,
      size_bytes: 8 * 1024 * 1024,
      estimated_peak_saved_bytes: 0,
      estimated_read_bytes: 0,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: 0,
    },
    PlannedState {
      object_id: "single_thread_runtime".to_owned(),
      strategy: StateStrategy::ControlledThreadConfiguration,
      size_bytes: 0,
      estimated_peak_saved_bytes: 0,
      estimated_read_bytes: 0,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: 0,
    },
  ];
  if estimated_peak > usable {
    return Err(io::Error::new(
      io::ErrorKind::OutOfMemory,
      format!("no FS5 plan fits: predicted {estimated_peak} > usable {usable}"),
    ));
  }
  let reserve = budget.reserved_runtime_bytes as u64;
  Ok(ProverMemoryPlan {
    relation_size: n,
    usable_prover_bytes: usable as usize,
    baseline_estimated_peak_bytes: fs4_peak,
    estimated_peak_bytes: estimated_peak,
    estimated_read_bytes: reads,
    estimated_write_bytes: writes,
    estimated_recompute_work_units: 28 * n64,
    estimated_temporary_storage_bytes: temporary,
    reserved_runtime_bytes: reserve,
    predicted_total_rss_bytes: estimated_peak + reserve,
    measured_disk_bytes_per_second,
    measured_recompute_units_per_second,
    network_profile: network_profile.to_owned(),
    credential_shape: None,
    predicted_relation_construction_peak_bytes: None,
    predicted_proving_peak_bytes: None,
    states,
  })
}

/// Plans FS6. The canonical joint dereference polynomial remains live because
/// its commitment precedes the transcript-derived opening point, but the
/// twelve per-table Scalar copies are no longer materialized. The planner
/// preserves the measured FS5 runtime reserve and an additional 8 MiB hard-cap
/// safety requirement.
pub fn plan_fs6(
  n: usize,
  budget: ProverMemoryBudget,
  measured_disk_bytes_per_second: u64,
  measured_recompute_units_per_second: u64,
  network_profile: &str,
) -> io::Result<ProverMemoryPlan> {
  let usable = budget.usable_prover_bytes()? as u64;
  let n64 = n as u64;
  let fs5 = plan_fs5(
    n,
    ProverMemoryBudget {
      hard_limit_bytes: u64::MAX as usize,
      ..budget.clone()
    },
    measured_disk_bytes_per_second,
    measured_recompute_units_per_second,
    network_profile,
  )?;
  let dereference_table_copies = 192u64.saturating_mul(n64);
  let canonical_joint_dereference = 256u64.saturating_mul(n64);
  let retained_equality_sources = 64u64.saturating_mul(n64);
  let dereference_net_saving = dereference_table_copies
    .saturating_add(canonical_joint_dereference)
    .saturating_sub(retained_equality_sources);
  // The logical copy removal shifts the runtime peak to the encoded relation,
  // joint opening witness, and allocator overlap. A measured 73 MiB overlap is
  // retained explicitly instead of weakening the 111 MiB runtime reserve.
  let calibrated_phase_overlap = 73 * 1024 * 1024u64;
  let estimated_peak = fs5
    .estimated_peak_bytes
    .saturating_sub(dereference_net_saving)
    .saturating_add(calibrated_phase_overlap);
  let source_fused_bytes = 640u64.saturating_mul(n64);
  let estimated_reads = fs5.estimated_read_bytes.saturating_sub(source_fused_bytes);
  let estimated_writes = fs5.estimated_write_bytes;
  let estimated_temporary = fs5
    .estimated_temporary_storage_bytes
    .saturating_sub(source_fused_bytes);
  let required_safety = 8 * 1024 * 1024u64;
  if estimated_peak.saturating_add(required_safety) > usable {
    return Err(io::Error::new(
      io::ErrorKind::OutOfMemory,
      format!(
        "no FS6 plan fits with 8 MiB safety: predicted {estimated_peak} + {required_safety} > usable {usable}"
      ),
    ));
  }
  let mut states = fs5.states;
  states.extend([
    PlannedState {
      object_id: "dereferenced_table_copies".to_owned(),
      strategy: StateStrategy::StreamDereference,
      size_bytes: dereference_table_copies,
      estimated_peak_saved_bytes: dereference_table_copies,
      estimated_read_bytes: 0,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: 12 * n64,
    },
    PlannedState {
      object_id: "canonical_joint_dereference".to_owned(),
      strategy: StateStrategy::StreamDirectly,
      size_bytes: canonical_joint_dereference,
      estimated_peak_saved_bytes: canonical_joint_dereference,
      estimated_read_bytes: 0,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: 6 * n64,
    },
    PlannedState {
      object_id: "dereference_equality_sources".to_owned(),
      strategy: StateStrategy::Retain,
      size_bytes: retained_equality_sources,
      estimated_peak_saved_bytes: 0,
      estimated_read_bytes: 0,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: 0,
    },
    PlannedState {
      object_id: "dereference_opening_consumer".to_owned(),
      strategy: StateStrategy::FuseDereferenceOpening,
      size_bytes: 512 * n64,
      estimated_peak_saved_bytes: 0,
      estimated_read_bytes: 0,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: 0,
    },
    PlannedState {
      object_id: "calibrated_phase_overlap".to_owned(),
      strategy: StateStrategy::Retain,
      size_bytes: calibrated_phase_overlap,
      estimated_peak_saved_bytes: 0,
      estimated_read_bytes: 0,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: 0,
    },
    PlannedState {
      object_id: "late_query_weights".to_owned(),
      strategy: StateStrategy::GenerateQueryWeightsChunked,
      size_bytes: 32 * n64,
      estimated_peak_saved_bytes: 32 * n64,
      estimated_read_bytes: 0,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: 12 * n64,
    },
    PlannedState {
      object_id: "phase_local_allocations".to_owned(),
      strategy: StateStrategy::ReleasePhaseArena,
      size_bytes: 0,
      estimated_peak_saved_bytes: 0,
      estimated_read_bytes: 0,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: 0,
    },
    PlannedState {
      object_id: "external_state_scans".to_owned(),
      strategy: StateStrategy::ConsolidateStateScan,
      size_bytes: estimated_temporary,
      estimated_peak_saved_bytes: 0,
      estimated_read_bytes: estimated_reads,
      estimated_write_bytes: estimated_writes,
      estimated_recompute_work_units: 0,
    },
    PlannedState {
      object_id: "temporary_objects".to_owned(),
      strategy: StateStrategy::ReuseTemporaryObject,
      size_bytes: estimated_temporary,
      estimated_peak_saved_bytes: 0,
      estimated_read_bytes: 0,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: 0,
    },
  ]);
  let reserve = budget.reserved_runtime_bytes as u64;
  Ok(ProverMemoryPlan {
    relation_size: n,
    usable_prover_bytes: usable as usize,
    baseline_estimated_peak_bytes: fs5.estimated_peak_bytes,
    estimated_peak_bytes: estimated_peak,
    estimated_read_bytes: estimated_reads,
    estimated_write_bytes: estimated_writes,
    estimated_recompute_work_units: fs5.estimated_recompute_work_units.saturating_add(24 * n64),
    estimated_temporary_storage_bytes: estimated_temporary,
    reserved_runtime_bytes: reserve,
    predicted_total_rss_bytes: estimated_peak + reserve,
    measured_disk_bytes_per_second,
    measured_recompute_units_per_second,
    network_profile: network_profile.to_owned(),
    credential_shape: None,
    predicted_relation_construction_peak_bytes: None,
    predicted_proving_peak_bytes: None,
    states,
  })
}

/// Plans the credential-aware FS7 path after canonical relation emission and
/// before instance encoding. The shape values are measured from the emitted
/// relation; no credential-specific nonzero count is inferred from `n`.
pub fn plan_fs7(
  n: usize,
  budget: ProverMemoryBudget,
  shape: CredentialPlanShape,
  measured_disk_bytes_per_second: u64,
  measured_recompute_units_per_second: u64,
  network_profile: &str,
) -> io::Result<ProverMemoryPlan> {
  let mut base = plan_fs6(
    n,
    ProverMemoryBudget {
      hard_limit_bytes: usize::MAX,
      ..budget.clone()
    },
    measured_disk_bytes_per_second,
    measured_recompute_units_per_second,
    network_profile,
  )?;
  let n64 = n as u64;
  let matrix_domain = shape.max_sparse_matrix_entries.next_power_of_two() as u64;
  let relation_source_bytes = (shape.sparse_nonzero_entry_count as u64).saturating_mul(48);
  let witness_source_bytes = 32u64.saturating_mul(n64);
  let matrix_value_bytes = 3u64.saturating_mul(matrix_domain).saturating_mul(32);
  // Frozen V4G phase-aware model. Coefficients come only from the disjoint
  // V4G calibration set; padded and matrix allocation domains are explicit.
  const MIB: f64 = (1024 * 1024) as f64;
  let sparse_unit = shape.sparse_nonzero_entry_count as f64 / 100_000.0;
  let matrix_domain_unit = matrix_domain as f64 / 100_000.0;
  let n_unit = n64 as f64 / 65_536.0;
  let relation_peak = ((2.919_096_330_632_188 + 14.290_346_515_038_22 * sparse_unit
    - 0.106_048_303_286_225_47 * matrix_domain_unit)
    * MIB)
    .max(0.0)
    .round() as u64;
  let instance_peak = ((-0.963_956_168_888_321_6
    + 3.914_468_758_469_503_5 * n_unit
    + 11.239_866_403_413_112 * sparse_unit
    + 14.926_245_033_249_753 * matrix_domain_unit)
    * MIB)
    .max(0.0)
    .round() as u64;
  let malicious_mode = u64::from(network_profile.ends_with("M4")) as f64;
  let proving_peak = ((5.207_176_314_459_877
    + 31.939_235_051_472_99 * n_unit
    + 1.359_809_239_705_407_3 * shape.credential_count as f64
    + 6.916_521_920_098_202 * shape.revocation_count as f64
    - 0.177_083_969_116_211_44 * malicious_mode)
    * MIB)
    .max(0.0)
    .round() as u64;
  let fixed_runtime_reserve = 2_139_750u64;
  let thread_stack_reserve = 157_286u64;
  let compact_index_savings = 56u64.saturating_mul(matrix_domain);
  let predicted_total = relation_peak.max(instance_peak).max(proving_peak);
  let workload_runtime_margin = predicted_total
    .saturating_sub(fixed_runtime_reserve)
    .saturating_sub(thread_stack_reserve);

  base.states.extend([
    PlannedState {
      object_id: "credential_relation_entries".to_owned(),
      strategy: StateStrategy::StreamCredentialRelation,
      size_bytes: relation_source_bytes,
      estimated_peak_saved_bytes: 0,
      estimated_read_bytes: 0,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: 0,
    },
    PlannedState {
      object_id: "compact_credential_witness_source".to_owned(),
      strategy: StateStrategy::ReplayCompactCredentialWitness,
      size_bytes: witness_source_bytes,
      estimated_peak_saved_bytes: witness_source_bytes,
      estimated_read_bytes: 0,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: n64,
    },
    PlannedState {
      object_id: "mimc_intermediates".to_owned(),
      strategy: StateStrategy::StreamMimcIntermediates,
      size_bytes: 0,
      estimated_peak_saved_bytes: 0,
      estimated_read_bytes: 0,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: 0,
    },
    PlannedState {
      object_id: "revocation_path".to_owned(),
      strategy: StateStrategy::StreamRevocationPath,
      size_bytes: (shape.revocation_depth as u64).saturating_mul(32),
      estimated_peak_saved_bytes: 0,
      estimated_read_bytes: 0,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: 0,
    },
    PlannedState {
      object_id: "cross_credential_bindings".to_owned(),
      strategy: StateStrategy::CompactCrossCredentialBinding,
      size_bytes: (shape.credential_count as u64).saturating_mul(16),
      estimated_peak_saved_bytes: 0,
      estimated_read_bytes: 0,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: 0,
    },
    PlannedState {
      object_id: "sparse_r1cs_matrix_values".to_owned(),
      strategy: StateStrategy::ExternalizeSparseR1csBuild,
      size_bytes: matrix_value_bytes,
      estimated_peak_saved_bytes: matrix_value_bytes,
      estimated_read_bytes: matrix_value_bytes,
      estimated_write_bytes: matrix_value_bytes,
      estimated_recompute_work_units: 0,
    },
    PlannedState {
      object_id: "matrix_value_consumer_ranges".to_owned(),
      strategy: StateStrategy::ExternalizeMatrixValues,
      size_bytes: matrix_value_bytes,
      estimated_peak_saved_bytes: matrix_value_bytes,
      estimated_read_bytes: matrix_value_bytes,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: 0,
    },
    PlannedState {
      object_id: "sparse_address_timestamp_tables".to_owned(),
      strategy: StateStrategy::CompactSparseAddressTimestamps,
      size_bytes: compact_index_savings,
      estimated_peak_saved_bytes: compact_index_savings,
      estimated_read_bytes: 0,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: 0,
    },
    PlannedState {
      object_id: "relation_prover_barrier".to_owned(),
      strategy: StateStrategy::SeparateRelationProverLifetimes,
      size_bytes: relation_source_bytes,
      estimated_peak_saved_bytes: relation_source_bytes,
      estimated_read_bytes: 0,
      estimated_write_bytes: 0,
      estimated_recompute_work_units: 0,
    },
  ]);
  base.estimated_read_bytes = base
    .estimated_read_bytes
    .saturating_add(2 * matrix_value_bytes);
  base.estimated_write_bytes = base
    .estimated_write_bytes
    .saturating_add(matrix_value_bytes);
  base.estimated_temporary_storage_bytes = base
    .estimated_temporary_storage_bytes
    .saturating_add(matrix_value_bytes);
  base.estimated_peak_bytes = workload_runtime_margin;
  base.reserved_runtime_bytes = fixed_runtime_reserve + thread_stack_reserve;
  base.predicted_relation_construction_peak_bytes = Some(relation_peak);
  base.predicted_proving_peak_bytes = Some(proving_peak);
  base.predicted_total_rss_bytes = predicted_total;
  base.credential_shape = Some(shape);
  base.usable_prover_bytes = budget.usable_prover_bytes()?;
  let calibrated_one_sided_residual = 604_299u64;
  let required_safety = 8 * 1024 * 1024u64;
  let safe_upper_bound = base
    .predicted_total_rss_bytes
    .saturating_add(calibrated_one_sided_residual)
    .saturating_add(required_safety);
  if base
    .predicted_total_rss_bytes
    .saturating_add(calibrated_one_sided_residual)
    .saturating_add(required_safety)
    > budget.hard_limit_bytes as u64
  {
    return Err(io::Error::new(
      io::ErrorKind::OutOfMemory,
      format!(
        "no V4G FS7 plan fits: expected {} + one-sided residual {calibrated_one_sided_residual} + safety {required_safety} = {safe_upper_bound} > hard limit {}",
        base.predicted_total_rss_bytes, budget.hard_limit_bytes
      ),
    ));
  }
  Ok(base)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn planner_never_exceeds_usable_budget() {
    let budget = ProverMemoryBudget {
      hard_limit_bytes: 512 * 1024 * 1024,
      reserved_runtime_bytes: 32 * 1024 * 1024,
      maximum_chunk_bytes: 1024 * 1024,
      maximum_inflight_network_bytes: 8 * 1024 * 1024,
      maximum_file_cache_bytes: 8 * 1024 * 1024,
      maximum_temporary_storage_bytes: 4 * 1024 * 1024 * 1024,
    };
    let result = plan(1 << 18, budget, 500_000_000, 1_000_000, "loopback").unwrap();
    assert!(result.estimated_peak_bytes <= result.usable_prover_bytes as u64);
    assert!(
      result
        .states
        .iter()
        .filter(|state| state.strategy != StateStrategy::Retain)
        .count()
        >= 3
    );
  }
}
