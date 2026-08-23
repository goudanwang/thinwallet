use anyhow::{anyhow, Result};
use serde::Serialize;

#[path = "../credential_workloads.rs"]
mod credential_workloads;

use credential_workloads::profile_s::{build_profile_s, ProfileSMutation, ProfileSWorkload};

#[derive(Serialize)]
struct ScaleDescription {
    workload: String,
    semantic_relation: String,
    raw_constraints: usize,
    padded_constraints: usize,
    public_inputs: usize,
    witness_elements: usize,
    nnz_a: usize,
    nnz_b: usize,
    nnz_c: usize,
    nnz_total: usize,
    q: usize,
    m: usize,
    q_times_m: usize,
    constraint_composition: std::collections::BTreeMap<String, usize>,
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let name = args.next().ok_or_else(|| anyhow!("expected workload"))?;
    let log_size = args
        .next()
        .ok_or_else(|| anyhow!("expected padded log size"))?
        .parse::<usize>()?;
    if args.next().is_some() {
        return Err(anyhow!("unexpected arguments"));
    }
    let workload = ProfileSWorkload::parse(&name)
        .ok_or_else(|| anyhow!("unknown Profile S workload {name}"))?;
    let fixture = build_profile_s(workload, ProfileSMutation::Valid, 1usize << log_size)
        .map_err(|error| anyhow!(error))?;
    let metadata = fixture.metadata;
    let description = ScaleDescription {
        workload: metadata.workload,
        semantic_relation: metadata.relation,
        raw_constraints: metadata.raw_constraints,
        padded_constraints: metadata.padded_size,
        public_inputs: metadata.public_inputs,
        witness_elements: metadata.witness_elements,
        nnz_a: fixture.a.len(),
        nnz_b: fixture.b.len(),
        nnz_c: fixture.c.len(),
        nnz_total: fixture.a.len() + fixture.b.len() + fixture.c.len(),
        q: metadata.q,
        m: metadata.m,
        q_times_m: metadata.q * metadata.m,
        constraint_composition: metadata.constraint_composition,
    };
    println!("{}", serde_json::to_string_pretty(&description)?);
    Ok(())
}
