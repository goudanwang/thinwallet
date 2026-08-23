#[path = "../credential_workloads.rs"]
mod credential_workloads;

use anyhow::{anyhow, Result};
use credential_workloads::{build, minimum_log_size, Mutation, Workload};
use libspartan_patched as patched;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;

#[derive(Serialize)]
struct TestResult {
    expected: &'static str,
    satisfiable: bool,
    passed: bool,
}

fn sat(workload: Workload, mutation: Mutation, padded_size: usize) -> Result<bool> {
    let fixture = build(workload, mutation, padded_size).map_err(|error| anyhow!(error))?;
    let instance = patched::Instance::new(
        padded_size,
        padded_size,
        fixture.inputs.len(),
        &fixture.a,
        &fixture.b,
        &fixture.c,
    )
    .map_err(|error| anyhow!("{error:?}"))?;
    let vars = patched::VarsAssignment::new(&fixture.vars).map_err(|error| anyhow!("{error:?}"))?;
    let inputs =
        patched::InputsAssignment::new(&fixture.inputs).map_err(|error| anyhow!("{error:?}"))?;
    instance
        .is_sat(&vars, &inputs)
        .map_err(|error| anyhow!("{error:?}"))
}

fn audit_one(workload: Workload) -> Result<serde_json::Value> {
    let log_size = minimum_log_size(workload);
    let padded_size = 1usize << log_size;
    let fixture = build(workload, Mutation::Valid, padded_size).map_err(|error| anyhow!(error))?;
    let mut tests = BTreeMap::new();
    let cases = [
        ("valid", Mutation::Valid, true),
        ("boundary", Mutation::Boundary, true),
        ("modified_attribute", Mutation::Attribute, false),
        ("modified_issuer", Mutation::Issuer, false),
        ("modified_holder_binding", Mutation::Holder, false),
        ("modified_mac", Mutation::Mac, false),
        ("wrong_nonce", Mutation::Nonce, false),
        ("expired", Mutation::Expired, false),
        ("revoked", Mutation::Revoked, false),
        ("stale_revocation_root", Mutation::StaleRoot, false),
        ("malformed_merkle_path", Mutation::MerklePath, false),
        (
            "cross_credential_mismatch",
            Mutation::CrossCredential,
            false,
        ),
    ];
    for (name, mutation, expected_sat) in cases {
        let applicable = match mutation {
            Mutation::Expired => matches!(workload, Workload::W2 | Workload::W3 | Workload::W4),
            Mutation::Revoked | Mutation::StaleRoot | Mutation::MerklePath => {
                matches!(workload, Workload::W3 | Workload::W4)
            }
            Mutation::CrossCredential => workload == Workload::W4,
            _ => workload != Workload::W0,
        };
        if !applicable {
            continue;
        }
        let satisfiable = sat(workload, mutation, padded_size)?;
        tests.insert(
            name,
            TestResult {
                expected: if expected_sat { "accept" } else { "reject" },
                satisfiable,
                passed: satisfiable == expected_sat,
            },
        );
    }
    let all_passed = tests.values().all(|test| test.passed);
    Ok(serde_json::json!({
        "metadata": fixture.metadata,
        "tests": tests,
        "all_tests_passed": all_passed,
    }))
}

fn main() -> Result<()> {
    let output = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "results/v4b/workload_audit.json".into());
    let mut workloads = BTreeMap::new();
    for workload in [
        Workload::W0,
        Workload::W1,
        Workload::W2,
        Workload::W3,
        Workload::W4,
    ] {
        workloads.insert(format!("{workload:?}"), audit_one(workload)?);
    }
    let all_passed = workloads.values().all(|value| {
        value
            .get("all_tests_passed")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
            || value["metadata"]["workload"] == "W0"
    });
    let report = serde_json::json!({
        "classification": if all_passed { "THINWALLET_CREDENTIAL_AUTHENTICITY_GADGET_PASS" } else { "PHASE_V4B_BLOCKED_CREDENTIAL_AUTHENTICATION" },
        "attribute_predicates": if all_passed { "THINWALLET_ATTRIBUTE_PREDICATES_PASS" } else { "BLOCKED" },
        "authenticated_revocation": if all_passed { "THINWALLET_AUTHENTICATED_REVOCATION_PASS" } else { "BLOCKED" },
        "workloads": workloads,
    });
    if let Some(parent) = std::path::Path::new(&output).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
    println!("{output}");
    if all_passed {
        Ok(())
    } else {
        Err(anyhow!("credential workload audit failed"))
    }
}
