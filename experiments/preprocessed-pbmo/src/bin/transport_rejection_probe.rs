fn main() -> anyhow::Result<()> {
    let records = preprocessed_pbmo::run_transport_rejection_suite();
    println!("{}", serde_json::to_string_pretty(&records)?);
    if records
        .iter()
        .any(|record| record.msm_started || record.status != "REJECTED")
    {
        anyhow::bail!("one or more rejected requests started an MSM");
    }
    Ok(())
}
