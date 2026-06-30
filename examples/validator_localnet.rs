use lattice_aggregation::adapter::localnet::{
    run_localnet, LocalnetConfig, LOCALNET_CLAIM_BOUNDARY,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let report = run_localnet(LocalnetConfig::new(4, 3))
        .await
        .expect("localnet runner should complete");

    println!("claim_boundary={LOCALNET_CLAIM_BOUNDARY}");
    println!("validators={}", report.validator_count);
    println!("threshold={}", report.threshold);
    println!("finalized={}", report.finalized.len());
    println!("evidence_count={}", report.evidence_count);
    println!("broadcast_count={}", report.broadcast_count);
    println!("direct_send_count={}", report.direct_send_count);
    println!("network_bytes={}", report.network_bytes);
}
