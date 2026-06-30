use lattice_aggregation::{
    adapter::localnet::{run_localnet, LocalnetConfig, LOCALNET_CLAIM_BOUNDARY},
    ThresholdError, MLDSA65_SIGNATURE_BYTES,
};

#[tokio::test]
async fn localnet_three_validators_finalize_without_manual_peer_injection() {
    let report = run_localnet(LocalnetConfig::new(3, 2)).await.unwrap();

    assert_eq!(report.claim_boundary, LOCALNET_CLAIM_BOUNDARY);
    assert_eq!(report.validator_count, 3);
    assert_eq!(report.threshold, 2);
    assert_eq!(report.finalized.len(), 3);
    assert!(report
        .finalized
        .iter()
        .all(|event| event.signature_bytes == MLDSA65_SIGNATURE_BYTES));
    assert_eq!(report.evidence_count, 0);
    assert!(report.broadcast_count >= 6);
    assert!(report.network_bytes > 0);
}

#[tokio::test]
async fn localnet_report_preserves_non_proof_boundary() {
    let report = run_localnet(LocalnetConfig::new(4, 3)).await.unwrap();

    assert_eq!(
        report.claim_boundary,
        "local validator-network engineering telemetry; not security evidence; not real-world validator performance; not production-readiness evidence; not production network liveness, authenticated transport, or consensus safety; not side-channel resistance; not CAVP/ACVTS validation; not FIPS validation; not production threshold ML-DSA security"
    );
    assert_eq!(report.validator_count, 4);
    assert_eq!(report.threshold, 3);
    assert_eq!(report.finalized.len(), 4);
}

#[tokio::test]
async fn localnet_rejects_invalid_threshold_shape() {
    let error = run_localnet(LocalnetConfig::new(2, 3)).await.unwrap_err();

    assert_eq!(
        error,
        ThresholdError::InvalidThresholdParameters {
            threshold: 3,
            total_nodes: 2
        }
    );
}
