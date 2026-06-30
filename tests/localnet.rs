use lattice_aggregation::{
    adapter::localnet::{
        run_localnet, LocalnetConfig, LocalnetFaultProfile, LocalnetTransportMode,
        LOCALNET_CLAIM_BOUNDARY,
    },
    ThresholdError, ValidatorId, MLDSA65_SIGNATURE_BYTES,
};

use std::collections::BTreeSet;
use std::time::Duration;

#[tokio::test]
async fn localnet_three_validators_finalize_without_manual_peer_injection() {
    let report = run_localnet(LocalnetConfig::new(3, 2)).await.unwrap();

    assert_eq!(report.claim_boundary, LOCALNET_CLAIM_BOUNDARY);
    assert_eq!(report.fault_profile, "honest");
    assert_eq!(report.validator_count, 3);
    assert_eq!(report.triggered_validator_count, 3);
    assert_eq!(report.threshold, 2);
    assert!(report.all_validators_finalized);
    assert_eq!(report.finalized.len(), 3);
    assert!(report
        .finalized
        .iter()
        .all(|event| event.signature_bytes == MLDSA65_SIGNATURE_BYTES));
    assert_eq!(report.evidence_count, 0);
    assert_eq!(report.dropped_message_count, 0);
    assert!(report.broadcast_count >= 6);
    assert!(report.network_bytes > 0);
}

#[tokio::test]
async fn localnet_threshold_subset_finalizes_with_passive_validator() {
    let report = run_localnet(LocalnetConfig::new(4, 3).with_triggered_validator_count(3))
        .await
        .unwrap();

    let finalized_validators = report
        .finalized
        .iter()
        .map(|event| event.validator)
        .collect::<BTreeSet<_>>();

    assert_eq!(report.validator_count, 4);
    assert_eq!(report.triggered_validator_count, 3);
    assert_eq!(report.threshold, 3);
    assert_eq!(report.finalized.len(), 3);
    assert_eq!(
        finalized_validators,
        [ValidatorId(1), ValidatorId(2), ValidatorId(3)]
            .into_iter()
            .collect()
    );
    assert!(!finalized_validators.contains(&ValidatorId(4)));
    assert!(!report.all_validators_finalized);
    assert_eq!(report.evidence_count, 0);
    assert_eq!(report.dropped_message_count, 0);
    assert!(report.network_bytes > 0);
    assert_eq!(report.claim_boundary, LOCALNET_CLAIM_BOUNDARY);
}

#[tokio::test]
async fn localnet_authenticated_transport_envelopes_bind_validator_identity() {
    let report = run_localnet(
        LocalnetConfig::new(4, 3).with_transport_mode(LocalnetTransportMode::AuthenticatedEnvelope),
    )
    .await
    .unwrap();

    assert_eq!(
        report.transport_mode,
        "authenticated local envelope over tokio mpsc"
    );
    assert_eq!(
        report.authentication_policy,
        "local validator identity digest envelope"
    );
    assert!(report.authenticated_envelope_count >= usize::from(report.validator_count));
    assert_eq!(report.rejected_envelope_count, 0);
    assert_eq!(report.finalized.len(), 4);
    assert!(report.all_validators_finalized);
    assert_eq!(report.claim_boundary, LOCALNET_CLAIM_BOUNDARY);
}

#[tokio::test]
async fn localnet_rejects_tampered_authenticated_envelope_without_slashing_claim() {
    let report = run_localnet(
        LocalnetConfig::new(4, 3)
            .with_transport_mode(LocalnetTransportMode::AuthenticatedEnvelope)
            .with_fault_profile(LocalnetFaultProfile::tampered_authenticated_envelope(
                ValidatorId(4),
            )),
    )
    .await
    .unwrap();

    assert_eq!(report.fault_profile, "authenticated-envelope-tamper");
    assert_eq!(
        report.transport_mode,
        "authenticated local envelope over tokio mpsc"
    );
    assert!(report.authenticated_envelope_count > 0);
    assert!(report.rejected_envelope_count > 0);
    assert_eq!(report.evidence_count, 0);
    assert_eq!(report.dropped_message_count, 0);
    assert_eq!(report.finalized.len(), 4);
    assert!(report.all_validators_finalized);
    assert_eq!(report.claim_boundary, LOCALNET_CLAIM_BOUNDARY);
}

#[tokio::test]
async fn localnet_rejects_triggered_count_below_threshold() {
    let error = run_localnet(LocalnetConfig::new(4, 3).with_triggered_validator_count(2))
        .await
        .unwrap_err();

    assert_eq!(
        error,
        ThresholdError::InvalidThresholdParameters {
            threshold: 3,
            total_nodes: 2
        }
    );
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

#[tokio::test]
async fn withheld_partial_fault_profile_records_liveness_evidence_without_success_claim() {
    let report = run_localnet(
        LocalnetConfig::new(4, 4)
            .with_round_timeout(Duration::from_millis(5))
            .with_fault_profile(LocalnetFaultProfile::withheld_partial(ValidatorId(4))),
    )
    .await
    .unwrap();

    assert_eq!(report.fault_profile, "withheld-partial");
    assert!(!report.all_validators_finalized);
    assert!(report.finalized.len() < usize::from(report.validator_count));
    assert!(report.evidence_count >= 3);
    assert!(report.dropped_message_count >= 3);
    assert!(report.broadcast_count >= 8);
    assert!(report.network_bytes > 0);
    assert_eq!(report.claim_boundary, LOCALNET_CLAIM_BOUNDARY);
}
