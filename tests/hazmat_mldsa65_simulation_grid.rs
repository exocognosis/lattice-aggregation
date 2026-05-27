#![cfg(feature = "hazmat-real-mldsa")]

#[cfg(feature = "experimental-vss")]
use dytallix_pq_threshold::utils::hazmat_artifacts::{
    generate_experimental_vss_complaint_csv, generate_experimental_vss_complaint_jsonl,
    verify_experimental_vss_complaint_csv, verify_experimental_vss_complaint_events,
    verify_experimental_vss_complaint_jsonl,
};
use dytallix_pq_threshold::{
    adapter::wire::PqcThresholdWireMsg,
    crypto::contribution_proof::ContributionProof,
    mldsa65::{MLDSA65_CHALLENGE_BYTES, MLDSA65_MU_BYTES},
    utils::{
        exporter::{generate_latex_table, generate_pgfplots_csv},
        hazmat_artifacts::{
            generate_hazmat_transcript_csv, generate_hazmat_transcript_jsonl,
            verify_hazmat_transcript_csv, verify_hazmat_transcript_event_frame_binding,
            verify_hazmat_transcript_events, verify_hazmat_transcript_frame_bindings,
            verify_hazmat_transcript_jsonl,
        },
        hazmat_simulation::{
            generate_mldsa65_baseline_comparison_csv, run_hazmat_mldsa65_benchmark_suite,
            run_mldsa65_single_signer_baseline_suite, ByzantineMode, HazmatExperimentSpec,
            NetworkProfile,
        },
    },
    MLDSA65_SIGNATURE_BYTES,
};

#[test]
fn hazmat_transcript_event_frame_binding_rejects_digest_tampering() {
    let frame = proof_bound_secret_frame_fixture();
    let event = dytallix_pq_threshold::utils::hazmat_artifacts::event_from_hazmat_wire_frame(
        "Frame Binding",
        0,
        3,
        "remote_inbound",
        &frame,
    );

    verify_hazmat_transcript_event_frame_binding(&event, &frame)
        .expect("event should bind to its source frame");

    let mut tampered_event = event.clone();
    tampered_event.frame_digest[0] ^= 0x01;
    let err = verify_hazmat_transcript_event_frame_binding(&tampered_event, &frame)
        .expect_err("frame digest tampering must fail binding verification");
    assert!(err.to_string().contains("frame_digest"));

    let mut tampered_production_digest = event;
    let digest = tampered_production_digest
        .production_statement_digest
        .as_mut()
        .expect("fixture is proof-bound");
    digest[0] ^= 0x01;
    let err = verify_hazmat_transcript_event_frame_binding(&tampered_production_digest, &frame)
        .expect_err("production statement digest tampering must fail binding verification");
    assert!(err.to_string().contains("production_statement_digest"));
}

#[test]
fn hazmat_transcript_frame_binding_rejects_event_frame_count_mismatch() {
    let frame = proof_bound_secret_frame_fixture();
    let event = dytallix_pq_threshold::utils::hazmat_artifacts::event_from_hazmat_wire_frame(
        "Frame Binding Count",
        0,
        3,
        "remote_inbound",
        &frame,
    );

    let err = verify_hazmat_transcript_frame_bindings(&[event], &[])
        .expect_err("missing source frame must fail binding verification");
    assert!(err.to_string().contains("event/frame count mismatch"));
}

#[tokio::test]
async fn hazmat_benchmark_suite_runs_three_publishable_profiles() {
    let reports = run_hazmat_mldsa65_benchmark_suite().await;

    assert_eq!(reports.len(), 3);
    assert_eq!(reports[0].spec.label, "Small-Scale Consensus");
    assert_eq!(reports[0].spec.validators, 3);
    assert_eq!(
        reports[0].finalized_signatures.len(),
        reports[0].metrics.len()
    );
    assert!(reports[0]
        .finalized_signatures
        .iter()
        .all(|signature| signature.len() == MLDSA65_SIGNATURE_BYTES));

    assert_eq!(reports[1].spec.label, "Mid-Scale Distributed Fabric");
    assert_eq!(reports[1].spec.validators, 7);
    assert!(
        reports[1].slashing_evidence_count > 0,
        "Byzantine run should produce attributable evidence"
    );
    assert_eq!(
        reports[1].finalized_signatures.len(),
        reports[1].metrics.len()
    );

    assert_eq!(reports[2].spec.label, "Adversarial WAN Cluster");
    assert_eq!(reports[2].spec.validators, 15);
    assert!(
        reports[2]
            .metrics
            .iter()
            .any(|metric| metric.abort_and_retry_count > 0),
        "WAN profile should model retry pressure"
    );
}

#[tokio::test]
async fn single_signer_baseline_suite_matches_threshold_profile_trials() {
    let reports = run_hazmat_mldsa65_benchmark_suite().await;
    let baselines = run_mldsa65_single_signer_baseline_suite(&reports);
    let threshold_trials = reports
        .iter()
        .map(|report| report.metrics.len())
        .sum::<usize>();

    assert_eq!(baselines.len(), threshold_trials);
    assert!(baselines
        .iter()
        .all(|baseline| baseline.signature_bytes == MLDSA65_SIGNATURE_BYTES));
    assert!(baselines.iter().all(|baseline| baseline.verified));
    assert!(baselines
        .iter()
        .any(|baseline| baseline.profile == "Small-Scale Consensus"));
    assert!(baselines
        .iter()
        .any(|baseline| baseline.profile == "Mid-Scale Distributed Fabric"));
    assert!(baselines
        .iter()
        .any(|baseline| baseline.profile == "Adversarial WAN Cluster"));
}

#[tokio::test]
async fn single_signer_baseline_non_timing_fields_are_reproducible() {
    let first_reports = run_hazmat_mldsa65_benchmark_suite().await;
    let second_reports = run_hazmat_mldsa65_benchmark_suite().await;
    let first = run_mldsa65_single_signer_baseline_suite(&first_reports);
    let second = run_mldsa65_single_signer_baseline_suite(&second_reports);

    let first_stable = first
        .iter()
        .map(|row| {
            (
                row.profile,
                row.validators,
                row.threshold,
                row.trial,
                row.seed_digest,
                row.public_key_digest,
                row.signature_digest,
                row.signature_bytes,
                row.verified,
            )
        })
        .collect::<Vec<_>>();
    let second_stable = second
        .iter()
        .map(|row| {
            (
                row.profile,
                row.validators,
                row.threshold,
                row.trial,
                row.seed_digest,
                row.public_key_digest,
                row.signature_digest,
                row.signature_bytes,
                row.verified,
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(first_stable, second_stable);
}

#[tokio::test]
async fn baseline_comparison_csv_has_stable_header_and_profile_rows() {
    let reports = run_hazmat_mldsa65_benchmark_suite().await;
    let baselines = run_mldsa65_single_signer_baseline_suite(&reports);
    let csv = generate_mldsa65_baseline_comparison_csv(&reports, &baselines);

    assert!(csv.starts_with(
        "profile,validators,threshold,trial,baseline_sign_ns,baseline_verify_ns,threshold_duration_ns,threshold_bytes,signature_bytes,latency_overhead_x\n"
    ));
    assert!(csv.contains("Small-Scale Consensus"));
    assert!(csv.contains("Mid-Scale Distributed Fabric"));
    assert!(csv.contains("Adversarial WAN Cluster"));
    assert_eq!(csv.lines().count(), baselines.len() + 1);
    for report in &reports {
        for trial in 0..report.metrics.len() {
            assert!(
                baselines
                    .iter()
                    .any(|baseline| baseline.profile == report.spec.label
                        && baseline.trial == trial as u16),
                "missing baseline row for {} trial {trial}",
                report.spec.label
            );
        }
    }
}

#[tokio::test]
async fn hazmat_reports_export_replayable_transcript_artifacts() {
    let spec = HazmatExperimentSpec {
        label: "Transcript Artifact",
        validators: 3,
        threshold: 2,
        trials: 1,
        network: NetworkProfile::IdealLocalMesh,
        byzantine: ByzantineMode::None,
        masking_seed: [0xB1; MLDSA65_MU_BYTES],
        mu: [0x1B; MLDSA65_MU_BYTES],
    };

    let report = spec.run().await;

    assert!(
        report
            .transcript_events
            .windows(2)
            .any(|events| events[0].round == "secret_commitment"
                && events[1].round == "secret_opening"
                && events[0].validator_index == events[1].validator_index),
        "secret opening must be preceded by a challenge-bound precommitment"
    );

    let jsonl = generate_hazmat_transcript_jsonl(&report.transcript_events);
    let csv = generate_hazmat_transcript_csv(&report.transcript_events);

    assert!(jsonl.contains("\"experiment\":\"Transcript Artifact\""));
    assert!(jsonl.contains("\"round\":\"masking_commitment\""));
    assert!(jsonl.contains("\"round\":\"secret_commitment\""));
    assert!(jsonl.contains("\"production_statement_digest\":\""));
    assert!(jsonl.lines().all(|line| line.ends_with('}')));
    assert!(csv.starts_with(
        "experiment,trial,attempt,direction,round,validator_index,block_height,session_id,encoded_len,frame_digest,production_statement_digest\n"
    ));
    assert!(csv.contains(",secret_opening,"));
    verify_hazmat_transcript_events(&report.transcript_events).expect("events should verify");
    verify_hazmat_transcript_jsonl(&jsonl).expect("JSONL artifact should verify");
    verify_hazmat_transcript_csv(&csv).expect("CSV artifact should verify");
}

#[tokio::test]
async fn hazmat_transcript_verifier_rejects_secret_opening_without_adjacent_commitment() {
    let spec = HazmatExperimentSpec {
        label: "Transcript Tamper",
        validators: 3,
        threshold: 2,
        trials: 1,
        network: NetworkProfile::IdealLocalMesh,
        byzantine: ByzantineMode::None,
        masking_seed: [0xC1; MLDSA65_MU_BYTES],
        mu: [0x1C; MLDSA65_MU_BYTES],
    };

    let mut report = spec.run().await;
    let opening_position = report
        .transcript_events
        .iter()
        .position(|event| event.round == "secret_opening")
        .expect("fixture should include a secret opening");
    report.transcript_events.remove(opening_position - 1);

    let err = verify_hazmat_transcript_events(&report.transcript_events)
        .expect_err("orphaned secret opening must fail verification");
    assert!(err.to_string().contains("secret_opening"));
}

#[tokio::test]
async fn hazmat_small_profile_transcript_snapshot_has_stable_round_counts() {
    let spec = HazmatExperimentSpec {
        label: "Snapshot N3T2",
        validators: 3,
        threshold: 2,
        trials: 1,
        network: NetworkProfile::IdealLocalMesh,
        byzantine: ByzantineMode::None,
        masking_seed: [0xD1; MLDSA65_MU_BYTES],
        mu: [0x1D; MLDSA65_MU_BYTES],
    };

    let report = spec.run().await;
    verify_hazmat_transcript_events(&report.transcript_events).expect("snapshot should verify");
    let masking_commitments = count_round(&report, "masking_commitment");
    let masking_openings = count_round(&report, "masking_opening");
    let secret_commitments = count_round(&report, "secret_commitment");
    let secret_openings = count_round(&report, "secret_opening");

    assert_eq!(masking_commitments, masking_openings);
    assert_eq!(secret_commitments, secret_openings);
    assert_eq!(masking_commitments, secret_commitments);
    assert_eq!(
        masking_commitments % usize::from(spec.threshold),
        0,
        "each completed attempt records one local and one remote frame per round"
    );

    let jsonl = generate_hazmat_transcript_jsonl(&report.transcript_events);
    let csv = generate_hazmat_transcript_csv(&report.transcript_events);
    verify_hazmat_transcript_jsonl(&jsonl).expect("snapshot JSONL should verify");
    verify_hazmat_transcript_csv(&csv).expect("snapshot CSV should verify");
}

#[tokio::test]
async fn hazmat_single_trial_transcript_artifacts_are_reproducible() {
    let spec = HazmatExperimentSpec {
        label: "Reproducible Artifact",
        validators: 3,
        threshold: 2,
        trials: 1,
        network: NetworkProfile::IdealLocalMesh,
        byzantine: ByzantineMode::None,
        masking_seed: [0xE1; MLDSA65_MU_BYTES],
        mu: [0x1E; MLDSA65_MU_BYTES],
    };

    let first = spec.run().await;
    let second = spec.run().await;

    let first_jsonl = generate_hazmat_transcript_jsonl(&first.transcript_events);
    let second_jsonl = generate_hazmat_transcript_jsonl(&second.transcript_events);
    let first_csv = generate_hazmat_transcript_csv(&first.transcript_events);
    let second_csv = generate_hazmat_transcript_csv(&second.transcript_events);

    assert_eq!(
        first_jsonl, second_jsonl,
        "transcript JSONL must be reproducible for a fixed deterministic spec"
    );
    assert_eq!(
        first_csv, second_csv,
        "transcript CSV must be reproducible for a fixed deterministic spec"
    );
    verify_hazmat_transcript_jsonl(&first_jsonl).expect("reproducible JSONL should verify");
    verify_hazmat_transcript_csv(&first_csv).expect("reproducible CSV should verify");
}

#[tokio::test]
async fn hazmat_byzantine_profile_finalizes_after_invalid_payload_when_quorum_remains() {
    let spec = HazmatExperimentSpec {
        label: "Byzantine Survivability",
        validators: 7,
        threshold: 5,
        trials: 1,
        network: NetworkProfile::IdealLocalMesh,
        byzantine: ByzantineMode::TamperMaskingContribution { validator: 7 },
        masking_seed: [0xA5; MLDSA65_MU_BYTES],
        mu: [0x5A; MLDSA65_MU_BYTES],
    };

    let report = spec.run().await;

    assert_eq!(report.metrics.len(), 1);
    assert_eq!(report.finalized_signatures.len(), 1);
    assert_eq!(
        report.finalized_signatures[0].len(),
        MLDSA65_SIGNATURE_BYTES
    );
    assert!(report.slashing_evidence_count >= 1);
    assert!(report.metrics[0].abort_and_retry_count >= 1);
}

#[cfg(feature = "experimental-vss")]
#[tokio::test]
async fn hazmat_byzantine_profile_exports_experimental_vss_complaint_artifacts() {
    let spec = HazmatExperimentSpec {
        label: "Byzantine Complaint Artifact",
        validators: 7,
        threshold: 5,
        trials: 1,
        network: NetworkProfile::IdealLocalMesh,
        byzantine: ByzantineMode::TamperSecretContribution { validator: 7 },
        masking_seed: [0xB7; MLDSA65_MU_BYTES],
        mu: [0x7B; MLDSA65_MU_BYTES],
    };

    let report = spec.run().await;

    assert_eq!(report.finalized_signatures.len(), 1);
    assert!(
        !report.experimental_vss_complaint_events.is_empty(),
        "Byzantine profile should export canonical complaint evidence artifacts"
    );
    let jsonl =
        generate_experimental_vss_complaint_jsonl(&report.experimental_vss_complaint_events);
    let csv = generate_experimental_vss_complaint_csv(&report.experimental_vss_complaint_events);

    assert!(jsonl.contains("\"experiment\":\"Byzantine Complaint Artifact\""));
    assert!(jsonl.contains("\"validator_index\":7"));
    assert!(jsonl.contains("\"evidence_kind\":\"InvalidPartialSignature\""));
    assert!(jsonl.contains("\"production_vss_relation_statement_digest\":\""));
    assert!(csv.starts_with(
        "experiment,trial,validator_index,evidence_kind,session_id,evidence_len,evidence_digest,production_vss_relation_statement_digest,evidence_hex\n"
    ));
    verify_experimental_vss_complaint_events(&report.experimental_vss_complaint_events)
        .expect("in-memory complaint evidence events should verify");
    verify_experimental_vss_complaint_jsonl(&jsonl).expect("complaint JSONL should verify");
    verify_experimental_vss_complaint_csv(&csv).expect("complaint CSV should verify");
}

#[tokio::test]
async fn hazmat_reports_feed_existing_latex_and_csv_exporters() {
    let reports = run_hazmat_mldsa65_benchmark_suite().await;

    for report in reports {
        let latex =
            generate_latex_table(report.spec.label, report.spec.validators, &report.metrics);
        let csv = generate_pgfplots_csv(&report.metrics);

        assert!(latex.contains("\\begin{table}"));
        assert!(latex.contains(report.spec.label));
        assert!(csv.starts_with("session_id,duration_ms,aborts,bandwidth_bytes"));
    }
}

fn count_round(
    report: &dytallix_pq_threshold::utils::hazmat_simulation::HazmatExperimentReport,
    round: &str,
) -> usize {
    report
        .transcript_events
        .iter()
        .filter(|event| event.round == round)
        .count()
}

fn proof_bound_secret_frame_fixture() -> PqcThresholdWireMsg {
    PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
        session_id: [0xA1; 32],
        block_height: 42,
        attempt: 3,
        validator_index: 2,
        challenge: [0xC3; MLDSA65_CHALLENGE_BYTES],
        masking_commitment_digest: [0x11; 32],
        secret_commitment_digest: [0x22; 32],
        dkg_commitment_digest: [0x33; 32],
        production_statement_digest: [0x44; 32],
        proof: ContributionProof {
            payload_len: 4,
            payload_digest: [0x55; 32],
            proof_digest: [0x66; 32],
        },
        payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
    }
}
