#![cfg(feature = "coordinator-assisted")]

#[path = "../src/production/abort_bias.rs"]
mod abort_bias;

use abort_bias::{
    AbortBiasBoundThresholdField, AbortBiasBoundThresholds, AbortBiasClosureStatus,
    AbortBiasEvidence, AbortBiasEvidenceError, AbortBiasProofArtifact, AbortBiasProofDigests,
    AbortLeakageModel, AbortObservable, AbortRetryBiasProofPackage, AcceptedSampleEvidence,
    DomainPurpose, DomainSeparationEvidence, DomainTag, ExternalReviewSignoff, LeakageBoundField,
};

fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn tag(label: &'static str) -> DomainTag {
    DomainTag::new(label).unwrap()
}

fn separated_domains() -> DomainSeparationEvidence {
    DomainSeparationEvidence::new(
        tag("lattice-aggregation/abort-bias/challenge/v1"),
        tag("lattice-aggregation/abort-bias/retry/v1"),
        tag("lattice-aggregation/abort-bias/accepted-sample/v1"),
    )
}

fn bounded_public_leakage() -> AbortLeakageModel {
    AbortLeakageModel::new(
        Some(8),
        Some(8),
        vec![
            AbortObservable::AggregateAbortBit,
            AbortObservable::RetryCounter,
        ],
    )
}

fn balanced_samples() -> AcceptedSampleEvidence {
    AcceptedSampleEvidence::new(vec![50, 49, 51, 50], 128, 10_000)
}

fn valid_evidence() -> AbortBiasEvidence {
    AbortBiasEvidence::new(
        separated_domains(),
        bounded_public_leakage(),
        balanced_samples(),
    )
}

fn proof_digests() -> AbortBiasProofDigests {
    AbortBiasProofDigests::new(digest(1), digest(2), digest(3), digest(4), digest(5))
}

fn closure_thresholds() -> AbortBiasBoundThresholds {
    AbortBiasBoundThresholds::new(8, 8, 128, 10_000)
}

fn external_review() -> ExternalReviewSignoff {
    ExternalReviewSignoff::new(digest(6), digest(7), true)
}

fn closure_package() -> AbortRetryBiasProofPackage {
    AbortRetryBiasProofPackage::new(
        valid_evidence(),
        proof_digests(),
        closure_thresholds(),
        external_review(),
    )
}

#[test]
fn bounded_public_evidence_reports_retry_bias_checks() {
    let report = valid_evidence().validate().unwrap();

    assert_eq!(report.accepted_samples(), 200);
    assert_eq!(report.accepted_sample_total_variation_ppm(), 5_000);
    assert_eq!(report.max_retry_count(), 8);
    assert_eq!(report.max_abort_observations(), 8);
    assert_eq!(report.status(), AbortBiasClosureStatus::EvidenceOnly);
}

#[test]
fn rejects_retry_domain_reuse() {
    let domains = DomainSeparationEvidence::new(
        tag("lattice-aggregation/abort-bias/challenge/v1"),
        tag("lattice-aggregation/abort-bias/challenge/v1"),
        tag("lattice-aggregation/abort-bias/accepted-sample/v1"),
    );
    let evidence = AbortBiasEvidence::new(domains, bounded_public_leakage(), balanced_samples());

    assert_eq!(
        evidence.validate().unwrap_err(),
        AbortBiasEvidenceError::MissingDomainSeparation {
            first: DomainPurpose::Challenge,
            second: DomainPurpose::Retry,
        }
    );
}

#[test]
fn complete_proof_package_reports_closure_ready_status() {
    let report = closure_package().validate_closure_ready().unwrap();

    assert_eq!(report.status(), AbortBiasClosureStatus::ClosureReady);
    assert_eq!(report.evidence_report().accepted_samples(), 200);
    assert_eq!(report.formal_leakage_model_digest(), &digest(1));
    assert_eq!(report.retry_domain_separation_proof_digest(), &digest(2));
    assert_eq!(
        report.accepted_signature_distribution_proof_digest(),
        &digest(3)
    );
    assert_eq!(report.adversarial_abort_policy_corpus_digest(), &digest(4));
    assert_eq!(report.sample_size_bucket_rationale_digest(), &digest(5));
    assert_eq!(report.bound_thresholds().max_retry_count(), 8);
    assert_eq!(report.bound_thresholds().max_abort_observations(), 8);
    assert_eq!(report.bound_thresholds().minimum_accepted_samples(), 128);
    assert_eq!(
        report
            .bound_thresholds()
            .max_accepted_sample_total_variation_ppm(),
        10_000
    );
    assert_eq!(report.external_review().review_digest(), &digest(6));
    assert_eq!(
        report.external_review().reviewer_signoff_digest(),
        &digest(7)
    );
    assert!(report.external_review().is_signed_off());
}

#[test]
fn proof_package_rejects_missing_required_proof_digest() {
    let proof_digests =
        AbortBiasProofDigests::new(digest(1), digest(2), [0; 32], digest(4), digest(5));
    let package = AbortRetryBiasProofPackage::new(
        valid_evidence(),
        proof_digests,
        closure_thresholds(),
        external_review(),
    );

    assert_eq!(
        package.validate_closure_ready().unwrap_err(),
        AbortBiasEvidenceError::MissingProofArtifact {
            artifact: AbortBiasProofArtifact::AcceptedSignatureDistributionProof,
        }
    );
}

#[test]
fn proof_package_rejects_missing_external_review_signoff() {
    let package = AbortRetryBiasProofPackage::new(
        valid_evidence(),
        proof_digests(),
        closure_thresholds(),
        ExternalReviewSignoff::new(digest(6), digest(7), false),
    );

    assert_eq!(
        package.validate_closure_ready().unwrap_err(),
        AbortBiasEvidenceError::ExternalReviewNotSignedOff
    );
}

#[test]
fn proof_package_rejects_thresholds_that_do_not_bound_evidence() {
    let package = AbortRetryBiasProofPackage::new(
        valid_evidence(),
        proof_digests(),
        AbortBiasBoundThresholds::new(4, 8, 128, 10_000),
        external_review(),
    );

    assert_eq!(
        package.validate_closure_ready().unwrap_err(),
        AbortBiasEvidenceError::BoundThresholdExceeded {
            field: AbortBiasBoundThresholdField::MaxRetryCount,
            measured: 8,
            threshold: 4,
        }
    );
}

#[test]
fn proof_package_rejects_biased_accepted_samples_before_closure_status() {
    let biased_evidence = AbortBiasEvidence::new(
        separated_domains(),
        bounded_public_leakage(),
        AcceptedSampleEvidence::new(vec![99, 1], 20, 100_000),
    );
    let package = AbortRetryBiasProofPackage::new(
        biased_evidence,
        proof_digests(),
        closure_thresholds(),
        external_review(),
    );

    assert_eq!(
        package.validate_closure_ready().unwrap_err(),
        AbortBiasEvidenceError::BiasedAcceptedSampleEvidence {
            total_variation_ppm: 490_000,
            max_total_variation_ppm: 100_000,
        }
    );
}

#[test]
fn rejects_unbounded_abort_retry_leakage() {
    let leakage = AbortLeakageModel::new(
        None,
        Some(8),
        vec![
            AbortObservable::AggregateAbortBit,
            AbortObservable::RetryCounter,
        ],
    );
    let evidence = AbortBiasEvidence::new(separated_domains(), leakage, balanced_samples());

    assert_eq!(
        evidence.validate().unwrap_err(),
        AbortBiasEvidenceError::UnboundedAbortLeakage {
            field: LeakageBoundField::RetryCount,
        }
    );
}

#[test]
fn rejects_secret_dependent_abort_observables() {
    let leakage = AbortLeakageModel::new(
        Some(8),
        Some(8),
        vec![
            AbortObservable::AggregateAbortBit,
            AbortObservable::SecretDependentAbortReason,
        ],
    );
    let evidence = AbortBiasEvidence::new(separated_domains(), leakage, balanced_samples());

    assert_eq!(
        evidence.validate().unwrap_err(),
        AbortBiasEvidenceError::DisallowedAbortLeakage {
            observable: AbortObservable::SecretDependentAbortReason,
        }
    );
}

#[test]
fn rejects_biased_accepted_sample_evidence() {
    let samples = AcceptedSampleEvidence::new(vec![99, 1], 20, 100_000);
    let evidence = AbortBiasEvidence::new(separated_domains(), bounded_public_leakage(), samples);

    assert_eq!(
        evidence.validate().unwrap_err(),
        AbortBiasEvidenceError::BiasedAcceptedSampleEvidence {
            total_variation_ppm: 490_000,
            max_total_variation_ppm: 100_000,
        }
    );
}
