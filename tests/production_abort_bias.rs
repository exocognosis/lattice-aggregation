#![cfg(feature = "coordinator-assisted")]

#[path = "../src/production/abort_bias.rs"]
mod abort_bias;

use abort_bias::{
    AbortBiasEvidence, AbortBiasEvidenceError, AbortLeakageModel, AbortObservable,
    AcceptedSampleEvidence, DomainPurpose, DomainSeparationEvidence, DomainTag, LeakageBoundField,
};

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

#[test]
fn bounded_public_evidence_reports_retry_bias_checks() {
    let report = valid_evidence().validate().unwrap();

    assert_eq!(report.accepted_samples(), 200);
    assert_eq!(report.accepted_sample_total_variation_ppm(), 5_000);
    assert_eq!(report.max_retry_count(), 8);
    assert_eq!(report.max_abort_observations(), 8);
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
