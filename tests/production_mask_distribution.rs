#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::production::{
    epsilon::EpsilonUnit,
    mask_distribution::{
        assess_mask_distribution, ExternalMaskDistributionReview, ExternalReviewSignoff,
        MaskDistributionAssessment, MaskDistributionClosureField, MaskDistributionClosurePackage,
        MaskDistributionConstructionId, MaskDistributionEvidence, MaskDistributionProofBoundary,
        MaskDistributionRequirements, MaskDistributionSupport,
    },
};

fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn requirements() -> MaskDistributionRequirements {
    MaskDistributionRequirements::new(EpsilonUnit::from_units(12), 192)
}

fn valid_evidence() -> MaskDistributionEvidence {
    MaskDistributionEvidence::new(
        MaskDistributionSupport::ApproximateWithRenyiBound,
        digest(1),
        digest(2),
        digest(3),
        EpsilonUnit::from_units(7),
        224,
    )
}

fn accepted_certificate(
) -> lattice_aggregation::production::mask_distribution::AcceptedMaskDistributionCertificate {
    *assess_mask_distribution(requirements(), Some(valid_evidence()))
        .accepted_certificate()
        .expect("valid evidence should produce a certificate")
}

#[test]
fn missing_mask_distribution_evidence_is_not_accepted() {
    let assessment = assess_mask_distribution(requirements(), None);

    assert_eq!(
        assessment,
        MaskDistributionAssessment::Missing {
            reason: "missing aggregate mask distribution evidence",
        }
    );
    assert!(!assessment.is_accepted());
}

#[test]
fn accepted_mask_distribution_evidence_records_bound_without_production_proof_claim() {
    let assessment = assess_mask_distribution(requirements(), Some(valid_evidence()));

    let certificate = assessment
        .accepted_certificate()
        .expect("valid evidence should produce a certificate");
    assert_eq!(certificate.renyi_divergence(), EpsilonUnit::from_units(7));
    assert_eq!(
        certificate.max_allowed_divergence(),
        EpsilonUnit::from_units(12)
    );
    assert_eq!(certificate.min_entropy_bits(), 224);
    assert_eq!(certificate.required_min_entropy_bits(), 192);
    assert_eq!(
        certificate.support(),
        MaskDistributionSupport::ApproximateWithRenyiBound
    );
    assert!(!certificate.claims_full_mldsa_security_proof());
}

#[test]
fn exact_match_claim_with_nonzero_divergence_is_rejected() {
    let evidence = MaskDistributionEvidence::new(
        MaskDistributionSupport::MatchesCentralizedMldsa,
        digest(1),
        digest(2),
        digest(3),
        EpsilonUnit::from_units(1),
        224,
    );

    let assessment = assess_mask_distribution(requirements(), Some(evidence));

    assert_eq!(
        assessment,
        MaskDistributionAssessment::Invalid {
            reason: "exact centralized mask match requires zero renyi divergence",
        }
    );
    assert!(!assessment.is_accepted());
}

#[test]
fn invalid_mask_distribution_digest_is_rejected() {
    let mut evidence = valid_evidence();
    evidence.renyi_proof_digest = [0; 32];

    let assessment = assess_mask_distribution(requirements(), Some(evidence));

    assert_eq!(
        assessment,
        MaskDistributionAssessment::Invalid {
            reason: "renyi proof digest is all zero",
        }
    );
    assert!(!assessment.is_accepted());
}

#[test]
fn divergence_above_allowed_bound_is_rejected() {
    let evidence = MaskDistributionEvidence::new(
        MaskDistributionSupport::ApproximateWithRenyiBound,
        digest(1),
        digest(2),
        digest(3),
        EpsilonUnit::from_units(13),
        224,
    );

    let assessment = assess_mask_distribution(requirements(), Some(evidence));

    assert_eq!(
        assessment,
        MaskDistributionAssessment::Invalid {
            reason: "renyi divergence exceeds allowed mask residual",
        }
    );
    assert!(!assessment.is_accepted());
}

#[test]
fn insufficient_entropy_is_rejected() {
    let evidence = MaskDistributionEvidence::new(
        MaskDistributionSupport::ApproximateWithRenyiBound,
        digest(1),
        digest(2),
        digest(3),
        EpsilonUnit::from_units(7),
        191,
    );

    let assessment = assess_mask_distribution(requirements(), Some(evidence));

    assert_eq!(
        assessment,
        MaskDistributionAssessment::Invalid {
            reason: "aggregate mask min-entropy is below requirement",
        }
    );
    assert!(!assessment.is_accepted());
}

#[test]
fn incomplete_closure_package_reports_missing_required_fields() {
    let package = MaskDistributionClosurePackage::empty()
        .with_selected_construction_id(MaskDistributionConstructionId::new(
            "coordinator-assisted-mldsa65-mask-v1",
        ))
        .with_centralized_distribution_artifact_digest(digest(1))
        .with_renyi_proof_digest(digest(3))
        .with_accepted_epsilon_mask_bound(EpsilonUnit::from_units(7))
        .with_min_entropy_threshold_bits(192)
        .with_proof_boundary(MaskDistributionProofBoundary::NonProductionProofFramework);

    let report = package.closure_report();

    assert!(!report.is_closure_ready());
    assert_eq!(
        report.missing_fields(),
        &[
            MaskDistributionClosureField::AggregateDistributionArtifactDigest,
            MaskDistributionClosureField::ExternalReviewDigest,
            MaskDistributionClosureField::ExternalReviewSignoff,
        ]
    );
    assert!(report.invalid_fields().is_empty());
    assert!(report.has_explicit_non_production_proof_boundary());
}

#[test]
fn complete_closure_package_reports_ready_without_production_proof_claim() {
    let package = MaskDistributionClosurePackage::from_accepted_certificate(
        MaskDistributionConstructionId::new("coordinator-assisted-mldsa65-mask-v1"),
        accepted_certificate(),
        ExternalMaskDistributionReview::new(digest(9), ExternalReviewSignoff::Accepted),
        MaskDistributionProofBoundary::NonProductionProofFramework,
    );

    let report = package.closure_report();

    assert!(report.is_closure_ready());
    assert!(report.missing_fields().is_empty());
    assert!(report.invalid_fields().is_empty());
    assert_eq!(
        report.selected_construction_id().unwrap().as_str(),
        "coordinator-assisted-mldsa65-mask-v1"
    );
    assert_eq!(
        report.accepted_epsilon_mask_bound(),
        Some(EpsilonUnit::from_units(7))
    );
    assert_eq!(report.min_entropy_threshold_bits(), Some(192));
    assert!(report.has_explicit_non_production_proof_boundary());
    assert!(!report.claims_production_proof());
}

#[test]
fn closure_package_rejects_production_proof_claim_boundary() {
    let package = MaskDistributionClosurePackage::from_accepted_certificate(
        MaskDistributionConstructionId::new("coordinator-assisted-mldsa65-mask-v1"),
        accepted_certificate(),
        ExternalMaskDistributionReview::new(digest(9), ExternalReviewSignoff::Accepted),
        MaskDistributionProofBoundary::ClaimsProductionProof,
    );

    let report = package.closure_report();

    assert!(!report.is_closure_ready());
    assert!(report.missing_fields().is_empty());
    assert_eq!(
        report.invalid_fields(),
        &[MaskDistributionClosureField::NonProductionProofBoundary]
    );
    assert!(report.claims_production_proof());
    assert!(!report.has_explicit_non_production_proof_boundary());
}
