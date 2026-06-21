//! Typed aggregate-mask distribution evidence for coordinator-assisted gates.
//!
//! This module records a reviewed Renyi-style distribution bound. Acceptance is
//! an evidence gate only; it is not a full ML-DSA production security proof.

use super::epsilon::EpsilonUnit;

/// Relationship asserted between the aggregate mask distribution and the
/// centralized ML-DSA mask distribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaskDistributionSupport {
    /// Evidence asserts exact support/distribution compatibility.
    MatchesCentralizedMldsa,
    /// Evidence asserts an approximation with an explicit Renyi bound.
    ApproximateWithRenyiBound,
}

/// Requirements for accepting aggregate-mask distribution evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaskDistributionRequirements {
    max_allowed_divergence: EpsilonUnit,
    required_min_entropy_bits: u16,
}

impl MaskDistributionRequirements {
    /// Construct deterministic evidence requirements.
    pub const fn new(max_allowed_divergence: EpsilonUnit, required_min_entropy_bits: u16) -> Self {
        Self {
            max_allowed_divergence,
            required_min_entropy_bits,
        }
    }

    /// Maximum accepted Renyi divergence for the mask residual.
    pub const fn max_allowed_divergence(self) -> EpsilonUnit {
        self.max_allowed_divergence
    }

    /// Minimum aggregate-mask entropy required by the reviewed proof artifact.
    pub const fn required_min_entropy_bits(self) -> u16 {
        self.required_min_entropy_bits
    }
}

/// Digest-only evidence for the aggregate-mask distribution bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaskDistributionEvidence {
    /// Support/distribution statement being reviewed.
    pub support: MaskDistributionSupport,
    /// Digest of the centralized ML-DSA reference distribution artifact.
    pub centralized_distribution_digest: [u8; 32],
    /// Digest of the aggregate threshold-mask distribution artifact.
    pub aggregate_distribution_digest: [u8; 32],
    /// Digest of the reviewed Renyi/divergence proof or evidence package.
    pub renyi_proof_digest: [u8; 32],
    /// Claimed Renyi divergence bound in deterministic epsilon units.
    pub renyi_divergence: EpsilonUnit,
    /// Claimed aggregate-mask min-entropy.
    pub min_entropy_bits: u16,
}

impl MaskDistributionEvidence {
    /// Construct digest-only aggregate-mask distribution evidence.
    pub const fn new(
        support: MaskDistributionSupport,
        centralized_distribution_digest: [u8; 32],
        aggregate_distribution_digest: [u8; 32],
        renyi_proof_digest: [u8; 32],
        renyi_divergence: EpsilonUnit,
        min_entropy_bits: u16,
    ) -> Self {
        Self {
            support,
            centralized_distribution_digest,
            aggregate_distribution_digest,
            renyi_proof_digest,
            renyi_divergence,
            min_entropy_bits,
        }
    }
}

/// Accepted aggregate-mask distribution evidence token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedMaskDistributionCertificate {
    support: MaskDistributionSupport,
    centralized_distribution_digest: [u8; 32],
    aggregate_distribution_digest: [u8; 32],
    renyi_proof_digest: [u8; 32],
    renyi_divergence: EpsilonUnit,
    max_allowed_divergence: EpsilonUnit,
    min_entropy_bits: u16,
    required_min_entropy_bits: u16,
}

impl AcceptedMaskDistributionCertificate {
    /// Return the accepted support statement.
    pub const fn support(self) -> MaskDistributionSupport {
        self.support
    }

    /// Borrow the centralized ML-DSA reference distribution digest.
    pub const fn centralized_distribution_digest(&self) -> &[u8; 32] {
        &self.centralized_distribution_digest
    }

    /// Borrow the aggregate threshold-mask distribution digest.
    pub const fn aggregate_distribution_digest(&self) -> &[u8; 32] {
        &self.aggregate_distribution_digest
    }

    /// Borrow the reviewed Renyi proof digest.
    pub const fn renyi_proof_digest(&self) -> &[u8; 32] {
        &self.renyi_proof_digest
    }

    /// Return the accepted Renyi divergence bound.
    pub const fn renyi_divergence(self) -> EpsilonUnit {
        self.renyi_divergence
    }

    /// Return the configured maximum allowed divergence.
    pub const fn max_allowed_divergence(self) -> EpsilonUnit {
        self.max_allowed_divergence
    }

    /// Return the accepted aggregate-mask min-entropy.
    pub const fn min_entropy_bits(self) -> u16 {
        self.min_entropy_bits
    }

    /// Return the configured minimum aggregate-mask entropy.
    pub const fn required_min_entropy_bits(self) -> u16 {
        self.required_min_entropy_bits
    }

    /// This certificate is a mask-distribution evidence gate, not a complete
    /// ML-DSA security proof.
    pub const fn claims_full_mldsa_security_proof(self) -> bool {
        false
    }
}

/// Stable identifier for the selected aggregate-mask construction under review.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaskDistributionConstructionId {
    label: &'static str,
}

impl MaskDistributionConstructionId {
    /// Construct a construction identifier.
    pub const fn new(label: &'static str) -> Self {
        Self { label }
    }

    /// Return the construction identifier string.
    pub const fn as_str(self) -> &'static str {
        self.label
    }

    const fn is_empty(self) -> bool {
        self.label.is_empty()
    }
}

/// External cryptographic review signoff status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalReviewSignoff {
    /// Review exists but has not signed off on the closure package.
    Pending,
    /// Review signed off on the exact package digests and stated bounds.
    Accepted,
}

impl ExternalReviewSignoff {
    const fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

/// Digest and signoff status for an external mask-distribution review.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalMaskDistributionReview {
    review_digest: [u8; 32],
    signoff: ExternalReviewSignoff,
}

impl ExternalMaskDistributionReview {
    /// Construct external review evidence for a closure package.
    pub const fn new(review_digest: [u8; 32], signoff: ExternalReviewSignoff) -> Self {
        Self {
            review_digest,
            signoff,
        }
    }

    /// Borrow the external review artifact digest.
    pub const fn review_digest(&self) -> &[u8; 32] {
        &self.review_digest
    }

    /// Return the external review signoff status.
    pub const fn signoff(self) -> ExternalReviewSignoff {
        self.signoff
    }
}

/// Explicit boundary for what a closure package is allowed to claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaskDistributionProofBoundary {
    /// The package is a non-production proof framework and not a production proof.
    NonProductionProofFramework,
    /// The package attempts to claim production ML-DSA proof closure.
    ClaimsProductionProof,
}

impl MaskDistributionProofBoundary {
    const fn claims_production_proof(self) -> bool {
        matches!(self, Self::ClaimsProductionProof)
    }
}

/// Required field tracked by the mask-distribution closure framework.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaskDistributionClosureField {
    /// Selected construction identifier.
    SelectedConstructionId,
    /// Centralized distribution artifact digest.
    CentralizedDistributionArtifactDigest,
    /// Aggregate distribution artifact digest.
    AggregateDistributionArtifactDigest,
    /// Renyi proof artifact digest.
    RenyiProofDigest,
    /// Accepted `epsilon_mask` bound.
    AcceptedEpsilonMaskBound,
    /// Minimum aggregate-mask entropy threshold.
    MinEntropyThreshold,
    /// External review artifact digest.
    ExternalReviewDigest,
    /// External review signoff.
    ExternalReviewSignoff,
    /// Explicit non-production proof boundary.
    NonProductionProofBoundary,
}

/// Candidate package for assessing aggregate-mask distribution proof closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaskDistributionClosurePackage {
    selected_construction_id: Option<MaskDistributionConstructionId>,
    centralized_distribution_artifact_digest: Option<[u8; 32]>,
    aggregate_distribution_artifact_digest: Option<[u8; 32]>,
    renyi_proof_digest: Option<[u8; 32]>,
    accepted_epsilon_mask_bound: Option<EpsilonUnit>,
    min_entropy_threshold_bits: Option<u16>,
    external_review: Option<ExternalMaskDistributionReview>,
    proof_boundary: Option<MaskDistributionProofBoundary>,
}

impl MaskDistributionClosurePackage {
    /// Construct an empty candidate package.
    pub const fn empty() -> Self {
        Self {
            selected_construction_id: None,
            centralized_distribution_artifact_digest: None,
            aggregate_distribution_artifact_digest: None,
            renyi_proof_digest: None,
            accepted_epsilon_mask_bound: None,
            min_entropy_threshold_bits: None,
            external_review: None,
            proof_boundary: None,
        }
    }

    /// Build a candidate package from an accepted digest evidence certificate.
    pub fn from_accepted_certificate(
        selected_construction_id: MaskDistributionConstructionId,
        certificate: AcceptedMaskDistributionCertificate,
        external_review: ExternalMaskDistributionReview,
        proof_boundary: MaskDistributionProofBoundary,
    ) -> Self {
        Self {
            selected_construction_id: Some(selected_construction_id),
            centralized_distribution_artifact_digest: Some(
                *certificate.centralized_distribution_digest(),
            ),
            aggregate_distribution_artifact_digest: Some(
                *certificate.aggregate_distribution_digest(),
            ),
            renyi_proof_digest: Some(*certificate.renyi_proof_digest()),
            accepted_epsilon_mask_bound: Some(certificate.renyi_divergence()),
            min_entropy_threshold_bits: Some(certificate.required_min_entropy_bits()),
            external_review: Some(external_review),
            proof_boundary: Some(proof_boundary),
        }
    }

    /// Add the selected construction identifier.
    pub const fn with_selected_construction_id(
        mut self,
        selected_construction_id: MaskDistributionConstructionId,
    ) -> Self {
        self.selected_construction_id = Some(selected_construction_id);
        self
    }

    /// Add the centralized distribution artifact digest.
    pub const fn with_centralized_distribution_artifact_digest(mut self, digest: [u8; 32]) -> Self {
        self.centralized_distribution_artifact_digest = Some(digest);
        self
    }

    /// Add the aggregate distribution artifact digest.
    pub const fn with_aggregate_distribution_artifact_digest(mut self, digest: [u8; 32]) -> Self {
        self.aggregate_distribution_artifact_digest = Some(digest);
        self
    }

    /// Add the Renyi proof artifact digest.
    pub const fn with_renyi_proof_digest(mut self, digest: [u8; 32]) -> Self {
        self.renyi_proof_digest = Some(digest);
        self
    }

    /// Add the accepted `epsilon_mask` bound.
    pub const fn with_accepted_epsilon_mask_bound(mut self, bound: EpsilonUnit) -> Self {
        self.accepted_epsilon_mask_bound = Some(bound);
        self
    }

    /// Add the minimum aggregate-mask entropy threshold.
    pub const fn with_min_entropy_threshold_bits(mut self, threshold_bits: u16) -> Self {
        self.min_entropy_threshold_bits = Some(threshold_bits);
        self
    }

    /// Add external review evidence.
    pub const fn with_external_review(
        mut self,
        external_review: ExternalMaskDistributionReview,
    ) -> Self {
        self.external_review = Some(external_review);
        self
    }

    /// Add the proof claim boundary.
    pub const fn with_proof_boundary(
        mut self,
        proof_boundary: MaskDistributionProofBoundary,
    ) -> Self {
        self.proof_boundary = Some(proof_boundary);
        self
    }

    /// Assess whether the candidate package is closure-ready as a framework.
    pub fn closure_report(&self) -> MaskDistributionClosureReport {
        let mut missing_fields = Vec::new();
        let mut invalid_fields = Vec::new();

        match self.selected_construction_id {
            None => missing_fields.push(MaskDistributionClosureField::SelectedConstructionId),
            Some(construction_id) if construction_id.is_empty() => {
                invalid_fields.push(MaskDistributionClosureField::SelectedConstructionId)
            }
            Some(_) => {}
        }
        record_digest_field(
            self.centralized_distribution_artifact_digest,
            MaskDistributionClosureField::CentralizedDistributionArtifactDigest,
            &mut missing_fields,
            &mut invalid_fields,
        );
        record_digest_field(
            self.aggregate_distribution_artifact_digest,
            MaskDistributionClosureField::AggregateDistributionArtifactDigest,
            &mut missing_fields,
            &mut invalid_fields,
        );
        record_digest_field(
            self.renyi_proof_digest,
            MaskDistributionClosureField::RenyiProofDigest,
            &mut missing_fields,
            &mut invalid_fields,
        );

        if self.accepted_epsilon_mask_bound.is_none() {
            missing_fields.push(MaskDistributionClosureField::AcceptedEpsilonMaskBound);
        }
        match self.min_entropy_threshold_bits {
            None => missing_fields.push(MaskDistributionClosureField::MinEntropyThreshold),
            Some(0) => invalid_fields.push(MaskDistributionClosureField::MinEntropyThreshold),
            Some(_) => {}
        }
        match self.external_review {
            None => {
                missing_fields.push(MaskDistributionClosureField::ExternalReviewDigest);
                missing_fields.push(MaskDistributionClosureField::ExternalReviewSignoff);
            }
            Some(review) => {
                if is_all_zero(&review.review_digest) {
                    invalid_fields.push(MaskDistributionClosureField::ExternalReviewDigest);
                }
                if !review.signoff.is_accepted() {
                    invalid_fields.push(MaskDistributionClosureField::ExternalReviewSignoff);
                }
            }
        }
        match self.proof_boundary {
            None => missing_fields.push(MaskDistributionClosureField::NonProductionProofBoundary),
            Some(boundary) if boundary.claims_production_proof() => {
                invalid_fields.push(MaskDistributionClosureField::NonProductionProofBoundary)
            }
            Some(_) => {}
        }

        MaskDistributionClosureReport {
            selected_construction_id: self.selected_construction_id,
            accepted_epsilon_mask_bound: self.accepted_epsilon_mask_bound,
            min_entropy_threshold_bits: self.min_entropy_threshold_bits,
            proof_boundary: self.proof_boundary,
            missing_fields,
            invalid_fields,
        }
    }
}

/// Report returned by the mask-distribution closure framework.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaskDistributionClosureReport {
    selected_construction_id: Option<MaskDistributionConstructionId>,
    accepted_epsilon_mask_bound: Option<EpsilonUnit>,
    min_entropy_threshold_bits: Option<u16>,
    proof_boundary: Option<MaskDistributionProofBoundary>,
    missing_fields: Vec<MaskDistributionClosureField>,
    invalid_fields: Vec<MaskDistributionClosureField>,
}

impl MaskDistributionClosureReport {
    /// Return true when the framework has every required non-production closure input.
    pub fn is_closure_ready(&self) -> bool {
        self.missing_fields.is_empty()
            && self.invalid_fields.is_empty()
            && self.has_explicit_non_production_proof_boundary()
    }

    /// Borrow the missing required fields.
    pub fn missing_fields(&self) -> &[MaskDistributionClosureField] {
        &self.missing_fields
    }

    /// Borrow the invalid supplied fields.
    pub fn invalid_fields(&self) -> &[MaskDistributionClosureField] {
        &self.invalid_fields
    }

    /// Return the selected construction identifier when supplied.
    pub const fn selected_construction_id(&self) -> Option<MaskDistributionConstructionId> {
        self.selected_construction_id
    }

    /// Return the accepted `epsilon_mask` bound when supplied.
    pub const fn accepted_epsilon_mask_bound(&self) -> Option<EpsilonUnit> {
        self.accepted_epsilon_mask_bound
    }

    /// Return the minimum aggregate-mask entropy threshold when supplied.
    pub const fn min_entropy_threshold_bits(&self) -> Option<u16> {
        self.min_entropy_threshold_bits
    }

    /// Return true when the package explicitly disclaims production proof closure.
    pub fn has_explicit_non_production_proof_boundary(&self) -> bool {
        self.proof_boundary == Some(MaskDistributionProofBoundary::NonProductionProofFramework)
    }

    /// Return true when the package attempts to claim production proof closure.
    pub fn claims_production_proof(&self) -> bool {
        self.proof_boundary
            .map(MaskDistributionProofBoundary::claims_production_proof)
            .unwrap_or(false)
    }
}

/// Result of assessing aggregate-mask distribution evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaskDistributionAssessment {
    /// No evidence package was supplied.
    Missing {
        /// Static reason for the missing-evidence assessment.
        reason: &'static str,
    },
    /// Evidence was supplied but failed deterministic validation.
    Invalid {
        /// Static reason for the invalid-evidence assessment.
        reason: &'static str,
    },
    /// Evidence satisfied the configured deterministic gate.
    Accepted(AcceptedMaskDistributionCertificate),
}

impl MaskDistributionAssessment {
    /// Return true when the assessment accepted the evidence gate.
    pub const fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted(_))
    }

    /// Borrow the accepted certificate when present.
    pub const fn accepted_certificate(&self) -> Option<&AcceptedMaskDistributionCertificate> {
        match self {
            Self::Accepted(certificate) => Some(certificate),
            Self::Missing { .. } | Self::Invalid { .. } => None,
        }
    }
}

/// Assess digest-only aggregate-mask distribution evidence.
pub fn assess_mask_distribution(
    requirements: MaskDistributionRequirements,
    evidence: Option<MaskDistributionEvidence>,
) -> MaskDistributionAssessment {
    let Some(evidence) = evidence else {
        return MaskDistributionAssessment::Missing {
            reason: "missing aggregate mask distribution evidence",
        };
    };

    if is_all_zero(&evidence.centralized_distribution_digest) {
        return MaskDistributionAssessment::Invalid {
            reason: "centralized mask distribution digest is all zero",
        };
    }
    if is_all_zero(&evidence.aggregate_distribution_digest) {
        return MaskDistributionAssessment::Invalid {
            reason: "aggregate mask distribution digest is all zero",
        };
    }
    if is_all_zero(&evidence.renyi_proof_digest) {
        return MaskDistributionAssessment::Invalid {
            reason: "renyi proof digest is all zero",
        };
    }
    if evidence.support == MaskDistributionSupport::MatchesCentralizedMldsa
        && evidence.renyi_divergence != EpsilonUnit::ZERO
    {
        return MaskDistributionAssessment::Invalid {
            reason: "exact centralized mask match requires zero renyi divergence",
        };
    }
    if evidence.renyi_divergence > requirements.max_allowed_divergence {
        return MaskDistributionAssessment::Invalid {
            reason: "renyi divergence exceeds allowed mask residual",
        };
    }
    if evidence.min_entropy_bits < requirements.required_min_entropy_bits {
        return MaskDistributionAssessment::Invalid {
            reason: "aggregate mask min-entropy is below requirement",
        };
    }

    MaskDistributionAssessment::Accepted(AcceptedMaskDistributionCertificate {
        support: evidence.support,
        centralized_distribution_digest: evidence.centralized_distribution_digest,
        aggregate_distribution_digest: evidence.aggregate_distribution_digest,
        renyi_proof_digest: evidence.renyi_proof_digest,
        renyi_divergence: evidence.renyi_divergence,
        max_allowed_divergence: requirements.max_allowed_divergence,
        min_entropy_bits: evidence.min_entropy_bits,
        required_min_entropy_bits: requirements.required_min_entropy_bits,
    })
}

fn record_digest_field(
    digest: Option<[u8; 32]>,
    field: MaskDistributionClosureField,
    missing_fields: &mut Vec<MaskDistributionClosureField>,
    invalid_fields: &mut Vec<MaskDistributionClosureField>,
) {
    match digest {
        None => missing_fields.push(field),
        Some(digest) if is_all_zero(&digest) => invalid_fields.push(field),
        Some(_) => {}
    }
}

const fn is_all_zero(bytes: &[u8; 32]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}
