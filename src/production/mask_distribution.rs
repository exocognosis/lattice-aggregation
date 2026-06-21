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
