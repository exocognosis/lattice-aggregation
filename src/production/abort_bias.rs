//! Typed conformance checks for abort/retry bias evidence.
//!
//! These checks are audit scaffolding. They reject evidence packages that are
//! missing retry domain separation, expose unbounded abort leakage, or show a
//! visibly skewed accepted-sample bucket distribution. Passing this module does
//! not prove ML-DSA Fiat-Shamir-with-aborts preservation.

/// Evidence validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AbortBiasEvidenceError {
    /// A domain tag is empty or otherwise unusable.
    InvalidDomainTag {
        /// Static reason the domain tag was rejected.
        reason: &'static str,
    },
    /// Two logically distinct transcript purposes reuse the same domain tag.
    MissingDomainSeparation {
        /// First purpose involved in the domain-tag collision.
        first: DomainPurpose,
        /// Second purpose involved in the domain-tag collision.
        second: DomainPurpose,
    },
    /// An abort or retry leakage bound is not finite.
    UnboundedAbortLeakage {
        /// Leakage field missing a finite bound.
        field: LeakageBoundField,
    },
    /// The leakage model exposes an observable outside the public evidence set.
    DisallowedAbortLeakage {
        /// Observable rejected by the leakage model.
        observable: AbortObservable,
    },
    /// Accepted-sample evidence is malformed.
    InvalidAcceptedSampleEvidence {
        /// Static reason the accepted-sample evidence was rejected.
        reason: &'static str,
    },
    /// The accepted-sample set is too small for the stated check.
    InsufficientAcceptedSampleEvidence {
        /// Number of accepted samples present in the evidence package.
        accepted_samples: u64,
        /// Minimum accepted sample count required by the evidence package.
        minimum_required: u64,
    },
    /// Accepted samples are farther from the reference bucket distribution than
    /// the evidence package permits.
    BiasedAcceptedSampleEvidence {
        /// Measured total variation from the reference bucket distribution.
        total_variation_ppm: u32,
        /// Maximum allowed total variation for the evidence package.
        max_total_variation_ppm: u32,
    },
    /// A required proof-package digest is absent.
    MissingProofArtifact {
        /// Proof artifact whose digest was not supplied.
        artifact: AbortBiasProofArtifact,
    },
    /// A closure threshold is malformed.
    InvalidBoundThreshold {
        /// Threshold field rejected by the checker.
        field: AbortBiasBoundThresholdField,
        /// Static reason the threshold was rejected.
        reason: &'static str,
    },
    /// Valid conformance evidence exceeds a stated closure threshold.
    BoundThresholdExceeded {
        /// Threshold exceeded by the evidence package.
        field: AbortBiasBoundThresholdField,
        /// Measured value from validated evidence.
        measured: u64,
        /// Maximum or minimum threshold that was not met.
        threshold: u64,
    },
    /// An external review digest is absent.
    MissingExternalReviewDigest {
        /// Review artifact whose digest was not supplied.
        artifact: ExternalReviewArtifact,
    },
    /// The external review is present but not signed off.
    ExternalReviewNotSignedOff,
}

/// Transcript or evidence purpose assigned to a domain tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainPurpose {
    /// Fiat-Shamir challenge derivation domain.
    Challenge,
    /// Retry or attempt-counter binding domain.
    Retry,
    /// Accepted-sample audit bucket domain.
    AcceptedSample,
}

/// Bounded leakage field that must be present in the evidence model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeakageBoundField {
    /// Maximum retry count for one signing request.
    RetryCount,
    /// Maximum number of public abort observations for one signing request.
    AbortObservationCount,
}

/// Required proof-package artifact digests for abort/retry-bias closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbortBiasProofArtifact {
    /// Formal leakage model proof package.
    FormalLeakageModel,
    /// Retry-domain separation proof package.
    RetryDomainSeparationProof,
    /// Accepted-signature distribution proof package.
    AcceptedSignatureDistributionProof,
    /// Corpus of adversarial abort policies covered by the proof package.
    AdversarialAbortPolicyCorpus,
    /// Sample-size and bucket-construction rationale.
    SampleSizeBucketRationale,
}

/// Closure threshold fields enforced against validated evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbortBiasBoundThresholdField {
    /// Maximum retry count allowed by the closure package.
    MaxRetryCount,
    /// Maximum public abort observations allowed by the closure package.
    MaxAbortObservations,
    /// Minimum accepted samples required by the closure package.
    MinimumAcceptedSamples,
    /// Maximum accepted-sample total variation allowed by the closure package.
    MaxAcceptedSampleTotalVariationPpm,
}

/// Required external review artifacts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalReviewArtifact {
    /// Digest of the external review report.
    ReviewReport,
    /// Digest of the reviewer signoff statement.
    ReviewerSignoff,
}

/// Domain tag used by one transcript or evidence purpose.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainTag(String);

impl DomainTag {
    /// Construct a non-empty domain tag.
    pub fn new(label: impl Into<String>) -> Result<Self, AbortBiasEvidenceError> {
        let label = label.into();
        if label.is_empty() {
            return Err(AbortBiasEvidenceError::InvalidDomainTag {
                reason: "domain tag is empty",
            });
        }
        Ok(Self(label))
    }
}

/// Evidence that challenge, retry, and accepted-sample domains are distinct.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainSeparationEvidence {
    challenge: DomainTag,
    retry: DomainTag,
    accepted_sample: DomainTag,
}

impl DomainSeparationEvidence {
    /// Construct domain-separation evidence.
    pub const fn new(challenge: DomainTag, retry: DomainTag, accepted_sample: DomainTag) -> Self {
        Self {
            challenge,
            retry,
            accepted_sample,
        }
    }

    fn validate(&self) -> Result<(), AbortBiasEvidenceError> {
        if self.challenge == self.retry {
            return Err(AbortBiasEvidenceError::MissingDomainSeparation {
                first: DomainPurpose::Challenge,
                second: DomainPurpose::Retry,
            });
        }
        if self.challenge == self.accepted_sample {
            return Err(AbortBiasEvidenceError::MissingDomainSeparation {
                first: DomainPurpose::Challenge,
                second: DomainPurpose::AcceptedSample,
            });
        }
        if self.retry == self.accepted_sample {
            return Err(AbortBiasEvidenceError::MissingDomainSeparation {
                first: DomainPurpose::Retry,
                second: DomainPurpose::AcceptedSample,
            });
        }
        Ok(())
    }
}

/// Observable abort/retry facts allowed or rejected by the leakage model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbortObservable {
    /// One public aggregate accept/abort bit per attempt.
    AggregateAbortBit,
    /// The public retry counter bound into the transcript.
    RetryCounter,
    /// A reason code whose value depends on secret or partial-response data.
    SecretDependentAbortReason,
}

impl AbortObservable {
    const fn is_public(self) -> bool {
        matches!(self, Self::AggregateAbortBit | Self::RetryCounter)
    }
}

/// Bounded model for abort and retry observables exposed to an adversary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbortLeakageModel {
    max_retry_count: Option<u32>,
    max_abort_observations: Option<u32>,
    observables: Vec<AbortObservable>,
}

impl AbortLeakageModel {
    /// Construct an abort leakage model.
    pub fn new(
        max_retry_count: Option<u32>,
        max_abort_observations: Option<u32>,
        observables: Vec<AbortObservable>,
    ) -> Self {
        Self {
            max_retry_count,
            max_abort_observations,
            observables,
        }
    }

    fn validate(&self) -> Result<(), AbortBiasEvidenceError> {
        if self.max_retry_count.is_none() {
            return Err(AbortBiasEvidenceError::UnboundedAbortLeakage {
                field: LeakageBoundField::RetryCount,
            });
        }
        if self.max_abort_observations.is_none() {
            return Err(AbortBiasEvidenceError::UnboundedAbortLeakage {
                field: LeakageBoundField::AbortObservationCount,
            });
        }
        for observable in &self.observables {
            if !observable.is_public() {
                return Err(AbortBiasEvidenceError::DisallowedAbortLeakage {
                    observable: *observable,
                });
            }
        }
        Ok(())
    }
}

/// Accepted-sample audit evidence grouped into deterministic public buckets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedSampleEvidence {
    bucket_counts: Vec<u64>,
    minimum_accepted_samples: u64,
    max_total_variation_ppm: u32,
}

impl AcceptedSampleEvidence {
    /// Construct accepted-sample evidence.
    pub fn new(
        bucket_counts: Vec<u64>,
        minimum_accepted_samples: u64,
        max_total_variation_ppm: u32,
    ) -> Self {
        Self {
            bucket_counts,
            minimum_accepted_samples,
            max_total_variation_ppm,
        }
    }

    fn validate(&self) -> Result<(u64, u32), AbortBiasEvidenceError> {
        if self.bucket_counts.len() < 2 {
            return Err(AbortBiasEvidenceError::InvalidAcceptedSampleEvidence {
                reason: "at least two accepted-sample buckets are required",
            });
        }
        if self.max_total_variation_ppm > 1_000_000 {
            return Err(AbortBiasEvidenceError::InvalidAcceptedSampleEvidence {
                reason: "total variation bound exceeds 1_000_000 ppm",
            });
        }

        let accepted_samples = self
            .bucket_counts
            .iter()
            .try_fold(0u64, |acc, count| acc.checked_add(*count))
            .ok_or(AbortBiasEvidenceError::InvalidAcceptedSampleEvidence {
                reason: "accepted sample count overflow",
            })?;

        if accepted_samples < self.minimum_accepted_samples {
            return Err(AbortBiasEvidenceError::InsufficientAcceptedSampleEvidence {
                accepted_samples,
                minimum_required: self.minimum_accepted_samples,
            });
        }
        if accepted_samples == 0 {
            return Err(AbortBiasEvidenceError::InsufficientAcceptedSampleEvidence {
                accepted_samples,
                minimum_required: 1,
            });
        }

        let total_variation_ppm = self.total_variation_ppm(accepted_samples);
        if total_variation_ppm > self.max_total_variation_ppm {
            return Err(AbortBiasEvidenceError::BiasedAcceptedSampleEvidence {
                total_variation_ppm,
                max_total_variation_ppm: self.max_total_variation_ppm,
            });
        }

        Ok((accepted_samples, total_variation_ppm))
    }

    fn total_variation_ppm(&self, accepted_samples: u64) -> u32 {
        let bucket_count = self.bucket_counts.len() as u128;
        let accepted_samples = u128::from(accepted_samples);
        let deviation_sum = self
            .bucket_counts
            .iter()
            .map(|count| (u128::from(*count) * bucket_count).abs_diff(accepted_samples))
            .sum::<u128>();
        let denominator = 2 * accepted_samples * bucket_count;
        ((deviation_sum * 1_000_000) / denominator) as u32
    }
}

/// Required digest handles for the complete abort/retry-bias proof package.
///
/// These digests identify externally reviewed artifacts; this type does not
/// parse or prove the referenced documents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbortBiasProofDigests {
    formal_leakage_model: [u8; 32],
    retry_domain_separation_proof: [u8; 32],
    accepted_signature_distribution_proof: [u8; 32],
    adversarial_abort_policy_corpus: [u8; 32],
    sample_size_bucket_rationale: [u8; 32],
}

impl AbortBiasProofDigests {
    /// Construct proof artifact digests for an abort/retry-bias closure package.
    pub const fn new(
        formal_leakage_model: [u8; 32],
        retry_domain_separation_proof: [u8; 32],
        accepted_signature_distribution_proof: [u8; 32],
        adversarial_abort_policy_corpus: [u8; 32],
        sample_size_bucket_rationale: [u8; 32],
    ) -> Self {
        Self {
            formal_leakage_model,
            retry_domain_separation_proof,
            accepted_signature_distribution_proof,
            adversarial_abort_policy_corpus,
            sample_size_bucket_rationale,
        }
    }

    /// Borrow the formal leakage model digest.
    pub const fn formal_leakage_model_digest(&self) -> &[u8; 32] {
        &self.formal_leakage_model
    }

    /// Borrow the retry-domain separation proof digest.
    pub const fn retry_domain_separation_proof_digest(&self) -> &[u8; 32] {
        &self.retry_domain_separation_proof
    }

    /// Borrow the accepted-signature distribution proof digest.
    pub const fn accepted_signature_distribution_proof_digest(&self) -> &[u8; 32] {
        &self.accepted_signature_distribution_proof
    }

    /// Borrow the adversarial abort policy corpus digest.
    pub const fn adversarial_abort_policy_corpus_digest(&self) -> &[u8; 32] {
        &self.adversarial_abort_policy_corpus
    }

    /// Borrow the sample-size and bucket-rationale digest.
    pub const fn sample_size_bucket_rationale_digest(&self) -> &[u8; 32] {
        &self.sample_size_bucket_rationale
    }

    fn validate(&self) -> Result<(), AbortBiasEvidenceError> {
        for (artifact, digest) in [
            (
                AbortBiasProofArtifact::FormalLeakageModel,
                &self.formal_leakage_model,
            ),
            (
                AbortBiasProofArtifact::RetryDomainSeparationProof,
                &self.retry_domain_separation_proof,
            ),
            (
                AbortBiasProofArtifact::AcceptedSignatureDistributionProof,
                &self.accepted_signature_distribution_proof,
            ),
            (
                AbortBiasProofArtifact::AdversarialAbortPolicyCorpus,
                &self.adversarial_abort_policy_corpus,
            ),
            (
                AbortBiasProofArtifact::SampleSizeBucketRationale,
                &self.sample_size_bucket_rationale,
            ),
        ] {
            if is_all_zero_digest(digest) {
                return Err(AbortBiasEvidenceError::MissingProofArtifact { artifact });
            }
        }
        Ok(())
    }
}

/// Closure thresholds that must bound validated abort/retry-bias evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbortBiasBoundThresholds {
    max_retry_count: u32,
    max_abort_observations: u32,
    minimum_accepted_samples: u64,
    max_accepted_sample_total_variation_ppm: u32,
}

impl AbortBiasBoundThresholds {
    /// Construct threshold bounds for a closure package.
    pub const fn new(
        max_retry_count: u32,
        max_abort_observations: u32,
        minimum_accepted_samples: u64,
        max_accepted_sample_total_variation_ppm: u32,
    ) -> Self {
        Self {
            max_retry_count,
            max_abort_observations,
            minimum_accepted_samples,
            max_accepted_sample_total_variation_ppm,
        }
    }

    /// Maximum retry count permitted by the closure package.
    pub const fn max_retry_count(&self) -> u32 {
        self.max_retry_count
    }

    /// Maximum public abort observations permitted by the closure package.
    pub const fn max_abort_observations(&self) -> u32 {
        self.max_abort_observations
    }

    /// Minimum accepted-sample count required by the closure package.
    pub const fn minimum_accepted_samples(&self) -> u64 {
        self.minimum_accepted_samples
    }

    /// Maximum accepted-sample total variation in parts per million.
    pub const fn max_accepted_sample_total_variation_ppm(&self) -> u32 {
        self.max_accepted_sample_total_variation_ppm
    }

    fn validate(&self) -> Result<(), AbortBiasEvidenceError> {
        if self.minimum_accepted_samples == 0 {
            return Err(AbortBiasEvidenceError::InvalidBoundThreshold {
                field: AbortBiasBoundThresholdField::MinimumAcceptedSamples,
                reason: "minimum accepted samples must be nonzero",
            });
        }
        if self.max_accepted_sample_total_variation_ppm > 1_000_000 {
            return Err(AbortBiasEvidenceError::InvalidBoundThreshold {
                field: AbortBiasBoundThresholdField::MaxAcceptedSampleTotalVariationPpm,
                reason: "total variation threshold exceeds 1_000_000 ppm",
            });
        }
        Ok(())
    }

    fn enforce(self, report: &RetryBiasEvidenceReport) -> Result<(), AbortBiasEvidenceError> {
        if report.max_retry_count() > self.max_retry_count {
            return Err(AbortBiasEvidenceError::BoundThresholdExceeded {
                field: AbortBiasBoundThresholdField::MaxRetryCount,
                measured: u64::from(report.max_retry_count()),
                threshold: u64::from(self.max_retry_count),
            });
        }
        if report.max_abort_observations() > self.max_abort_observations {
            return Err(AbortBiasEvidenceError::BoundThresholdExceeded {
                field: AbortBiasBoundThresholdField::MaxAbortObservations,
                measured: u64::from(report.max_abort_observations()),
                threshold: u64::from(self.max_abort_observations),
            });
        }
        if report.accepted_samples() < self.minimum_accepted_samples {
            return Err(AbortBiasEvidenceError::BoundThresholdExceeded {
                field: AbortBiasBoundThresholdField::MinimumAcceptedSamples,
                measured: report.accepted_samples(),
                threshold: self.minimum_accepted_samples,
            });
        }
        if report.accepted_sample_total_variation_ppm()
            > self.max_accepted_sample_total_variation_ppm
        {
            return Err(AbortBiasEvidenceError::BoundThresholdExceeded {
                field: AbortBiasBoundThresholdField::MaxAcceptedSampleTotalVariationPpm,
                measured: u64::from(report.accepted_sample_total_variation_ppm()),
                threshold: u64::from(self.max_accepted_sample_total_variation_ppm),
            });
        }
        Ok(())
    }
}

/// Digest-backed external review report and reviewer signoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalReviewSignoff {
    review_digest: [u8; 32],
    reviewer_signoff_digest: [u8; 32],
    signed_off: bool,
}

impl ExternalReviewSignoff {
    /// Construct an external review signoff record.
    pub const fn new(
        review_digest: [u8; 32],
        reviewer_signoff_digest: [u8; 32],
        signed_off: bool,
    ) -> Self {
        Self {
            review_digest,
            reviewer_signoff_digest,
            signed_off,
        }
    }

    /// Borrow the external review report digest.
    pub const fn review_digest(&self) -> &[u8; 32] {
        &self.review_digest
    }

    /// Borrow the reviewer signoff digest.
    pub const fn reviewer_signoff_digest(&self) -> &[u8; 32] {
        &self.reviewer_signoff_digest
    }

    /// Whether the external reviewer signed off the package.
    pub const fn is_signed_off(&self) -> bool {
        self.signed_off
    }

    fn validate(&self) -> Result<(), AbortBiasEvidenceError> {
        if is_all_zero_digest(&self.review_digest) {
            return Err(AbortBiasEvidenceError::MissingExternalReviewDigest {
                artifact: ExternalReviewArtifact::ReviewReport,
            });
        }
        if is_all_zero_digest(&self.reviewer_signoff_digest) {
            return Err(AbortBiasEvidenceError::MissingExternalReviewDigest {
                artifact: ExternalReviewArtifact::ReviewerSignoff,
            });
        }
        if !self.signed_off {
            return Err(AbortBiasEvidenceError::ExternalReviewNotSignedOff);
        }
        Ok(())
    }
}

/// Complete abort/retry-bias evidence package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbortBiasEvidence {
    domains: DomainSeparationEvidence,
    leakage_model: AbortLeakageModel,
    accepted_samples: AcceptedSampleEvidence,
}

impl AbortBiasEvidence {
    /// Construct an evidence package.
    pub const fn new(
        domains: DomainSeparationEvidence,
        leakage_model: AbortLeakageModel,
        accepted_samples: AcceptedSampleEvidence,
    ) -> Self {
        Self {
            domains,
            leakage_model,
            accepted_samples,
        }
    }

    /// Validate the evidence package and return the deterministic check report.
    pub fn validate(&self) -> Result<RetryBiasEvidenceReport, AbortBiasEvidenceError> {
        self.domains.validate()?;
        self.leakage_model.validate()?;
        let (accepted_samples, accepted_sample_total_variation_ppm) =
            self.accepted_samples.validate()?;

        Ok(RetryBiasEvidenceReport {
            accepted_samples,
            accepted_sample_total_variation_ppm,
            max_retry_count: self.leakage_model.max_retry_count.unwrap_or(0),
            max_abort_observations: self.leakage_model.max_abort_observations.unwrap_or(0),
        })
    }
}

/// Closure status returned by a validated abort/retry-bias proof package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbortBiasClosureStatus {
    /// Conformance evidence is present, but proof closure has not been checked.
    EvidenceOnly,
    /// All typed closure-package fields are present and bounded.
    ClosureReady,
}

/// Complete closure package for abort/retry-bias blocker evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbortRetryBiasProofPackage {
    evidence: AbortBiasEvidence,
    proof_digests: AbortBiasProofDigests,
    thresholds: AbortBiasBoundThresholds,
    external_review: ExternalReviewSignoff,
}

impl AbortRetryBiasProofPackage {
    /// Construct a closure package from conformance evidence and proof handles.
    pub const fn new(
        evidence: AbortBiasEvidence,
        proof_digests: AbortBiasProofDigests,
        thresholds: AbortBiasBoundThresholds,
        external_review: ExternalReviewSignoff,
    ) -> Self {
        Self {
            evidence,
            proof_digests,
            thresholds,
            external_review,
        }
    }

    /// Validate the package and return closure-ready typed status.
    pub fn validate_closure_ready(&self) -> Result<AbortBiasClosureReport, AbortBiasEvidenceError> {
        let evidence_report = self.evidence.validate()?;
        self.proof_digests.validate()?;
        self.thresholds.validate()?;
        self.thresholds.enforce(&evidence_report)?;
        self.external_review.validate()?;

        Ok(AbortBiasClosureReport {
            status: AbortBiasClosureStatus::ClosureReady,
            evidence_report,
            proof_digests: self.proof_digests,
            thresholds: self.thresholds,
            external_review: self.external_review,
        })
    }
}

/// Deterministic summary returned by a validated evidence package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryBiasEvidenceReport {
    accepted_samples: u64,
    accepted_sample_total_variation_ppm: u32,
    max_retry_count: u32,
    max_abort_observations: u32,
}

impl RetryBiasEvidenceReport {
    /// Number of accepted samples checked.
    pub const fn accepted_samples(self) -> u64 {
        self.accepted_samples
    }

    /// Total variation distance from the reference bucket distribution in ppm.
    pub const fn accepted_sample_total_variation_ppm(self) -> u32 {
        self.accepted_sample_total_variation_ppm
    }

    /// Maximum retry count allowed by the leakage model.
    pub const fn max_retry_count(self) -> u32 {
        self.max_retry_count
    }

    /// Maximum public abort observations allowed by the leakage model.
    pub const fn max_abort_observations(self) -> u32 {
        self.max_abort_observations
    }

    /// Conformance-only reports are not proof-closure packages.
    pub const fn status(self) -> AbortBiasClosureStatus {
        AbortBiasClosureStatus::EvidenceOnly
    }
}

/// Deterministic summary returned by a validated closure package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbortBiasClosureReport {
    status: AbortBiasClosureStatus,
    evidence_report: RetryBiasEvidenceReport,
    proof_digests: AbortBiasProofDigests,
    thresholds: AbortBiasBoundThresholds,
    external_review: ExternalReviewSignoff,
}

impl AbortBiasClosureReport {
    /// Closure status for the checked package.
    pub const fn status(&self) -> AbortBiasClosureStatus {
        self.status
    }

    /// Validated conformance evidence summary.
    pub const fn evidence_report(&self) -> RetryBiasEvidenceReport {
        self.evidence_report
    }

    /// Borrow the formal leakage model digest.
    pub const fn formal_leakage_model_digest(&self) -> &[u8; 32] {
        self.proof_digests.formal_leakage_model_digest()
    }

    /// Borrow the retry-domain separation proof digest.
    pub const fn retry_domain_separation_proof_digest(&self) -> &[u8; 32] {
        self.proof_digests.retry_domain_separation_proof_digest()
    }

    /// Borrow the accepted-signature distribution proof digest.
    pub const fn accepted_signature_distribution_proof_digest(&self) -> &[u8; 32] {
        self.proof_digests
            .accepted_signature_distribution_proof_digest()
    }

    /// Borrow the adversarial abort policy corpus digest.
    pub const fn adversarial_abort_policy_corpus_digest(&self) -> &[u8; 32] {
        self.proof_digests.adversarial_abort_policy_corpus_digest()
    }

    /// Borrow the sample-size and bucket-rationale digest.
    pub const fn sample_size_bucket_rationale_digest(&self) -> &[u8; 32] {
        self.proof_digests.sample_size_bucket_rationale_digest()
    }

    /// Borrow the closure thresholds enforced by the package.
    pub const fn bound_thresholds(&self) -> &AbortBiasBoundThresholds {
        &self.thresholds
    }

    /// Borrow the external review signoff.
    pub const fn external_review(&self) -> &ExternalReviewSignoff {
        &self.external_review
    }
}

fn is_all_zero_digest(digest: &[u8; 32]) -> bool {
    digest.iter().all(|byte| *byte == 0)
}
