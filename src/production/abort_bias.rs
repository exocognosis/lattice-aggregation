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
}
