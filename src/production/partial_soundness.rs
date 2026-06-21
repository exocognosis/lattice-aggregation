//! Typed partial-contribution soundness evidence checks.
//!
//! This module is conformance scaffolding. It checks that public evidence for an
//! accepted partial contribution is bound to the accepted-partial token,
//! transcript context, local proof label, and leakage budget. It does not verify
//! a production ML-DSA proof system by itself.

use sha3::{Digest, Sha3_256};

use crate::{
    production::{
        acceptance::AcceptedPartialContribution,
        epsilon::{EpsilonLedger, EpsilonUnit},
        transcript::{CommitmentDigest, ProductionSigningTranscript},
        types::{
            ActiveSignerSet, AttemptId, DkgTranscriptDigest, EpochId, KeyId, MessageBinding,
            ValidatorSetDigest,
        },
    },
    ThresholdError, ValidatorId,
};

/// Evidence class carried by a partial-contribution soundness token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceClass {
    /// Digest-only scaffold evidence; useful for conformance wiring, not a real proof.
    ScaffoldDigestOnly,
    /// Evidence produced by a reviewed local proof verifier boundary.
    ProofBacked,
}

/// Requirement selected by the caller for a partial soundness check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PartialEvidenceRequirement {
    /// Accept either scaffold digest-only evidence or proof-backed evidence.
    ScaffoldDigestOrProofBacked,
    /// Require proof-backed evidence and reject digest-only scaffolding.
    ProofBackedOnly,
}

/// Closure status exposed by a verified partial-soundness evidence token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PartialSoundnessClosureStatus {
    /// Evidence passed conformance checks, but no complete closure package was checked.
    ConformanceOnly,
    /// Evidence passed the full closure-package framework checks.
    ClosureReady,
}

/// Proof-evidence requirement declared by a partial-soundness closure package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClosureProofRequirement {
    /// Invalid for closure: included so digest-only evidence is rejected explicitly.
    DigestOnlyEvidenceAllowed,
    /// Closure requires proof-backed local verifier evidence.
    ProofBackedLocalVerifierRequired,
}

/// Leakage model label for the checked epsilon budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeakageModel {
    /// Only public digest-shaped scaffold evidence is being accounted.
    PublicDigestOnly,
    /// The caller supplied fixed-point Renyi-style bounds for observable leakage.
    RenyiBounded,
}

/// Per-component epsilon ceilings for accepted partial evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeakageLimits {
    epsilon_mask: EpsilonUnit,
    epsilon_rej: EpsilonUnit,
    epsilon_withhold: EpsilonUnit,
}

impl LeakageLimits {
    /// Construct per-component leakage ceilings.
    pub const fn new(
        epsilon_mask: EpsilonUnit,
        epsilon_rej: EpsilonUnit,
        epsilon_withhold: EpsilonUnit,
    ) -> Self {
        Self {
            epsilon_mask,
            epsilon_rej,
            epsilon_withhold,
        }
    }

    /// Return the masking leakage ceiling.
    pub const fn epsilon_mask(self) -> EpsilonUnit {
        self.epsilon_mask
    }

    /// Return the rejection leakage ceiling.
    pub const fn epsilon_rej(self) -> EpsilonUnit {
        self.epsilon_rej
    }

    /// Return the withholding leakage ceiling.
    pub const fn epsilon_withhold(self) -> EpsilonUnit {
        self.epsilon_withhold
    }
}

/// Observed epsilon ledger and selected leakage model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeakageBudget {
    model: LeakageModel,
    observed: EpsilonLedger,
    limits: LeakageLimits,
}

impl LeakageBudget {
    /// Construct a leakage-budget check input.
    pub const fn new(model: LeakageModel, observed: EpsilonLedger, limits: LeakageLimits) -> Self {
        Self {
            model,
            observed,
            limits,
        }
    }

    /// Return the selected leakage model.
    pub const fn model(self) -> LeakageModel {
        self.model
    }

    /// Return the observed epsilon ledger.
    pub const fn observed(self) -> EpsilonLedger {
        self.observed
    }

    /// Return the configured leakage limits.
    pub const fn limits(self) -> LeakageLimits {
        self.limits
    }

    fn verify(self) -> Result<(), ThresholdError> {
        if self.observed.epsilon_mask() > self.limits.epsilon_mask()
            || self.observed.epsilon_rej() > self.limits.epsilon_rej()
            || self.observed.epsilon_withhold() > self.limits.epsilon_withhold()
        {
            return Err(ThresholdError::ProductionPolicyBlocked {
                reason: "partial leakage budget exceeded",
            });
        }

        Ok(())
    }
}

/// Public verifier binding claimed for an accepted partial contribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PartialVerifierBinding {
    /// Validator whose accepted partial is being checked.
    pub signer: ValidatorId,
    /// Commitment digest bound to the partial verifier statement.
    pub commitment_digest: CommitmentDigest,
    /// Challenge digest carried by the accepted partial token.
    pub challenge_digest: [u8; 32],
    /// Partial-share digest carried by the accepted partial token.
    pub partial_share_digest: [u8; 32],
    /// Local proof digest carried by the accepted partial token.
    pub local_bounds_proof_digest: [u8; 32],
    /// Digest of the local verifier statement, not the raw statement.
    pub verifier_statement_digest: [u8; 32],
    /// Challenge digest used by the local verifier statement.
    pub transcript_challenge_digest: [u8; 32],
}

impl PartialVerifierBinding {
    /// Construct a partial-verifier binding claim.
    pub const fn new(
        signer: ValidatorId,
        commitment_digest: CommitmentDigest,
        challenge_digest: [u8; 32],
        partial_share_digest: [u8; 32],
        local_bounds_proof_digest: [u8; 32],
        verifier_statement_digest: [u8; 32],
        transcript_challenge_digest: [u8; 32],
    ) -> Self {
        Self {
            signer,
            commitment_digest,
            challenge_digest,
            partial_share_digest,
            local_bounds_proof_digest,
            verifier_statement_digest,
            transcript_challenge_digest,
        }
    }

    fn verify(
        self,
        transcript: &ProductionSigningTranscript,
        partial: &AcceptedPartialContribution,
    ) -> Result<(), ThresholdError> {
        let signer = partial.signer();
        if self.signer != signer {
            return Err(ThresholdError::PartialShareVerificationFailed { validator: signer });
        }

        if self.partial_share_digest != *partial.partial_share_digest() {
            return Err(ThresholdError::PartialShareVerificationFailed { validator: signer });
        }

        if self.local_bounds_proof_digest != *partial.local_bounds_proof_digest() {
            return Err(ThresholdError::RejectionSamplingFailed { validator: signer });
        }

        if self.commitment_digest != partial.commitment_digest() {
            return Err(ThresholdError::CommitmentVerificationFailed { validator: signer });
        }

        if self.challenge_digest != *partial.challenge_digest()
            || self.transcript_challenge_digest != *transcript.challenge_digest()
            || partial.challenge_digest() != transcript.challenge_digest()
        {
            return Err(ThresholdError::TranscriptMismatch);
        }

        let expected_commitment = transcript
            .input()
            .commitment_digests
            .iter()
            .find(|(validator, _)| *validator == signer)
            .map(|(_, digest)| *digest)
            .ok_or(ThresholdError::CommitmentVerificationFailed { validator: signer })?;

        if expected_commitment != self.commitment_digest {
            return Err(ThresholdError::CommitmentVerificationFailed { validator: signer });
        }

        if is_all_zero(&self.verifier_statement_digest) {
            return Err(ThresholdError::MalformedSerialization {
                reason: "partial verifier statement digest is all zero",
            });
        }

        Ok(())
    }
}

/// Transcript-context binding for one accepted partial contribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialContextBinding {
    session_id: [u8; 32],
    epoch: EpochId,
    key_id: KeyId,
    validator_set_digest: ValidatorSetDigest,
    dkg_transcript_digest: DkgTranscriptDigest,
    active_signers: ActiveSignerSet,
    threshold: u16,
    public_key_digest: [u8; 32],
    application_message_digest: [u8; 32],
    message_binding: MessageBinding,
    attempt_id: AttemptId,
    coordinator_attestation_digest: [u8; 32],
    retry_counter: u32,
    challenge_digest: [u8; 32],
}

impl PartialContextBinding {
    /// Construct a context binding from the transcript's public context.
    pub fn from_transcript(transcript: &ProductionSigningTranscript) -> Self {
        let input = transcript.input();
        Self {
            session_id: input.session_id,
            epoch: input.epoch,
            key_id: input.key_id,
            validator_set_digest: input.validator_set_digest,
            dkg_transcript_digest: input.dkg_transcript_digest,
            active_signers: input.active_signers.clone(),
            threshold: input.threshold,
            public_key_digest: digest_bytes(&input.public_key.0),
            application_message_digest: digest_bytes(&input.application_message),
            message_binding: input.message_binding,
            attempt_id: input.attempt_id,
            coordinator_attestation_digest: input.coordinator_attestation_digest,
            retry_counter: input.retry_counter,
            challenge_digest: *transcript.challenge_digest(),
        }
    }

    fn verify(&self, transcript: &ProductionSigningTranscript) -> Result<(), ThresholdError> {
        let input = transcript.input();
        if self.session_id != input.session_id
            || self.epoch != input.epoch
            || self.key_id != input.key_id
            || self.validator_set_digest != input.validator_set_digest
            || self.dkg_transcript_digest != input.dkg_transcript_digest
            || self.active_signers != input.active_signers
            || self.threshold != input.threshold
            || self.public_key_digest != digest_bytes(&input.public_key.0)
            || self.application_message_digest != digest_bytes(&input.application_message)
            || self.message_binding != input.message_binding
            || self.attempt_id != input.attempt_id
            || self.coordinator_attestation_digest != input.coordinator_attestation_digest
            || self.retry_counter != input.retry_counter
            || self.challenge_digest != *transcript.challenge_digest()
        {
            return Err(ThresholdError::TranscriptMismatch);
        }

        Ok(())
    }

    /// Return a digest that binds the closure package to this transcript context.
    pub fn closure_digest(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"lattice-aggregation/partial-soundness/context-binding/v1");
        hasher.update(&self.session_id);
        hasher.update(self.epoch.to_be_bytes());
        hasher.update(self.key_id.as_bytes());
        hasher.update(self.validator_set_digest.as_bytes());
        hasher.update(self.dkg_transcript_digest.as_bytes());
        hasher.update((self.active_signers.len() as u64).to_be_bytes());
        for validator in self.active_signers.as_slice() {
            hasher.update(validator.0.to_be_bytes());
        }
        hasher.update(self.threshold.to_be_bytes());
        hasher.update(&self.public_key_digest);
        hasher.update(&self.application_message_digest);
        hasher.update(self.message_binding.as_bytes());
        hasher.update(self.attempt_id.as_bytes());
        hasher.update(&self.coordinator_attestation_digest);
        hasher.update(self.retry_counter.to_be_bytes());
        hasher.update(&self.challenge_digest);
        hasher.finalize().into()
    }
}

/// Soundness label for local proof evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalProofSoundnessLabel {
    /// Digest-only scaffold evidence carries no proof-backed soundness claim.
    ScaffoldDigestOnly,
    /// Reviewed proof-backed verifier evidence and its theorem digest.
    ProofBacked {
        /// Local proof system label.
        proof_system: &'static str,
        /// Digest of the reviewed verifier key or verifier circuit.
        verifier_key_digest: [u8; 32],
        /// Digest of the reviewed soundness theorem or proof package.
        soundness_theorem_digest: [u8; 32],
    },
}

/// Evidence emitted by a reviewed local proof verifier boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofBackedLocalVerifier {
    proof_system: &'static str,
    verifier_key_digest: [u8; 32],
    soundness_theorem_digest: [u8; 32],
    proof_digest: [u8; 32],
    verifier_transcript_digest: [u8; 32],
}

impl ProofBackedLocalVerifier {
    /// Construct proof-backed local verifier evidence.
    pub fn new(
        proof_system: &'static str,
        verifier_key_digest: [u8; 32],
        soundness_theorem_digest: [u8; 32],
        proof_digest: [u8; 32],
        verifier_transcript_digest: [u8; 32],
    ) -> Result<Self, ThresholdError> {
        if proof_system.trim().is_empty() {
            return Err(ThresholdError::ProductionPolicyBlocked {
                reason: "partial proof system label is empty",
            });
        }

        if is_all_zero(&verifier_key_digest)
            || is_all_zero(&soundness_theorem_digest)
            || is_all_zero(&proof_digest)
            || is_all_zero(&verifier_transcript_digest)
        {
            return Err(ThresholdError::MalformedSerialization {
                reason: "proof-backed partial evidence digest is all zero",
            });
        }

        Ok(Self {
            proof_system,
            verifier_key_digest,
            soundness_theorem_digest,
            proof_digest,
            verifier_transcript_digest,
        })
    }

    /// Return the proof-backed soundness label.
    pub const fn soundness_label(self) -> LocalProofSoundnessLabel {
        LocalProofSoundnessLabel::ProofBacked {
            proof_system: self.proof_system,
            verifier_key_digest: self.verifier_key_digest,
            soundness_theorem_digest: self.soundness_theorem_digest,
        }
    }

    /// Borrow the proof digest checked against the accepted partial.
    pub const fn proof_digest(&self) -> &[u8; 32] {
        &self.proof_digest
    }

    /// Borrow the verifier transcript digest.
    pub const fn verifier_transcript_digest(&self) -> &[u8; 32] {
        &self.verifier_transcript_digest
    }
}

/// Local proof evidence class for an accepted partial.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalProofEvidence {
    /// Digest-only local proof scaffold.
    ScaffoldDigestOnly {
        /// Digest of the local proof placeholder.
        local_bounds_proof_digest: [u8; 32],
    },
    /// Proof-backed local verifier evidence.
    ProofBacked(ProofBackedLocalVerifier),
}

impl LocalProofEvidence {
    /// Construct digest-only scaffold evidence.
    pub const fn scaffold_digest_only(local_bounds_proof_digest: [u8; 32]) -> Self {
        Self::ScaffoldDigestOnly {
            local_bounds_proof_digest,
        }
    }

    /// Construct proof-backed local verifier evidence.
    pub const fn proof_backed(verifier: ProofBackedLocalVerifier) -> Self {
        Self::ProofBacked(verifier)
    }

    /// Return the evidence class.
    pub const fn evidence_class(self) -> EvidenceClass {
        match self {
            Self::ScaffoldDigestOnly { .. } => EvidenceClass::ScaffoldDigestOnly,
            Self::ProofBacked(_) => EvidenceClass::ProofBacked,
        }
    }

    /// Return true when the evidence is proof backed.
    pub const fn is_proof_backed(self) -> bool {
        matches!(self, Self::ProofBacked(_))
    }

    /// Return the local proof soundness label.
    pub const fn soundness_label(self) -> LocalProofSoundnessLabel {
        match self {
            Self::ScaffoldDigestOnly { .. } => LocalProofSoundnessLabel::ScaffoldDigestOnly,
            Self::ProofBacked(verifier) => verifier.soundness_label(),
        }
    }

    fn verify(self, partial: &AcceptedPartialContribution) -> Result<(), ThresholdError> {
        let expected = partial.local_bounds_proof_digest();
        match self {
            Self::ScaffoldDigestOnly {
                local_bounds_proof_digest,
            } => {
                if is_all_zero(&local_bounds_proof_digest) {
                    return Err(ThresholdError::RejectionSamplingFailed {
                        validator: partial.signer(),
                    });
                }
                if &local_bounds_proof_digest != expected {
                    return Err(ThresholdError::RejectionSamplingFailed {
                        validator: partial.signer(),
                    });
                }
            }
            Self::ProofBacked(verifier) => {
                if verifier.proof_digest() != expected {
                    return Err(ThresholdError::RejectionSamplingFailed {
                        validator: partial.signer(),
                    });
                }
            }
        }

        Ok(())
    }
}

/// Complete metadata package required before partial soundness can be marked closure-ready.
///
/// This package verifies that all proof artifacts needed for closure are named
/// and context-bound. It does not execute the local proof verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PartialSoundnessClosurePackage {
    proof_system_label: &'static str,
    audited_local_verifier_digest: [u8; 32],
    vss_dkg_binding_proof_digest: [u8; 32],
    hiding_leakage_proof_digest: [u8; 32],
    transcript_context_binding_digest: [u8; 32],
    proof_requirement: ClosureProofRequirement,
    external_review_digest: [u8; 32],
}

impl PartialSoundnessClosurePackage {
    /// Construct a partial-soundness closure package.
    pub fn new(
        proof_system_label: &'static str,
        audited_local_verifier_digest: [u8; 32],
        vss_dkg_binding_proof_digest: [u8; 32],
        hiding_leakage_proof_digest: [u8; 32],
        transcript_context_binding_digest: [u8; 32],
        proof_requirement: ClosureProofRequirement,
        external_review_digest: [u8; 32],
    ) -> Result<Self, ThresholdError> {
        if proof_system_label.trim().is_empty() {
            return Err(ThresholdError::ProductionPolicyBlocked {
                reason: "partial closure proof system label is empty",
            });
        }

        if is_all_zero(&audited_local_verifier_digest)
            || is_all_zero(&vss_dkg_binding_proof_digest)
            || is_all_zero(&hiding_leakage_proof_digest)
            || is_all_zero(&transcript_context_binding_digest)
            || is_all_zero(&external_review_digest)
        {
            return Err(ThresholdError::MalformedSerialization {
                reason: "partial closure package digest is all zero",
            });
        }

        Ok(Self {
            proof_system_label,
            audited_local_verifier_digest,
            vss_dkg_binding_proof_digest,
            hiding_leakage_proof_digest,
            transcript_context_binding_digest,
            proof_requirement,
            external_review_digest,
        })
    }

    /// Return the proof-system label this closure package reviewed.
    pub const fn proof_system_label(&self) -> &'static str {
        self.proof_system_label
    }

    /// Borrow the audited local verifier digest.
    pub const fn audited_local_verifier_digest(&self) -> &[u8; 32] {
        &self.audited_local_verifier_digest
    }

    /// Borrow the VSS/DKG binding proof digest.
    pub const fn vss_dkg_binding_proof_digest(&self) -> &[u8; 32] {
        &self.vss_dkg_binding_proof_digest
    }

    /// Borrow the hiding and leakage proof digest.
    pub const fn hiding_leakage_proof_digest(&self) -> &[u8; 32] {
        &self.hiding_leakage_proof_digest
    }

    /// Borrow the transcript/context binding digest.
    pub const fn transcript_context_binding_digest(&self) -> &[u8; 32] {
        &self.transcript_context_binding_digest
    }

    /// Return the declared proof-evidence requirement.
    pub const fn proof_requirement(&self) -> ClosureProofRequirement {
        self.proof_requirement
    }

    /// Borrow the external review digest.
    pub const fn external_review_digest(&self) -> &[u8; 32] {
        &self.external_review_digest
    }

    /// Verify that the closure package rejects digest-only proof requirements.
    pub fn verify_proof_requirement(&self) -> Result<(), ThresholdError> {
        if self.proof_requirement != ClosureProofRequirement::ProofBackedLocalVerifierRequired {
            return Err(ThresholdError::ProductionPolicyBlocked {
                reason: "partial closure package must require proof-backed evidence",
            });
        }

        Ok(())
    }

    fn verify(
        self,
        context_binding: &PartialContextBinding,
        local_proof: LocalProofEvidence,
    ) -> Result<(), ThresholdError> {
        self.verify_proof_requirement()?;

        let LocalProofSoundnessLabel::ProofBacked { proof_system, .. } =
            local_proof.soundness_label()
        else {
            return Err(ThresholdError::ProductionPolicyBlocked {
                reason: "closure package requires proof-backed partial evidence",
            });
        };

        if proof_system != self.proof_system_label {
            return Err(ThresholdError::ProductionPolicyBlocked {
                reason: "partial closure proof system label mismatch",
            });
        }

        if self.transcript_context_binding_digest != context_binding.closure_digest() {
            return Err(ThresholdError::ProductionPolicyBlocked {
                reason: "partial closure transcript context digest mismatch",
            });
        }

        Ok(())
    }
}

/// Verified partial-contribution soundness evidence token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialContributionSoundnessEvidence {
    signer: ValidatorId,
    evidence_class: EvidenceClass,
    local_proof_soundness_label: LocalProofSoundnessLabel,
    leakage_budget: LeakageBudget,
    context_binding: PartialContextBinding,
    closure_status: PartialSoundnessClosureStatus,
    closure_package: Option<PartialSoundnessClosurePackage>,
}

impl PartialContributionSoundnessEvidence {
    /// Verify accepted-partial soundness evidence against a transcript.
    pub fn verify(
        transcript: &ProductionSigningTranscript,
        partial: &AcceptedPartialContribution,
        verifier_binding: PartialVerifierBinding,
        context_binding: PartialContextBinding,
        local_proof: LocalProofEvidence,
        leakage_budget: LeakageBudget,
        requirement: PartialEvidenceRequirement,
    ) -> Result<Self, ThresholdError> {
        verifier_binding.verify(transcript, partial)?;
        context_binding.verify(transcript)?;
        local_proof.verify(partial)?;
        leakage_budget.verify()?;

        if requirement == PartialEvidenceRequirement::ProofBackedOnly
            && !local_proof.is_proof_backed()
        {
            return Err(ThresholdError::ProductionPolicyBlocked {
                reason: "proof-backed partial evidence required",
            });
        }

        Ok(Self {
            signer: partial.signer(),
            evidence_class: local_proof.evidence_class(),
            local_proof_soundness_label: local_proof.soundness_label(),
            leakage_budget,
            context_binding,
            closure_status: PartialSoundnessClosureStatus::ConformanceOnly,
            closure_package: None,
        })
    }

    /// Verify accepted-partial evidence plus a full closure package.
    pub fn verify_closure_package(
        transcript: &ProductionSigningTranscript,
        partial: &AcceptedPartialContribution,
        verifier_binding: PartialVerifierBinding,
        context_binding: PartialContextBinding,
        local_proof: LocalProofEvidence,
        leakage_budget: LeakageBudget,
        closure_package: PartialSoundnessClosurePackage,
    ) -> Result<Self, ThresholdError> {
        verifier_binding.verify(transcript, partial)?;
        context_binding.verify(transcript)?;
        local_proof.verify(partial)?;
        leakage_budget.verify()?;
        closure_package.verify(&context_binding, local_proof)?;

        Ok(Self {
            signer: partial.signer(),
            evidence_class: local_proof.evidence_class(),
            local_proof_soundness_label: local_proof.soundness_label(),
            leakage_budget,
            context_binding,
            closure_status: PartialSoundnessClosureStatus::ClosureReady,
            closure_package: Some(closure_package),
        })
    }

    /// Return the signer bound to this evidence token.
    pub const fn signer(&self) -> ValidatorId {
        self.signer
    }

    /// Return the evidence class.
    pub const fn evidence_class(&self) -> EvidenceClass {
        self.evidence_class
    }

    /// Return true when proof-backed evidence was checked.
    pub const fn is_proof_backed(&self) -> bool {
        matches!(self.evidence_class, EvidenceClass::ProofBacked)
    }

    /// Return the local proof soundness label.
    pub const fn local_proof_soundness_label(&self) -> LocalProofSoundnessLabel {
        self.local_proof_soundness_label
    }

    /// Return the checked leakage budget.
    pub const fn leakage_budget(&self) -> LeakageBudget {
        self.leakage_budget
    }

    /// Borrow the checked context binding.
    pub const fn context_binding(&self) -> &PartialContextBinding {
        &self.context_binding
    }

    /// Return the partial-soundness closure status.
    pub const fn closure_status(&self) -> PartialSoundnessClosureStatus {
        self.closure_status
    }

    /// Return true when a full closure package was checked.
    pub const fn is_closure_ready(&self) -> bool {
        matches!(
            self.closure_status,
            PartialSoundnessClosureStatus::ClosureReady
        )
    }

    /// Return the checked closure package, when closure-ready.
    pub const fn closure_package(&self) -> Option<PartialSoundnessClosurePackage> {
        self.closure_package
    }
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha3_256::digest(bytes).into()
}

fn is_all_zero(digest: &[u8; 32]) -> bool {
    digest.iter().all(|byte| *byte == 0)
}
