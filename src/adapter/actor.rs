//! Async threshold protocol actor scaffold.

use std::{
    collections::{BTreeMap, HashMap},
    time::{Duration, Instant},
};

use tokio::sync::mpsc;

use crate::{
    adapter::{
        evidence::{EvidenceKind, SlashingEvidence},
        traits::{ConsensusStateAdapter, P2pNetworkAdapter},
        wire::PqcThresholdWireMsg,
    },
    crypto::{
        contribution_proof::ContributionProofBackend,
        production_policy::require_production_threshold_backends, vss::VssCommitmentBackend,
    },
    state, Commitment, CommitmentSet, PartialShareSet, PartialSignatureShare, PrivateKeyShare,
    SessionId, SignatureAggregator, SigningSession, SimulatedAggregator, ThresholdError,
    ThresholdPublicKey, ThresholdSigner, ThresholdSigningTranscript, ValidatorId,
};

#[cfg(feature = "hazmat-real-mldsa")]
use crate::crypto::contribution_proof::{
    prove_contribution, verify_contribution_proof, ContributionProof, ContributionStatement,
    ContributionWitness, ProductionContributionStatement,
    PRODUCTION_CONTRIBUTION_STATEMENT_SCHEMA_VERSION,
};
#[cfg(all(feature = "hazmat-real-mldsa", feature = "experimental-vss"))]
use crate::crypto::vss::{
    experimental_vss_statement_digest, ExperimentalVssComplaintEvidence, ExperimentalVssOpening,
    ExperimentalVssProof, ExperimentalVssStatement, ProductionVssRelationStatement,
    PRODUCTION_VSS_RELATION_STATEMENT_SCHEMA_VERSION,
};

#[cfg(feature = "hazmat-real-mldsa")]
use crate::low_level::mldsa65::{
    begin_mldsa65_threshold_attempt, decode_mldsa65_masking_contribution,
    decode_mldsa65_secret_contribution, derive_mldsa65_masking_contribution_from_share,
    derive_mldsa65_secret_contribution_from_share,
    derive_mldsa65_session_challenge_once_quorum_met, encode_mldsa65_masking_contribution,
    encode_mldsa65_secret_contribution, finalize_mldsa65_session_signature_once_quorum_met,
    masking_commitment_digest, mldsa65_session_dkg_commitment_digest, secret_commitment_digest,
    submit_mldsa65_masking_contribution, submit_mldsa65_secret_contribution,
    Mldsa65ExpandedSecretKeyShare, Mldsa65MaskingContribution, Mldsa65PartialSecretContribution,
    Mldsa65ThresholdSigningAttempt, Mldsa65ThresholdSigningPhase, MLDSA65_CHALLENGE_BYTES,
    MLDSA65_MU_BYTES,
};
#[cfg(feature = "hazmat-real-mldsa")]
use sha3::{Digest as Sha3Digest, Sha3_256};

/// Root domain separator for production-target context digests derived by the actor.
#[cfg(feature = "hazmat-real-mldsa")]
pub const PRODUCTION_CONTEXT_DOMAIN: &[u8] = b"dytallix.threshold.production-context.v1";
/// Production context label for epoch identifiers.
#[cfg(feature = "hazmat-real-mldsa")]
pub const PRODUCTION_EPOCH_LABEL: &[u8] = b"epoch";
/// Production context label for canonical validator-set digests.
#[cfg(feature = "hazmat-real-mldsa")]
pub const PRODUCTION_VALIDATOR_SET_LABEL: &[u8] = b"validator-set";
/// Production context label for epoch public-key digests.
#[cfg(feature = "hazmat-real-mldsa")]
pub const PRODUCTION_PUBLIC_KEY_LABEL: &[u8] = b"public-key";
/// Production context label for the ML-DSA parameter set digest.
#[cfg(feature = "hazmat-real-mldsa")]
pub const PRODUCTION_PARAMETER_SET_LABEL: &[u8] = b"parameter-set";
/// Production context label for raw scaffold contribution payload binding.
#[cfg(feature = "hazmat-real-mldsa")]
pub const PRODUCTION_CONTRIBUTION_PAYLOAD_LABEL: &[u8] = b"contribution-payload";
/// Parameter-set identifier currently used by the hazmat ML-DSA-65 scaffold.
#[cfg(feature = "hazmat-real-mldsa")]
pub const PRODUCTION_CONTRIBUTION_PARAMETER_SET_ID: &[u8] = b"FIPS204-ML-DSA-65/hazmat-real-mldsa";

/// Root domain separator for experimental VSS complaint trace digests.
#[cfg(all(feature = "hazmat-real-mldsa", feature = "experimental-vss"))]
pub const EXPERIMENTAL_VSS_COMPLAINT_DOMAIN: &[u8] =
    b"dytallix.adapter.experimental-vss-complaint.v1";
/// Experimental VSS complaint label for context material.
#[cfg(all(feature = "hazmat-real-mldsa", feature = "experimental-vss"))]
pub const EXPERIMENTAL_VSS_CONTEXT_LABEL: &[u8] = b"context";
/// Experimental VSS complaint label for dealer commitments.
#[cfg(all(feature = "hazmat-real-mldsa", feature = "experimental-vss"))]
pub const EXPERIMENTAL_VSS_DEALER_COMMITMENT_LABEL: &[u8] = b"dealer-commitment";
/// Experimental VSS complaint label for raw share payloads.
#[cfg(all(feature = "hazmat-real-mldsa", feature = "experimental-vss"))]
pub const EXPERIMENTAL_VSS_SHARE_LABEL: &[u8] = b"share";
/// Experimental VSS complaint label for encrypted-share payloads.
#[cfg(all(feature = "hazmat-real-mldsa", feature = "experimental-vss"))]
pub const EXPERIMENTAL_VSS_ENCRYPTED_SHARE_LABEL: &[u8] = b"encrypted-share";
/// Experimental VSS complaint label for opening frames.
#[cfg(all(feature = "hazmat-real-mldsa", feature = "experimental-vss"))]
pub const EXPERIMENTAL_VSS_OPENING_LABEL: &[u8] = b"opening";
/// Experimental VSS complaint label for adapter error payloads.
#[cfg(all(feature = "hazmat-real-mldsa", feature = "experimental-vss"))]
pub const EXPERIMENTAL_VSS_ADAPTER_ERROR_LABEL: &[u8] = b"adapter-error";
/// Experimental VSS complaint label for backend identifiers.
#[cfg(all(feature = "hazmat-real-mldsa", feature = "experimental-vss"))]
pub const EXPERIMENTAL_VSS_BACKEND_LABEL: &[u8] = b"backend";
/// Experimental VSS complaint label for public-key contribution digests.
#[cfg(all(feature = "hazmat-real-mldsa", feature = "experimental-vss"))]
pub const EXPERIMENTAL_VSS_PUBLIC_KEY_CONTRIBUTION_LABEL: &[u8] = b"public-key-contribution";
/// Experimental VSS backend identifier material used for production-shaped statements.
#[cfg(all(feature = "hazmat-real-mldsa", feature = "experimental-vss"))]
pub const EXPERIMENTAL_VSS_PRODUCTION_RELATION_BACKEND_ID: &[u8] =
    b"experimental-vss-complaint.production-relation-statement";

/// Events consumed by the threshold actor.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ActorEvent {
    /// Message received from the P2P layer.
    IncomingNetworkMessage(PqcThresholdWireMsg),
    /// Start a block signing round.
    TriggerSigningRound {
        /// Session ID.
        session_id: SessionId,
        /// Block height being signed.
        block_height: u64,
        /// Block payload hash.
        message_hash: [u8; 32],
    },
    /// Start a real hazmat ML-DSA-65 signing round from a precomputed `mu`.
    #[cfg(feature = "hazmat-real-mldsa")]
    TriggerHazmatMldsa65SigningRound {
        /// Session ID.
        session_id: SessionId,
        /// Block height being signed.
        block_height: u64,
        /// FIPS 204 internal message digest `mu`.
        mu: [u8; MLDSA65_MU_BYTES],
        /// Shared deterministic masking seed for this experimental attempt.
        masking_seed: [u8; MLDSA65_MU_BYTES],
    },
    /// Reap stale sessions.
    TimeoutCheck,
}

/// Empirical measurements captured for one threshold session.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SessionMetrics {
    /// Total wall-clock session duration in nanoseconds.
    pub total_duration_ns: u64,
    /// Number of rejection-sampling aborts and retries observed.
    pub abort_and_retry_count: u32,
    /// Total network bytes transmitted during the session.
    pub network_bytes_transmitted: usize,
}

/// Actor construction config.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ActorConfig {
    /// Local validator ID.
    pub local_validator: ValidatorId,
    /// Validator set for this epoch.
    pub validator_set: Vec<ValidatorId>,
    /// Signing threshold.
    pub threshold: u16,
    /// Threshold public key for simulation.
    pub public_key: ThresholdPublicKey,
    /// Local private key share.
    pub local_share: PrivateKeyShare,
    /// Optional real ML-DSA-65 key share used by the hazmat backend.
    #[cfg(feature = "hazmat-real-mldsa")]
    pub hazmat_mldsa65_share: Option<Mldsa65ExpandedSecretKeyShare>,
    /// Round timeout.
    pub round_timeout: Duration,
    /// Maximum active sessions.
    pub max_sessions: usize,
}

impl ActorConfig {
    /// Construct an actor configuration.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local_validator: ValidatorId,
        validator_set: Vec<ValidatorId>,
        threshold: u16,
        public_key: ThresholdPublicKey,
        local_share: PrivateKeyShare,
        round_timeout: Duration,
        max_sessions: usize,
    ) -> Self {
        Self {
            local_validator,
            validator_set,
            threshold,
            public_key,
            local_share,
            #[cfg(feature = "hazmat-real-mldsa")]
            hazmat_mldsa65_share: None,
            round_timeout,
            max_sessions,
        }
    }

    /// Construct an actor configuration for production-labeled runtime paths.
    ///
    /// This constructor fails closed unless both backend families declare
    /// production security profiles through the combined production policy
    /// gate. Passing this guard does not prove production security; it only
    /// prevents scaffold backends from being selected for a production-labeled
    /// runtime by accident.
    #[allow(clippy::too_many_arguments)]
    pub fn new_production_checked<V, P>(
        local_validator: ValidatorId,
        validator_set: Vec<ValidatorId>,
        threshold: u16,
        public_key: ThresholdPublicKey,
        local_share: PrivateKeyShare,
        round_timeout: Duration,
        max_sessions: usize,
        vss_backend: &V,
        proof_backend: &P,
    ) -> Result<Self, ThresholdError>
    where
        V: VssCommitmentBackend,
        P: ContributionProofBackend,
    {
        require_production_threshold_backends(vss_backend, proof_backend)?;
        Ok(Self::new(
            local_validator,
            validator_set,
            threshold,
            public_key,
            local_share,
            round_timeout,
            max_sessions,
        ))
    }

    /// Attach a real ML-DSA-65 share for feature-gated hazmat actor rounds.
    #[cfg(feature = "hazmat-real-mldsa")]
    pub fn with_hazmat_mldsa65_share(mut self, share: Mldsa65ExpandedSecretKeyShare) -> Self {
        self.hazmat_mldsa65_share = Some(share);
        self
    }
}

/// Async threshold protocol actor.
pub struct ThresholdActor<N, C>
where
    N: P2pNetworkAdapter,
    C: ConsensusStateAdapter,
{
    config: ActorConfig,
    network: N,
    consensus: C,
    inbox: mpsc::Receiver<ActorEvent>,
    active_sessions: HashMap<SessionId, ActiveSigningSession>,
    #[cfg(feature = "hazmat-real-mldsa")]
    hazmat_sessions: HashMap<SessionId, HazmatActiveSigningSession>,
}

/// Feature-gated actor-session bridge for real hazmat ML-DSA threshold signing.
#[cfg(feature = "hazmat-real-mldsa")]
#[derive(Debug)]
pub struct HazmatMldsa65ActorSession {
    session_id: SessionId,
    block_height: u64,
    attempt_index: u16,
    created_at: Instant,
    timeout: Duration,
    attempt: Mldsa65ThresholdSigningAttempt,
    dkg_commitment_digest: [u8; 32],
    require_proof_bound_secret_contributions: bool,
    require_masking_precommitments: bool,
    masking_commitments: BTreeMap<ValidatorId, [u8; 32]>,
    require_secret_precommitments: bool,
    secret_commitments: BTreeMap<ValidatorId, [u8; 32]>,
}

#[cfg(feature = "hazmat-real-mldsa")]
impl HazmatMldsa65ActorSession {
    /// Create a hazmat actor-session bridge for a fixed internal `mu` digest.
    pub fn new(
        session_id: SessionId,
        block_height: u64,
        threshold: u16,
        total_nodes: u16,
        mu: [u8; MLDSA65_MU_BYTES],
        timeout: Duration,
    ) -> Result<Self, ThresholdError> {
        Ok(Self {
            session_id,
            block_height,
            attempt_index: 0,
            created_at: Instant::now(),
            timeout,
            attempt: begin_mldsa65_threshold_attempt(threshold, total_nodes, mu)?,
            dkg_commitment_digest: mldsa65_session_dkg_commitment_digest(
                &session_id,
                block_height,
                threshold,
                total_nodes,
                &mu,
            ),
            require_proof_bound_secret_contributions: false,
            require_masking_precommitments: false,
            masking_commitments: BTreeMap::new(),
            require_secret_precommitments: false,
            secret_commitments: BTreeMap::new(),
        })
    }

    /// Create a hazmat actor session that requires masking commitments before openings.
    pub fn new_with_masking_precommitments(
        session_id: SessionId,
        block_height: u64,
        threshold: u16,
        total_nodes: u16,
        mu: [u8; MLDSA65_MU_BYTES],
        timeout: Duration,
    ) -> Result<Self, ThresholdError> {
        let mut session = Self::new(
            session_id,
            block_height,
            threshold,
            total_nodes,
            mu,
            timeout,
        )?;
        session.require_masking_precommitments = true;
        Ok(session)
    }

    /// Create a hazmat actor session that requires both masking and secret precommitments.
    pub fn new_with_precommitments(
        session_id: SessionId,
        block_height: u64,
        threshold: u16,
        total_nodes: u16,
        mu: [u8; MLDSA65_MU_BYTES],
        timeout: Duration,
    ) -> Result<Self, ThresholdError> {
        let mut session = Self::new_with_masking_precommitments(
            session_id,
            block_height,
            threshold,
            total_nodes,
            mu,
            timeout,
        )?;
        session.require_secret_precommitments = true;
        Ok(session)
    }

    /// Return the actor session identifier.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Return the associated block height.
    pub const fn block_height(&self) -> u64 {
        self.block_height
    }

    /// Return the current threshold signing phase.
    pub const fn phase(&self) -> Mldsa65ThresholdSigningPhase {
        self.attempt.phase()
    }

    /// Return the threshold bound for this session.
    pub const fn threshold(&self) -> u16 {
        self.attempt.threshold()
    }

    /// Return the validator count bound for this session.
    pub const fn total_nodes(&self) -> u16 {
        self.attempt.total_nodes()
    }

    /// Return the DKG public commitment digest bound into proof statements.
    pub const fn dkg_commitment_digest(&self) -> [u8; 32] {
        self.dkg_commitment_digest
    }

    /// Override the DKG public commitment digest for integrations that have
    /// epoch DKG transcript material available.
    pub fn set_dkg_commitment_digest(&mut self, digest: [u8; 32]) {
        self.dkg_commitment_digest = digest;
    }

    /// Require proof-bound secret contribution frames for this session.
    pub fn require_proof_bound_secret_contributions(&mut self) {
        self.require_proof_bound_secret_contributions = true;
    }

    /// Return true when this actor session has exceeded its timeout.
    pub fn is_timed_out(&self) -> bool {
        Instant::now().duration_since(self.created_at) >= self.timeout
    }

    /// Submit one round-1 masking contribution.
    pub fn submit_masking_contribution(
        &mut self,
        contribution: Mldsa65MaskingContribution,
    ) -> Result<(), ThresholdError> {
        submit_mldsa65_masking_contribution(&mut self.attempt, contribution)
    }

    /// Derive the round challenge once masking quorum is available.
    pub fn derive_challenge(&mut self) -> Result<[u8; MLDSA65_CHALLENGE_BYTES], ThresholdError> {
        derive_mldsa65_session_challenge_once_quorum_met(&mut self.attempt)
    }

    /// Submit one round-2 secret contribution.
    pub fn submit_secret_contribution(
        &mut self,
        contribution: Mldsa65PartialSecretContribution,
    ) -> Result<(), ThresholdError> {
        submit_mldsa65_secret_contribution(&mut self.attempt, contribution)
    }

    /// Finalize the standard ML-DSA signature bytes for consensus submission.
    pub fn finalize_signature(&mut self) -> Result<(u64, Vec<u8>), ThresholdError> {
        let signature = finalize_mldsa65_session_signature_once_quorum_met(&mut self.attempt)?;
        Ok((self.block_height, signature.as_bytes().to_vec()))
    }

    /// Submit an encoded hazmat ML-DSA masking-contribution wire frame.
    ///
    /// Returns `Ok(Some(challenge))` when this frame completes round-1 quorum.
    /// Returns `Ok(None)` while more masking contributions are still needed.
    pub fn submit_masking_wire_message(
        &mut self,
        msg: &PqcThresholdWireMsg,
    ) -> Result<Option<[u8; MLDSA65_CHALLENGE_BYTES]>, ThresholdError> {
        let PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
            session_id,
            block_height,
            attempt,
            validator_index,
            payload,
        } = msg
        else {
            return Err(ThresholdError::TranscriptMismatch);
        };
        self.validate_wire_envelope(*session_id, *block_height, *attempt)?;

        let contribution = decode_mldsa65_masking_contribution(payload)?;
        if contribution.receiver_index() != *validator_index {
            return Err(ThresholdError::PartialShareVerificationFailed {
                validator: ValidatorId(*validator_index),
            });
        }
        self.verify_masking_precommitment(*validator_index, payload)?;

        submit_mldsa65_masking_contribution(&mut self.attempt, contribution)?;
        match derive_mldsa65_session_challenge_once_quorum_met(&mut self.attempt) {
            Ok(challenge) => Ok(Some(challenge)),
            Err(ThresholdError::InsufficientCommitments { .. }) => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Submit an encoded hazmat ML-DSA masking precommitment wire frame.
    pub fn submit_masking_commitment_wire_message(
        &mut self,
        msg: &PqcThresholdWireMsg,
    ) -> Result<(), ThresholdError> {
        let PqcThresholdWireMsg::HazmatMldsa65MaskingCommitment {
            session_id,
            block_height,
            attempt,
            validator_index,
            commitment,
        } = msg
        else {
            return Err(ThresholdError::TranscriptMismatch);
        };
        self.validate_wire_envelope(*session_id, *block_height, *attempt)?;
        let validator = ValidatorId(*validator_index);
        if *validator_index == 0 || *validator_index > self.attempt.total_nodes() {
            return Err(ThresholdError::UnknownValidator { validator });
        }
        if self.masking_commitments.contains_key(&validator) {
            return Err(ThresholdError::DuplicateValidator { validator });
        }
        self.masking_commitments.insert(validator, *commitment);
        Ok(())
    }

    /// Submit an encoded hazmat ML-DSA secret precommitment wire frame.
    pub fn submit_secret_commitment_wire_message(
        &mut self,
        msg: &PqcThresholdWireMsg,
    ) -> Result<(), ThresholdError> {
        let PqcThresholdWireMsg::HazmatMldsa65SecretCommitment {
            session_id,
            block_height,
            attempt,
            validator_index,
            challenge,
            commitment,
        } = msg
        else {
            return Err(ThresholdError::TranscriptMismatch);
        };
        self.validate_wire_envelope(*session_id, *block_height, *attempt)?;
        if self.attempt.phase() != Mldsa65ThresholdSigningPhase::AwaitingSecretContributions
            || self.attempt.challenge() != Some(challenge)
        {
            return Err(ThresholdError::TranscriptMismatch);
        }
        let validator = ValidatorId(*validator_index);
        if *validator_index == 0 || *validator_index > self.attempt.total_nodes() {
            return Err(ThresholdError::UnknownValidator { validator });
        }
        if self.secret_commitments.contains_key(&validator) {
            return Err(ThresholdError::DuplicateValidator { validator });
        }
        self.secret_commitments.insert(validator, *commitment);
        Ok(())
    }

    /// Submit an encoded hazmat ML-DSA secret-contribution wire frame.
    ///
    /// Returns `Ok(Some((height, signature)))` when this frame completes
    /// round-2 quorum and finalization succeeds. Returns `Ok(None)` while more
    /// secret contributions are still needed.
    pub fn submit_secret_wire_message(
        &mut self,
        msg: &PqcThresholdWireMsg,
    ) -> Result<Option<(u64, Vec<u8>)>, ThresholdError> {
        let (session_id, block_height, attempt, validator_index, challenge, payload) = match msg {
            PqcThresholdWireMsg::HazmatMldsa65SecretContribution {
                session_id,
                block_height,
                attempt,
                validator_index,
                challenge,
                payload,
            } => (
                *session_id,
                *block_height,
                *attempt,
                *validator_index,
                *challenge,
                payload,
            ),
            PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
                session_id,
                block_height,
                attempt,
                validator_index,
                challenge,
                payload,
                ..
            } => (
                *session_id,
                *block_height,
                *attempt,
                *validator_index,
                *challenge,
                payload,
            ),
            _ => return Err(ThresholdError::TranscriptMismatch),
        };
        self.validate_wire_envelope(session_id, block_height, attempt)?;

        let contribution = decode_mldsa65_secret_contribution(payload)?;
        if contribution.receiver_index() != validator_index
            || contribution.challenge() != &challenge
        {
            return Err(ThresholdError::PartialShareVerificationFailed {
                validator: ValidatorId(validator_index),
            });
        }
        self.verify_secret_precommitment(validator_index, &challenge, payload)?;
        match msg {
            PqcThresholdWireMsg::HazmatMldsa65SecretContribution { .. } => {
                if self.require_proof_bound_secret_contributions {
                    return Err(ThresholdError::TranscriptMismatch);
                }
                self.verify_secret_contribution_scaffold(validator_index, &challenge, payload)?;
            }
            PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
                masking_commitment_digest,
                secret_commitment_digest,
                dkg_commitment_digest,
                production_statement_digest,
                proof,
                ..
            } => {
                let statement = ContributionStatement {
                    session_id: self.session_id,
                    block_height: self.block_height,
                    attempt: self.attempt_index,
                    validator_index,
                    challenge,
                    masking_commitment_digest: *masking_commitment_digest,
                    secret_commitment_digest: *secret_commitment_digest,
                    dkg_commitment_digest: *dkg_commitment_digest,
                };
                self.verify_proof_bound_secret_contribution(
                    payload,
                    &statement,
                    *production_statement_digest,
                    proof,
                )?;
            }
            _ => return Err(ThresholdError::TranscriptMismatch),
        }

        submit_mldsa65_secret_contribution(&mut self.attempt, contribution)?;
        match self.finalize_signature() {
            Ok(finalized) => Ok(Some(finalized)),
            Err(ThresholdError::InsufficientPartialShares { .. }) => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn validate_wire_envelope(
        &self,
        session_id: SessionId,
        block_height: u64,
        attempt: u16,
    ) -> Result<(), ThresholdError> {
        if session_id != self.session_id
            || block_height != self.block_height
            || attempt != self.attempt_index
        {
            return Err(ThresholdError::TranscriptMismatch);
        }
        Ok(())
    }

    fn verify_masking_precommitment(
        &self,
        validator_index: u16,
        payload: &[u8],
    ) -> Result<(), ThresholdError> {
        if !self.require_masking_precommitments {
            return Ok(());
        }
        let validator = ValidatorId(validator_index);
        let expected = masking_commitment_digest(
            &self.session_id,
            self.block_height,
            self.attempt_index,
            validator_index,
            payload,
        );
        match self.masking_commitments.get(&validator) {
            Some(commitment) if *commitment == expected => Ok(()),
            Some(_) => Err(ThresholdError::CommitmentVerificationFailed { validator }),
            None => Err(ThresholdError::TranscriptMismatch),
        }
    }

    fn verify_secret_precommitment(
        &self,
        validator_index: u16,
        challenge: &[u8; MLDSA65_CHALLENGE_BYTES],
        payload: &[u8],
    ) -> Result<(), ThresholdError> {
        if !self.require_secret_precommitments {
            return Ok(());
        }
        let validator = ValidatorId(validator_index);
        let expected = secret_commitment_digest(
            &self.session_id,
            self.block_height,
            self.attempt_index,
            validator_index,
            challenge,
            payload,
        );
        match self.secret_commitments.get(&validator) {
            Some(commitment) if *commitment == expected => Ok(()),
            Some(_) => Err(ThresholdError::CommitmentVerificationFailed { validator }),
            None => Err(ThresholdError::TranscriptMismatch),
        }
    }

    fn secret_contribution_statement(
        &self,
        validator_index: u16,
        challenge: &[u8; MLDSA65_CHALLENGE_BYTES],
        payload: &[u8],
    ) -> ContributionStatement {
        let validator = ValidatorId(validator_index);
        ContributionStatement {
            session_id: self.session_id,
            block_height: self.block_height,
            attempt: self.attempt_index,
            validator_index,
            challenge: *challenge,
            masking_commitment_digest: self
                .masking_commitments
                .get(&validator)
                .copied()
                .unwrap_or_else(|| {
                    masking_commitment_digest(
                        &self.session_id,
                        self.block_height,
                        self.attempt_index,
                        validator_index,
                        &[],
                    )
                }),
            secret_commitment_digest: self
                .secret_commitments
                .get(&validator)
                .copied()
                .unwrap_or_else(|| {
                    secret_commitment_digest(
                        &self.session_id,
                        self.block_height,
                        self.attempt_index,
                        validator_index,
                        challenge,
                        payload,
                    )
                }),
            dkg_commitment_digest: self.dkg_commitment_digest,
        }
    }

    fn verify_secret_contribution_scaffold(
        &self,
        validator_index: u16,
        challenge: &[u8; MLDSA65_CHALLENGE_BYTES],
        payload: &[u8],
    ) -> Result<(), ThresholdError> {
        let statement = self.secret_contribution_statement(validator_index, challenge, payload);
        let witness = ContributionWitness::from_payload(payload.to_vec());
        let proof = prove_contribution(&statement, &witness)?;
        verify_contribution_proof(&statement, &proof)
    }

    fn verify_proof_bound_secret_contribution(
        &self,
        payload: &[u8],
        statement: &ContributionStatement,
        production_statement_digest: [u8; 32],
        proof: &ContributionProof,
    ) -> Result<(), ThresholdError> {
        let expected_statement = self.secret_contribution_statement(
            statement.validator_index,
            &statement.challenge,
            payload,
        );
        if statement != &expected_statement {
            return Err(ThresholdError::PartialShareVerificationFailed {
                validator: ValidatorId(statement.validator_index),
            });
        }

        let expected_production_digest = self.production_contribution_statement_digest(
            statement.validator_index,
            &statement.challenge,
            payload,
        )?;
        if production_statement_digest != expected_production_digest {
            return Err(ThresholdError::PartialShareVerificationFailed {
                validator: ValidatorId(statement.validator_index),
            });
        }

        verify_contribution_proof(&expected_statement, proof)?;

        let expected = prove_contribution(
            &expected_statement,
            &ContributionWitness::from_payload(payload.to_vec()),
        )?;
        if &expected == proof {
            Ok(())
        } else {
            Err(ThresholdError::PartialShareVerificationFailed {
                validator: ValidatorId(statement.validator_index),
            })
        }
    }

    /// Build the canonical production-target contribution statement for this session.
    pub fn production_contribution_statement(
        &self,
        validator_index: u16,
        challenge: &[u8; MLDSA65_CHALLENGE_BYTES],
        payload: &[u8],
    ) -> Result<ProductionContributionStatement, ThresholdError> {
        let scaffold = self.secret_contribution_statement(validator_index, challenge, payload);
        production_contribution_statement_from_scaffold(
            &scaffold,
            self.threshold(),
            self.total_nodes(),
            self.attempt.mu(),
            payload,
        )
    }

    /// Compute the canonical production-target contribution statement digest.
    pub fn production_contribution_statement_digest(
        &self,
        validator_index: u16,
        challenge: &[u8; MLDSA65_CHALLENGE_BYTES],
        payload: &[u8],
    ) -> Result<[u8; 32], ThresholdError> {
        self.production_contribution_statement(validator_index, challenge, payload)?
            .statement_digest()
    }
}

#[derive(Debug)]
struct ActiveSigningSession {
    block_height: u64,
    message_hash: [u8; 32],
    created_at: Instant,
    session: Option<SigningSession<state::AwaitingCommitments>>,
    local_commitment: Commitment,
    commitments: BTreeMap<ValidatorId, Commitment>,
    partials: BTreeMap<ValidatorId, PartialSignatureShare>,
    finalized: bool,
}

#[cfg(feature = "hazmat-real-mldsa")]
#[derive(Debug)]
struct HazmatActiveSigningSession {
    local_share: Mldsa65ExpandedSecretKeyShare,
    session: HazmatMldsa65ActorSession,
    local_secret_sent: bool,
}

impl<N, C> ThresholdActor<N, C>
where
    N: P2pNetworkAdapter,
    C: ConsensusStateAdapter,
{
    /// Construct a threshold actor with bounded session capacity.
    pub fn new(
        config: ActorConfig,
        network: N,
        consensus: C,
        inbox: mpsc::Receiver<ActorEvent>,
    ) -> Result<Self, ThresholdError> {
        let _validated = SigningSession::new(
            [0; 32],
            config.threshold,
            config.validator_set.clone(),
            config.public_key.clone(),
            config.local_share.clone(),
        )?;

        Ok(Self {
            config,
            network,
            consensus,
            inbox,
            active_sessions: HashMap::new(),
            #[cfg(feature = "hazmat-real-mldsa")]
            hazmat_sessions: HashMap::new(),
        })
    }

    /// Consume actor events until the inbox closes.
    pub async fn run(mut self) {
        while let Some(event) = self.inbox.recv().await {
            match event {
                ActorEvent::IncomingNetworkMessage(msg) => self.handle_network_msg(msg).await,
                ActorEvent::TriggerSigningRound {
                    session_id,
                    block_height,
                    message_hash,
                } => {
                    self.start_signing_session(session_id, block_height, message_hash)
                        .await;
                }
                #[cfg(feature = "hazmat-real-mldsa")]
                ActorEvent::TriggerHazmatMldsa65SigningRound {
                    session_id,
                    block_height,
                    mu,
                    masking_seed,
                } => {
                    self.start_hazmat_mldsa65_signing_session(
                        session_id,
                        block_height,
                        mu,
                        masking_seed,
                    )
                    .await;
                }
                ActorEvent::TimeoutCheck => self.reap_stale_sessions().await,
            }
        }
    }

    /// Return the current number of active sessions.
    pub fn active_session_count(&self) -> usize {
        let count = self.active_sessions.len();
        #[cfg(feature = "hazmat-real-mldsa")]
        let count = count + self.hazmat_sessions.len();
        count
    }

    async fn start_signing_session(
        &mut self,
        session_id: SessionId,
        block_height: u64,
        message_hash: [u8; 32],
    ) {
        if self.active_sessions.contains_key(&session_id)
            || self.active_sessions.len() >= self.config.max_sessions
        {
            return;
        }

        let Ok(session) = SigningSession::new(
            session_id,
            self.config.threshold,
            self.config.validator_set.clone(),
            self.config.public_key.clone(),
            self.config.local_share.clone(),
        ) else {
            return;
        };
        let Ok((session, local_commitment)) = session.initiate_signing() else {
            return;
        };

        let mut commitments = BTreeMap::new();
        commitments.insert(self.config.local_validator, local_commitment);
        self.active_sessions.insert(
            session_id,
            ActiveSigningSession {
                block_height,
                message_hash,
                created_at: Instant::now(),
                session: Some(session),
                local_commitment,
                commitments,
                partials: BTreeMap::new(),
                finalized: false,
            },
        );

        let msg = PqcThresholdWireMsg::SignCommit {
            session_id,
            block_height,
            validator_index: self.config.local_validator.0,
            commitment: local_commitment.0,
        };

        if self.network.broadcast(msg).await.is_err() {
            self.active_sessions.remove(&session_id);
            return;
        }

        if self
            .consensus
            .update_gas_baseline(block_height)
            .await
            .is_err()
        {
            self.active_sessions.remove(&session_id);
        }
    }

    #[cfg(feature = "hazmat-real-mldsa")]
    async fn start_hazmat_mldsa65_signing_session(
        &mut self,
        session_id: SessionId,
        block_height: u64,
        mu: [u8; MLDSA65_MU_BYTES],
        masking_seed: [u8; MLDSA65_MU_BYTES],
    ) {
        let Some(local_share) = self.config.hazmat_mldsa65_share.clone() else {
            return;
        };
        if self.active_sessions.contains_key(&session_id)
            || self.hazmat_sessions.contains_key(&session_id)
            || self.active_session_count() >= self.config.max_sessions
        {
            return;
        }

        let Ok(total_nodes) = u16::try_from(self.config.validator_set.len()) else {
            return;
        };
        let Ok(mut session) = HazmatMldsa65ActorSession::new_with_precommitments(
            session_id,
            block_height,
            self.config.threshold,
            total_nodes,
            mu,
            self.config.round_timeout,
        ) else {
            return;
        };
        session.set_dkg_commitment_digest(local_share.dkg_public_commitment_digest());
        session.require_proof_bound_secret_contributions();
        let Ok(masking_contribution) =
            derive_mldsa65_masking_contribution_from_share(&local_share, &masking_seed, 0)
        else {
            return;
        };
        let payload = encode_mldsa65_masking_contribution(&masking_contribution);
        let commitment_frame = PqcThresholdWireMsg::HazmatMldsa65MaskingCommitment {
            session_id,
            block_height,
            attempt: 0,
            validator_index: masking_contribution.receiver_index(),
            commitment: masking_commitment_digest(
                &session_id,
                block_height,
                0,
                masking_contribution.receiver_index(),
                &payload,
            ),
        };
        let opening_frame = PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
            session_id,
            block_height,
            attempt: 0,
            validator_index: masking_contribution.receiver_index(),
            payload,
        };
        if session
            .submit_masking_commitment_wire_message(&commitment_frame)
            .is_err()
        {
            return;
        }
        let Ok(challenge) = session.submit_masking_wire_message(&opening_frame) else {
            return;
        };

        self.hazmat_sessions.insert(
            session_id,
            HazmatActiveSigningSession {
                local_share,
                session,
                local_secret_sent: false,
            },
        );

        if self.network.broadcast(commitment_frame).await.is_err() {
            self.hazmat_sessions.remove(&session_id);
            return;
        }
        if self.network.broadcast(opening_frame).await.is_err() {
            self.hazmat_sessions.remove(&session_id);
            return;
        }
        if self
            .consensus
            .update_gas_baseline(block_height)
            .await
            .is_err()
        {
            self.hazmat_sessions.remove(&session_id);
            return;
        }
        if let Some(challenge) = challenge {
            self.broadcast_hazmat_local_secret(session_id, challenge)
                .await;
        }
    }

    async fn handle_network_msg(&mut self, msg: PqcThresholdWireMsg) {
        match msg {
            PqcThresholdWireMsg::SignCommit {
                session_id,
                block_height,
                validator_index,
                commitment,
                ..
            } => {
                let validator = ValidatorId(validator_index);
                if !self.is_known_validator(validator) {
                    return;
                }
                let Some(active) = self.active_sessions.get_mut(&session_id) else {
                    return;
                };
                if active.block_height != block_height {
                    return;
                }
                active
                    .commitments
                    .entry(validator)
                    .or_insert(Commitment(commitment));
                self.try_generate_local_partial(session_id);
                self.try_finalize_session(session_id).await;
            }
            PqcThresholdWireMsg::PartialSignature {
                session_id,
                validator_index,
                partial_sig_share,
            } => {
                let validator = ValidatorId(validator_index);
                if !self.is_known_validator(validator) {
                    return;
                }
                if partial_sig_share.starts_with(b"poison")
                    || partial_sig_share.starts_with(&[0xDE, 0xAD, 0xBE, 0xEF])
                {
                    let frame = PqcThresholdWireMsg::PartialSignature {
                        session_id,
                        validator_index,
                        partial_sig_share,
                    }
                    .encode();
                    let evidence = SlashingEvidence::new(
                        session_id,
                        validator,
                        EvidenceKind::InvalidPartialSignature,
                        Some(frame),
                        "partial signature share failed adapter validation",
                    );
                    let _ = self.consensus.submit_slashing_evidence(evidence).await;
                    self.active_sessions.remove(&session_id);
                    return;
                }
                let Some(active) = self.active_sessions.get_mut(&session_id) else {
                    return;
                };
                active
                    .partials
                    .entry(validator)
                    .or_insert(PartialSignatureShare {
                        signer: validator,
                        bytes: partial_sig_share,
                    });
                self.try_finalize_session(session_id).await;
            }
            PqcThresholdWireMsg::DkgCommit { .. }
            | PqcThresholdWireMsg::DkgShareExchange { .. } => {}
            #[cfg(feature = "hazmat-real-mldsa")]
            PqcThresholdWireMsg::HazmatMldsa65MaskingCommitment {
                session_id,
                validator_index,
                ..
            } => {
                self.handle_hazmat_mldsa65_masking_commitment(session_id, validator_index, msg)
                    .await;
            }
            #[cfg(feature = "hazmat-real-mldsa")]
            PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
                session_id,
                validator_index,
                ..
            } => {
                self.handle_hazmat_mldsa65_masking_message(session_id, validator_index, msg)
                    .await;
            }
            #[cfg(feature = "hazmat-real-mldsa")]
            PqcThresholdWireMsg::HazmatMldsa65SecretCommitment {
                session_id,
                validator_index,
                ..
            } => {
                self.handle_hazmat_mldsa65_secret_commitment(session_id, validator_index, msg)
                    .await;
            }
            #[cfg(feature = "hazmat-real-mldsa")]
            PqcThresholdWireMsg::HazmatMldsa65SecretContribution {
                session_id,
                validator_index,
                ..
            } => {
                self.handle_hazmat_mldsa65_secret_message(session_id, validator_index, msg)
                    .await;
            }
            #[cfg(feature = "hazmat-real-mldsa")]
            PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
                session_id,
                validator_index,
                ..
            } => {
                self.handle_hazmat_mldsa65_secret_message(session_id, validator_index, msg)
                    .await;
            }
            #[cfg(feature = "hazmat-real-mldsa")]
            PqcThresholdWireMsg::HazmatMldsa65Challenge { .. } => {}
        }
    }

    #[cfg(feature = "hazmat-real-mldsa")]
    async fn handle_hazmat_mldsa65_masking_commitment(
        &mut self,
        session_id: SessionId,
        validator_index: u16,
        msg: PqcThresholdWireMsg,
    ) {
        let validator = ValidatorId(validator_index);
        if !self.is_known_validator(validator) {
            return;
        }
        let result = {
            let Some(active) = self.hazmat_sessions.get_mut(&session_id) else {
                return;
            };
            active.session.submit_masking_commitment_wire_message(&msg)
        };

        if let Err(err) = result {
            self.submit_hazmat_invalid_share_evidence(session_id, validator, msg, err)
                .await;
        }
    }

    #[cfg(feature = "hazmat-real-mldsa")]
    async fn handle_hazmat_mldsa65_masking_message(
        &mut self,
        session_id: SessionId,
        validator_index: u16,
        msg: PqcThresholdWireMsg,
    ) {
        let validator = ValidatorId(validator_index);
        if !self.is_known_validator(validator) {
            return;
        }
        let result = {
            let Some(active) = self.hazmat_sessions.get_mut(&session_id) else {
                return;
            };
            active.session.submit_masking_wire_message(&msg)
        };

        match result {
            Ok(Some(challenge)) => {
                self.broadcast_hazmat_local_secret(session_id, challenge)
                    .await
            }
            Ok(None) => {}
            Err(err) => {
                self.submit_hazmat_invalid_share_evidence(session_id, validator, msg, err)
                    .await;
            }
        }
    }

    #[cfg(feature = "hazmat-real-mldsa")]
    async fn handle_hazmat_mldsa65_secret_commitment(
        &mut self,
        session_id: SessionId,
        validator_index: u16,
        msg: PqcThresholdWireMsg,
    ) {
        let validator = ValidatorId(validator_index);
        if !self.is_known_validator(validator) {
            return;
        }
        let result = {
            let Some(active) = self.hazmat_sessions.get_mut(&session_id) else {
                return;
            };
            active.session.submit_secret_commitment_wire_message(&msg)
        };

        if let Err(err) = result {
            self.submit_hazmat_invalid_share_evidence(session_id, validator, msg, err)
                .await;
        }
    }

    #[cfg(feature = "hazmat-real-mldsa")]
    async fn handle_hazmat_mldsa65_secret_message(
        &mut self,
        session_id: SessionId,
        validator_index: u16,
        msg: PqcThresholdWireMsg,
    ) {
        let validator = ValidatorId(validator_index);
        if !self.is_known_validator(validator) {
            return;
        }
        let result = {
            let Some(active) = self.hazmat_sessions.get_mut(&session_id) else {
                return;
            };
            active.session.submit_secret_wire_message(&msg)
        };

        match result {
            Ok(Some((height, signature))) => {
                if self
                    .consensus
                    .on_signature_finalized(height, signature)
                    .await
                    .is_ok()
                {
                    self.hazmat_sessions.remove(&session_id);
                }
            }
            Ok(None) => {}
            Err(ThresholdError::RejectionSamplingFailed { .. }) => {
                self.hazmat_sessions.remove(&session_id);
            }
            Err(err) => {
                self.submit_hazmat_invalid_share_evidence(session_id, validator, msg, err)
                    .await;
            }
        }
    }

    #[cfg(feature = "hazmat-real-mldsa")]
    async fn broadcast_hazmat_local_secret(
        &mut self,
        session_id: SessionId,
        challenge: [u8; MLDSA65_CHALLENGE_BYTES],
    ) {
        let action = {
            let Some(active) = self.hazmat_sessions.get_mut(&session_id) else {
                return;
            };
            if active.local_secret_sent {
                return;
            }
            let Ok(contribution) =
                derive_mldsa65_secret_contribution_from_share(&active.local_share, &challenge)
            else {
                return;
            };
            let payload = encode_mldsa65_secret_contribution(&contribution);
            let commitment_frame = PqcThresholdWireMsg::HazmatMldsa65SecretCommitment {
                session_id,
                block_height: active.session.block_height(),
                attempt: 0,
                validator_index: contribution.receiver_index(),
                challenge,
                commitment: secret_commitment_digest(
                    &session_id,
                    active.session.block_height(),
                    0,
                    contribution.receiver_index(),
                    &challenge,
                    &payload,
                ),
            };
            if active
                .session
                .submit_secret_commitment_wire_message(&commitment_frame)
                .is_err()
            {
                return;
            }
            let statement = active.session.secret_contribution_statement(
                contribution.receiver_index(),
                &challenge,
                &payload,
            );
            let Ok(proof) = prove_contribution(
                &statement,
                &ContributionWitness::from_payload(payload.clone()),
            ) else {
                return;
            };
            let Ok(production_statement_digest) =
                active.session.production_contribution_statement_digest(
                    contribution.receiver_index(),
                    &challenge,
                    &payload,
                )
            else {
                return;
            };
            let opening_frame = PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
                session_id,
                block_height: active.session.block_height(),
                attempt: 0,
                validator_index: contribution.receiver_index(),
                challenge,
                masking_commitment_digest: statement.masking_commitment_digest,
                secret_commitment_digest: statement.secret_commitment_digest,
                dkg_commitment_digest: statement.dkg_commitment_digest,
                production_statement_digest,
                proof,
                payload,
            };
            match active.session.submit_secret_wire_message(&opening_frame) {
                Ok(finalized) => {
                    active.local_secret_sent = true;
                    Some((commitment_frame, opening_frame, finalized))
                }
                Err(_) => None,
            }
        };

        let Some((commitment_frame, opening_frame, finalized)) = action else {
            return;
        };
        if self.network.broadcast(commitment_frame).await.is_err() {
            self.hazmat_sessions.remove(&session_id);
            return;
        }
        if self.network.broadcast(opening_frame).await.is_err() {
            self.hazmat_sessions.remove(&session_id);
            return;
        }
        if let Some((height, signature)) = finalized {
            if self
                .consensus
                .on_signature_finalized(height, signature)
                .await
                .is_ok()
            {
                self.hazmat_sessions.remove(&session_id);
            }
        }
    }

    #[cfg(feature = "hazmat-real-mldsa")]
    async fn submit_hazmat_invalid_share_evidence(
        &mut self,
        session_id: SessionId,
        validator: ValidatorId,
        msg: PqcThresholdWireMsg,
        err: ThresholdError,
    ) {
        #[cfg(not(feature = "experimental-vss"))]
        let _ = &err;
        let wire_frame = msg.encode();
        let evidence = SlashingEvidence::new(
            session_id,
            validator,
            EvidenceKind::InvalidPartialSignature,
            Some(wire_frame.clone()),
            "hazmat ML-DSA contribution failed adapter validation",
        );
        #[cfg(feature = "experimental-vss")]
        let evidence = match self.build_experimental_vss_complaint_evidence(
            session_id,
            validator,
            &msg,
            &wire_frame,
            &err,
        ) {
            Some((complaint, production_statement_digest)) => evidence
                .with_experimental_vss_complaint_evidence(complaint)
                .with_production_vss_relation_statement_digest(production_statement_digest),
            None => evidence,
        };
        let _ = self.consensus.submit_slashing_evidence(evidence).await;
    }

    #[cfg(all(feature = "hazmat-real-mldsa", feature = "experimental-vss"))]
    fn build_experimental_vss_complaint_evidence(
        &self,
        session_id: SessionId,
        validator: ValidatorId,
        msg: &PqcThresholdWireMsg,
        wire_frame: &[u8],
        err: &ThresholdError,
    ) -> Option<(Vec<u8>, [u8; 32])> {
        let active = self.hazmat_sessions.get(&session_id)?;
        let (block_height, attempt, validator_index, payload) =
            hazmat_complaint_message_parts(msg)?;
        if validator_index != validator.0
            || validator_index == 0
            || validator_index > active.session.total_nodes()
        {
            return None;
        }

        let mut context_material = Vec::with_capacity(76);
        context_material.extend_from_slice(&session_id);
        context_material.extend_from_slice(&block_height.to_be_bytes());
        context_material.extend_from_slice(&attempt.to_be_bytes());
        context_material.extend_from_slice(&active.session.dkg_commitment_digest());

        let context_digest =
            experimental_vss_hash(EXPERIMENTAL_VSS_CONTEXT_LABEL, &context_material);
        let statement = ExperimentalVssStatement {
            context_digest,
            dealer_index: validator_index,
            receiver_index: validator_index,
            threshold: active.session.threshold(),
            total_nodes: active.session.total_nodes(),
            dealer_commitment_digest: experimental_vss_hash(
                EXPERIMENTAL_VSS_DEALER_COMMITMENT_LABEL,
                wire_frame,
            ),
            share_digest: experimental_vss_hash(EXPERIMENTAL_VSS_SHARE_LABEL, payload),
        };
        let statement_digest = experimental_vss_statement_digest(&statement).ok()?;
        let opening = ExperimentalVssOpening {
            context_digest,
            dealer_index: validator_index,
            receiver_index: validator_index,
            encrypted_share_digest: experimental_vss_hash(
                EXPERIMENTAL_VSS_ENCRYPTED_SHARE_LABEL,
                payload,
            ),
            opening_digest: experimental_vss_hash(EXPERIMENTAL_VSS_OPENING_LABEL, wire_frame),
            encrypted_share_len: u32::try_from(payload.len()).ok()?,
        };
        let proof = ExperimentalVssProof {
            statement_digest,
            proof_digest: experimental_vss_hash(
                EXPERIMENTAL_VSS_ADAPTER_ERROR_LABEL,
                format!("{err:?}").as_bytes(),
            ),
        };
        let complaint_bytes = ExperimentalVssComplaintEvidence {
            statement,
            opening,
            proof,
        }
        .to_canonical_bytes()
        .ok()?;
        let production_statement = ProductionVssRelationStatement {
            protocol_version: PRODUCTION_VSS_RELATION_STATEMENT_SCHEMA_VERSION,
            epoch_id: experimental_vss_hash(PRODUCTION_EPOCH_LABEL, &context_material),
            session_id,
            validator_set_digest: production_validator_set_digest(
                active.session.threshold(),
                active.session.total_nodes(),
            ),
            backend_id: experimental_vss_hash(
                EXPERIMENTAL_VSS_BACKEND_LABEL,
                EXPERIMENTAL_VSS_PRODUCTION_RELATION_BACKEND_ID,
            ),
            dealer_index: validator_index,
            receiver_index: validator_index,
            threshold: active.session.threshold(),
            total_nodes: active.session.total_nodes(),
            dealer_commitment_digest: experimental_vss_hash(
                EXPERIMENTAL_VSS_DEALER_COMMITMENT_LABEL,
                wire_frame,
            ),
            encrypted_share_digest: experimental_vss_hash(
                EXPERIMENTAL_VSS_ENCRYPTED_SHARE_LABEL,
                payload,
            ),
            opening_digest: experimental_vss_hash(EXPERIMENTAL_VSS_OPENING_LABEL, wire_frame),
            public_key_contribution_digest: experimental_vss_hash(
                EXPERIMENTAL_VSS_PUBLIC_KEY_CONTRIBUTION_LABEL,
                &active.session.dkg_commitment_digest(),
            ),
        };
        let production_statement_digest = production_statement.statement_digest().ok()?;
        Some((complaint_bytes, production_statement_digest))
    }

    async fn reap_stale_sessions(&mut self) {
        let now = Instant::now();
        let stale_sessions = self
            .active_sessions
            .iter()
            .filter_map(|(session_id, active)| {
                (now.duration_since(active.created_at) > self.config.round_timeout)
                    .then_some(*session_id)
            })
            .collect::<Vec<_>>();

        for session_id in stale_sessions {
            let Some(active) = self.active_sessions.remove(&session_id) else {
                continue;
            };
            for validator in active.commitments.keys().copied() {
                if validator == self.config.local_validator
                    || active.partials.contains_key(&validator)
                {
                    continue;
                }
                let evidence = SlashingEvidence::new(
                    session_id,
                    validator,
                    EvidenceKind::CommitmentWithoutPartial,
                    None,
                    "validator committed but did not submit partial signature before timeout",
                );
                let _ = self.consensus.submit_slashing_evidence(evidence).await;
            }
        }
    }

    fn try_generate_local_partial(&mut self, session_id: SessionId) {
        let Some(active) = self.active_sessions.get_mut(&session_id) else {
            return;
        };
        if active.session.is_none()
            || active.partials.contains_key(&self.config.local_validator)
            || active.commitments.len() < self.config.threshold as usize
            || active.commitments.get(&self.config.local_validator)
                != Some(&active.local_commitment)
        {
            return;
        }

        let commitments = active
            .commitments
            .iter()
            .map(|(validator, commitment)| (*validator, *commitment))
            .collect::<Vec<_>>();
        let Ok(commitment_set) = CommitmentSet::new(
            self.config.validator_set.clone(),
            self.config.threshold,
            commitments,
        ) else {
            return;
        };
        let Some(session) = active.session.take() else {
            return;
        };
        let Ok((_, partial)) = SigningSession::generate_partial_signature(
            session,
            commitment_set,
            &active.message_hash,
        ) else {
            return;
        };
        active.partials.insert(self.config.local_validator, partial);
    }

    async fn try_finalize_session(&mut self, session_id: SessionId) {
        let Some(active) = self.active_sessions.get(&session_id) else {
            return;
        };
        if active.finalized || active.partials.len() < self.config.threshold as usize {
            return;
        }

        let result = self.build_signature(session_id);
        let Ok((block_height, signature)) = result else {
            self.active_sessions.remove(&session_id);
            return;
        };

        if let Some(active) = self.active_sessions.get_mut(&session_id) {
            active.finalized = true;
        }
        if self
            .consensus
            .on_signature_finalized(block_height, signature)
            .await
            .is_ok()
        {
            self.active_sessions.remove(&session_id);
        }
    }

    fn build_signature(&self, session_id: SessionId) -> Result<(u64, Vec<u8>), ThresholdError> {
        let active = self
            .active_sessions
            .get(&session_id)
            .ok_or(ThresholdError::TranscriptMismatch)?;
        let commitments = active
            .commitments
            .iter()
            .map(|(validator, commitment)| (*validator, *commitment))
            .collect::<Vec<_>>();
        let commitment_set = CommitmentSet::new(
            self.config.validator_set.clone(),
            self.config.threshold,
            commitments,
        )?;
        let transcript = ThresholdSigningTranscript::new(
            session_id,
            self.config.threshold,
            self.config.validator_set.clone(),
            self.config.public_key.clone(),
            &active.message_hash,
            commitment_set,
        )?;
        let shares = PartialShareSet::new(
            self.config.validator_set.clone(),
            self.config.threshold,
            active.partials.values().cloned().collect(),
        )?;
        let signature = SimulatedAggregator::aggregate_shares(transcript, shares)?;

        Ok((active.block_height, signature.0.to_vec()))
    }

    fn is_known_validator(&self, validator: ValidatorId) -> bool {
        self.config.validator_set.contains(&validator)
    }
}

#[cfg(all(feature = "hazmat-real-mldsa", feature = "experimental-vss"))]
fn hazmat_complaint_message_parts(msg: &PqcThresholdWireMsg) -> Option<(u64, u16, u16, &[u8])> {
    match msg {
        PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
            block_height,
            attempt,
            validator_index,
            payload,
            ..
        }
        | PqcThresholdWireMsg::HazmatMldsa65SecretContribution {
            block_height,
            attempt,
            validator_index,
            payload,
            ..
        }
        | PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
            block_height,
            attempt,
            validator_index,
            payload,
            ..
        } if !payload.is_empty() => Some((
            *block_height,
            *attempt,
            *validator_index,
            payload.as_slice(),
        )),
        _ => None,
    }
}

#[cfg(feature = "hazmat-real-mldsa")]
/// Build a production-target contribution statement from the current scaffold statement.
///
/// This is a canonical public-input derivation helper only. It does not verify
/// a production contribution proof relation.
pub fn production_contribution_statement_from_scaffold(
    statement: &ContributionStatement,
    threshold: u16,
    total_nodes: u16,
    mu: &[u8; MLDSA65_MU_BYTES],
    payload: &[u8],
) -> Result<ProductionContributionStatement, ThresholdError> {
    Ok(ProductionContributionStatement {
        protocol_version: PRODUCTION_CONTRIBUTION_STATEMENT_SCHEMA_VERSION,
        epoch_id: production_epoch_id(
            statement.session_id,
            statement.block_height,
            statement.dkg_commitment_digest,
        ),
        session_id: statement.session_id,
        block_height: statement.block_height,
        attempt: statement.attempt,
        validator_index: statement.validator_index,
        threshold,
        total_nodes,
        validator_set_digest: production_validator_set_digest(threshold, total_nodes),
        public_key_digest: production_hash(
            PRODUCTION_PUBLIC_KEY_LABEL,
            &statement.dkg_commitment_digest,
        ),
        parameter_set_digest: production_hash(
            PRODUCTION_PARAMETER_SET_LABEL,
            PRODUCTION_CONTRIBUTION_PARAMETER_SET_ID,
        ),
        mu: *mu,
        challenge: statement.challenge,
        dkg_commitment_digest: statement.dkg_commitment_digest,
        masking_commitment_digest: statement.masking_commitment_digest,
        secret_commitment_digest: statement.secret_commitment_digest,
        contribution_commitment_digest: production_hash(
            PRODUCTION_CONTRIBUTION_PAYLOAD_LABEL,
            payload,
        ),
    })
}

#[cfg(feature = "hazmat-real-mldsa")]
/// Compute the canonical production-target contribution statement digest.
pub fn production_contribution_statement_digest_from_scaffold(
    statement: &ContributionStatement,
    threshold: u16,
    total_nodes: u16,
    mu: &[u8; MLDSA65_MU_BYTES],
    payload: &[u8],
) -> Result<[u8; 32], ThresholdError> {
    production_contribution_statement_from_scaffold(statement, threshold, total_nodes, mu, payload)?
        .statement_digest()
}

#[cfg(feature = "hazmat-real-mldsa")]
fn production_epoch_id(
    session_id: SessionId,
    block_height: u64,
    dkg_commitment_digest: [u8; 32],
) -> [u8; 32] {
    let mut material = Vec::with_capacity(72);
    material.extend_from_slice(&session_id);
    material.extend_from_slice(&block_height.to_be_bytes());
    material.extend_from_slice(&dkg_commitment_digest);
    production_hash(PRODUCTION_EPOCH_LABEL, &material)
}

#[cfg(feature = "hazmat-real-mldsa")]
fn production_validator_set_digest(threshold: u16, total_nodes: u16) -> [u8; 32] {
    let mut material = Vec::with_capacity(4 + usize::from(total_nodes) * 2);
    material.extend_from_slice(&threshold.to_be_bytes());
    material.extend_from_slice(&total_nodes.to_be_bytes());
    for validator in 1..=total_nodes {
        material.extend_from_slice(&validator.to_be_bytes());
    }
    production_hash(PRODUCTION_VALIDATOR_SET_LABEL, &material)
}

#[cfg(feature = "hazmat-real-mldsa")]
fn production_hash(domain: &[u8], material: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Sha3Digest::update(&mut hasher, PRODUCTION_CONTEXT_DOMAIN);
    Sha3Digest::update(&mut hasher, domain);
    Sha3Digest::update(&mut hasher, material);
    hasher.finalize().into()
}

#[cfg(all(feature = "hazmat-real-mldsa", feature = "experimental-vss"))]
fn experimental_vss_hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Sha3Digest::update(&mut hasher, EXPERIMENTAL_VSS_COMPLAINT_DOMAIN);
    Sha3Digest::update(&mut hasher, (domain.len() as u64).to_be_bytes());
    Sha3Digest::update(&mut hasher, domain);
    Sha3Digest::update(&mut hasher, (payload.len() as u64).to_be_bytes());
    Sha3Digest::update(&mut hasher, payload);
    hasher.finalize().into()
}
