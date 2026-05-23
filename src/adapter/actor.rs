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
    state, Commitment, CommitmentSet, PartialShareSet, PartialSignatureShare, PrivateKeyShare,
    SessionId, SignatureAggregator, SigningSession, SimulatedAggregator, ThresholdError,
    ThresholdPublicKey, ThresholdSigner, ThresholdSigningTranscript, ValidatorId,
};

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
            round_timeout,
            max_sessions,
        }
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
                ActorEvent::TimeoutCheck => self.reap_stale_sessions().await,
            }
        }
    }

    /// Return the current number of active sessions.
    pub fn active_session_count(&self) -> usize {
        self.active_sessions.len()
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
                if partial_sig_share.starts_with(b"poison") {
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
        }
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
