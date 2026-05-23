//! Async threshold protocol actor scaffold.

use std::{
    collections::{BTreeMap, HashMap},
    time::{Duration, Instant},
};

use tokio::sync::mpsc;

use crate::{
    adapter::{
        traits::{ConsensusStateAdapter, P2pNetworkAdapter},
        wire::PqcThresholdWireMsg,
    },
    state, Commitment, PartialSignatureShare, PrivateKeyShare, SessionId, SigningSession,
    ThresholdError, ThresholdPublicKey, ThresholdSigner, ValidatorId,
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

/// Actor construction config.
#[derive(Clone, Debug)]
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
    _message_hash: [u8; 32],
    created_at: Instant,
    _session: SigningSession<state::AwaitingCommitments>,
    commitments: BTreeMap<ValidatorId, Commitment>,
    partials: BTreeMap<ValidatorId, PartialSignatureShare>,
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
                _message_hash: message_hash,
                created_at: Instant::now(),
                _session: session,
                commitments,
                partials: BTreeMap::new(),
            },
        );

        let msg = PqcThresholdWireMsg::SignCommit {
            session_id,
            block_height,
            validator_index: self.config.local_validator.0,
            commitment: local_commitment.0,
        };

        let _ = self.network.broadcast(msg).await;
        let _ = self.consensus.update_gas_baseline(block_height).await;
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
                let Some(active) = self.active_sessions.get_mut(&session_id) else {
                    return;
                };
                if active.block_height != block_height {
                    return;
                }
                active
                    .commitments
                    .entry(ValidatorId(validator_index))
                    .or_insert(Commitment(commitment));
            }
            PqcThresholdWireMsg::PartialSignature {
                session_id,
                validator_index,
                partial_sig_share,
            } => {
                let Some(active) = self.active_sessions.get_mut(&session_id) else {
                    return;
                };
                active
                    .partials
                    .entry(ValidatorId(validator_index))
                    .or_insert(PartialSignatureShare {
                        signer: ValidatorId(validator_index),
                        bytes: partial_sig_share,
                    });
            }
            PqcThresholdWireMsg::DkgCommit { .. }
            | PqcThresholdWireMsg::DkgShareExchange { .. } => {}
        }
    }

    async fn reap_stale_sessions(&mut self) {
        let now = Instant::now();
        self.active_sessions
            .retain(|_, active| now.duration_since(active.created_at) <= self.config.round_timeout);
    }
}
