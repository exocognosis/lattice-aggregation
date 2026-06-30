//! In-memory local validator-network runner for adapter orchestration tests.
//!
//! This runner exercises multiple `ThresholdActor` instances through the
//! adapter traits. It still uses the deterministic simulation backend and is
//! local engineering telemetry only.

use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::{
    adapter::{
        actor::{ActorConfig, ActorEvent, ThresholdActor},
        evidence::SlashingEvidence,
        traits::{ConsensusStateAdapter, P2pNetworkAdapter},
        wire::PqcThresholdWireMsg,
    },
    PrivateKeyShare, ThresholdError, ThresholdPublicKey, ValidatorId,
};

/// Localnet runner claim boundary.
pub const LOCALNET_CLAIM_BOUNDARY: &str = "local validator-network engineering telemetry; not security evidence; not real-world validator performance; not production-readiness evidence; not production network liveness, authenticated transport, or consensus safety; not side-channel resistance; not CAVP/ACVTS validation; not FIPS validation; not production threshold ML-DSA security";

const DEFAULT_ROUND_TIMEOUT: Duration = Duration::from_millis(250);
const DEFAULT_MAX_SESSIONS: usize = 4;
const DEFAULT_BLOCK_HEIGHT: u64 = 70_000;
const DEFAULT_SESSION_ID: [u8; 32] = [0xA7; 32];
const DEFAULT_MESSAGE_HASH: [u8; 32] = [0x4C; 32];

/// Configuration for a bounded in-memory validator localnet run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalnetConfig {
    /// Number of local validator actors.
    pub validator_count: u16,
    /// Signing threshold for the session.
    pub threshold: u16,
    /// Actor round timeout.
    pub round_timeout: Duration,
    /// Maximum active sessions per actor.
    pub max_sessions: usize,
}

impl LocalnetConfig {
    /// Construct a default localnet configuration for one signing session.
    pub fn new(validator_count: u16, threshold: u16) -> Self {
        Self {
            validator_count,
            threshold,
            round_timeout: DEFAULT_ROUND_TIMEOUT,
            max_sessions: DEFAULT_MAX_SESSIONS,
        }
    }
}

/// Finalization observed from one local validator actor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalnetFinalizedEvent {
    /// Validator that reported finalization.
    pub validator: ValidatorId,
    /// Block height finalized by the actor.
    pub block_height: u64,
    /// Length of the finalized signature bytes.
    pub signature_bytes: usize,
}

/// Summary of one in-memory localnet run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalnetReport {
    /// Explicit non-proof claim boundary.
    pub claim_boundary: &'static str,
    /// Number of local validator actors.
    pub validator_count: u16,
    /// Signing threshold.
    pub threshold: u16,
    /// Finalization events reported by local actors.
    pub finalized: Vec<LocalnetFinalizedEvent>,
    /// Number of local adapter evidence records.
    pub evidence_count: usize,
    /// Number of logical broadcast calls.
    pub broadcast_count: usize,
    /// Number of direct-send calls.
    pub direct_send_count: usize,
    /// Fanout-adjusted wire bytes sent through the in-memory network.
    pub network_bytes: usize,
}

/// Run one deterministic in-memory validator localnet session.
pub async fn run_localnet(config: LocalnetConfig) -> Result<LocalnetReport, ThresholdError> {
    validate_localnet_config(config)?;

    let validator_set = (1..=config.validator_count)
        .map(ValidatorId)
        .collect::<Vec<_>>();
    let hub = InMemoryNetworkHub::default();
    let finalized = Shared::default();
    let evidence = Shared::default();
    let public_key = ThresholdPublicKey([config.validator_count as u8; 1952]);

    let mut senders = Vec::with_capacity(usize::from(config.validator_count));
    let mut handles = Vec::with_capacity(usize::from(config.validator_count));

    for validator in validator_set.iter().copied() {
        let (tx, rx) = mpsc::channel(256);
        hub.register(validator, tx.clone());
        senders.push(tx);
        let actor = ThresholdActor::new(
            ActorConfig::new(
                validator,
                validator_set.clone(),
                config.threshold,
                public_key.clone(),
                PrivateKeyShare::new(
                    validator,
                    format!("localnet-share-{}", validator.0).into_bytes(),
                ),
                config.round_timeout,
                config.max_sessions,
            ),
            InMemoryNetworkEndpoint {
                local_validator: validator,
                hub: hub.clone(),
            },
            LocalnetConsensus {
                validator,
                finalized: finalized.clone(),
                evidence: evidence.clone(),
            },
            rx,
        )?;
        handles.push(tokio::spawn(actor.run()));
    }

    for tx in &senders {
        tx.send(ActorEvent::TriggerSigningRound {
            session_id: DEFAULT_SESSION_ID,
            block_height: DEFAULT_BLOCK_HEIGHT,
            message_hash: DEFAULT_MESSAGE_HASH,
        })
        .await
        .map_err(|_| ThresholdError::BackendUnavailable {
            reason: "localnet actor inbox closed",
        })?;
    }

    wait_for_finalizations(&finalized, usize::from(config.validator_count)).await?;
    hub.clear();
    drop(senders);
    for handle in handles {
        let _ = handle.await;
    }

    let metrics = hub.metrics();
    let finalized = finalized.lock().expect("finalized lock poisoned").clone();
    let evidence_count = evidence.lock().expect("evidence lock poisoned").len();
    Ok(LocalnetReport {
        claim_boundary: LOCALNET_CLAIM_BOUNDARY,
        validator_count: config.validator_count,
        threshold: config.threshold,
        finalized,
        evidence_count,
        broadcast_count: metrics.broadcast_count,
        direct_send_count: metrics.direct_send_count,
        network_bytes: metrics.network_bytes,
    })
}

fn validate_localnet_config(config: LocalnetConfig) -> Result<(), ThresholdError> {
    if config.threshold == 0
        || config.validator_count == 0
        || config.threshold > config.validator_count
    {
        return Err(ThresholdError::InvalidThresholdParameters {
            threshold: config.threshold,
            total_nodes: config.validator_count,
        });
    }
    Ok(())
}

async fn wait_for_finalizations(
    finalized: &Shared<Vec<LocalnetFinalizedEvent>>,
    expected: usize,
) -> Result<(), ThresholdError> {
    for _ in 0..100 {
        if finalized.lock().expect("finalized lock poisoned").len() >= expected {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Err(ThresholdError::BackendUnavailable {
        reason: "localnet did not finalize all validators before timeout",
    })
}

type Shared<T> = Arc<Mutex<T>>;

#[derive(Clone, Default)]
struct InMemoryNetworkHub {
    inner: Shared<InMemoryNetworkHubInner>,
}

#[derive(Default)]
struct InMemoryNetworkHubInner {
    senders: BTreeMap<ValidatorId, mpsc::Sender<ActorEvent>>,
    metrics: NetworkMetrics,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct NetworkMetrics {
    broadcast_count: usize,
    direct_send_count: usize,
    network_bytes: usize,
}

impl InMemoryNetworkHub {
    fn register(&self, validator: ValidatorId, sender: mpsc::Sender<ActorEvent>) {
        self.inner
            .lock()
            .expect("network hub lock poisoned")
            .senders
            .insert(validator, sender);
    }

    fn clear(&self) {
        self.inner
            .lock()
            .expect("network hub lock poisoned")
            .senders
            .clear();
    }

    fn metrics(&self) -> NetworkMetrics {
        self.inner
            .lock()
            .expect("network hub lock poisoned")
            .metrics
    }
}

#[derive(Clone)]
struct InMemoryNetworkEndpoint {
    local_validator: ValidatorId,
    hub: InMemoryNetworkHub,
}

#[async_trait]
impl P2pNetworkAdapter for InMemoryNetworkEndpoint {
    type Error = Infallible;

    async fn broadcast(&self, msg: PqcThresholdWireMsg) -> Result<(), Self::Error> {
        let encoded = msg.encode();
        let decoded =
            PqcThresholdWireMsg::decode(&encoded).expect("localnet should emit valid wire frames");
        let recipients = {
            let mut inner = self.hub.inner.lock().expect("network hub lock poisoned");
            let recipients = inner
                .senders
                .iter()
                .filter_map(|(validator, sender)| {
                    (*validator != self.local_validator).then_some(sender.clone())
                })
                .collect::<Vec<_>>();
            inner.metrics.broadcast_count += 1;
            inner.metrics.network_bytes += encoded.len() * recipients.len();
            recipients
        };
        for sender in recipients {
            let _ = sender
                .send(ActorEvent::IncomingNetworkMessage(decoded.clone()))
                .await;
        }
        Ok(())
    }

    async fn send_to(&self, target: u16, msg: PqcThresholdWireMsg) -> Result<(), Self::Error> {
        let encoded = msg.encode();
        let decoded =
            PqcThresholdWireMsg::decode(&encoded).expect("localnet should emit valid wire frames");
        let recipient = {
            let mut inner = self.hub.inner.lock().expect("network hub lock poisoned");
            let recipient = inner.senders.get(&ValidatorId(target)).cloned();
            inner.metrics.direct_send_count += 1;
            if recipient.is_some() {
                inner.metrics.network_bytes += encoded.len();
            }
            recipient
        };
        if let Some(sender) = recipient {
            let _ = sender
                .send(ActorEvent::IncomingNetworkMessage(decoded))
                .await;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct LocalnetConsensus {
    validator: ValidatorId,
    finalized: Shared<Vec<LocalnetFinalizedEvent>>,
    evidence: Shared<Vec<SlashingEvidence>>,
}

#[async_trait]
impl ConsensusStateAdapter for LocalnetConsensus {
    type Error = Infallible;

    async fn on_signature_finalized(
        &self,
        block_height: u64,
        signature: Vec<u8>,
    ) -> Result<(), Self::Error> {
        self.finalized
            .lock()
            .expect("finalized lock poisoned")
            .push(LocalnetFinalizedEvent {
                validator: self.validator,
                block_height,
                signature_bytes: signature.len(),
            });
        Ok(())
    }

    async fn submit_slashing_evidence(
        &self,
        evidence: SlashingEvidence,
    ) -> Result<(), Self::Error> {
        self.evidence
            .lock()
            .expect("evidence lock poisoned")
            .push(evidence);
        Ok(())
    }

    async fn update_gas_baseline(&self, _block_height: u64) -> Result<(), Self::Error> {
        Ok(())
    }
}
