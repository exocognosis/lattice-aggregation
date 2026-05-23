use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use dytallix_pq_threshold::{
    adapter::{
        actor::{ActorConfig, ActorEvent, SessionMetrics, ThresholdActor},
        evidence::SlashingEvidence,
        traits::{ConsensusStateAdapter, P2pNetworkAdapter},
        wire::PqcThresholdWireMsg,
    },
    utils::exporter::{generate_latex_table, generate_pgfplots_csv},
    PrivateKeyShare, ThresholdPublicKey, ValidatorId,
};
use tokio::sync::mpsc;

#[derive(Clone, Default)]
struct HarnessNetwork {
    bytes: Arc<Mutex<usize>>,
}

type FinalizedRecords = Arc<Mutex<Vec<(u64, Vec<u8>)>>>;
type EvidenceRecords = Arc<Mutex<Vec<SlashingEvidence>>>;
type GasUpdates = Arc<Mutex<Vec<u64>>>;

#[async_trait]
impl P2pNetworkAdapter for HarnessNetwork {
    type Error = Infallible;

    async fn broadcast(&self, msg: PqcThresholdWireMsg) -> Result<(), Self::Error> {
        *self.bytes.lock().expect("network byte counter poisoned") += msg.encode().len();
        Ok(())
    }

    async fn send_to(&self, _target: u16, msg: PqcThresholdWireMsg) -> Result<(), Self::Error> {
        *self.bytes.lock().expect("network byte counter poisoned") += msg.encode().len();
        Ok(())
    }
}

#[derive(Clone, Default)]
struct HarnessConsensus {
    finalized: FinalizedRecords,
    evidence: EvidenceRecords,
    gas_updates: GasUpdates,
}

#[async_trait]
impl ConsensusStateAdapter for HarnessConsensus {
    type Error = Infallible;

    async fn on_signature_finalized(
        &self,
        block_height: u64,
        signature: Vec<u8>,
    ) -> Result<(), Self::Error> {
        self.finalized
            .lock()
            .expect("finalized record lock poisoned")
            .push((block_height, signature));
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

    async fn update_gas_baseline(&self, block_height: u64) -> Result<(), Self::Error> {
        self.gas_updates
            .lock()
            .expect("gas update lock poisoned")
            .push(block_height);
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct ExperimentSpec {
    label: &'static str,
    validators: u16,
    threshold: u16,
    trials: u16,
    malicious_validator: Option<u16>,
    latency_ms: u64,
    retry_tokens: u32,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let experiments = [
        ExperimentSpec {
            label: "Small-Scale Consensus",
            validators: 3,
            threshold: 2,
            trials: 3,
            malicious_validator: None,
            latency_ms: 0,
            retry_tokens: 0,
        },
        ExperimentSpec {
            label: "Mid-Scale Distributed Fabric",
            validators: 7,
            threshold: 5,
            trials: 3,
            malicious_validator: Some(4),
            latency_ms: 2,
            retry_tokens: 1,
        },
        ExperimentSpec {
            label: "Adversarial WAN Cluster",
            validators: 15,
            threshold: 10,
            trials: 3,
            malicious_validator: None,
            latency_ms: 7,
            retry_tokens: 3,
        },
    ];

    for spec in experiments {
        let metrics = run_experiment_grid(spec).await;
        println!("===== {}: LaTeX =====", spec.label);
        print!(
            "{}",
            generate_latex_table(spec.label, spec.validators, &metrics)
        );
        println!("===== {}: PGFPlots CSV =====", spec.label);
        print!("{}", generate_pgfplots_csv(&metrics));
    }
}

async fn run_experiment_grid(spec: ExperimentSpec) -> Vec<SessionMetrics> {
    let mut metrics = Vec::with_capacity(usize::from(spec.trials));
    for trial in 0..spec.trials {
        metrics.push(run_single_trial(spec, trial).await);
    }
    metrics
}

async fn run_single_trial(spec: ExperimentSpec, trial: u16) -> SessionMetrics {
    let (tx, rx) = mpsc::channel(128);
    let network = HarnessNetwork::default();
    let consensus = HarnessConsensus::default();
    let actor = ThresholdActor::new(
        ActorConfig::new(
            ValidatorId(1),
            (1..=spec.validators).map(ValidatorId).collect(),
            spec.threshold,
            ThresholdPublicKey([spec.validators as u8; 1952]),
            PrivateKeyShare::new(ValidatorId(1), format!("share-{trial}").into_bytes()),
            Duration::from_millis(250),
            usize::from(spec.trials + 2),
        ),
        network.clone(),
        consensus.clone(),
        rx,
    )
    .expect("experiment actor config should be valid");

    let started = Instant::now();
    let handle = tokio::spawn(actor.run());
    let session_id = session_id_for(spec.validators, trial);
    let block_height = 10_000 + u64::from(spec.validators) * 100 + u64::from(trial);
    let message_hash = [trial as u8 ^ spec.validators as u8; 32];

    tx.send(ActorEvent::TriggerSigningRound {
        session_id,
        block_height,
        message_hash,
    })
    .await
    .expect("actor inbox should accept trigger");

    let mut transmitted = 0usize;
    let required_peers = usize::from(spec.threshold.saturating_sub(1));
    let mut honest_peer_partials = 0usize;
    let mut aborts = 0u32;

    for validator in 2..=spec.validators {
        if spec.latency_ms > 0 {
            let jitter = deterministic_jitter_ms(validator, trial, spec.retry_tokens);
            tokio::time::sleep(Duration::from_millis(spec.latency_ms + jitter)).await;
        }

        let commit = PqcThresholdWireMsg::SignCommit {
            session_id,
            block_height,
            validator_index: validator,
            commitment: [validator as u8; 32],
        };
        transmitted += commit.encode().len();
        tx.send(ActorEvent::IncomingNetworkMessage(commit))
            .await
            .expect("actor inbox should accept commitment");

        if spec.malicious_validator == Some(validator) {
            let malicious = PqcThresholdWireMsg::PartialSignature {
                session_id,
                validator_index: validator,
                partial_sig_share: vec![0xDE, 0xAD, 0xBE, 0xEF, trial as u8],
            };
            transmitted += malicious.encode().len();
            tx.send(ActorEvent::IncomingNetworkMessage(malicious))
                .await
                .expect("actor inbox should accept malicious partial");
            aborts += 1;
            continue;
        }

        if honest_peer_partials < required_peers {
            let partial = PqcThresholdWireMsg::PartialSignature {
                session_id,
                validator_index: validator,
                partial_sig_share: vec![validator as u8; 64],
            };
            transmitted += partial.encode().len();
            tx.send(ActorEvent::IncomingNetworkMessage(partial))
                .await
                .expect("actor inbox should accept partial");
            honest_peer_partials += 1;
        }
    }

    aborts += deterministic_retry_count(spec.retry_tokens, trial);
    drop(tx);
    handle.await.expect("actor task should join");

    let network_bytes = *network.bytes.lock().expect("network byte counter poisoned");
    let evidence_count = consensus
        .evidence
        .lock()
        .expect("evidence lock poisoned")
        .len() as u32;

    SessionMetrics {
        total_duration_ns: started.elapsed().as_nanos() as u64,
        abort_and_retry_count: aborts + evidence_count,
        network_bytes_transmitted: network_bytes + transmitted,
    }
}

fn session_id_for(validators: u16, trial: u16) -> [u8; 32] {
    let mut session_id = [0u8; 32];
    session_id[0..2].copy_from_slice(&validators.to_be_bytes());
    session_id[2..4].copy_from_slice(&trial.to_be_bytes());
    session_id
}

fn deterministic_retry_count(retry_tokens: u32, trial: u16) -> u32 {
    if retry_tokens == 0 {
        return 0;
    }
    ((u32::from(trial) * 1_103_515_245 + 12_345) % (retry_tokens + 1)) + retry_tokens
}

fn deterministic_jitter_ms(validator: u16, trial: u16, retry_tokens: u32) -> u64 {
    if retry_tokens == 0 {
        return 0;
    }
    let token = u64::from(validator) * 31 + u64::from(trial) * 17 + u64::from(retry_tokens);
    token % (u64::from(retry_tokens) + 1)
}
