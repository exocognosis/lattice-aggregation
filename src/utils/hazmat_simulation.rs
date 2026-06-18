//! Real hazmat ML-DSA-65 in-memory benchmark simulation grid.

use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use sha3::{Digest as Sha3Digest, Sha3_256};
use tokio::sync::mpsc;

use crate::{
    adapter::{
        actor::{
            production_contribution_statement_digest_from_scaffold, ActorConfig, ActorEvent,
            SessionMetrics, ThresholdActor,
        },
        evidence::SlashingEvidence,
        traits::{ConsensusStateAdapter, P2pNetworkAdapter},
        wire::PqcThresholdWireMsg,
    },
    crypto::contribution_proof::{prove_contribution, ContributionStatement, ContributionWitness},
    mldsa65::{
        derive_mldsa65_expanded_secret_key_from_seed,
        derive_mldsa65_masking_contribution_from_share,
        derive_mldsa65_public_key_from_expanded_secret_key,
        derive_mldsa65_secret_contribution_from_share, encode_mldsa65_masking_contribution,
        encode_mldsa65_secret_contribution, masking_commitment_digest, secret_commitment_digest,
        sign_mldsa65_internal_mu_deterministic_from_expanded_secret_key,
        split_mldsa65_expanded_secret_key, verify_mldsa65_internal_mu, MLDSA65_MU_BYTES,
    },
    utils::hazmat_artifacts::{event_from_hazmat_wire_frame, HazmatTranscriptEvent},
    PrivateKeyShare, ThresholdPublicKey, ThresholdSignature, ValidatorId,
};

#[cfg(feature = "experimental-vss")]
use crate::utils::hazmat_artifacts::{
    experimental_vss_complaint_artifacts_from_evidence, ExperimentalVssComplaintArtifact,
};

const MAX_ATTEMPTS: u16 = 24;

type FinalizedRecords = Arc<Mutex<Vec<(u64, Vec<u8>)>>>;
type EvidenceRecords = Arc<Mutex<Vec<SlashingEvidence>>>;
type GasUpdates = Arc<Mutex<Vec<u64>>>;
type TranscriptRecords = Arc<Mutex<Vec<HazmatTranscriptEvent>>>;

/// Network behavior profile for an in-memory hazmat benchmark run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkProfile {
    /// No artificial delay or retries.
    IdealLocalMesh,
    /// Small bounded delay used for regional distributed-validator tests.
    DistributedFabric {
        /// Base latency applied to each peer message.
        latency_ms: u64,
    },
    /// Higher bounded latency plus deterministic retry pressure.
    AdversarialWan {
        /// Base latency applied to each peer message.
        latency_ms: u64,
        /// Deterministic retry pressure added to metrics.
        retry_tokens: u32,
    },
}

/// Byzantine behavior injected into one trial.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ByzantineMode {
    /// Every validator submits well-formed contributions.
    None,
    /// One validator sends a malformed masking contribution before honest quorum completes.
    TamperMaskingContribution {
        /// One-based validator index.
        validator: u16,
    },
    /// One validator sends a malformed secret contribution after challenge derivation.
    TamperSecretContribution {
        /// One-based validator index.
        validator: u16,
    },
}

/// One benchmark experiment profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HazmatExperimentSpec {
    /// Human-readable experiment label for publication tables.
    pub label: &'static str,
    /// Total validator count.
    pub validators: u16,
    /// Signing threshold.
    pub threshold: u16,
    /// Number of independent trials.
    pub trials: u16,
    /// Network simulation profile.
    pub network: NetworkProfile,
    /// Byzantine behavior profile.
    pub byzantine: ByzantineMode,
    /// Base masking seed.
    pub masking_seed: [u8; MLDSA65_MU_BYTES],
    /// Base internal ML-DSA `mu` digest.
    pub mu: [u8; MLDSA65_MU_BYTES],
}

impl HazmatExperimentSpec {
    /// Run this profile and collect publication-oriented telemetry.
    pub async fn run(self) -> HazmatExperimentReport {
        let mut metrics = Vec::with_capacity(usize::from(self.trials));
        let mut finalized_signatures = Vec::with_capacity(usize::from(self.trials));
        let mut transcript_events = Vec::new();
        #[cfg(feature = "experimental-vss")]
        let mut experimental_vss_complaint_events = Vec::new();
        let mut slashing_evidence_count = 0u32;

        for trial in 0..self.trials {
            let trial = run_hazmat_trial(self, trial).await;
            metrics.push(trial.metrics);
            finalized_signatures.extend(trial.finalized_signatures);
            transcript_events.extend(trial.transcript_events);
            #[cfg(feature = "experimental-vss")]
            experimental_vss_complaint_events.extend(trial.experimental_vss_complaint_events);
            slashing_evidence_count += trial.slashing_evidence_count;
        }

        HazmatExperimentReport {
            spec: self,
            metrics,
            finalized_signatures,
            transcript_events,
            #[cfg(feature = "experimental-vss")]
            experimental_vss_complaint_events,
            slashing_evidence_count,
        }
    }
}

/// Aggregated output for one benchmark profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HazmatExperimentReport {
    /// Experiment specification used to produce this report.
    pub spec: HazmatExperimentSpec,
    /// Per-trial session metrics.
    pub metrics: Vec<SessionMetrics>,
    /// Standard ML-DSA-65 signature bytes finalized by each successful trial.
    pub finalized_signatures: Vec<Vec<u8>>,
    /// Replay-oriented hazmat transcript events captured from benchmark wire frames.
    pub transcript_events: Vec<HazmatTranscriptEvent>,
    /// Replay-oriented experimental VSS complaint evidence artifacts.
    #[cfg(feature = "experimental-vss")]
    pub experimental_vss_complaint_events: Vec<ExperimentalVssComplaintArtifact>,
    /// Total slashing evidence records emitted during this profile.
    pub slashing_evidence_count: u32,
}

/// Deterministic single-signer ML-DSA-65 baseline row for one threshold trial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mldsa65SingleSignerBaseline {
    /// Experiment label joined to the threshold report.
    pub profile: &'static str,
    /// Total validator count in the corresponding threshold profile.
    pub validators: u16,
    /// Threshold in the corresponding threshold profile.
    pub threshold: u16,
    /// Trial index in the corresponding threshold profile.
    pub trial: u16,
    /// Deterministic key seed digest for reproducibility without exposing the seed.
    pub seed_digest: [u8; 32],
    /// Public-key digest for stable artifact joins.
    pub public_key_digest: [u8; 32],
    /// Baseline signature digest for reproducibility checks.
    pub signature_digest: [u8; 32],
    /// Baseline signature byte length.
    pub signature_bytes: usize,
    /// Deterministic sign duration in nanoseconds.
    pub sign_duration_ns: u64,
    /// Deterministic verify duration in nanoseconds.
    pub verify_duration_ns: u64,
    /// Whether the baseline signature verifies under standard internal-`mu` verification.
    pub verified: bool,
}

struct HazmatTrialReport {
    metrics: SessionMetrics,
    finalized_signatures: Vec<Vec<u8>>,
    transcript_events: Vec<HazmatTranscriptEvent>,
    #[cfg(feature = "experimental-vss")]
    experimental_vss_complaint_events: Vec<ExperimentalVssComplaintArtifact>,
    slashing_evidence_count: u32,
}

fn single_signer_baseline_for_report_trial(
    report: &HazmatExperimentReport,
    trial: u16,
) -> Mldsa65SingleSignerBaseline {
    let seed = keygen_seed(report.spec.validators, trial, 0);
    let secret = derive_mldsa65_expanded_secret_key_from_seed(&seed)
        .expect("baseline key derivation must succeed for deterministic seed");
    let public_key = ThresholdPublicKey(
        *derive_mldsa65_public_key_from_expanded_secret_key(secret.as_bytes())
            .expect("baseline public key derivation must succeed")
            .as_bytes(),
    );
    let mu = derived_mu(report.spec.mu, trial, 0);

    let sign_started = Instant::now();
    let signature =
        sign_mldsa65_internal_mu_deterministic_from_expanded_secret_key(secret.as_bytes(), &mu)
            .expect("deterministic baseline signing must succeed");
    let sign_duration_ns = sign_started.elapsed().as_nanos() as u64;

    let threshold_signature = ThresholdSignature(*signature.as_bytes());
    let verify_started = Instant::now();
    let verified = verify_mldsa65_internal_mu(&public_key, &mu, &threshold_signature)
        .expect("baseline internal-mu verification must run");
    let verify_duration_ns = verify_started.elapsed().as_nanos() as u64;

    Mldsa65SingleSignerBaseline {
        profile: report.spec.label,
        validators: report.spec.validators,
        threshold: report.spec.threshold,
        trial,
        seed_digest: digest_bytes(&seed),
        public_key_digest: digest_bytes(&public_key.0),
        signature_digest: digest_bytes(signature.as_bytes()),
        signature_bytes: signature.as_bytes().len(),
        sign_duration_ns: sign_duration_ns.max(1),
        verify_duration_ns: verify_duration_ns.max(1),
        verified,
    }
}

/// Run the three default publication benchmark profiles.
pub async fn run_hazmat_mldsa65_benchmark_suite() -> Vec<HazmatExperimentReport> {
    let specs = [
        HazmatExperimentSpec {
            label: "Small-Scale Consensus",
            validators: 3,
            threshold: 2,
            trials: 3,
            network: NetworkProfile::IdealLocalMesh,
            byzantine: ByzantineMode::None,
            masking_seed: [0x11; MLDSA65_MU_BYTES],
            mu: [0x21; MLDSA65_MU_BYTES],
        },
        HazmatExperimentSpec {
            label: "Mid-Scale Distributed Fabric",
            validators: 7,
            threshold: 5,
            trials: 3,
            network: NetworkProfile::DistributedFabric { latency_ms: 2 },
            byzantine: ByzantineMode::TamperSecretContribution { validator: 7 },
            masking_seed: [0x31; MLDSA65_MU_BYTES],
            mu: [0x41; MLDSA65_MU_BYTES],
        },
        HazmatExperimentSpec {
            label: "Adversarial WAN Cluster",
            validators: 15,
            threshold: 10,
            trials: 3,
            network: NetworkProfile::AdversarialWan {
                latency_ms: 7,
                retry_tokens: 3,
            },
            byzantine: ByzantineMode::None,
            masking_seed: [0x51; MLDSA65_MU_BYTES],
            mu: [0x61; MLDSA65_MU_BYTES],
        },
    ];

    let mut reports = Vec::with_capacity(specs.len());
    for spec in specs {
        reports.push(spec.run().await);
    }
    reports
}

/// Run deterministic single-signer ML-DSA-65 baselines for threshold reports.
pub fn run_mldsa65_single_signer_baseline_suite(
    reports: &[HazmatExperimentReport],
) -> Vec<Mldsa65SingleSignerBaseline> {
    reports
        .iter()
        .flat_map(|report| {
            (0..report.metrics.len())
                .map(move |trial| single_signer_baseline_for_report_trial(report, trial as u16))
        })
        .collect()
}

/// Generate a threshold-vs-single-signer comparison CSV.
pub fn generate_mldsa65_baseline_comparison_csv(
    reports: &[HazmatExperimentReport],
    baselines: &[Mldsa65SingleSignerBaseline],
) -> String {
    let mut output = String::from(
        "profile,validators,threshold,trial,baseline_sign_ns,baseline_verify_ns,threshold_duration_ns,threshold_bytes,signature_bytes,latency_overhead_x\n",
    );
    for report in reports {
        for (trial, metric) in report.metrics.iter().enumerate() {
            let baseline = baselines
                .iter()
                .find(|row| row.profile == report.spec.label && row.trial == trial as u16);
            let Some(baseline) = baseline else {
                continue;
            };
            let baseline_total = baseline
                .sign_duration_ns
                .saturating_add(baseline.verify_duration_ns)
                .max(1);
            let latency_overhead = metric.total_duration_ns as f64 / baseline_total as f64;
            output.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{:.4}\n",
                report.spec.label,
                report.spec.validators,
                report.spec.threshold,
                trial,
                baseline.sign_duration_ns,
                baseline.verify_duration_ns,
                metric.total_duration_ns,
                metric.network_bytes_transmitted,
                baseline.signature_bytes,
                latency_overhead
            ));
        }
    }
    output
}

#[derive(Clone)]
struct HarnessNetwork {
    trace: TraceContext,
    outbound_bytes: Arc<Mutex<usize>>,
    broadcasts: Arc<Mutex<Vec<PqcThresholdWireMsg>>>,
}

impl HarnessNetwork {
    fn new(trace: TraceContext) -> Self {
        Self {
            trace,
            outbound_bytes: Arc::new(Mutex::new(0)),
            broadcasts: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl P2pNetworkAdapter for HarnessNetwork {
    type Error = Infallible;

    async fn broadcast(&self, msg: PqcThresholdWireMsg) -> Result<(), Self::Error> {
        *self.outbound_bytes.lock().expect("byte counter poisoned") += msg.encode().len();
        self.trace.record("local_broadcast", &msg);
        self.broadcasts
            .lock()
            .expect("broadcast records poisoned")
            .push(msg);
        Ok(())
    }

    async fn send_to(&self, _target: u16, msg: PqcThresholdWireMsg) -> Result<(), Self::Error> {
        *self.outbound_bytes.lock().expect("byte counter poisoned") += msg.encode().len();
        self.trace.record("local_send_to", &msg);
        self.broadcasts
            .lock()
            .expect("broadcast records poisoned")
            .push(msg);
        Ok(())
    }
}

#[derive(Clone)]
struct TraceContext {
    experiment: &'static str,
    trial_index: u16,
    attempt_index: u16,
    records: TranscriptRecords,
}

impl TraceContext {
    fn new(
        experiment: &'static str,
        trial_index: u16,
        attempt_index: u16,
        records: TranscriptRecords,
    ) -> Self {
        Self {
            experiment,
            trial_index,
            attempt_index,
            records,
        }
    }

    fn record(&self, direction: &'static str, msg: &PqcThresholdWireMsg) {
        self.records
            .lock()
            .expect("transcript records poisoned")
            .push(event_from_hazmat_wire_frame(
                self.experiment,
                self.trial_index,
                self.attempt_index,
                direction,
                msg,
            ));
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
            .expect("finalized records poisoned")
            .push((block_height, signature));
        Ok(())
    }

    async fn submit_slashing_evidence(
        &self,
        evidence: SlashingEvidence,
    ) -> Result<(), Self::Error> {
        self.evidence
            .lock()
            .expect("evidence records poisoned")
            .push(evidence);
        Ok(())
    }

    async fn update_gas_baseline(&self, block_height: u64) -> Result<(), Self::Error> {
        self.gas_updates
            .lock()
            .expect("gas update records poisoned")
            .push(block_height);
        Ok(())
    }
}

async fn run_hazmat_trial(spec: HazmatExperimentSpec, trial: u16) -> HazmatTrialReport {
    let started = Instant::now();
    let mut total_bytes = 0usize;
    let mut aborts = deterministic_retry_count(spec.network, trial);
    let mut last_finalized = Vec::new();
    let mut transcript_events = Vec::new();
    #[cfg(feature = "experimental-vss")]
    let mut experimental_vss_complaint_events = Vec::new();
    let mut last_evidence_count = 0u32;

    for attempt in 0..MAX_ATTEMPTS {
        let trace_records = Arc::new(Mutex::new(Vec::new()));
        let trace = TraceContext::new(spec.label, trial, attempt, trace_records.clone());
        let attempt_seed = keygen_seed(spec.validators, trial, attempt);
        let secret = derive_mldsa65_expanded_secret_key_from_seed(&attempt_seed)
            .expect("hazmat key derivation must succeed for deterministic seed");
        let public_key = ThresholdPublicKey(
            *derive_mldsa65_public_key_from_expanded_secret_key(secret.as_bytes())
                .expect("public key derivation must succeed")
                .as_bytes(),
        );
        let shares =
            split_mldsa65_expanded_secret_key(secret.as_bytes(), spec.threshold, spec.validators)
                .expect("expanded key split must succeed for valid threshold");
        let network = HarnessNetwork::new(trace.clone());
        let consensus = HarnessConsensus::default();
        let (tx, rx) = mpsc::channel(usize::from(spec.validators) * 4);
        let actor = ThresholdActor::new(
            ActorConfig::new(
                ValidatorId(1),
                (1..=spec.validators).map(ValidatorId).collect(),
                spec.threshold,
                public_key,
                PrivateKeyShare::new(ValidatorId(1), format!("hazmat-share-{trial}").into_bytes()),
                Duration::from_millis(500),
                4,
            )
            .with_hazmat_mldsa65_share(shares[0].clone()),
            network.clone(),
            consensus.clone(),
            rx,
        )
        .expect("hazmat actor config must be valid");
        let handle = tokio::spawn(actor.run());

        let session_id = session_id_for(spec.validators, trial, attempt);
        let block_height = 100_000 + u64::from(spec.validators) * 100 + u64::from(trial);
        let mu = derived_mu(spec.mu, trial, attempt);
        let masking_seed = derived_mu(spec.masking_seed, trial, attempt);

        tx.send(ActorEvent::TriggerHazmatMldsa65SigningRound {
            session_id,
            block_height,
            mu,
            masking_seed,
        })
        .await
        .expect("actor inbox should accept hazmat trigger");
        wait_for_broadcast_count(&network, 1).await;

        let mut incoming_bytes = 0usize;
        if let ByzantineMode::TamperMaskingContribution { validator } = spec.byzantine {
            incoming_bytes += send_masking(
                &tx,
                &trace,
                session_id,
                block_height,
                &shares[usize::from(validator - 1)],
                masking_seed,
                true,
            )
            .await;
        }

        let honest_masking_target = usize::from(spec.threshold.saturating_sub(1));
        let mut sent_honest_masking = 0usize;
        for validator in 2..=spec.validators {
            if is_byzantine_validator(spec.byzantine, validator) {
                continue;
            }
            apply_network_delay(spec.network, validator, trial).await;
            incoming_bytes += send_masking(
                &tx,
                &trace,
                session_id,
                block_height,
                &shares[usize::from(validator - 1)],
                masking_seed,
                false,
            )
            .await;
            sent_honest_masking += 1;
            if sent_honest_masking >= honest_masking_target {
                break;
            }
        }
        wait_for_broadcast_count(&network, 2).await;

        let challenge = extract_secret_challenge(&network)
            .await
            .expect("local secret broadcast should expose challenge");
        let secret_context = SecretSendContext {
            tx: &tx,
            trace: &trace,
            session_id,
            block_height,
            masking_seed,
            threshold: spec.threshold,
            total_nodes: spec.validators,
            mu,
            challenge,
        };
        if let ByzantineMode::TamperSecretContribution { validator } = spec.byzantine {
            incoming_bytes +=
                send_secret(&secret_context, &shares[usize::from(validator - 1)], true).await;
        }

        let honest_secret_target = usize::from(spec.threshold.saturating_sub(1));
        let mut sent_honest_secret = 0usize;
        for validator in 2..=spec.validators {
            if is_byzantine_validator(spec.byzantine, validator) {
                continue;
            }
            apply_network_delay(spec.network, validator, trial).await;
            incoming_bytes +=
                send_secret(&secret_context, &shares[usize::from(validator - 1)], false).await;
            sent_honest_secret += 1;
            if sent_honest_secret >= honest_secret_target {
                break;
            }
        }

        wait_for_actor_settle(&consensus).await;
        drop(tx);
        handle.await.expect("hazmat actor task should join");

        let outbound = *network
            .outbound_bytes
            .lock()
            .expect("byte counter poisoned");
        total_bytes += incoming_bytes + outbound;
        let evidence_records = consensus
            .evidence
            .lock()
            .expect("evidence records poisoned")
            .clone();
        let evidence_count = evidence_records.len() as u32;
        last_evidence_count += evidence_count;
        aborts += evidence_count;
        #[cfg(feature = "experimental-vss")]
        experimental_vss_complaint_events.extend(
            experimental_vss_complaint_artifacts_from_evidence(
                spec.label,
                trial,
                &evidence_records,
            ),
        );
        let finalized = consensus
            .finalized
            .lock()
            .expect("finalized records poisoned")
            .iter()
            .map(|(_, signature)| signature.clone())
            .collect::<Vec<_>>();
        transcript_events.extend(
            trace_records
                .lock()
                .expect("transcript records poisoned")
                .iter()
                .cloned(),
        );
        if !finalized.is_empty() {
            last_finalized = finalized;
            break;
        }
        aborts += 1;
    }

    HazmatTrialReport {
        metrics: SessionMetrics {
            total_duration_ns: started.elapsed().as_nanos() as u64,
            abort_and_retry_count: aborts,
            network_bytes_transmitted: total_bytes,
        },
        finalized_signatures: last_finalized,
        transcript_events,
        #[cfg(feature = "experimental-vss")]
        experimental_vss_complaint_events,
        slashing_evidence_count: last_evidence_count,
    }
}

async fn send_masking(
    tx: &mpsc::Sender<ActorEvent>,
    trace: &TraceContext,
    session_id: [u8; 32],
    block_height: u64,
    share: &crate::mldsa65::Mldsa65ExpandedSecretKeyShare,
    masking_seed: [u8; MLDSA65_MU_BYTES],
    tamper: bool,
) -> usize {
    let contribution = derive_mldsa65_masking_contribution_from_share(share, &masking_seed, 0)
        .expect("masking contribution derivation must succeed");
    let mut payload = encode_mldsa65_masking_contribution(&contribution);
    if tamper {
        payload[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    }
    let commitment = PqcThresholdWireMsg::HazmatMldsa65MaskingCommitment {
        session_id,
        block_height,
        attempt: 0,
        validator_index: contribution.receiver_index(),
        commitment: masking_commitment_digest(
            &session_id,
            block_height,
            0,
            contribution.receiver_index(),
            &payload,
        ),
    };
    let frame = PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
        session_id,
        block_height,
        attempt: 0,
        validator_index: contribution.receiver_index(),
        payload,
    };
    let bytes = commitment.encode().len() + frame.encode().len();
    trace.record("remote_inbound", &commitment);
    tx.send(ActorEvent::IncomingNetworkMessage(commitment))
        .await
        .expect("actor inbox should accept masking commitment");
    trace.record("remote_inbound", &frame);
    tx.send(ActorEvent::IncomingNetworkMessage(frame))
        .await
        .expect("actor inbox should accept masking contribution");
    bytes
}

struct SecretSendContext<'a> {
    tx: &'a mpsc::Sender<ActorEvent>,
    trace: &'a TraceContext,
    session_id: [u8; 32],
    block_height: u64,
    masking_seed: [u8; MLDSA65_MU_BYTES],
    threshold: u16,
    total_nodes: u16,
    mu: [u8; MLDSA65_MU_BYTES],
    challenge: [u8; crate::mldsa65::MLDSA65_CHALLENGE_BYTES],
}

async fn send_secret(
    context: &SecretSendContext<'_>,
    share: &crate::mldsa65::Mldsa65ExpandedSecretKeyShare,
    tamper: bool,
) -> usize {
    let contribution = derive_mldsa65_secret_contribution_from_share(share, &context.challenge)
        .expect("secret contribution derivation must succeed");
    let mut payload = encode_mldsa65_secret_contribution(&contribution);
    if tamper {
        payload[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    }
    let masking_contribution =
        derive_mldsa65_masking_contribution_from_share(share, &context.masking_seed, 0)
            .expect("masking contribution derivation must succeed");
    let masking_payload = encode_mldsa65_masking_contribution(&masking_contribution);
    let masking_digest = masking_commitment_digest(
        &context.session_id,
        context.block_height,
        0,
        contribution.receiver_index(),
        &masking_payload,
    );
    let secret_digest = secret_commitment_digest(
        &context.session_id,
        context.block_height,
        0,
        contribution.receiver_index(),
        &context.challenge,
        &payload,
    );
    let commitment = PqcThresholdWireMsg::HazmatMldsa65SecretCommitment {
        session_id: context.session_id,
        block_height: context.block_height,
        attempt: 0,
        validator_index: contribution.receiver_index(),
        challenge: context.challenge,
        commitment: secret_digest,
    };
    let statement = ContributionStatement {
        session_id: context.session_id,
        block_height: context.block_height,
        attempt: 0,
        validator_index: contribution.receiver_index(),
        challenge: context.challenge,
        masking_commitment_digest: masking_digest,
        secret_commitment_digest: secret_digest,
        dkg_commitment_digest: share.dkg_public_commitment_digest(),
    };
    let proof = prove_contribution(
        &statement,
        &ContributionWitness::from_payload(payload.clone()),
    )
    .expect("proof-bound secret contribution proof must build");
    let frame = PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
        session_id: context.session_id,
        block_height: context.block_height,
        attempt: 0,
        validator_index: contribution.receiver_index(),
        challenge: context.challenge,
        masking_commitment_digest: statement.masking_commitment_digest,
        secret_commitment_digest: statement.secret_commitment_digest,
        dkg_commitment_digest: statement.dkg_commitment_digest,
        production_statement_digest: production_contribution_statement_digest_from_scaffold(
            &statement,
            context.threshold,
            context.total_nodes,
            &context.mu,
            &payload,
        )
        .expect("production contribution statement digest must build"),
        proof,
        payload,
    };
    let bytes = commitment.encode().len() + frame.encode().len();
    context.trace.record("remote_inbound", &commitment);
    context
        .tx
        .send(ActorEvent::IncomingNetworkMessage(commitment))
        .await
        .expect("actor inbox should accept secret commitment");
    context.trace.record("remote_inbound", &frame);
    context
        .tx
        .send(ActorEvent::IncomingNetworkMessage(frame))
        .await
        .expect("actor inbox should accept secret contribution");
    bytes
}

fn is_byzantine_validator(mode: ByzantineMode, validator: u16) -> bool {
    match mode {
        ByzantineMode::None => false,
        ByzantineMode::TamperMaskingContribution { validator: bad }
        | ByzantineMode::TamperSecretContribution { validator: bad } => bad == validator,
    }
}

async fn apply_network_delay(network: NetworkProfile, validator: u16, trial: u16) {
    let (base, retry_tokens) = match network {
        NetworkProfile::IdealLocalMesh => return,
        NetworkProfile::DistributedFabric { latency_ms } => (latency_ms, 1),
        NetworkProfile::AdversarialWan {
            latency_ms,
            retry_tokens,
        } => (latency_ms, retry_tokens),
    };
    let jitter = deterministic_jitter_ms(validator, trial, retry_tokens);
    tokio::time::sleep(Duration::from_millis(base + jitter)).await;
}

async fn wait_for_broadcast_count(network: &HarnessNetwork, expected: usize) {
    for _ in 0..256 {
        if network
            .broadcasts
            .lock()
            .expect("broadcast records poisoned")
            .len()
            >= expected
        {
            return;
        }
        tokio::task::yield_now().await;
    }
}

async fn extract_secret_challenge(
    network: &HarnessNetwork,
) -> Option<[u8; crate::mldsa65::MLDSA65_CHALLENGE_BYTES]> {
    for _ in 0..256 {
        if let Some(challenge) = network
            .broadcasts
            .lock()
            .expect("broadcast records poisoned")
            .iter()
            .find_map(|msg| {
                if let PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
                    challenge,
                    ..
                } = msg
                {
                    Some(*challenge)
                } else {
                    None
                }
            })
        {
            return Some(challenge);
        }
        tokio::task::yield_now().await;
    }
    None
}

async fn wait_for_actor_settle(consensus: &HarnessConsensus) {
    for _ in 0..256 {
        if !consensus
            .finalized
            .lock()
            .expect("finalized records poisoned")
            .is_empty()
        {
            tokio::task::yield_now().await;
            return;
        }
        tokio::task::yield_now().await;
    }
}

fn keygen_seed(validators: u16, trial: u16, attempt: u16) -> [u8; 32] {
    core::array::from_fn(|index| {
        (index as u8)
            .wrapping_mul(37)
            .wrapping_add(validators as u8)
            .wrapping_add(trial as u8)
            .wrapping_add(attempt as u8)
    })
}

fn derived_mu(base: [u8; MLDSA65_MU_BYTES], trial: u16, attempt: u16) -> [u8; MLDSA65_MU_BYTES] {
    core::array::from_fn(|index| {
        base[index]
            .wrapping_add(trial as u8)
            .wrapping_add((attempt as u8).wrapping_mul(3))
    })
}

fn session_id_for(validators: u16, trial: u16, attempt: u16) -> [u8; 32] {
    let mut session_id = [0u8; 32];
    session_id[0..2].copy_from_slice(&validators.to_be_bytes());
    session_id[2..4].copy_from_slice(&trial.to_be_bytes());
    session_id[4..6].copy_from_slice(&attempt.to_be_bytes());
    session_id
}

fn deterministic_retry_count(network: NetworkProfile, trial: u16) -> u32 {
    match network {
        NetworkProfile::IdealLocalMesh | NetworkProfile::DistributedFabric { .. } => 0,
        NetworkProfile::AdversarialWan { retry_tokens, .. } => {
            ((u32::from(trial) * 1_103_515_245 + 12_345) % (retry_tokens + 1)) + retry_tokens
        }
    }
}

fn deterministic_jitter_ms(validator: u16, trial: u16, retry_tokens: u32) -> u64 {
    if retry_tokens == 0 {
        return 0;
    }
    let token = u64::from(validator) * 31 + u64::from(trial) * 17 + u64::from(retry_tokens);
    token % (u64::from(retry_tokens) + 1)
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha3_256::digest(bytes).into()
}
