use std::{
    convert::Infallible,
    env, fmt, process,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use lattice_aggregation::{
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

type FinalizedSignatures = Vec<(u64, Vec<u8>)>;
type Shared<T> = Arc<Mutex<T>>;

#[derive(Clone, Default)]
struct HarnessNetwork {
    bytes: Shared<usize>,
}

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
    finalized: Shared<FinalizedSignatures>,
    evidence: Shared<Vec<SlashingEvidence>>,
    gas_updates: Shared<Vec<u64>>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BenchmarkProfile {
    Smoke,
    Large,
}

impl BenchmarkProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Large => "large",
        }
    }
}

impl fmt::Display for BenchmarkProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputFormat {
    Human,
    Csv,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HarnessOptions {
    profile: BenchmarkProfile,
    output_format: OutputFormat,
    no_wall_sleep: bool,
}

impl Default for HarnessOptions {
    fn default() -> Self {
        Self {
            profile: BenchmarkProfile::Smoke,
            output_format: OutputFormat::Human,
            no_wall_sleep: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BenchmarkTrial {
    profile: BenchmarkProfile,
    experiment_label: &'static str,
    trial: u16,
    validators: u16,
    threshold: u16,
    malicious_validator: Option<u16>,
    logical_latency_ms: u64,
    no_wall_sleep: bool,
    metrics: SessionMetrics,
}

impl BenchmarkTrial {
    fn wall_duration_ms(self) -> f64 {
        self.metrics.total_duration_ns as f64 / 1_000_000.0
    }
}

const SMOKE_EXPERIMENTS: [ExperimentSpec; 3] = [
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

const LARGE_EXPERIMENTS: [ExperimentSpec; 4] = [
    ExperimentSpec {
        label: "Large Baseline 3",
        validators: 3,
        threshold: 2,
        trials: 10,
        malicious_validator: None,
        latency_ms: 0,
        retry_tokens: 0,
    },
    ExperimentSpec {
        label: "Large Regional 64",
        validators: 64,
        threshold: 43,
        trials: 10,
        malicious_validator: Some(44),
        latency_ms: 2,
        retry_tokens: 1,
    },
    ExperimentSpec {
        label: "Large Continental 512",
        validators: 512,
        threshold: 342,
        trials: 5,
        malicious_validator: Some(377),
        latency_ms: 7,
        retry_tokens: 3,
    },
    ExperimentSpec {
        label: "Large Validator Set 10000",
        validators: 10_000,
        threshold: 6_667,
        trials: 3,
        malicious_validator: Some(9_999),
        latency_ms: 12,
        retry_tokens: 5,
    },
];

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let options = match parse_options(env::args().skip(1)) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("{}", usage());
            process::exit(2);
        }
    };

    let mut records = Vec::new();
    for spec in experiments_for_profile(options.profile) {
        records.extend(run_experiment_grid(options.profile, *spec, options.no_wall_sleep).await);
    }

    match options.output_format {
        OutputFormat::Human => print_human_report(options.profile, &records),
        OutputFormat::Csv => print!("{}", render_trials_csv(&records)),
    }
}

fn experiments_for_profile(profile: BenchmarkProfile) -> &'static [ExperimentSpec] {
    match profile {
        BenchmarkProfile::Smoke => &SMOKE_EXPERIMENTS,
        BenchmarkProfile::Large => &LARGE_EXPERIMENTS,
    }
}

async fn run_experiment_grid(
    profile: BenchmarkProfile,
    spec: ExperimentSpec,
    no_wall_sleep: bool,
) -> Vec<BenchmarkTrial> {
    let mut metrics = Vec::with_capacity(usize::from(spec.trials));
    for trial in 0..spec.trials {
        metrics.push(run_single_trial(profile, spec, trial, no_wall_sleep).await);
    }
    metrics
}

async fn run_single_trial(
    profile: BenchmarkProfile,
    spec: ExperimentSpec,
    trial: u16,
    no_wall_sleep: bool,
) -> BenchmarkTrial {
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
    let mut logical_latency_ms = 0u64;

    for validator in 2..=spec.validators {
        let scheduled_latency_ms = if spec.latency_ms > 0 {
            let jitter = deterministic_jitter_ms(validator, trial, spec.retry_tokens);
            spec.latency_ms + jitter
        } else {
            0
        };
        logical_latency_ms += scheduled_latency_ms;
        if scheduled_latency_ms > 0 && !no_wall_sleep {
            tokio::time::sleep(Duration::from_millis(scheduled_latency_ms)).await;
        };

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

    BenchmarkTrial {
        profile,
        experiment_label: spec.label,
        trial,
        validators: spec.validators,
        threshold: spec.threshold,
        malicious_validator: spec.malicious_validator,
        logical_latency_ms,
        no_wall_sleep,
        metrics: SessionMetrics {
            total_duration_ns: started.elapsed().as_nanos() as u64,
            abort_and_retry_count: aborts + evidence_count,
            network_bytes_transmitted: network_bytes + transmitted,
        },
    }
}

fn print_human_report(_profile: BenchmarkProfile, records: &[BenchmarkTrial]) {
    let mut index = 0usize;
    while index < records.len() {
        let label = records[index].experiment_label;
        let validators = records[index].validators;
        let start = index;
        while index < records.len() && records[index].experiment_label == label {
            index += 1;
        }
        let metrics: Vec<_> = records[start..index]
            .iter()
            .map(|record| record.metrics)
            .collect();
        println!("===== {label}: LaTeX =====");
        print!("{}", generate_latex_table(label, validators, &metrics));
        println!("===== {label}: PGFPlots CSV =====");
        print!("{}", generate_pgfplots_csv(&metrics));
    }
}

fn render_trials_csv(records: &[BenchmarkTrial]) -> String {
    let mut csv = String::from(
        "profile,experiment,trial,validators,threshold,malicious_validator,wall_duration_ms,logical_latency_ms,aborts,bandwidth_bytes,mldsa65_public_key_bytes,mldsa65_signature_bytes,commitment_bytes,no_wall_sleep\n",
    );
    for record in records {
        let malicious_validator = record
            .malicious_validator
            .map(|validator| validator.to_string())
            .unwrap_or_else(|| "none".to_string());
        csv.push_str(&format!(
            "{},{},{},{},{},{},{:.4},{},{},{},{},{},{},{}\n",
            record.profile,
            csv_cell(record.experiment_label),
            record.trial,
            record.validators,
            record.threshold,
            malicious_validator,
            record.wall_duration_ms(),
            record.logical_latency_ms,
            record.metrics.abort_and_retry_count,
            record.metrics.network_bytes_transmitted,
            lattice_aggregation::MLDSA65_PUBLICKEY_BYTES,
            lattice_aggregation::MLDSA65_SIGNATURE_BYTES,
            lattice_aggregation::COMMITMENT_BYTES,
            record.no_wall_sleep
        ));
    }
    csv
}

fn csv_cell(value: &str) -> String {
    if value.contains([',', '"', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn parse_options<I>(args: I) -> Result<HarnessOptions, String>
where
    I: IntoIterator<Item = String>,
{
    let mut options = HarnessOptions::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--profile requires smoke or large".to_string())?;
                options.profile = match value.as_str() {
                    "smoke" => BenchmarkProfile::Smoke,
                    "large" => BenchmarkProfile::Large,
                    _ => return Err(format!("unsupported profile: {value}")),
                };
            }
            "--format" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--format requires human or csv".to_string())?;
                options.output_format = match value.as_str() {
                    "human" => OutputFormat::Human,
                    "csv" => OutputFormat::Csv,
                    _ => return Err(format!("unsupported output format: {value}")),
                };
            }
            "--no-wall-sleep" => options.no_wall_sleep = true,
            "--help" | "-h" => return Err(usage().to_string()),
            _ => return Err(format!("unsupported argument: {arg}")),
        }
    }
    Ok(options)
}

fn usage() -> &'static str {
    "usage: cargo run -- [--profile smoke|large] [--format human|csv] [--no-wall-sleep]"
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
    let token = (u64::from(trial) * 1_103_515_245 + 12_345) % (u64::from(retry_tokens) + 1);
    token as u32 + retry_tokens
}

fn deterministic_jitter_ms(validator: u16, trial: u16, retry_tokens: u32) -> u64 {
    if retry_tokens == 0 {
        return 0;
    }
    let token = u64::from(validator) * 31 + u64::from(trial) * 17 + u64::from(retry_tokens);
    token % (u64::from(retry_tokens) + 1)
}

#[cfg(test)]
mod harness_tests {
    use super::*;

    #[test]
    fn large_profile_defines_requested_scenarios() {
        let scenarios: Vec<_> = experiments_for_profile(BenchmarkProfile::Large)
            .iter()
            .map(|spec| (spec.validators, spec.threshold, spec.trials))
            .collect();

        assert_eq!(
            scenarios,
            vec![(3, 2, 10), (64, 43, 10), (512, 342, 5), (10_000, 6_667, 3)]
        );
    }

    #[test]
    fn csv_output_includes_reproducibility_fields() {
        let record = BenchmarkTrial {
            profile: BenchmarkProfile::Large,
            experiment_label: "Example",
            trial: 0,
            validators: 64,
            threshold: 43,
            malicious_validator: Some(4),
            logical_latency_ms: 12,
            no_wall_sleep: true,
            metrics: SessionMetrics {
                total_duration_ns: 1_500_000,
                abort_and_retry_count: 2,
                network_bytes_transmitted: 4_096,
            },
        };

        let csv = render_trials_csv(&[record]);

        assert!(csv.starts_with(
            "profile,experiment,trial,validators,threshold,malicious_validator,wall_duration_ms,logical_latency_ms,aborts,bandwidth_bytes,mldsa65_public_key_bytes,mldsa65_signature_bytes,commitment_bytes,no_wall_sleep\n"
        ));
        assert!(csv.contains("large,Example,0,64,43,4,1.5000,12,2,4096,1952,3309,32,true\n"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn no_wall_sleep_records_logical_latency_without_sleeping() {
        let spec = ExperimentSpec {
            label: "No Sleep",
            validators: 3,
            threshold: 2,
            trials: 1,
            malicious_validator: None,
            latency_ms: 10,
            retry_tokens: 2,
        };

        let records = run_experiment_grid(BenchmarkProfile::Large, spec, true).await;

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].profile, BenchmarkProfile::Large);
        assert_eq!(records[0].logical_latency_ms, 23);
        assert!(records[0].no_wall_sleep);
    }

    #[test]
    fn retry_count_handles_large_trial_indices_without_overflow() {
        assert!(deterministic_retry_count(5, 9) <= 10);
    }
}
