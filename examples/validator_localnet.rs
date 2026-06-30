use std::env;

use lattice_aggregation::{
    adapter::localnet::{
        run_localnet, LocalnetConfig, LocalnetFaultProfile, LOCALNET_CLAIM_BOUNDARY,
    },
    ValidatorId,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = parse_args();
    let report = run_localnet(args.config)
        .await
        .expect("localnet runner should complete");

    println!("claim_boundary={LOCALNET_CLAIM_BOUNDARY}");
    println!("fault_profile={}", report.fault_profile);
    println!("validators={}", report.validator_count);
    println!(
        "triggered_validator_count={}",
        report.triggered_validator_count
    );
    println!("threshold={}", report.threshold);
    println!("finalized={}", report.finalized.len());
    println!(
        "all_validators_finalized={}",
        report.all_validators_finalized
    );
    println!("evidence_count={}", report.evidence_count);
    println!("broadcast_count={}", report.broadcast_count);
    println!("direct_send_count={}", report.direct_send_count);
    println!("dropped_message_count={}", report.dropped_message_count);
    println!("network_bytes={}", report.network_bytes);
}

struct ExampleArgs {
    config: LocalnetConfig,
}

fn parse_args() -> ExampleArgs {
    let mut validators = 4;
    let mut threshold = 3;
    let mut triggered_validators = None;
    let mut profile = "honest".to_string();
    let mut withheld_validator = 4;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--validators" => {
                validators = parse_u16("--validators", args.next());
            }
            "--threshold" => {
                threshold = parse_u16("--threshold", args.next());
            }
            "--triggered-validators" => {
                triggered_validators = Some(parse_u16("--triggered-validators", args.next()));
            }
            "--profile" => {
                profile = args.next().expect("--profile requires a value");
            }
            "--withheld-validator" => {
                withheld_validator = parse_u16("--withheld-validator", args.next());
            }
            unknown => panic!("unknown localnet example argument: {unknown}"),
        }
    }

    let fault_profile = match profile.as_str() {
        "honest" => LocalnetFaultProfile::Honest,
        "withheld-partial" => {
            LocalnetFaultProfile::withheld_partial(ValidatorId(withheld_validator))
        }
        other => panic!("unknown localnet profile: {other}"),
    };

    ExampleArgs {
        config: LocalnetConfig::new(validators, threshold)
            .with_triggered_validator_count(triggered_validators.unwrap_or(validators))
            .with_fault_profile(fault_profile),
    }
}

fn parse_u16(flag: &str, value: Option<String>) -> u16 {
    value
        .unwrap_or_else(|| panic!("{flag} requires a value"))
        .parse()
        .unwrap_or_else(|_| panic!("{flag} requires a u16 value"))
}
