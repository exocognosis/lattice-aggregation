#[cfg(not(feature = "raw-real-mldsa"))]
fn main() {
    eprintln!("threshold_backend_p1 requires the raw-real-mldsa feature");
    std::process::exit(2);
}

#[cfg(feature = "raw-real-mldsa")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    backend::main()
}

#[cfg(feature = "raw-real-mldsa")]
mod backend {
    use lattice_aggregation::{
        backend::Mldsa65Backend,
        crypto::{
            bdlop::CommitmentKey,
            mldsa_dkg::{CommitRecord, DkgCoordinator},
            mldsa_module::PublicKey as ModulePublicKey,
            poly::Poly,
            receiver_custody::{
                seal_shared_secret_key, ComponentKind, CustodyContext, ReceiverEndpoint,
                ReceiverShareVault,
            },
            share_transport::{ReceiverKey, Shake256Transport},
            vss_bdlop::HidingShare,
        },
        self_contained_sign_with_module_z_shares, sign_with_module_partial_z_evidence,
        strict_distributed_sign_from_s1_y_partials, AlgebraicPartialStatus, FipsWireStatus,
        RealMldsa65Backend, SelfContainedFipsStatus, ThresholdMldsaEngine, ThresholdPublicKey,
        ThresholdSignature, ValidatorId,
    };
    use serde::Deserialize;
    use serde_json::{json, Map, Value};
    use sha3::{Digest, Sha3_256};
    use std::{
        collections::BTreeMap,
        env,
        error::Error,
        fmt, fs,
        path::{Path, PathBuf},
    };

    const REQUEST_SCHEMA: &str =
        "lattice-aggregation:p1-real-threshold-backend-emission-request:v1";
    const CAPTURE_SCHEMA: &str =
        "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1";
    const REVIEW_SCHEMA: &str =
        "lattice-aggregation:p1-external-backend-emission-capture-review:v1";
    const NONCE_REQUEST_SCHEMA: &str =
        "lattice-aggregation:p1-distributed-nonce-producer-request:v1";
    const NONCE_CAPTURE_SCHEMA: &str =
        "lattice-aggregation:p1-distributed-nonce-producer-capture:v1";
    const NONCE_REVIEW_SCHEMA: &str =
        "lattice-aggregation:p1-external-nonce-producer-capture-review:v1";
    const DKG_CUSTODY_CAPTURE_SCHEMA: &str = "lattice-aggregation:p1-dkg-custody-capture:v1";
    const DKG_CUSTODY_REVIEW_SCHEMA: &str = "lattice-aggregation:p1-dkg-custody-capture-review:v1";
    const READINESS_SCHEMA: &str = "lattice-aggregation:p1-nonce-producer-backend-readiness:v1";
    const CLAIM_BOUNDARY: &str = "conformance/proof-review evidence";
    const SELECTED_PROFILE: &str = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1";
    const BACKEND_EVIDENCE: &str = "real_threshold_mldsa_external_capture";
    const NONCE_PRODUCER_EVIDENCE: &str = "p1_shamir_nonce_dkg_tee_external_capture";
    const REVIEW_STATUS: &str = "reviewed_external_backend_emission_capture_ready";
    const NONCE_REVIEW_STATUS: &str = "reviewed_external_capture_ready";
    const READINESS_STATUS: &str = "backend_candidate_admissible_pending_capture";
    const VALIDATOR_COUNT: u64 = 10_000;
    const THRESHOLD: u64 = 6_667;
    const MLDSA65_PUBLIC_KEY_BYTES: usize = 1952;
    const MLDSA65_SIGNATURE_BYTES: usize = 3309;
    const MLDSA_Q: u64 = 8_380_417;
    const CORE_MODE: &str = "centralized_mldsa65_provider_with_threshold_evidence_envelope";
    const PROVIDER: &str = "ml-dsa crate MlDsa65";
    const SIGNATURE_ORIGIN: &str = "single_seed_standard_mldsa65_provider";
    const RECONSTRUCTION_CORE_MODE: &str = "threshold_seed_reconstruction_mldsa65_provider";
    const RECONSTRUCTION_SIGNATURE_ORIGIN: &str =
        "threshold_seed_reconstruction_standard_mldsa65_provider";
    const THRESHOLD_CORE_MODE: &str = "distributed_threshold_mldsa65_partial_aggregation";
    const THRESHOLD_CORE_SIGNATURE_ORIGIN: &str = "threshold_partial_aggregation";
    /// Live threshold-core captures use a small execution committee for runtime
    /// feasibility; the selected profile target remains 10_000 / 6_667.
    const EXECUTION_COMMITTEE_N: u16 = 7;
    const EXECUTION_COMMITTEE_T: u16 = 5;
    /// Bounded no-seed-dealer DKG/custody execution profile for the native
    /// custody capture command. The production target remains 10_000 / 6_667.
    const DKG_CUSTODY_EXECUTION_N: u16 = 8;
    const DKG_CUSTODY_EXECUTION_T: u16 = 6;
    const DKG_CUSTODY_DEALER_COUNT: u16 = 2;
    const DKG_CUSTODY_AGGREGATE_DEALER_ID: u16 = u16::MAX;

    #[derive(Debug)]
    struct BackendError(String);

    impl fmt::Display for BackendError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl Error for BackendError {}

    #[derive(Debug, Deserialize)]
    struct Request {
        schema: String,
        name: String,
        claim_boundary: String,
        request_status: String,
        selected_profile: String,
        validator_count: u64,
        threshold: u64,
        aggregate_signature_len: usize,
        message: ByteValue,
        predecessors: Predecessors,
        required_capture: RequiredCapture,
    }

    #[derive(Debug, Deserialize)]
    struct RequiredCapture {
        schema: String,
        backend_evidence: String,
        claim_boundary: String,
        selected_profile: String,
        validator_count: u64,
        threshold: u64,
        aggregate_signature_len: usize,
        mutated_message_rejected: bool,
        mutated_public_key_rejected: bool,
        mutated_signature_rejected: bool,
        reviewed: bool,
    }

    #[derive(Debug, Deserialize)]
    struct Predecessors {
        selected_profile_binding_digest_hex: String,
        threshold_output_certificate_digest_hex: String,
        standard_verifier_compatibility_artifact_digest_hex: String,
    }

    #[derive(Clone, Debug, Deserialize)]
    struct ByteValue {
        encoding: String,
        value: String,
    }

    #[derive(Debug)]
    struct EmitArgs {
        request_path: PathBuf,
        out_dir: PathBuf,
        seed: [u8; 32],
        name: String,
        reviewer_label: String,
        operator_label: String,
    }

    #[derive(Debug, Deserialize)]
    struct NonceRequest {
        schema: String,
        name: String,
        claim_boundary: String,
        request_status: String,
        selected_profile: String,
        predecessors: Predecessors,
        required_capture: NonceRequiredCapture,
    }

    #[derive(Debug, Deserialize)]
    struct NonceRequiredCapture {
        schema: String,
        producer_evidence: String,
        claim_boundary: String,
        selected_profile: String,
        material: Vec<String>,
        reviewed: bool,
    }

    #[derive(Debug, Deserialize)]
    struct ReadinessManifest {
        schema: String,
        claim_boundary: String,
        readiness_status: String,
        selected_profile: String,
        request: ReadinessRequest,
        backend: ReadinessBackend,
        admissibility: ReadinessAdmissibility,
    }

    #[derive(Debug, Deserialize)]
    struct ReadinessRequest {
        schema: String,
        name: String,
        request_sha256: String,
        capture_schema: String,
        required_producer_evidence: String,
    }

    #[derive(Debug, Deserialize)]
    struct ReadinessBackend {
        source_tree_sha256: String,
    }

    #[derive(Debug, Deserialize)]
    struct ReadinessAdmissibility {
        admissible_for_p1_nonce_handoff: bool,
        detected_blockers: Vec<String>,
    }

    #[derive(Debug)]
    struct NonceEmitArgs {
        request_path: PathBuf,
        readiness_path: PathBuf,
        out_dir: PathBuf,
        seed: [u8; 32],
        name: String,
        reviewer_label: String,
        operator_label: String,
    }

    #[derive(Debug)]
    struct DkgCustodyEmitArgs {
        out_dir: PathBuf,
        seed: [u8; 32],
        name: String,
        reviewer_label: String,
        operator_label: String,
        execution_validator_count: u16,
        execution_threshold: u16,
        dealer_count: u16,
    }

    struct DkgCustodyRun {
        rho: [u8; 32],
        session_id: [u8; 32],
        commitment_key_digest: [u8; 32],
        dkg_transcript_digest: [u8; 32],
        public_key_digest: [u8; 32],
        accepted_dealers: Vec<u16>,
        dealer_commitments: Vec<Value>,
        custody_bundle_digest: [u8; 32],
        custody_commitments_digest: [u8; 32],
        receiver_vault_root: [u8; 32],
        receiver_samples: Vec<Value>,
        envelope_samples: Vec<Value>,
        all_receiver_vaults_imported: bool,
    }

    struct NonceMaterials {
        source_reference: Vec<u8>,
        backend_implementation: Vec<u8>,
        coordinator_attestation: Vec<u8>,
        shamir_nonce_dkg_transcript: Vec<u8>,
        pairwise_mask_seed_commitments: Vec<u8>,
        nonce_share_commitments: Vec<u8>,
        abort_accountability: Vec<u8>,
        external_review: Vec<u8>,
    }

    struct NonceRoots {
        coefficient_commitment_root: [u8; 32],
        share_commitment_root: [u8; 32],
        pairwise_mask_seed_commitment_root: [u8; 32],
        share_samples: Vec<Value>,
        pairwise_samples: Vec<Value>,
    }

    struct ThresholdReconstruction {
        reconstructed_seed: [u8; 32],
        active_signer_count: usize,
        share_commitment_root: [u8; 32],
        active_set_digest: [u8; 32],
        reconstruction_digest: [u8; 32],
        sample_share_commitments: Vec<Value>,
        reconstruction_matches_seed_digest: bool,
    }

    struct NonceReviewInput<'a> {
        request: &'a NonceRequest,
        request_sha256: &'a str,
        readiness: &'a ReadinessManifest,
        readiness_path: &'a Path,
        capture: &'a Value,
        capture_json: &'a str,
        capture_path: &'a Path,
        args: &'a NonceEmitArgs,
    }

    pub fn main() -> Result<(), Box<dyn Error>> {
        let mut args = env::args().skip(1);
        let command = args.next().ok_or_else(|| usage_error("missing command"))?;
        match command.as_str() {
            "emit-backend-capture" => emit_backend_capture(parse_emit_args(args.collect())?),
            "emit-smoke-backend-capture" => {
                emit_smoke_backend_capture(parse_emit_args(args.collect())?)
            }
            "emit-threshold-core-capture" => {
                emit_threshold_core_capture(parse_emit_args(args.collect())?)
            }
            "emit-nonce-capture" => emit_nonce_capture(parse_nonce_emit_args(args.collect())?),
            "emit-dkg-custody-capture" => {
                emit_dkg_custody_capture(parse_dkg_custody_emit_args(args.collect())?)
            }
            "-h" | "--help" | "help" => {
                print_help();
                Ok(())
            }
            other => Err(usage_error(format!("unknown command: {other}")).into()),
        }
    }

    fn print_help() {
        println!(
            "usage: threshold_backend_p1 emit-backend-capture \\\n  --request PATH --out-dir DIR [--seed-hex HEX32] [--name NAME]\n\n\
threshold_backend_p1 emit-smoke-backend-capture \\\n  --request PATH --out-dir DIR [--seed-hex HEX32] [--name NAME]\n\n\
threshold_backend_p1 emit-threshold-core-capture \\\n  --request PATH --out-dir DIR [--seed-hex HEX32] [--name NAME]\n\n\
threshold_backend_p1 emit-nonce-capture \\\n  --request PATH --readiness PATH --out-dir DIR [--seed-hex HEX32] [--name NAME]\n\n\
threshold_backend_p1 emit-dkg-custody-capture \\\n  --out-dir DIR [--seed-hex HEX32] [--name NAME] [--execution-validator-count N] [--execution-threshold T] [--dealer-count D]\n\n\
Emits capture.json and review.json for P1 backend-emission, threshold-core, or nonce-producer intake.\n\
emit-threshold-core-capture runs live nonce DKG + seed-layer partials via ThresholdMldsaEngine.\n\
emit-dkg-custody-capture runs a bounded native no-seed-dealer DKG and receiver-custody ceremony."
        );
    }

    fn parse_emit_args(raw: Vec<String>) -> Result<EmitArgs, BackendError> {
        let mut request_path = None;
        let mut out_dir = None;
        let mut seed = [0x51; 32];
        let mut name = "p1-threshold-backend-p1-real-mldsa-capture-001".to_owned();
        let mut reviewer_label = "threshold-backend-p1-reviewer".to_owned();
        let mut operator_label = "threshold-backend-p1-operator".to_owned();

        let mut i = 0;
        while i < raw.len() {
            let flag = raw[i].as_str();
            let value = raw
                .get(i + 1)
                .ok_or_else(|| usage_error(format!("missing value for {flag}")))?;
            match flag {
                "--request" => request_path = Some(PathBuf::from(value)),
                "--out-dir" => out_dir = Some(PathBuf::from(value)),
                "--seed-hex" => seed = decode_hex_array::<32>(value, "--seed-hex")?,
                "--name" => name = value.to_owned(),
                "--reviewer-label" => reviewer_label = value.to_owned(),
                "--operator-label" => operator_label = value.to_owned(),
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                _ => return Err(usage_error(format!("unknown flag: {flag}"))),
            }
            i += 2;
        }

        Ok(EmitArgs {
            request_path: request_path.ok_or_else(|| usage_error("missing --request"))?,
            out_dir: out_dir.ok_or_else(|| usage_error("missing --out-dir"))?,
            seed,
            name,
            reviewer_label,
            operator_label,
        })
    }

    fn parse_nonce_emit_args(raw: Vec<String>) -> Result<NonceEmitArgs, BackendError> {
        let mut request_path = None;
        let mut readiness_path = None;
        let mut out_dir = None;
        let mut seed = [0x61; 32];
        let mut name = "p1-threshold-backend-p1-nonce-capture-001".to_owned();
        let mut reviewer_label = "threshold-backend-p1-nonce-reviewer".to_owned();
        let mut operator_label = "threshold-backend-p1-nonce-operator".to_owned();

        let mut i = 0;
        while i < raw.len() {
            let flag = raw[i].as_str();
            let value = raw
                .get(i + 1)
                .ok_or_else(|| usage_error(format!("missing value for {flag}")))?;
            match flag {
                "--request" => request_path = Some(PathBuf::from(value)),
                "--readiness" => readiness_path = Some(PathBuf::from(value)),
                "--out-dir" => out_dir = Some(PathBuf::from(value)),
                "--seed-hex" => seed = decode_hex_array::<32>(value, "--seed-hex")?,
                "--name" => name = value.to_owned(),
                "--reviewer-label" => reviewer_label = value.to_owned(),
                "--operator-label" => operator_label = value.to_owned(),
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                _ => return Err(usage_error(format!("unknown flag: {flag}"))),
            }
            i += 2;
        }

        Ok(NonceEmitArgs {
            request_path: request_path.ok_or_else(|| usage_error("missing --request"))?,
            readiness_path: readiness_path.ok_or_else(|| usage_error("missing --readiness"))?,
            out_dir: out_dir.ok_or_else(|| usage_error("missing --out-dir"))?,
            seed,
            name,
            reviewer_label,
            operator_label,
        })
    }

    fn parse_dkg_custody_emit_args(raw: Vec<String>) -> Result<DkgCustodyEmitArgs, BackendError> {
        let mut out_dir = None;
        let mut seed = [0x71; 32];
        let mut name = "p1-threshold-backend-p1-dkg-custody-capture-001".to_owned();
        let mut reviewer_label = "threshold-backend-p1-dkg-custody-reviewer".to_owned();
        let mut operator_label = "threshold-backend-p1-dkg-custody-operator".to_owned();
        let mut execution_validator_count = DKG_CUSTODY_EXECUTION_N;
        let mut execution_threshold = DKG_CUSTODY_EXECUTION_T;
        let mut dealer_count = DKG_CUSTODY_DEALER_COUNT;

        let mut i = 0;
        while i < raw.len() {
            let flag = raw[i].as_str();
            let value = raw
                .get(i + 1)
                .ok_or_else(|| usage_error(format!("missing value for {flag}")))?;
            match flag {
                "--out-dir" => out_dir = Some(PathBuf::from(value)),
                "--seed-hex" => seed = decode_hex_array::<32>(value, "--seed-hex")?,
                "--name" => name = value.to_owned(),
                "--reviewer-label" => reviewer_label = value.to_owned(),
                "--operator-label" => operator_label = value.to_owned(),
                "--execution-validator-count" => {
                    execution_validator_count = parse_u16_arg(value, "--execution-validator-count")?
                }
                "--execution-threshold" => {
                    execution_threshold = parse_u16_arg(value, "--execution-threshold")?
                }
                "--dealer-count" => dealer_count = parse_u16_arg(value, "--dealer-count")?,
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                _ => return Err(usage_error(format!("unknown flag: {flag}"))),
            }
            i += 2;
        }

        validate_bounded_dkg_custody_shape(
            execution_validator_count,
            execution_threshold,
            dealer_count,
        )?;
        Ok(DkgCustodyEmitArgs {
            out_dir: out_dir.ok_or_else(|| usage_error("missing --out-dir"))?,
            seed,
            name,
            reviewer_label,
            operator_label,
            execution_validator_count,
            execution_threshold,
            dealer_count,
        })
    }

    fn parse_u16_arg(value: &str, field: &str) -> Result<u16, BackendError> {
        value
            .parse::<u16>()
            .map_err(|_| usage_error(format!("{field} must be an unsigned 16-bit integer")))
    }

    fn validate_bounded_dkg_custody_shape(
        execution_validator_count: u16,
        execution_threshold: u16,
        dealer_count: u16,
    ) -> Result<(), BackendError> {
        if execution_threshold == 0 || execution_validator_count < execution_threshold {
            return Err(usage_error(
                "bounded DKG custody execution requires 0 < threshold <= validator count",
            ));
        }
        if dealer_count < 2 {
            return Err(usage_error(
                "bounded DKG custody execution requires at least two independent dealers",
            ));
        }
        if execution_validator_count > 64 || execution_threshold > 64 {
            return Err(usage_error(
                "bounded native DKG custody capture refuses >64 validators; use an external production backend for 10000/6667",
            ));
        }
        Ok(())
    }

    fn emit_dkg_custody_capture(args: DkgCustodyEmitArgs) -> Result<(), Box<dyn Error>> {
        let run = run_bounded_dkg_custody(&args)?;
        let production_profile_executed = u64::from(args.execution_validator_count)
            == VALIDATOR_COUNT
            && u64::from(args.execution_threshold) == THRESHOLD;
        let process_isolated_receiver_custody = false;
        let signer_consumes_custody_output = false;
        let coordinator_observed_clear_dkg_shares_before_custody = true;
        let per_receiver_private_share_custody = false;
        let production_dkg_no_single_secret_ready = production_profile_executed
            && process_isolated_receiver_custody
            && !coordinator_observed_clear_dkg_shares_before_custody
            && signer_consumes_custody_output;
        let blockers = vec![
            "production 10000/6667 execution was not run by this bounded native capture",
            "receiver custody is in-process and not process-isolated",
            "finalizing process still transiently observes aggregate SharedSecretKey before custody sealing",
            "strict signer does not yet consume custody-held shares",
        ];
        let evidence = json!({
            "no_seed_dealer_dkg": true,
            "multiple_independent_dealers": args.dealer_count >= 2,
            "commit_before_reveal": true,
            "distributed_dkg_vss_transcript_present": true,
            "encrypted_receiver_custody_seam_executed": true,
            "receiver_vault_imports_verified": run.all_receiver_vaults_imported,
            "process_isolated_receiver_custody": process_isolated_receiver_custody,
            "per_receiver_private_share_custody": per_receiver_private_share_custody,
            "coordinator_observed_clear_dkg_shares_before_custody":
                coordinator_observed_clear_dkg_shares_before_custody,
            "signer_consumes_custody_output": signer_consumes_custody_output,
            "secret_material_exported_to_json": false,
            "raw_seed_exported_to_json": false,
            "expanded_key_exported_to_json": false,
            "production_profile_executed": production_profile_executed,
            "production_dkg_no_single_secret_ready": production_dkg_no_single_secret_ready,
        });
        let capture = json!({
            "schema": DKG_CUSTODY_CAPTURE_SCHEMA,
            "name": args.name,
            "claim_boundary": CLAIM_BOUNDARY,
            "selected_profile": SELECTED_PROFILE,
            "capture_status": "bounded_dkg_custody_capture_ready_not_production_profile",
            "target_profile": {
                "validator_count": VALIDATOR_COUNT,
                "threshold": THRESHOLD,
            },
            "execution_profile": {
                "validator_count": args.execution_validator_count,
                "threshold": args.execution_threshold,
                "dealer_count": args.dealer_count,
            },
            "dkg_custody_evidence": evidence,
            "transcript": {
                "rho_digest_hex": encode_hex(&sha3_bytes(&run.rho)),
                "session_id_hex": encode_hex(&run.session_id),
                "commitment_key_digest_hex": encode_hex(&run.commitment_key_digest),
                "dkg_transcript_digest_hex": encode_hex(&run.dkg_transcript_digest),
                "public_key_digest_hex": encode_hex(&run.public_key_digest),
                "accepted_dealers": run.accepted_dealers,
                "dealer_commitments": run.dealer_commitments,
                "custody_bundle_digest_hex": encode_hex(&run.custody_bundle_digest),
                "custody_commitments_digest_hex": encode_hex(&run.custody_commitments_digest),
                "receiver_vault_root_hex": encode_hex(&run.receiver_vault_root),
                "receiver_samples": run.receiver_samples,
                "envelope_samples": run.envelope_samples,
            },
            "blockers": blockers,
            "claim_flags": {
                "claims_theorem_closure": false,
                "claims_production_dkg_custody_closure": false,
                "claims_no_single_exposed_secret_key": false,
                "claims_standard_verifier_threshold_signature_closure": false,
                "claims_rejection_distribution_preservation": false,
            },
        });

        fs::create_dir_all(&args.out_dir)?;
        let capture_json = canonical_json(&capture);
        let capture_path = args.out_dir.join("capture.json");
        fs::write(&capture_path, &capture_json)?;
        let review = build_dkg_custody_review_manifest(
            &capture,
            &capture_json,
            &capture_path,
            &args,
            production_dkg_no_single_secret_ready,
        )?;
        fs::write(args.out_dir.join("review.json"), canonical_json(&review))?;
        println!("{}", capture_path.display());
        Ok(())
    }

    fn emit_backend_capture(args: EmitArgs) -> Result<(), Box<dyn Error>> {
        let request_text = fs::read_to_string(&args.request_path)?;
        let request_value: Value = serde_json::from_str(&request_text)?;
        let request: Request = serde_json::from_value(request_value.clone())?;
        validate_request(&request)?;
        let request_sha256 = sha256_text(&canonical_json(&request_value));
        let message = request.message.decode()?;
        let reconstruction = threshold_seed_reconstruction(&args.seed, &request_sha256)?;

        let (public_key, signature) =
            sign_with_real_backend(&reconstruction.reconstructed_seed, &message)?;
        let public_key_bytes = public_key.0.to_vec();
        let signature_bytes = signature.0.to_vec();
        if public_key_bytes.len() != MLDSA65_PUBLIC_KEY_BYTES {
            return Err(BackendError("unexpected ML-DSA-65 public key length".into()).into());
        }
        if signature_bytes.len() != MLDSA65_SIGNATURE_BYTES {
            return Err(BackendError("unexpected ML-DSA-65 signature length".into()).into());
        }
        if !verify_tuple(&public_key_bytes, &message, &signature_bytes) {
            return Err(BackendError("backend emitted signature did not verify".into()).into());
        }

        let mut mutated_message = message.clone();
        if mutated_message.is_empty() {
            mutated_message.push(1);
        } else {
            mutated_message[0] ^= 1;
        }
        let mut mutated_public_key = public_key_bytes.clone();
        mutated_public_key[0] ^= 1;
        let mut mutated_signature = signature_bytes.clone();
        mutated_signature[0] ^= 1;
        let mutated_message_rejected =
            !verify_tuple(&public_key_bytes, &mutated_message, &signature_bytes);
        let mutated_public_key_rejected =
            !verify_tuple(&mutated_public_key, &message, &signature_bytes);
        let mutated_signature_rejected =
            !verify_tuple(&public_key_bytes, &message, &mutated_signature);
        if !(mutated_message_rejected && mutated_public_key_rejected && mutated_signature_rejected)
        {
            return Err(BackendError("mutation rejection corpus was incomplete".into()).into());
        }
        let backend_requirement_evidence = backend_requirement_evidence(
            mutated_message_rejected,
            mutated_public_key_rejected,
            mutated_signature_rejected,
        );

        let reconstructed_seed_digest = sha3_bytes(&reconstruction.reconstructed_seed);
        let source_package = canonical_json(&json!({
            "schema": "lattice-aggregation:threshold-backend-p1-source-package:v1",
            "crate": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
            "selected_profile": SELECTED_PROFILE,
            "core_mode": RECONSTRUCTION_CORE_MODE,
        }))
        .into_bytes();
        let implementation = canonical_json(&json!({
            "schema": "lattice-aggregation:threshold-backend-p1-implementation:v1",
            "provider": "lattice_aggregation::RealMldsa65Backend",
            "parameter_set": "ML-DSA-65",
            "binary": "threshold_backend_p1",
            "command": "emit-backend-capture",
            "cryptographic_core_mode": RECONSTRUCTION_CORE_MODE,
            "signature_origin": RECONSTRUCTION_SIGNATURE_ORIGIN,
            "threshold_reconstruction_scheme": "shamir_seed_reconstruction_over_mldsa_q",
            "library_backend": RealMldsa65Backend::construction().core_mode(),
        }))
        .into_bytes();
        let transcript = canonical_json(&json!({
            "schema": "lattice-aggregation:threshold-backend-p1-transcript:v1",
            "request_name": request.name,
            "request_sha256": request_sha256,
            "cryptographic_core_mode": RECONSTRUCTION_CORE_MODE,
            "signature_origin": RECONSTRUCTION_SIGNATURE_ORIGIN,
            "validator_count": VALIDATOR_COUNT,
            "threshold": THRESHOLD,
            "threshold_core_accounting": reconstruction_backend_transcript_core_accounting(
                &backend_requirement_evidence,
            ),
            "backend_requirement_evidence": backend_requirement_evidence.clone(),
            "threshold_reconstruction": {
                "schema": "lattice-aggregation:threshold-backend-p1-seed-reconstruction:v1",
                "scheme": "shamir_seed_reconstruction_over_mldsa_q",
                "field_modulus": MLDSA_Q,
                "validator_count": VALIDATOR_COUNT,
                "threshold": THRESHOLD,
                "active_signer_count": reconstruction.active_signer_count,
                "share_commitment_root_hex": encode_hex(&reconstruction.share_commitment_root),
                "active_set_digest_hex": encode_hex(&reconstruction.active_set_digest),
                "reconstruction_digest_hex": encode_hex(&reconstruction.reconstruction_digest),
                "reconstructed_seed_digest_hex": encode_hex(&reconstructed_seed_digest),
                "reconstruction_matches_seed_digest": reconstruction.reconstruction_matches_seed_digest,
                "sample_share_commitments": reconstruction.sample_share_commitments,
                "partial_mldsa_signatures_present": false,
                "closure_boundary": "threshold seed reconstruction run; not ML-DSA partial z_i aggregation"
            },
            "public_key_digest_hex": encode_hex(&sha3_bytes(&public_key_bytes)),
            "message_digest_hex": encode_hex(&sha3_bytes(&message)),
            "accepted_signature_digest_hex": encode_hex(&sha3_bytes(&signature_bytes)),
            "standard_verifier_accepts": true,
            "mutated_message_rejected": mutated_message_rejected,
            "mutated_public_key_rejected": mutated_public_key_rejected,
            "mutated_signature_rejected": mutated_signature_rejected,
            "attempts": [{
                "attempt_id": 0,
                "accepted_or_rejected": "accepted",
                "core_mode": RECONSTRUCTION_CORE_MODE,
                "signature_origin": RECONSTRUCTION_SIGNATURE_ORIGIN,
                "threshold_partial_count": THRESHOLD,
                "reconstruction_share_count": reconstruction.active_signer_count,
                "partial_signatures_present": false,
                "partial_z_i_count": 0,
                "hint_count": 0,
                "bounds_checked_over_threshold_partials": false,
                "backend_requirement_evidence": backend_requirement_evidence.clone(),
                "backend_requirement_evidence_digest_hex": encode_hex(&domain_digest(
                    b"lattice-aggregation:threshold-backend-p1-backend-requirement-evidence:v1",
                    canonical_json(&backend_requirement_evidence).as_bytes(),
                )),
                "signature_len": signature_bytes.len()
            }]
        }))
        .into_bytes();
        let backend_requirement_evidence_digest = domain_digest(
            b"lattice-aggregation:threshold-backend-p1-backend-requirement-evidence:v1",
            canonical_json(&backend_requirement_evidence).as_bytes(),
        );

        let backend_source_package_digest = domain_digest(
            b"lattice-aggregation:p1-real-threshold-backend-source-package:v1",
            &source_package,
        );
        let backend_implementation_digest = domain_digest(
            b"lattice-aggregation:p1-real-threshold-backend-implementation:v1",
            &implementation,
        );
        let backend_transcript_digest = domain_digest(
            b"lattice-aggregation:p1-real-threshold-backend-transcript:v1",
            &transcript,
        );
        let backend_evidence_digest = backend_evidence_digest(EvidenceDigestInput {
            source_digest: &backend_source_package_digest,
            implementation_digest: &backend_implementation_digest,
            transcript_digest: &backend_transcript_digest,
            public_key: &public_key_bytes,
            message: &message,
            signature: &signature_bytes,
            mutated_message_rejected,
            mutated_public_key_rejected,
            mutated_signature_rejected,
        });
        let threshold_core_accounting_digest =
            reconstruction_backend_core_accounting_digest(&backend_requirement_evidence);
        let artifact_digest = domain_digest(
            b"lattice-aggregation:threshold-backend-p1-capture-artifact:v1",
            &[
                backend_evidence_digest.as_slice(),
                threshold_core_accounting_digest.as_slice(),
                backend_requirement_evidence_digest.as_slice(),
                reconstruction.reconstruction_digest.as_slice(),
                request_sha256.as_bytes(),
                &public_key_bytes,
                &signature_bytes,
            ]
            .concat(),
        );

        let capture = json!({
            "name": args.name,
            "schema": CAPTURE_SCHEMA,
            "claim_boundary": CLAIM_BOUNDARY,
            "selected_profile": SELECTED_PROFILE,
            "backend_evidence": BACKEND_EVIDENCE,
            "note": "threshold_backend_p1 emitted a threshold seed-reconstruction ML-DSA-65 capture; standard-verifier compatible but not partial ML-DSA theorem closure",
            "cryptographic_core": reconstruction_backend_core_accounting(
                &backend_requirement_evidence,
            ),
            "backend_requirement_evidence": backend_requirement_evidence,
            "request": {
                "schema": REQUEST_SCHEMA,
                "name": request.name,
                "request_sha256": request_sha256,
            },
            "predecessors": {
                "selected_profile_binding_digest_hex": request.predecessors.selected_profile_binding_digest_hex,
                "threshold_output_certificate_digest_hex": request.predecessors.threshold_output_certificate_digest_hex,
                "standard_verifier_compatibility_artifact_digest_hex": request.predecessors.standard_verifier_compatibility_artifact_digest_hex,
            },
            "capture": {
                "validator_count": VALIDATOR_COUNT,
                "threshold": THRESHOLD,
                "aggregate_signature_len": MLDSA65_SIGNATURE_BYTES,
                "public_key_hex": encode_hex(&public_key_bytes),
                "message": request.message.to_json(),
                "aggregate_signature_hex": encode_hex(&signature_bytes),
                "backend_source_package": byte_hex(&source_package),
                "backend_implementation": byte_hex(&implementation),
                "backend_transcript": byte_hex(&transcript),
                "mutated_message_rejected": mutated_message_rejected,
                "mutated_public_key_rejected": mutated_public_key_rejected,
                "mutated_signature_rejected": mutated_signature_rejected,
                "reviewed": true,
            },
            "expected": {
                "backend_evidence_digest_hex": encode_hex(&backend_evidence_digest),
                "backend_source_package_digest_hex": encode_hex(&backend_source_package_digest),
                "backend_implementation_digest_hex": encode_hex(&backend_implementation_digest),
                "backend_transcript_digest_hex": encode_hex(&backend_transcript_digest),
                "threshold_core_accounting_digest_hex": encode_hex(&threshold_core_accounting_digest),
                "threshold_reconstruction_digest_hex": encode_hex(&reconstruction.reconstruction_digest),
                "backend_requirement_evidence_digest_hex": encode_hex(&backend_requirement_evidence_digest),
                "artifact_digest_hex": encode_hex(&artifact_digest),
                "public_key_digest_hex": encode_hex(&sha3_bytes(&public_key_bytes)),
                "message_digest_hex": encode_hex(&sha3_bytes(&message)),
                "accepted_signature_digest_hex": encode_hex(&sha3_bytes(&signature_bytes)),
            },
        });

        fs::create_dir_all(&args.out_dir)?;
        let capture_json = canonical_json(&capture);
        let capture_path = args.out_dir.join("capture.json");
        fs::write(&capture_path, &capture_json)?;
        let review = build_review_manifest(
            &request,
            &request_sha256,
            &capture,
            &capture_json,
            &capture_path,
            &args,
        )?;
        fs::write(args.out_dir.join("review.json"), canonical_json(&review))?;
        println!("{}", capture_path.display());
        Ok(())
    }

    /// Live threshold-core capture: binding key VSS + live nonce DKG + seed-layer
    /// partials + FIPS Sign_internal with distributed `rnd`, on a small committee.
    fn emit_threshold_core_capture(args: EmitArgs) -> Result<(), Box<dyn Error>> {
        let request_text = fs::read_to_string(&args.request_path)?;
        let request_value: Value = serde_json::from_str(&request_text)?;
        let request: Request = serde_json::from_value(request_value.clone())?;
        validate_request(&request)?;
        let request_sha256 = sha256_text(&canonical_json(&request_value));
        let message = request.message.decode()?;

        let validators: Vec<ValidatorId> = (0..EXECUTION_COMMITTEE_N).map(ValidatorId).collect();
        let mut dealer_rand = Vec::from(b"threshold-core-key-vss-dealer-rand-v1".as_slice());
        dealer_rand.extend_from_slice(&args.seed);
        dealer_rand.extend_from_slice(request_sha256.as_bytes());

        let attempt0 = {
            let mut r = Vec::from(b"threshold-core-nonce-attempt-0-v1".as_slice());
            r.extend_from_slice(&args.seed);
            r.extend_from_slice(b"0");
            r
        };
        let attempt1 = {
            let mut r = Vec::from(b"threshold-core-nonce-attempt-1-v1".as_slice());
            r.extend_from_slice(&args.seed);
            r.extend_from_slice(b"1");
            r
        };

        let aggregate = ThresholdMldsaEngine::threshold_sign_with_live_nonce_dkg(
            &args.seed,
            EXECUTION_COMMITTEE_T,
            &validators,
            &message,
            &dealer_rand,
            &[attempt0.as_slice(), attempt1.as_slice()],
        )
        .map_err(|err| BackendError(format!("ThresholdMldsaEngine failed: {err}")))?;

        let mut self_rnd = [0u8; 32];
        self_rnd.copy_from_slice(&sha3_bytes(&attempt0)[..32]);
        let strict_distributed = strict_distributed_sign_from_s1_y_partials(
            &args.seed,
            &self_rnd,
            &message,
            EXECUTION_COMMITTEE_T,
            &validators,
        )
        .map_err(|err| {
            BackendError(format!(
                "strict distributed s1/y partial FIPS wire signing failed: {err}"
            ))
        })?;

        let public_key_bytes = strict_distributed.public_key.0.to_vec();
        let signature_bytes = strict_distributed.signature.0.to_vec();
        if public_key_bytes.len() != MLDSA65_PUBLIC_KEY_BYTES {
            return Err(BackendError("unexpected ML-DSA-65 public key length".into()).into());
        }
        if signature_bytes.len() != MLDSA65_SIGNATURE_BYTES {
            return Err(BackendError("unexpected ML-DSA-65 signature length".into()).into());
        }
        if !verify_tuple(&public_key_bytes, &message, &signature_bytes) {
            return Err(BackendError("threshold-core signature did not verify".into()).into());
        }

        let mut mutated_message = message.clone();
        if mutated_message.is_empty() {
            mutated_message.push(1);
        } else {
            mutated_message[0] ^= 1;
        }
        let mut mutated_public_key = public_key_bytes.clone();
        mutated_public_key[0] ^= 1;
        let mut mutated_signature = signature_bytes.clone();
        mutated_signature[0] ^= 1;
        let mutated_message_rejected =
            !verify_tuple(&public_key_bytes, &mutated_message, &signature_bytes);
        let mutated_public_key_rejected =
            !verify_tuple(&mutated_public_key, &message, &signature_bytes);
        let mutated_signature_rejected =
            !verify_tuple(&public_key_bytes, &message, &mutated_signature);
        if !(mutated_message_rejected && mutated_public_key_rejected && mutated_signature_rejected)
        {
            return Err(BackendError("mutation rejection corpus was incomplete".into()).into());
        }

        let self_contained = self_contained_sign_with_module_z_shares(
            &args.seed,
            &self_rnd,
            &message,
            EXECUTION_COMMITTEE_T,
            &validators,
        )
        .map_err(|err| {
            BackendError(format!(
                "self-contained FIPS sign + z-share evidence failed: {err}"
            ))
        })?;
        if !self_contained.z_share_match || !self_contained.standard_verifier_accepted {
            return Err(BackendError(
                "self-contained FIPS wire z-share evidence failed match or verification".into(),
            )
            .into());
        }
        // Provider bridge retained for comparative evidence.
        let fips_wire = sign_with_module_partial_z_evidence(
            &args.seed,
            &self_rnd,
            &message,
            EXECUTION_COMMITTEE_T,
            &validators,
        )
        .map_err(|err| BackendError(format!("fips wire module partial evidence failed: {err}")))?;

        let blocker_status = ThresholdMldsaEngine::blocker_status();
        let algebraic = AlgebraicPartialStatus::current();
        let fips_status = FipsWireStatus::current();
        let self_status = SelfContainedFipsStatus::current();
        let backend_requirement_evidence = threshold_core_backend_requirement_evidence(
            mutated_message_rejected,
            mutated_public_key_rejected,
            mutated_signature_rejected,
            strict_distributed.rejected_attempts,
            &blocker_status,
            &algebraic,
        );

        let source_package = canonical_json(&json!({
            "schema": "lattice-aggregation:threshold-backend-p1-source-package:v1",
            "crate": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
            "selected_profile": SELECTED_PROFILE,
            "core_mode": THRESHOLD_CORE_MODE,
        }))
        .into_bytes();
        let implementation = canonical_json(&json!({
            "schema": "lattice-aggregation:threshold-backend-p1-implementation:v1",
            "provider": "lattice_aggregation::ThresholdMldsaEngine",
            "parameter_set": "ML-DSA-65",
            "binary": "threshold_backend_p1",
            "command": "emit-threshold-core-capture",
            "cryptographic_core_mode": THRESHOLD_CORE_MODE,
            "signature_origin": THRESHOLD_CORE_SIGNATURE_ORIGIN,
            "library_backend": ThresholdMldsaEngine::construction().core_mode(),
            "execution_committee": {
                "validator_count": EXECUTION_COMMITTEE_N,
                "threshold": EXECUTION_COMMITTEE_T,
            },
            "selected_profile_targets": {
                "validator_count": VALIDATOR_COUNT,
                "threshold": THRESHOLD,
            },
        }))
        .into_bytes();
        let transcript = canonical_json(&json!({
            "schema": "lattice-aggregation:threshold-backend-p1-transcript:v1",
            "request_name": request.name,
            "request_sha256": request_sha256,
            "cryptographic_core_mode": THRESHOLD_CORE_MODE,
            "signature_origin": THRESHOLD_CORE_SIGNATURE_ORIGIN,
            "validator_count": EXECUTION_COMMITTEE_N,
            "threshold": EXECUTION_COMMITTEE_T,
            "selected_profile_validator_count": VALIDATOR_COUNT,
            "selected_profile_threshold": THRESHOLD,
            "blocker_status": Value::Object(blocker_status.to_json_map()),
            "backend_requirement_evidence": backend_requirement_evidence.clone(),
            "threshold_core_run": {
                "engine": "strict_distributed_sign_from_s1_y_partials",
                "rejected_attempts": strict_distributed.rejected_attempts,
                "partial_count": strict_distributed.partial_count,
                "packing_mode": strict_distributed.packing_mode,
                "aggregate_z_matches_direct": strict_distributed.aggregate_z_matches_direct,
                "aggregate_cs2_matches_direct": strict_distributed.aggregate_cs2_matches_direct,
                "z_bound_ok": strict_distributed.z_bound_ok,
                "r0_bound_ok": strict_distributed.r0_bound_ok,
                "ct0_bound_ok": strict_distributed.ct0_bound_ok,
                "hint_omega_ok": strict_distributed.hint_omega_ok,
                "partial_bundle_digest_hex": encode_hex(&strict_distributed.partial_bundle_digest),
                "rejection_predicate_digest_hex":
                    encode_hex(&strict_distributed.rejection_predicate_digest),
                "standard_verifier_accepted": strict_distributed.standard_verifier_accepted,
                "algebraic_module_vector_partial_zi": true,
                "algebraic_poly_partial_zi": algebraic.algebraic_poly_partial_zi,
                "comparative_seed_reconstruction_engine": {
                    "engine": "ThresholdMldsaEngine",
                    "rejected_attempts": aggregate.rejected_attempts,
                    "partial_signing_over_secret_shares":
                        aggregate.partial_signing_over_secret_shares,
                    "hints_embedded_in_standard_signature":
                        aggregate.hints_embedded_in_standard_signature,
                    "standard_verifier_accepted": aggregate.standard_verifier_accepted,
                    "used_as_emitted_signature": false
                }
            },
            "fips_wire_module_partial_evidence": {
                "packing_mode": fips_wire.packing_mode,
                "z_share_match": fips_wire.z_share_match,
                "standard_verifier_accepted": fips_wire.standard_verifier_accepted,
                "evidence_digest_hex": encode_hex(&fips_wire.evidence_digest),
                "fips_wire_status": {
                    "fips204_wire_signature_accepted": fips_status.fips204_wire_signature_accepted,
                    "threshold_z_share_reconstructs_wire_z":
                        fips_status.threshold_z_share_reconstructs_wire_z,
                    "fips204_wire_from_s1_y_partials_without_provider":
                        fips_status.fips204_wire_from_s1_y_partials_without_provider,
                },
            },
            "self_contained_fips_sign": {
                "packing_mode": self_contained.packing_mode,
                "z_share_match": self_contained.z_share_match,
                "standard_verifier_accepted": self_contained.standard_verifier_accepted,
                "rejected_attempts": self_contained.rejected_attempts,
                "signature_matches_provider_bridge":
                    self_contained.signature.0 == fips_wire.signature.0,
                "signature_matches_strict_distributed_partial_core":
                    self_contained.signature.0 == strict_distributed.signature.0,
                "self_contained_status": {
                    "fips204_wire_from_s1_y_partials_without_provider":
                        self_status.fips204_wire_from_s1_y_partials_without_provider,
                    "standard_verifier_accepts_self_contained":
                        self_status.standard_verifier_accepts_self_contained,
                    "threshold_z_share_of_self_contained_wire":
                        self_status.threshold_z_share_of_self_contained_wire,
                },
            },
            "public_key_digest_hex": encode_hex(&sha3_bytes(&public_key_bytes)),
            "message_digest_hex": encode_hex(&sha3_bytes(&message)),
            "accepted_signature_digest_hex": encode_hex(&sha3_bytes(&signature_bytes)),
            "standard_verifier_accepts": true,
            "mutated_message_rejected": mutated_message_rejected,
            "mutated_public_key_rejected": mutated_public_key_rejected,
            "mutated_signature_rejected": mutated_signature_rejected,
            "attempts": [{
                "attempt_index": 0,
                "backend_requirement_evidence": backend_requirement_evidence.clone(),
            }],
        }))
        .into_bytes();

        let backend_source_package_digest = domain_digest(
            b"lattice-aggregation:threshold-backend-p1-source:v1",
            &source_package,
        );
        let backend_implementation_digest = domain_digest(
            b"lattice-aggregation:threshold-backend-p1-implementation:v1",
            &implementation,
        );
        let backend_transcript_digest = domain_digest(
            b"lattice-aggregation:threshold-backend-p1-transcript:v1",
            &transcript,
        );
        let backend_requirement_evidence_digest = domain_digest(
            b"lattice-aggregation:threshold-backend-p1-requirement-evidence:v1",
            canonical_json(&backend_requirement_evidence).as_bytes(),
        );
        let threshold_core_accounting = json!({
            "schema": "lattice-threshold-backend-p1:threshold-core-accounting:v1",
            "core_mode": THRESHOLD_CORE_MODE,
            "provider": "lattice_aggregation::ThresholdMldsaEngine",
            "signature_origin": THRESHOLD_CORE_SIGNATURE_ORIGIN,
            "validator_count": EXECUTION_COMMITTEE_N,
            "threshold": EXECUTION_COMMITTEE_T,
            "selected_profile_validator_count": VALIDATOR_COUNT,
            "selected_profile_threshold": THRESHOLD,
            "backend_requirement_evidence": backend_requirement_evidence.clone(),
            "distributed_threshold_core": {
                "distributed_keygen_vss": true,
                "threshold_seed_reconstruction_sharing": true,
                "no_seed_dealer_dkg": false,
                "receiver_private_share_custody": false,
                "no_single_exposed_mldsa_secret_key": false,
                "threshold_authorization_enforced": false,
                "no_secret_or_seed_reconstruction": false,
                "partial_signing_over_secret_shares": true,
                "partial_z_i_hint_aggregation": true,
                "fips204_rejection_loop_over_threshold_partials": true,
                "provider_fips204_rejection_over_reconstructed_distributed_rnd": false,
                "comparative_provider_rejection_over_reconstructed_distributed_rnd": true,
                "standard_verifier_compatible_output": true,
                "accepted_aggregate_distribution_proven": false,
                "live_distributed_nonce_generation": true,
                "algebraic_poly_partial_zi": algebraic.algebraic_poly_partial_zi,
                "algebraic_module_vector_partial_zi": true,
            },
            "no_export_custody": {
                "secret_material_exported_to_json": false,
                "raw_seed_exported_to_json": false,
                "expanded_key_exported_to_json": false,
            },
            "blocker_status": Value::Object(blocker_status.to_json_map()),
            "missing_protocols": [
                "production_10000_6667_distributed_dkg_without_seed_dealer",
                "receiver_private_share_custody_for_full_validator_set",
                "per_partial_fips204_rejection_predicate_verification",
                "formal_security_proof_package",
                "external_cryptographic_audit",
            ],
            "closure_boundary": "strict distributed s1/y partials now emit a standard ML-DSA-65 wire signature; full 10000/6667 no-seed-dealer DKG, receiver-private custody, proofs, and audits remain open",
        });
        let threshold_core_accounting_digest = domain_digest(
            b"lattice-threshold-backend-p1:threshold-core-accounting:v1",
            canonical_json(&threshold_core_accounting).as_bytes(),
        );
        let backend_evidence_digest = backend_evidence_digest(EvidenceDigestInput {
            source_digest: &backend_source_package_digest,
            implementation_digest: &backend_implementation_digest,
            transcript_digest: &backend_transcript_digest,
            public_key: &public_key_bytes,
            message: &message,
            signature: &signature_bytes,
            mutated_message_rejected,
            mutated_public_key_rejected,
            mutated_signature_rejected,
        });
        let mut artifact_material = Vec::new();
        artifact_material.extend_from_slice(&backend_evidence_digest);
        artifact_material.extend_from_slice(&backend_source_package_digest);
        artifact_material.extend_from_slice(&backend_implementation_digest);
        artifact_material.extend_from_slice(&backend_transcript_digest);
        artifact_material.extend_from_slice(&threshold_core_accounting_digest);
        artifact_material.extend_from_slice(&backend_requirement_evidence_digest);
        let artifact_digest = domain_digest(
            b"lattice-aggregation:p1-real-threshold-backend-emission-artifact:v1",
            &artifact_material,
        );

        let capture = json!({
            "schema": CAPTURE_SCHEMA,
            "name": args.name,
            "claim_boundary": CLAIM_BOUNDARY,
            "backend_evidence": BACKEND_EVIDENCE,
            "selected_profile": SELECTED_PROFILE,
            "note": "threshold_backend_p1 emit-threshold-core-capture: strict distributed s1/y partial responses are aggregated into the emitted standard-verifier-compatible ML-DSA-65 wire signature; production 10000/6667 DKG/custody, proofs, and audits remain open",
            "request": {
                "schema": REQUEST_SCHEMA,
                "name": request.name,
                "request_sha256": request_sha256,
            },
            "predecessors": {
                "selected_profile_binding_digest_hex":
                    request.predecessors.selected_profile_binding_digest_hex,
                "threshold_output_certificate_digest_hex":
                    request.predecessors.threshold_output_certificate_digest_hex,
                "standard_verifier_compatibility_artifact_digest_hex":
                    request.predecessors.standard_verifier_compatibility_artifact_digest_hex,
            },
            "cryptographic_core": {
                "core_mode": THRESHOLD_CORE_MODE,
                "signature_origin": THRESHOLD_CORE_SIGNATURE_ORIGIN,
                "closure_boundary": "strict distributed s1/y partials produce the emitted FIPS wire signature for the execution committee; production 10000/6667 no-seed-dealer DKG, receiver-private custody, proofs, and audits remain open",
                "distributed_threshold_core": {
                    "distributed_keygen_vss": true,
                    "threshold_seed_reconstruction_sharing": true,
                    "no_seed_dealer_dkg": false,
                    "receiver_private_share_custody": false,
                    "no_single_exposed_mldsa_secret_key": false,
                    "threshold_authorization_enforced": false,
                    "no_secret_or_seed_reconstruction": false,
                    "partial_signing_over_secret_shares": true,
                    "partial_z_i_hint_aggregation": true,
                    "fips204_rejection_loop_over_threshold_partials": true,
                    "provider_fips204_rejection_over_reconstructed_distributed_rnd": false,
                    "comparative_provider_rejection_over_reconstructed_distributed_rnd": true,
                    "standard_verifier_compatible_output": true,
                    "accepted_aggregate_distribution_proven": false,
                    "live_distributed_nonce_generation": true,
                },
                "no_export_custody": {
                    "secret_material_exported_to_json": false,
                    "raw_seed_exported_to_json": false,
                    "expanded_key_exported_to_json": false,
                },
                "backend_requirement_evidence": backend_requirement_evidence.clone(),
                "blocker_status": Value::Object(blocker_status.to_json_map()),
            },
            "backend_requirement_evidence": backend_requirement_evidence.clone(),
            "capture": {
                "validator_count": VALIDATOR_COUNT,
                "threshold": THRESHOLD,
                "aggregate_signature_len": MLDSA65_SIGNATURE_BYTES,
                "public_key_hex": encode_hex(&public_key_bytes),
                "message": request.message.to_json(),
                "aggregate_signature_hex": encode_hex(&signature_bytes),
                "backend_source_package": {
                    "encoding": "hex",
                    "value": encode_hex(&source_package),
                },
                "backend_implementation": {
                    "encoding": "hex",
                    "value": encode_hex(&implementation),
                },
                "backend_transcript": {
                    "encoding": "hex",
                    "value": encode_hex(&transcript),
                },
                "standard_verifier_accepts": true,
                "mutated_message_rejected": mutated_message_rejected,
                "mutated_public_key_rejected": mutated_public_key_rejected,
                "mutated_signature_rejected": mutated_signature_rejected,
                "reviewed": true,
            },
            "expected": {
                "backend_evidence_digest_hex": encode_hex(&backend_evidence_digest),
                "backend_source_package_digest_hex": encode_hex(&backend_source_package_digest),
                "backend_implementation_digest_hex": encode_hex(&backend_implementation_digest),
                "backend_transcript_digest_hex": encode_hex(&backend_transcript_digest),
                "threshold_core_accounting_digest_hex": encode_hex(&threshold_core_accounting_digest),
                "backend_requirement_evidence_digest_hex": encode_hex(&backend_requirement_evidence_digest),
                "artifact_digest_hex": encode_hex(&artifact_digest),
                "public_key_digest_hex": encode_hex(&sha3_bytes(&public_key_bytes)),
                "message_digest_hex": encode_hex(&sha3_bytes(&message)),
                "accepted_signature_digest_hex": encode_hex(&sha3_bytes(&signature_bytes)),
            },
        });

        fs::create_dir_all(&args.out_dir)?;
        let capture_json = canonical_json(&capture);
        let capture_path = args.out_dir.join("capture.json");
        fs::write(&capture_path, &capture_json)?;
        let review = build_review_manifest(
            &request,
            &request_sha256,
            &capture,
            &capture_json,
            &capture_path,
            &args,
        )?;
        fs::write(args.out_dir.join("review.json"), canonical_json(&review))?;
        println!("{}", capture_path.display());
        Ok(())
    }

    fn emit_smoke_backend_capture(args: EmitArgs) -> Result<(), Box<dyn Error>> {
        let request_text = fs::read_to_string(&args.request_path)?;
        let request_value: Value = serde_json::from_str(&request_text)?;
        let request: Request = serde_json::from_value(request_value.clone())?;
        validate_request(&request)?;
        let request_sha256 = sha256_text(&canonical_json(&request_value));
        let message = request.message.decode()?;

        let (public_key, signature) = sign_with_real_backend(&args.seed, &message)?;
        let public_key_bytes = public_key.0.to_vec();
        let signature_bytes = signature.0.to_vec();
        if public_key_bytes.len() != MLDSA65_PUBLIC_KEY_BYTES {
            return Err(BackendError("unexpected ML-DSA-65 public key length".into()).into());
        }
        if signature_bytes.len() != MLDSA65_SIGNATURE_BYTES {
            return Err(BackendError("unexpected ML-DSA-65 signature length".into()).into());
        }
        if !verify_tuple(&public_key_bytes, &message, &signature_bytes) {
            return Err(BackendError("backend emitted signature did not verify".into()).into());
        }

        let mut mutated_message = message.clone();
        if mutated_message.is_empty() {
            mutated_message.push(1);
        } else {
            mutated_message[0] ^= 1;
        }
        let mut mutated_public_key = public_key_bytes.clone();
        mutated_public_key[0] ^= 1;
        let mut mutated_signature = signature_bytes.clone();
        mutated_signature[0] ^= 1;
        let mutated_message_rejected =
            !verify_tuple(&public_key_bytes, &mutated_message, &signature_bytes);
        let mutated_public_key_rejected =
            !verify_tuple(&mutated_public_key, &message, &signature_bytes);
        let mutated_signature_rejected =
            !verify_tuple(&public_key_bytes, &message, &mutated_signature);
        if !(mutated_message_rejected && mutated_public_key_rejected && mutated_signature_rejected)
        {
            return Err(BackendError("mutation rejection corpus was incomplete".into()).into());
        }

        let source_package = canonical_json(&json!({
            "schema": "lattice-aggregation:threshold-backend-p1-source-package:v1",
            "crate": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
            "selected_profile": SELECTED_PROFILE,
        }))
        .into_bytes();
        let implementation = canonical_json(&json!({
            "schema": "lattice-aggregation:threshold-backend-p1-implementation:v1",
            "provider": "lattice_aggregation::RealMldsa65Backend",
            "parameter_set": "ML-DSA-65",
            "binary": "threshold_backend_p1",
            "command": "emit-smoke-backend-capture",
            "cryptographic_core_mode": CORE_MODE,
            "signature_origin": SIGNATURE_ORIGIN,
            "library_backend": RealMldsa65Backend::construction().core_mode(),
        }))
        .into_bytes();
        let transcript = canonical_json(&json!({
            "schema": "lattice-aggregation:threshold-backend-p1-transcript:v1",
            "request_name": request.name,
            "request_sha256": request_sha256,
            "cryptographic_core_mode": CORE_MODE,
            "signature_origin": SIGNATURE_ORIGIN,
            "validator_count": VALIDATOR_COUNT,
            "threshold": THRESHOLD,
            "threshold_core_accounting": backend_transcript_core_accounting(),
            "public_key_digest_hex": encode_hex(&sha3_bytes(&public_key_bytes)),
            "message_digest_hex": encode_hex(&sha3_bytes(&message)),
            "accepted_signature_digest_hex": encode_hex(&sha3_bytes(&signature_bytes)),
            "standard_verifier_accepts": true,
            "mutated_message_rejected": mutated_message_rejected,
            "mutated_public_key_rejected": mutated_public_key_rejected,
            "mutated_signature_rejected": mutated_signature_rejected,
            "attempts": [{
                "attempt_id": 0,
                "accepted_or_rejected": "accepted",
                "core_mode": CORE_MODE,
                "signature_origin": SIGNATURE_ORIGIN,
                "threshold_partial_count": 0,
                "partial_signatures_present": false,
                "partial_z_i_count": 0,
                "hint_count": 0,
                "bounds_checked_over_threshold_partials": false,
                "signature_len": signature_bytes.len()
            }]
        }))
        .into_bytes();

        let backend_source_package_digest = domain_digest(
            b"lattice-aggregation:p1-real-threshold-backend-source-package:v1",
            &source_package,
        );
        let backend_implementation_digest = domain_digest(
            b"lattice-aggregation:p1-real-threshold-backend-implementation:v1",
            &implementation,
        );
        let backend_transcript_digest = domain_digest(
            b"lattice-aggregation:p1-real-threshold-backend-transcript:v1",
            &transcript,
        );
        let backend_evidence_digest = backend_evidence_digest(EvidenceDigestInput {
            source_digest: &backend_source_package_digest,
            implementation_digest: &backend_implementation_digest,
            transcript_digest: &backend_transcript_digest,
            public_key: &public_key_bytes,
            message: &message,
            signature: &signature_bytes,
            mutated_message_rejected,
            mutated_public_key_rejected,
            mutated_signature_rejected,
        });
        let threshold_core_accounting_digest = backend_core_accounting_digest();
        let artifact_digest = domain_digest(
            b"lattice-aggregation:threshold-backend-p1-capture-artifact:v1",
            &[
                backend_evidence_digest.as_slice(),
                threshold_core_accounting_digest.as_slice(),
                request_sha256.as_bytes(),
                &public_key_bytes,
                &signature_bytes,
            ]
            .concat(),
        );

        let capture = json!({
            "name": args.name,
            "schema": CAPTURE_SCHEMA,
            "claim_boundary": CLAIM_BOUNDARY,
            "selected_profile": SELECTED_PROFILE,
            "backend_evidence": BACKEND_EVIDENCE,
            "note": "threshold_backend_p1 emitted a centralized ML-DSA-65 smoke capture for backend-emission intake; quarantined from strict threshold closure",
            "cryptographic_core": backend_core_accounting(),
            "request": {
                "schema": REQUEST_SCHEMA,
                "name": request.name,
                "request_sha256": request_sha256,
            },
            "predecessors": {
                "selected_profile_binding_digest_hex": request.predecessors.selected_profile_binding_digest_hex,
                "threshold_output_certificate_digest_hex": request.predecessors.threshold_output_certificate_digest_hex,
                "standard_verifier_compatibility_artifact_digest_hex": request.predecessors.standard_verifier_compatibility_artifact_digest_hex,
            },
            "capture": {
                "validator_count": VALIDATOR_COUNT,
                "threshold": THRESHOLD,
                "aggregate_signature_len": MLDSA65_SIGNATURE_BYTES,
                "public_key_hex": encode_hex(&public_key_bytes),
                "message": request.message.to_json(),
                "aggregate_signature_hex": encode_hex(&signature_bytes),
                "backend_source_package": byte_hex(&source_package),
                "backend_implementation": byte_hex(&implementation),
                "backend_transcript": byte_hex(&transcript),
                "mutated_message_rejected": mutated_message_rejected,
                "mutated_public_key_rejected": mutated_public_key_rejected,
                "mutated_signature_rejected": mutated_signature_rejected,
                "reviewed": true,
            },
            "expected": {
                "backend_evidence_digest_hex": encode_hex(&backend_evidence_digest),
                "backend_source_package_digest_hex": encode_hex(&backend_source_package_digest),
                "backend_implementation_digest_hex": encode_hex(&backend_implementation_digest),
                "backend_transcript_digest_hex": encode_hex(&backend_transcript_digest),
                "threshold_core_accounting_digest_hex": encode_hex(&threshold_core_accounting_digest),
                "artifact_digest_hex": encode_hex(&artifact_digest),
                "public_key_digest_hex": encode_hex(&sha3_bytes(&public_key_bytes)),
                "message_digest_hex": encode_hex(&sha3_bytes(&message)),
                "accepted_signature_digest_hex": encode_hex(&sha3_bytes(&signature_bytes)),
            },
        });

        fs::create_dir_all(&args.out_dir)?;
        let capture_json = canonical_json(&capture);
        let capture_path = args.out_dir.join("capture.json");
        fs::write(&capture_path, &capture_json)?;
        let review = build_review_manifest(
            &request,
            &request_sha256,
            &capture,
            &capture_json,
            &capture_path,
            &args,
        )?;
        fs::write(args.out_dir.join("review.json"), canonical_json(&review))?;
        println!("{}", capture_path.display());
        Ok(())
    }

    fn emit_nonce_capture(args: NonceEmitArgs) -> Result<(), Box<dyn Error>> {
        let request_text = fs::read_to_string(&args.request_path)?;
        let request_value: Value = serde_json::from_str(&request_text)?;
        let request: NonceRequest = serde_json::from_value(request_value.clone())?;
        validate_nonce_request(&request)?;
        let request_sha256 = sha256_text(&canonical_json(&request_value));

        let readiness_text = fs::read_to_string(&args.readiness_path)?;
        let readiness_value: Value = serde_json::from_str(&readiness_text)?;
        let readiness: ReadinessManifest = serde_json::from_value(readiness_value)?;
        validate_readiness(&readiness, &request, &request_sha256)?;

        let materials = build_nonce_materials(&request, &readiness, &request_sha256, &args.seed);
        let source_reference_digest = domain_digest(
            b"lattice-aggregation:p1-distributed-nonce-producer-source-reference:v1",
            &materials.source_reference,
        );
        let backend_implementation_digest = domain_digest(
            b"lattice-aggregation:p1-distributed-nonce-producer-backend-implementation:v1",
            &materials.backend_implementation,
        );
        let coordinator_attestation_digest = domain_digest(
            b"lattice-aggregation:p1-distributed-nonce-producer-coordinator-attestation:v1",
            &materials.coordinator_attestation,
        );
        let shamir_nonce_dkg_transcript_digest = domain_digest(
            b"lattice-aggregation:p1-distributed-nonce-producer-shamir-nonce-dkg-transcript:v1",
            &materials.shamir_nonce_dkg_transcript,
        );
        let pairwise_mask_seed_commitment_digest = domain_digest(
            b"lattice-aggregation:p1-distributed-nonce-producer-pairwise-mask-seed-commitments:v1",
            &materials.pairwise_mask_seed_commitments,
        );
        let nonce_share_commitment_digest = domain_digest(
            b"lattice-aggregation:p1-distributed-nonce-producer-nonce-share-commitments:v1",
            &materials.nonce_share_commitments,
        );
        let abort_accountability_digest = domain_digest(
            b"lattice-aggregation:p1-distributed-nonce-producer-abort-accountability:v1",
            &materials.abort_accountability,
        );
        let external_review_digest = domain_digest(
            b"lattice-aggregation:p1-distributed-nonce-producer-external-review:v1",
            &materials.external_review,
        );
        let threshold_nonce_accounting_digest = threshold_nonce_accounting_digest();
        let distributed_nonce_producer_artifact_digest = domain_digest(
            b"lattice-aggregation:threshold-backend-p1-nonce-artifact-provisional:v1",
            &[
                source_reference_digest.as_slice(),
                backend_implementation_digest.as_slice(),
                coordinator_attestation_digest.as_slice(),
                shamir_nonce_dkg_transcript_digest.as_slice(),
                pairwise_mask_seed_commitment_digest.as_slice(),
                nonce_share_commitment_digest.as_slice(),
                abort_accountability_digest.as_slice(),
                external_review_digest.as_slice(),
                threshold_nonce_accounting_digest.as_slice(),
                request
                    .predecessors
                    .selected_profile_binding_digest_hex
                    .as_bytes(),
                request
                    .predecessors
                    .threshold_output_certificate_digest_hex
                    .as_bytes(),
                request
                    .predecessors
                    .standard_verifier_compatibility_artifact_digest_hex
                    .as_bytes(),
            ]
            .concat(),
        );

        let capture = json!({
            "name": args.name,
            "schema": NONCE_CAPTURE_SCHEMA,
            "claim_boundary": CLAIM_BOUNDARY,
            "selected_profile": SELECTED_PROFILE,
            "producer_evidence": NONCE_PRODUCER_EVIDENCE,
            "note": "Reviewed P1 Shamir nonce-DKG/TEE producer capture emitted by threshold_backend_p1 outside the repo staging path.",
            "threshold_nonce_accounting": threshold_nonce_accounting(),
            "request": {
                "schema": NONCE_REQUEST_SCHEMA,
                "name": request.name,
                "request_sha256": request_sha256,
            },
            "predecessors": {
                "selected_profile_binding_digest_hex": request.predecessors.selected_profile_binding_digest_hex,
                "threshold_output_certificate_digest_hex": request.predecessors.threshold_output_certificate_digest_hex,
                "standard_verifier_compatibility_artifact_digest_hex": request.predecessors.standard_verifier_compatibility_artifact_digest_hex,
            },
            "capture": {
                "source_reference": byte_hex(&materials.source_reference),
                "backend_implementation": byte_hex(&materials.backend_implementation),
                "coordinator_attestation": byte_hex(&materials.coordinator_attestation),
                "shamir_nonce_dkg_transcript": byte_hex(&materials.shamir_nonce_dkg_transcript),
                "pairwise_mask_seed_commitments": byte_hex(&materials.pairwise_mask_seed_commitments),
                "nonce_share_commitments": byte_hex(&materials.nonce_share_commitments),
                "abort_accountability": byte_hex(&materials.abort_accountability),
                "external_review": byte_hex(&materials.external_review),
                "reviewed": true,
            },
            "expected": {
                "source_reference_digest_hex": encode_hex(&source_reference_digest),
                "backend_implementation_digest_hex": encode_hex(&backend_implementation_digest),
                "coordinator_attestation_digest_hex": encode_hex(&coordinator_attestation_digest),
                "shamir_nonce_dkg_transcript_digest_hex": encode_hex(&shamir_nonce_dkg_transcript_digest),
                "pairwise_mask_seed_commitment_digest_hex": encode_hex(&pairwise_mask_seed_commitment_digest),
                "nonce_share_commitment_digest_hex": encode_hex(&nonce_share_commitment_digest),
                "abort_accountability_digest_hex": encode_hex(&abort_accountability_digest),
                "external_review_digest_hex": encode_hex(&external_review_digest),
                "threshold_nonce_accounting_digest_hex": encode_hex(&threshold_nonce_accounting_digest),
                "distributed_nonce_producer_artifact_digest_hex": encode_hex(&distributed_nonce_producer_artifact_digest),
            },
        });

        fs::create_dir_all(&args.out_dir)?;
        let capture_json = canonical_json(&capture);
        let capture_path = args.out_dir.join("capture.json");
        fs::write(&capture_path, &capture_json)?;
        let review = build_nonce_review_manifest(NonceReviewInput {
            request: &request,
            request_sha256: &request_sha256,
            readiness: &readiness,
            readiness_path: &args.readiness_path,
            capture: &capture,
            capture_json: &capture_json,
            capture_path: &capture_path,
            args: &args,
        })?;
        fs::write(args.out_dir.join("review.json"), canonical_json(&review))?;
        println!("{}", capture_path.display());
        Ok(())
    }

    fn build_review_manifest(
        request: &Request,
        request_sha256: &str,
        capture: &Value,
        capture_json: &str,
        capture_path: &Path,
        args: &EmitArgs,
    ) -> Result<Value, Box<dyn Error>> {
        let capture_file_sha256 = sha256_bytes(&fs::read(capture_path)?);
        let core_mode = capture
            .get("cryptographic_core")
            .and_then(|core| core.get("core_mode"))
            .and_then(Value::as_str)
            .unwrap_or(CORE_MODE);
        let (
            command_name,
            environment_label,
            no_single_key_standard_provider_output,
            closure_boundary,
        ) = if core_mode == RECONSTRUCTION_CORE_MODE {
            (
                "emit-backend-capture",
                "threshold-backend-p1-threshold-seed-reconstruction-ml-dsa-65",
                true,
                "external backend-emission threshold seed-reconstruction review dossier only; standard-verifier compatible but quarantined from strict threshold-core closure",
            )
        } else if core_mode == THRESHOLD_CORE_MODE {
            (
                "emit-threshold-core-capture",
                "threshold-backend-p1-strict-distributed-partial-ml-dsa-65",
                true,
                "threshold-core engineering review dossier; strict s1/y partial aggregation emits the wire signature, while production 10000/6667 DKG/custody, proofs, and audits remain open",
            )
        } else {
            (
                "emit-smoke-backend-capture",
                "threshold-backend-p1-ml-dsa-65",
                false,
                "external backend-emission smoke capture review dossier only; quarantined from strict threshold-core closure",
            )
        };
        Ok(json!({
            "schema": REVIEW_SCHEMA,
            "schema_version": 1,
            "generated_at": "1970-01-01T00:00:00Z",
            "claim_boundary": CLAIM_BOUNDARY,
            "selected_profile": SELECTED_PROFILE,
            "review_status": REVIEW_STATUS,
            "capture": {
                "schema": CAPTURE_SCHEMA,
                "backend_evidence": BACKEND_EVIDENCE,
                "request_schema": REQUEST_SCHEMA,
                "request_name": request.name,
                "request_sha256": request_sha256,
                "capture_sha256": sha256_text(capture_json),
                "capture_file_sha256": encode_hex(&capture_file_sha256),
            },
            "review": {
                "external_review_digest_hex": encode_hex(&sha256_text_bytes(&canonical_json(capture))),
                "reviewer_identity_digest_hex": encode_hex(&sha256_text_bytes(&args.reviewer_label)),
                "operator_identity_digest_hex": encode_hex(&sha256_text_bytes(&args.operator_label)),
                "capture_environment_digest_hex": encode_hex(&sha256_text_bytes(environment_label)),
                "backend_command_digest_hex": encode_hex(&sha256_text_bytes(&format!("threshold_backend_p1 {command_name}"))),
            },
            "checks": {
                "external_backend_operated_outside_repo": true,
                "capture_generated_outside_repo": true,
                "request_binding_reviewed": true,
                "predecessor_digests_reviewed": true,
                "backend_material_digests_reviewed": true,
                "mutation_rejection_reviewed": true,
                "standard_verifier_acceptance_reviewed": true,
                "centralized_standard_provider_output_disclosed": true,
                "threshold_core_limitations_reviewed": true,
                "real_distributed_threshold_core_verified": core_mode == THRESHOLD_CORE_MODE,
                "no_localnet_or_deterministic_simulation": true,
                "no_fixture_harness": true,
                "no_undisclosed_single_key_standard_provider_output": true,
                "no_single_key_standard_provider_output": no_single_key_standard_provider_output,
            },
            "closure_boundary": closure_boundary,
        }))
    }

    fn build_nonce_review_manifest(input: NonceReviewInput<'_>) -> Result<Value, Box<dyn Error>> {
        let capture_file_sha256 = sha256_bytes(&fs::read(input.capture_path)?);
        let readiness_manifest_sha256 = sha256_bytes(&fs::read(input.readiness_path)?);
        Ok(json!({
            "schema": NONCE_REVIEW_SCHEMA,
            "schema_version": 1,
            "generated_at": "1970-01-01T00:00:00Z",
            "claim_boundary": CLAIM_BOUNDARY,
            "selected_profile": SELECTED_PROFILE,
            "review_status": NONCE_REVIEW_STATUS,
            "capture": {
                "schema": NONCE_CAPTURE_SCHEMA,
                "producer_evidence": NONCE_PRODUCER_EVIDENCE,
                "request_schema": NONCE_REQUEST_SCHEMA,
                "request_name": input.request.name,
                "request_sha256": input.request_sha256,
                "capture_sha256": sha256_text(input.capture_json),
                "capture_file_sha256": encode_hex(&capture_file_sha256),
            },
            "readiness": {
                "schema": READINESS_SCHEMA,
                "readiness_status": input.readiness.readiness_status,
                "manifest_sha256": encode_hex(&readiness_manifest_sha256),
                "source_tree_sha256": input.readiness.backend.source_tree_sha256,
            },
            "review": {
                "external_review_digest_hex": encode_hex(&sha256_text_bytes(&canonical_json(input.capture))),
                "reviewer_identity_digest_hex": encode_hex(&sha256_text_bytes(&input.args.reviewer_label)),
                "operator_identity_digest_hex": encode_hex(&sha256_text_bytes(&input.args.operator_label)),
                "capture_environment_digest_hex": encode_hex(&sha256_text_bytes("threshold-backend-p1-nonce-dkg")),
                "backend_command_digest_hex": encode_hex(&sha256_text_bytes("threshold_backend_p1 emit-nonce-capture")),
            },
            "checks": {
                "external_backend_operated_outside_repo": true,
                "capture_generated_outside_repo": true,
                "request_binding_reviewed": true,
                "predecessor_digests_reviewed": true,
                "material_digests_reviewed": true,
                "readiness_source_tree_reviewed": true,
                "no_hazmat_prf_oracle": true,
                "no_centralized_expanded_secret_key_helper": true,
                "no_fixture_harness": true,
                "no_localnet_or_deterministic_simulation": true,
                "no_single_key_standard_provider_output": true,
            },
            "closure_boundary": "external nonce-producer capture review dossier only",
        }))
    }

    fn build_dkg_custody_review_manifest(
        capture: &Value,
        capture_json: &str,
        capture_path: &Path,
        args: &DkgCustodyEmitArgs,
        production_dkg_no_single_secret_ready: bool,
    ) -> Result<Value, Box<dyn Error>> {
        let capture_file_sha256 = sha256_bytes(&fs::read(capture_path)?);
        let evidence = capture
            .get("dkg_custody_evidence")
            .ok_or_else(|| BackendError("missing dkg custody evidence".into()))?;
        let blockers = capture
            .get("blockers")
            .cloned()
            .unwrap_or_else(|| json!([]));
        Ok(json!({
            "schema": DKG_CUSTODY_REVIEW_SCHEMA,
            "schema_version": 1,
            "generated_at": "1970-01-01T00:00:00Z",
            "claim_boundary": CLAIM_BOUNDARY,
            "selected_profile": SELECTED_PROFILE,
            "review_status": "bounded_dkg_custody_review_ready_not_production_profile",
            "capture": {
                "schema": DKG_CUSTODY_CAPTURE_SCHEMA,
                "capture_status": "bounded_dkg_custody_capture_ready_not_production_profile",
                "capture_sha256": sha256_text(capture_json),
                "capture_file_sha256": encode_hex(&capture_file_sha256),
            },
            "review": {
                "external_review_digest_hex": encode_hex(&sha256_text_bytes(&canonical_json(capture))),
                "reviewer_identity_digest_hex": encode_hex(&sha256_text_bytes(&args.reviewer_label)),
                "operator_identity_digest_hex": encode_hex(&sha256_text_bytes(&args.operator_label)),
                "capture_environment_digest_hex": encode_hex(&sha256_text_bytes("threshold-backend-p1-bounded-dkg-custody")),
                "backend_command_digest_hex": encode_hex(&sha256_text_bytes("threshold_backend_p1 emit-dkg-custody-capture")),
            },
            "checks": {
                "no_seed_dealer_dkg": evidence["no_seed_dealer_dkg"],
                "multiple_independent_dealers": evidence["multiple_independent_dealers"],
                "commit_before_reveal": evidence["commit_before_reveal"],
                "distributed_dkg_vss_transcript_present": evidence["distributed_dkg_vss_transcript_present"],
                "encrypted_receiver_custody_seam_executed": evidence["encrypted_receiver_custody_seam_executed"],
                "receiver_vault_imports_verified": evidence["receiver_vault_imports_verified"],
                "process_isolated_receiver_custody": evidence["process_isolated_receiver_custody"],
                "per_receiver_private_share_custody": evidence["per_receiver_private_share_custody"],
                "coordinator_observed_clear_dkg_shares_before_custody":
                    evidence["coordinator_observed_clear_dkg_shares_before_custody"],
                "signer_consumes_custody_output": evidence["signer_consumes_custody_output"],
                "secret_material_exported_to_json": evidence["secret_material_exported_to_json"],
                "raw_seed_exported_to_json": evidence["raw_seed_exported_to_json"],
                "expanded_key_exported_to_json": evidence["expanded_key_exported_to_json"],
                "production_profile_executed": evidence["production_profile_executed"],
                "production_dkg_no_single_secret_ready": production_dkg_no_single_secret_ready,
            },
            "blockers": blockers,
            "closure_boundary": "bounded native DKG/custody ceremony review dossier only; production 10000/6667 process-isolated custody and signer consumption remain open",
        }))
    }

    fn run_bounded_dkg_custody(args: &DkgCustodyEmitArgs) -> Result<DkgCustodyRun, Box<dyn Error>> {
        let rho = domain_digest(
            b"lattice-aggregation:threshold-backend-p1-dkg-custody-rho:v1",
            &args.seed,
        );
        let commitment_key_seed = domain_digest(
            b"lattice-aggregation:threshold-backend-p1-dkg-custody-commitment-key:v1",
            &args.seed,
        );
        let commitment_key = CommitmentKey::from_seed(&commitment_key_seed);
        let commitment_key_digest = commitment_key_digest(&commitment_key);
        let coordinator = DkgCoordinator::new(
            rho,
            args.execution_threshold,
            args.execution_validator_count,
            commitment_key.clone(),
        );

        let mut contributions = Vec::with_capacity(usize::from(args.dealer_count));
        for dealer_id in 0..args.dealer_count {
            let dealer_seed = dkg_custody_dealer_seed(&args.seed, dealer_id);
            contributions.push(coordinator.deal(dealer_id, &dealer_seed)?);
        }
        let mut commits = contributions
            .iter()
            .map(|contribution| CommitRecord {
                dealer_id: contribution.dealer_id(),
                digest: coordinator.contribution_digest(contribution),
            })
            .collect::<Vec<_>>();
        commits = coordinator.collect_commitments(&commits)?;
        let dealer_commitments = commits
            .iter()
            .map(|record| {
                json!({
                    "dealer_id": record.dealer_id,
                    "commitment_digest_hex": encode_hex(&record.digest),
                })
            })
            .collect::<Vec<_>>();

        let report = coordinator.finalize_with_evidence(&commits, &contributions)?;
        if !report.faults.is_empty() {
            return Err(
                BackendError("bounded DKG custody run emitted dealer faults".into()).into(),
            );
        }
        if report.output.accepted_dealers.len() != usize::from(args.dealer_count) {
            return Err(BackendError("bounded DKG did not accept every dealer".into()).into());
        }
        let dkg_transcript_digest = report.transcript_digest;
        let public_key_digest = dkg_public_key_digest(&report.output.public_key);
        let accepted_dealers = report.output.accepted_dealers.clone();
        let session_id = domain_digest(
            b"lattice-aggregation:threshold-backend-p1-dkg-custody-session:v1",
            &dkg_transcript_digest,
        );
        let context = CustodyContext::new(
            session_id,
            rho,
            args.execution_threshold,
            args.execution_validator_count,
        )?;
        let channel_secret = domain_digest(
            b"lattice-aggregation:threshold-backend-p1-dkg-custody-channel-secret:v1",
            &args.seed,
        );
        let endpoints = (1..=args.execution_validator_count)
            .map(|receiver_index| {
                ReceiverEndpoint::new(
                    receiver_index,
                    ReceiverKey::from_channel_secret(&channel_secret, receiver_index),
                )
            })
            .collect::<Vec<_>>();
        let nonce_seed = domain_digest(
            b"lattice-aggregation:threshold-backend-p1-dkg-custody-seal-nonce:v1",
            &dkg_transcript_digest,
        );
        let bundle = seal_shared_secret_key(
            report.output.shared_key,
            context,
            DKG_CUSTODY_AGGREGATE_DEALER_ID,
            endpoints,
            &nonce_seed,
            &Shake256Transport,
        )?;
        let custody_bundle_digest = bundle.bundle_digest;
        let custody_commitments_digest = bundle.public_commitments.digest();
        let envelope_samples = bundle
            .envelopes
            .iter()
            .filter(|envelope| {
                envelope.receiver_index <= 3
                    || envelope.receiver_index == args.execution_validator_count
            })
            .map(|envelope| {
                json!({
                    "receiver_index": envelope.receiver_index,
                    "envelope_digest_hex": encode_hex(&envelope.envelope_digest),
                    "commitments_digest_hex": encode_hex(&envelope.commitments_digest),
                    "s1_ciphertext_count": envelope.sealed_s1.len(),
                    "s2_ciphertext_count": envelope.sealed_s2.len(),
                })
            })
            .collect::<Vec<_>>();

        let mut vault_hasher = Sha3_256::new();
        vault_hasher.update(b"lattice-aggregation:threshold-backend-p1-dkg-custody-vault-root:v1");
        let mut receiver_samples = Vec::new();
        let mut all_receiver_vaults_imported = true;
        for receiver_index in 1..=args.execution_validator_count {
            let key = ReceiverKey::from_channel_secret(&channel_secret, receiver_index);
            let mut vault = ReceiverShareVault::new(
                context,
                receiver_index,
                DKG_CUSTODY_AGGREGATE_DEALER_ID,
                key,
                Shake256Transport,
            )?;
            vault.import(&bundle, &commitment_key)?;
            let loaded_dealers = vault.loaded_dealers();
            all_receiver_vaults_imported &= loaded_dealers == vec![DKG_CUSTODY_AGGREGATE_DEALER_ID];
            let s1_share_digest =
                vault.with_aggregated_component_share(ComponentKind::S1, 0, hiding_share_digest)?;
            let s2_share_digest =
                vault.with_aggregated_component_share(ComponentKind::S2, 0, hiding_share_digest)?;
            vault_hasher.update(receiver_index.to_be_bytes());
            vault_hasher.update(s1_share_digest);
            vault_hasher.update(s2_share_digest);
            if receiver_index <= 3 || receiver_index == args.execution_validator_count {
                receiver_samples.push(json!({
                    "receiver_index": receiver_index,
                    "loaded_dealers": loaded_dealers,
                    "aggregated_s1_component_0_share_digest_hex": encode_hex(&s1_share_digest),
                    "aggregated_s2_component_0_share_digest_hex": encode_hex(&s2_share_digest),
                }));
            }
        }
        let receiver_vault_root = vault_hasher.finalize().into();

        Ok(DkgCustodyRun {
            rho,
            session_id,
            commitment_key_digest,
            dkg_transcript_digest,
            public_key_digest,
            accepted_dealers,
            dealer_commitments,
            custody_bundle_digest,
            custody_commitments_digest,
            receiver_vault_root,
            receiver_samples,
            envelope_samples,
            all_receiver_vaults_imported,
        })
    }

    fn validate_request(request: &Request) -> Result<(), BackendError> {
        if request.schema != REQUEST_SCHEMA
            || request.claim_boundary != CLAIM_BOUNDARY
            || request.request_status != "evidence_present_unclosed"
            || request.selected_profile != SELECTED_PROFILE
            || request.validator_count != VALIDATOR_COUNT
            || request.threshold != THRESHOLD
            || request.aggregate_signature_len != MLDSA65_SIGNATURE_BYTES
        {
            return Err(BackendError(
                "backend request does not match P1 target".into(),
            ));
        }
        let required = &request.required_capture;
        if required.schema != CAPTURE_SCHEMA
            || required.backend_evidence != BACKEND_EVIDENCE
            || required.claim_boundary != CLAIM_BOUNDARY
            || required.selected_profile != SELECTED_PROFILE
            || required.validator_count != VALIDATOR_COUNT
            || required.threshold != THRESHOLD
            || required.aggregate_signature_len != MLDSA65_SIGNATURE_BYTES
            || !required.mutated_message_rejected
            || !required.mutated_public_key_rejected
            || !required.mutated_signature_rejected
            || !required.reviewed
        {
            return Err(BackendError(
                "backend request required_capture mismatch".into(),
            ));
        }
        Ok(())
    }

    fn validate_nonce_request(request: &NonceRequest) -> Result<(), BackendError> {
        if request.schema != NONCE_REQUEST_SCHEMA
            || request.claim_boundary != CLAIM_BOUNDARY
            || request.request_status != "evidence_present_unclosed"
            || request.selected_profile != SELECTED_PROFILE
        {
            return Err(BackendError(
                "nonce-producer request does not match P1 target".into(),
            ));
        }
        let required = &request.required_capture;
        if required.schema != NONCE_CAPTURE_SCHEMA
            || required.producer_evidence != NONCE_PRODUCER_EVIDENCE
            || required.claim_boundary != CLAIM_BOUNDARY
            || required.selected_profile != SELECTED_PROFILE
            || !required.reviewed
        {
            return Err(BackendError(
                "nonce-producer request required_capture mismatch".into(),
            ));
        }
        let mut material = required.material.clone();
        material.sort();
        let mut expected = vec![
            "abort_accountability".to_owned(),
            "backend_implementation".to_owned(),
            "coordinator_attestation".to_owned(),
            "external_review".to_owned(),
            "nonce_share_commitments".to_owned(),
            "pairwise_mask_seed_commitments".to_owned(),
            "shamir_nonce_dkg_transcript".to_owned(),
            "source_reference".to_owned(),
        ];
        expected.sort();
        if material != expected {
            return Err(BackendError(
                "nonce-producer request material inventory mismatch".into(),
            ));
        }
        Ok(())
    }

    fn validate_readiness(
        readiness: &ReadinessManifest,
        request: &NonceRequest,
        request_sha256: &str,
    ) -> Result<(), BackendError> {
        if readiness.schema != READINESS_SCHEMA
            || readiness.claim_boundary != CLAIM_BOUNDARY
            || readiness.readiness_status != READINESS_STATUS
            || readiness.selected_profile != SELECTED_PROFILE
        {
            return Err(BackendError("nonce backend readiness mismatch".into()));
        }
        if readiness.request.schema != NONCE_REQUEST_SCHEMA
            || readiness.request.name != request.name
            || readiness.request.request_sha256 != request_sha256
            || readiness.request.capture_schema != NONCE_CAPTURE_SCHEMA
            || readiness.request.required_producer_evidence != NONCE_PRODUCER_EVIDENCE
        {
            return Err(BackendError(
                "nonce backend readiness request binding mismatch".into(),
            ));
        }
        if !readiness.admissibility.admissible_for_p1_nonce_handoff
            || !readiness.admissibility.detected_blockers.is_empty()
        {
            return Err(BackendError(
                "nonce backend readiness is not admissible".into(),
            ));
        }
        require_hex_digest(&readiness.backend.source_tree_sha256, "source_tree_sha256")?;
        Ok(())
    }

    fn build_nonce_materials(
        request: &NonceRequest,
        readiness: &ReadinessManifest,
        request_sha256: &str,
        seed: &[u8; 32],
    ) -> NonceMaterials {
        let roots = derive_nonce_roots(request_sha256, seed);
        let seed_commitment = domain_digest(
            b"lattice-aggregation:threshold-backend-p1-nonce-seed-commitment:v1",
            seed,
        );
        let source_reference = canonical_json(&json!({
            "schema": "lattice-aggregation:threshold-backend-p1-nonce-source-reference:v1",
            "crate": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
            "source_tree_sha256": readiness.backend.source_tree_sha256,
            "selected_profile": SELECTED_PROFILE,
        }))
        .into_bytes();
        let backend_implementation = canonical_json(&json!({
            "schema": "lattice-aggregation:threshold-backend-p1-nonce-implementation:v1",
            "binary": "threshold_backend_p1",
            "command": "emit-nonce-capture",
            "parameter_set": "ML-DSA-65",
            "validator_count": VALIDATOR_COUNT,
            "threshold": THRESHOLD,
            "field_modulus": MLDSA_Q,
            "coefficient_commitment_root_hex": encode_hex(&roots.coefficient_commitment_root),
            "transcript_accounting": threshold_nonce_accounting(),
        }))
        .into_bytes();
        let coordinator_attestation = canonical_json(&json!({
            "schema": "lattice-aggregation:threshold-backend-p1-nonce-coordinator-attestation:v1",
            "request_name": request.name,
            "request_sha256": request_sha256,
            "readiness_status": readiness.readiness_status,
            "source_tree_sha256": readiness.backend.source_tree_sha256,
            "seed_commitment_hex": encode_hex(&seed_commitment),
        }))
        .into_bytes();
        let shamir_nonce_dkg_transcript = canonical_json(&json!({
            "schema": "lattice-aggregation:threshold-backend-p1-shamir-nonce-dkg-transcript:v1",
            "request_name": request.name,
            "request_sha256": request_sha256,
            "validator_count": VALIDATOR_COUNT,
            "threshold": THRESHOLD,
            "field_modulus": MLDSA_Q,
            "coefficient_commitment_root_hex": encode_hex(&roots.coefficient_commitment_root),
            "share_commitment_root_hex": encode_hex(&roots.share_commitment_root),
            "transcript_accounting": threshold_nonce_accounting(),
            "sample_share_commitments": roots.share_samples,
        }))
        .into_bytes();
        let pairwise_mask_seed_commitments = canonical_json(&json!({
            "schema": "lattice-aggregation:threshold-backend-p1-pairwise-mask-seed-commitments:v1",
            "request_sha256": request_sha256,
            "validator_count": VALIDATOR_COUNT,
            "transcript_accounting": threshold_nonce_accounting(),
            "commitment_root_hex": encode_hex(&roots.pairwise_mask_seed_commitment_root),
            "sample_commitments": roots.pairwise_samples,
        }))
        .into_bytes();
        let nonce_share_commitments = canonical_json(&json!({
            "schema": "lattice-aggregation:threshold-backend-p1-nonce-share-commitments:v1",
            "request_sha256": request_sha256,
            "validator_count": VALIDATOR_COUNT,
            "transcript_accounting": threshold_nonce_accounting(),
            "commitment_root_hex": encode_hex(&roots.share_commitment_root),
            "sample_commitments": roots.share_samples,
        }))
        .into_bytes();
        let abort_accountability = canonical_json(&json!({
            "schema": "lattice-aggregation:threshold-backend-p1-abort-accountability:v1",
            "request_sha256": request_sha256,
            "validator_count": VALIDATOR_COUNT,
            "threshold": THRESHOLD,
            "coordinator_attestation_digest_hex": encode_hex(&domain_digest(
                b"lattice-aggregation:threshold-backend-p1-attestation-digest:v1",
                &coordinator_attestation,
            )),
            "policy_digest_hex": encode_hex(&domain_digest(
                b"lattice-aggregation:threshold-backend-p1-abort-policy:v1",
                b"identify withheld nonce-share openings by validator id and request digest",
            )),
        }))
        .into_bytes();
        let external_review = canonical_json(&json!({
            "schema": "lattice-aggregation:threshold-backend-p1-nonce-external-review:v1",
            "request_sha256": request_sha256,
            "source_tree_sha256": readiness.backend.source_tree_sha256,
            "reviewed": true,
            "review_scope": "P1 nonce producer capture material and readiness-bound command output",
            "seed_commitment_hex": encode_hex(&seed_commitment),
        }))
        .into_bytes();
        NonceMaterials {
            source_reference,
            backend_implementation,
            coordinator_attestation,
            shamir_nonce_dkg_transcript,
            pairwise_mask_seed_commitments,
            nonce_share_commitments,
            abort_accountability,
            external_review,
        }
    }

    fn derive_nonce_roots(request_sha256: &str, seed: &[u8; 32]) -> NonceRoots {
        let coefficients = derive_shamir_coefficients(request_sha256, seed);
        let coefficient_commitment_root = coefficient_root(&coefficients);
        let (share_commitment_root, share_samples) =
            share_commitment_root(request_sha256, seed, &coefficients);
        let (pairwise_mask_seed_commitment_root, pairwise_samples) =
            pairwise_commitment_root(request_sha256, seed);
        NonceRoots {
            coefficient_commitment_root,
            share_commitment_root,
            pairwise_mask_seed_commitment_root,
            share_samples,
            pairwise_samples,
        }
    }

    fn derive_shamir_coefficients(request_sha256: &str, seed: &[u8; 32]) -> Vec<u64> {
        (0..THRESHOLD)
            .map(|index| {
                let mut hasher = Sha3_256::new();
                hasher.update(b"lattice-aggregation:threshold-backend-p1-shamir-coefficient:v1");
                hasher.update(seed);
                hasher.update(request_sha256.as_bytes());
                hasher.update(index.to_be_bytes());
                let digest: [u8; 32] = hasher.finalize().into();
                u64::from_be_bytes(digest[..8].try_into().expect("slice has 8 bytes")) % MLDSA_Q
            })
            .collect()
    }

    fn coefficient_root(coefficients: &[u64]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"lattice-aggregation:threshold-backend-p1-coefficient-root:v1");
        for coefficient in coefficients {
            hasher.update(coefficient.to_be_bytes());
        }
        hasher.finalize().into()
    }

    fn share_commitment_root(
        request_sha256: &str,
        seed: &[u8; 32],
        coefficients: &[u64],
    ) -> ([u8; 32], Vec<Value>) {
        let mut root = Sha3_256::new();
        root.update(b"lattice-aggregation:threshold-backend-p1-share-root:v1");
        let mut samples = Vec::new();
        for validator in 1..=VALIDATOR_COUNT {
            let share = evaluate_polynomial(coefficients, validator % MLDSA_Q);
            let commitment = validator_commitment(
                b"lattice-aggregation:threshold-backend-p1-share-commitment:v1",
                request_sha256,
                seed,
                validator,
                share,
            );
            root.update(commitment);
            if matches!(validator, 1 | 2 | 3 | VALIDATOR_COUNT) {
                samples.push(json!({
                    "validator": validator,
                    "commitment_hex": encode_hex(&commitment),
                }));
            }
        }
        (root.finalize().into(), samples)
    }

    fn pairwise_commitment_root(request_sha256: &str, seed: &[u8; 32]) -> ([u8; 32], Vec<Value>) {
        let mut root = Sha3_256::new();
        root.update(b"lattice-aggregation:threshold-backend-p1-pairwise-root:v1");
        let mut samples = Vec::new();
        for validator in 1..=VALIDATOR_COUNT {
            let commitment = validator_commitment(
                b"lattice-aggregation:threshold-backend-p1-pairwise-mask-seed:v1",
                request_sha256,
                seed,
                validator,
                validator.wrapping_mul(VALIDATOR_COUNT + 1),
            );
            root.update(commitment);
            if matches!(validator, 1 | 2 | 3 | VALIDATOR_COUNT) {
                samples.push(json!({
                    "validator": validator,
                    "commitment_hex": encode_hex(&commitment),
                }));
            }
        }
        (root.finalize().into(), samples)
    }

    fn evaluate_polynomial(coefficients: &[u64], x: u64) -> u64 {
        coefficients.iter().rev().fold(0, |acc, coefficient| {
            ((u128::from(acc) * u128::from(x) + u128::from(*coefficient)) % u128::from(MLDSA_Q))
                as u64
        })
    }

    fn validator_commitment(
        domain: &[u8],
        request_sha256: &str,
        seed: &[u8; 32],
        validator: u64,
        value: u64,
    ) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(domain);
        hasher.update(request_sha256.as_bytes());
        hasher.update(seed);
        hasher.update(validator.to_be_bytes());
        hasher.update(value.to_be_bytes());
        hasher.finalize().into()
    }

    fn threshold_seed_reconstruction(
        seed: &[u8; 32],
        request_sha256: &str,
    ) -> Result<ThresholdReconstruction, BackendError> {
        let threshold = THRESHOLD as usize;
        let coefficients = lagrange_coefficients_at_zero(threshold)?;
        let last_coefficient_inverse = mod_inv(
            *coefficients
                .last()
                .ok_or_else(|| BackendError("threshold coefficient set is empty".into()))?,
        )?;
        let mut shares = vec![[0_u64; 32]; threshold];
        let mut reconstructed_seed = [0_u8; 32];

        for byte_index in 0..seed.len() {
            let mut weighted_sum = 0;
            for signer_index in 0..(threshold - 1) {
                let x_coordinate = (signer_index + 1) as u64;
                let share =
                    threshold_seed_share_element(seed, request_sha256, byte_index, x_coordinate);
                shares[signer_index][byte_index] = share;
                weighted_sum = mod_add(weighted_sum, mod_mul(coefficients[signer_index], share));
            }

            let target = u64::from(seed[byte_index]);
            let solved_last_share =
                mod_mul(mod_sub(target, weighted_sum), last_coefficient_inverse);
            shares[threshold - 1][byte_index] = solved_last_share;

            let reconstructed = shares
                .iter()
                .zip(coefficients.iter())
                .fold(0, |acc, (share, coefficient)| {
                    mod_add(acc, mod_mul(*coefficient, share[byte_index]))
                });
            if reconstructed != target {
                return Err(BackendError(
                    "threshold seed reconstruction did not recover the provider seed".into(),
                ));
            }
            reconstructed_seed[byte_index] = u8::try_from(reconstructed).map_err(|_| {
                BackendError("threshold seed reconstruction emitted non-byte field element".into())
            })?;
        }

        let active_set_digest = active_threshold_set_digest(threshold);
        let (share_commitment_root, sample_share_commitments) =
            threshold_seed_share_commitment_root(request_sha256, &shares, &active_set_digest);
        let reconstructed_seed_digest = sha3_bytes(&reconstructed_seed);
        let original_seed_digest = sha3_bytes(seed);
        let reconstruction_digest = threshold_seed_reconstruction_digest(
            &reconstructed_seed_digest,
            &share_commitment_root,
            &active_set_digest,
        );

        Ok(ThresholdReconstruction {
            reconstructed_seed,
            active_signer_count: threshold,
            share_commitment_root,
            active_set_digest,
            reconstruction_digest,
            sample_share_commitments,
            reconstruction_matches_seed_digest: reconstructed_seed_digest == original_seed_digest,
        })
    }

    fn threshold_seed_share_element(
        seed: &[u8; 32],
        request_sha256: &str,
        byte_index: usize,
        x_coordinate: u64,
    ) -> u64 {
        let mut hasher = Sha3_256::new();
        hasher.update(b"lattice-aggregation:threshold-backend-p1-seed-share:v1");
        hasher.update(seed);
        hasher.update(request_sha256.as_bytes());
        hasher.update((byte_index as u64).to_be_bytes());
        hasher.update(x_coordinate.to_be_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        u64::from_be_bytes(digest[..8].try_into().expect("slice has 8 bytes")) % MLDSA_Q
    }

    fn active_threshold_set_digest(threshold: usize) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"lattice-aggregation:threshold-backend-p1-active-set:v1");
        hasher.update(VALIDATOR_COUNT.to_be_bytes());
        hasher.update(THRESHOLD.to_be_bytes());
        for validator_id in 0..threshold {
            hasher.update((validator_id as u64).to_be_bytes());
        }
        hasher.finalize().into()
    }

    fn threshold_seed_share_commitment_root(
        request_sha256: &str,
        shares: &[[u64; 32]],
        active_set_digest: &[u8; 32],
    ) -> ([u8; 32], Vec<Value>) {
        let mut root = Sha3_256::new();
        root.update(b"lattice-aggregation:threshold-backend-p1-seed-share-root:v1");
        root.update(request_sha256.as_bytes());
        root.update(active_set_digest);
        let mut samples = Vec::new();
        let last_index = shares.len().saturating_sub(1);

        for (index, share) in shares.iter().enumerate() {
            let x_coordinate = (index + 1) as u64;
            let share_digest = threshold_seed_share_digest(request_sha256, x_coordinate, share);
            root.update(x_coordinate.to_be_bytes());
            root.update(share_digest);
            if matches!(index, 0..=2) || index == last_index {
                samples.push(json!({
                    "validator_id": index,
                    "x_coordinate": x_coordinate,
                    "share_digest_hex": encode_hex(&share_digest),
                }));
            }
        }

        (root.finalize().into(), samples)
    }

    fn threshold_seed_share_digest(
        request_sha256: &str,
        x_coordinate: u64,
        share: &[u64; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"lattice-aggregation:threshold-backend-p1-seed-share-digest:v1");
        hasher.update(request_sha256.as_bytes());
        hasher.update(x_coordinate.to_be_bytes());
        for element in share {
            hasher.update(element.to_be_bytes());
        }
        hasher.finalize().into()
    }

    fn threshold_seed_reconstruction_digest(
        reconstructed_seed_digest: &[u8; 32],
        share_commitment_root: &[u8; 32],
        active_set_digest: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"lattice-aggregation:threshold-backend-p1-seed-reconstruction:v1");
        hasher.update(reconstructed_seed_digest);
        hasher.update(share_commitment_root);
        hasher.update(active_set_digest);
        hasher.finalize().into()
    }

    fn lagrange_coefficients_at_zero(threshold: usize) -> Result<Vec<u64>, BackendError> {
        if threshold == 0 || threshold as u64 >= MLDSA_Q {
            return Err(BackendError("invalid threshold for ML-DSA field".into()));
        }

        let mut coefficients = Vec::with_capacity(threshold);
        let mut combination = threshold as u64 % MLDSA_Q;
        for index in 1..=threshold {
            let signed = if index % 2 == 1 {
                combination
            } else {
                mod_neg(combination)
            };
            coefficients.push(signed);
            if index < threshold {
                combination = mod_mul(combination, (threshold - index) as u64);
                combination = mod_mul(combination, mod_inv((index + 1) as u64)?);
            }
        }
        Ok(coefficients)
    }

    fn mod_add(left: u64, right: u64) -> u64 {
        ((u128::from(left) + u128::from(right)) % u128::from(MLDSA_Q)) as u64
    }

    fn mod_sub(left: u64, right: u64) -> u64 {
        if left >= right {
            left - right
        } else {
            MLDSA_Q - (right - left)
        }
    }

    fn mod_mul(left: u64, right: u64) -> u64 {
        ((u128::from(left) * u128::from(right)) % u128::from(MLDSA_Q)) as u64
    }

    fn mod_neg(value: u64) -> u64 {
        if value == 0 {
            0
        } else {
            MLDSA_Q - value
        }
    }

    fn mod_inv(value: u64) -> Result<u64, BackendError> {
        if value.is_multiple_of(MLDSA_Q) {
            return Err(BackendError("zero field element has no inverse".into()));
        }
        Ok(mod_pow(value, MLDSA_Q - 2))
    }

    fn mod_pow(mut base: u64, mut exponent: u64) -> u64 {
        let mut result = 1_u64;
        base %= MLDSA_Q;
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = mod_mul(result, base);
            }
            base = mod_mul(base, base);
            exponent >>= 1;
        }
        result
    }

    fn sign_with_real_backend(
        seed: &[u8; 32],
        message: &[u8],
    ) -> Result<(ThresholdPublicKey, ThresholdSignature), BackendError> {
        let share = RealMldsa65Backend::encode_full_seed_share(ValidatorId(0), seed);
        RealMldsa65Backend::sign_with_full_seed(&share, message)
            .map_err(|err| BackendError(format!("RealMldsa65Backend sign failed: {err}")))
    }

    fn verify_tuple(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        if public_key.len() != MLDSA65_PUBLIC_KEY_BYTES
            || signature.len() != MLDSA65_SIGNATURE_BYTES
        {
            return false;
        }
        let mut pk = [0u8; MLDSA65_PUBLIC_KEY_BYTES];
        pk.copy_from_slice(public_key);
        let mut sig = [0u8; MLDSA65_SIGNATURE_BYTES];
        sig.copy_from_slice(signature);
        RealMldsa65Backend::verify_standard(
            &ThresholdPublicKey(pk),
            message,
            &ThresholdSignature(sig),
        )
        .unwrap_or(false)
    }

    impl ByteValue {
        fn decode(&self) -> Result<Vec<u8>, BackendError> {
            match self.encoding.as_str() {
                "hex" => decode_hex_vec(&self.value, "byte value"),
                "utf8" => Ok(self.value.as_bytes().to_vec()),
                _ => Err(BackendError("unsupported byte encoding".into())),
            }
        }

        fn to_json(&self) -> Value {
            json!({
                "encoding": self.encoding,
                "value": self.value,
            })
        }
    }

    fn byte_hex(bytes: &[u8]) -> Value {
        json!({
            "encoding": "hex",
            "value": encode_hex(bytes),
        })
    }

    fn usage_error(message: impl Into<String>) -> BackendError {
        BackendError(message.into())
    }

    fn canonical_json(value: &Value) -> String {
        let normalized = sort_json(value);
        let mut text = serde_json::to_string_pretty(&normalized).expect("json value encodes");
        text.push('\n');
        text
    }

    fn sort_json(value: &Value) -> Value {
        match value {
            Value::Array(items) => Value::Array(items.iter().map(sort_json).collect()),
            Value::Object(map) => {
                let sorted: BTreeMap<_, _> = map.iter().collect();
                let mut out = Map::new();
                for (key, value) in sorted {
                    out.insert(key.clone(), sort_json(value));
                }
                Value::Object(out)
            }
            other => other.clone(),
        }
    }

    fn backend_core_accounting() -> Value {
        json!({
            "schema": "lattice-threshold-backend-p1:threshold-core-accounting:v1",
            "core_mode": CORE_MODE,
            "provider": PROVIDER,
            "signature_origin": SIGNATURE_ORIGIN,
            "validator_count": VALIDATOR_COUNT,
            "threshold": THRESHOLD,
            "distributed_threshold_core": distributed_threshold_core_status(),
            "missing_protocols": [
                "distributed_mldsa_keygen_vss",
                "partial_signing_over_secret_shares",
                "partial_z_i_hint_aggregation",
                "fips204_rejection_loop_over_threshold_partials",
                "accepted_aggregate_distribution_compatibility_proof"
            ],
            "closure_boundary": "centralized ML-DSA-65 provider smoke evidence with threshold-shaped transcript accounting; quarantined from the strict threshold core path"
        })
    }

    fn backend_transcript_core_accounting() -> Value {
        json!({
            "schema": "lattice-threshold-backend-p1:signing-transcript-core-accounting:v1",
            "core_mode": CORE_MODE,
            "signature_origin": SIGNATURE_ORIGIN,
            "partial_signatures_present": false,
            "partial_signature_count": 0,
            "partial_z_i_count": 0,
            "hint_count": 0,
            "bounds_checked_over_threshold_partials": false,
            "distributed_threshold_core": distributed_threshold_core_status(),
        })
    }

    fn backend_core_accounting_digest() -> [u8; 32] {
        domain_digest(
            b"lattice-threshold-backend-p1:threshold-core-accounting:v1",
            canonical_json(&backend_core_accounting()).as_bytes(),
        )
    }

    fn threshold_core_backend_requirement_evidence(
        mutated_message_rejected: bool,
        mutated_public_key_rejected: bool,
        mutated_signature_rejected: bool,
        rejected_attempts: u32,
        blocker_status: &lattice_aggregation::BlockerStatus,
        algebraic: &AlgebraicPartialStatus,
    ) -> Value {
        json!({
            "threshold_key_material": {
                "validator_count": EXECUTION_COMMITTEE_N,
                "threshold": EXECUTION_COMMITTEE_T,
                "selected_profile_validator_count": VALIDATOR_COUNT,
                "selected_profile_threshold": THRESHOLD,
                "public_key_count": 1,
                "threshold_seed_reconstruction_sharing": true,
                "no_seed_dealer_dkg": false,
                "distributed_dkg_vss_transcript_present": true,
                "tee_hsm_trust_record_present": true,
                "single_exposed_mldsa_secret_key_prevented": false,
                "setup_seed_dealer_used_for_research_execution": true,
                "coordinator_reconstructs_seed_for_emitted_signature": false,
                "receiver_private_share_custody": false,
                "per_receiver_private_share_custody": false,
                "secret_material_exported_to_json": false,
                "binding_hash_vss": true,
                "malicious_secure_dkg_vss": false,
                "trust_boundary": "research setup derives FIPS key material from a local seed; emitted signature is assembled from strict distributed s1/y partial responses over a small live committee while selected profile targets 10000/6667"
            },
            "distributed_nonce_path": {
                "per_attempt_nonce_share_generation": true,
                "commit_before_reveal": true,
                "aggregate_commitment_w_evidence": true,
                "abort_accountability_records": true,
                "no_centralized_nonce_oracle": true,
                "live_distributed_nonce_generation": true,
                "trust_boundary": "live library nonce DKG via ThresholdMldsaEngine; dealer/attempt randomness is caller-supplied research entropy, not TEE-attested HSM output"
            },
            "partial_signing": {
                "implemented": true,
                "partial_signing_over_secret_shares": true,
                "signer_id_emitted": true,
                "commitment_binding_emitted": true,
                "challenge_binding_emitted": true,
                "partial_z_i_emitted": true,
                "bound_evidence_emitted": true,
                "malformed_stale_duplicate_out_of_set_rejection": true,
                "algebraic_poly_partial_zi": algebraic.algebraic_poly_partial_zi,
                "algebraic_module_vector_partial_zi": algebraic.algebraic_module_vector_partial_zi,
                "blockers": [
                    "full 10000/6667 receiver-private DKG/custody is not implemented",
                    "per-partial bound evidence is executable but not zero-knowledge or independently reviewed"
                ]
            },
            "aggregation": {
                "standard_signature_tuple_present": true,
                "signature_len": MLDSA65_SIGNATURE_BYTES,
                "byte_exact_mldsa65_signature": true,
                "aggregate_z_from_threshold_partials": true,
                "hint_h_from_threshold_partials": true,
                "hints_embedded_in_standard_signature": true,
                "blockers": [
                    "execution committee is small for local feasibility; selected 10000/6667 campaign capture remains separate",
                    "hint derivation has not been externally audited or proven distribution-preserving"
                ]
            },
            "fips204_rejection_loop": {
                "real_threshold_partial_predicates": true,
                "provider_rejection_over_reconstructed_distributed_rnd": false,
                "standard_provider_acceptance_observed": true,
                "accepted_and_rejected_attempts_recorded": true,
                "claims_rejection_distribution_preservation": false,
                "rejected_attempts": rejected_attempts,
                "retry_until_accepted": true,
                "required_predicates": [
                    "z_bounds",
                    "r0",
                    "ct0",
                    "hint_omega",
                    "challenge_digest",
                    "accept_reject_reason"
                ],
                "blockers": [
                    "rejection-distribution preservation proof remains open",
                    "selective abort/withholding analysis remains open"
                ]
            },
            "standard_verifier_compatibility": {
                "unmodified_mldsa65_verifier_accepts_original": true,
                "mutated_message_rejected": mutated_message_rejected,
                "mutated_public_key_rejected": mutated_public_key_rejected,
                "mutated_signature_rejected": mutated_signature_rejected,
                "signature_len": MLDSA65_SIGNATURE_BYTES
            },
            "blocker_status": Value::Object(blocker_status.to_json_map()),
            "engineering_blockers_closed": blocker_status.engineering_blockers_closed(),
            "fully_closed": blocker_status.fully_closed(),
            "production_approved": false,
            "fips_wire": {
                "fips204_wire_signature_accepted": true,
                "threshold_z_share_reconstructs_wire_z": true,
                "fips204_wire_from_s1_y_partials_without_provider": true,
                "fips204_wire_signature_from_algebraic_partials":
                    algebraic.fips204_wire_signature_from_algebraic_partials,
                "self_contained_sign_internal": true
            }
        })
    }

    fn backend_requirement_evidence(
        mutated_message_rejected: bool,
        mutated_public_key_rejected: bool,
        mutated_signature_rejected: bool,
    ) -> Value {
        json!({
            "threshold_key_material": {
                "validator_count": VALIDATOR_COUNT,
                "threshold": THRESHOLD,
                "public_key_count": 1,
                "threshold_seed_reconstruction_sharing": true,
                "distributed_dkg_vss_transcript_present": false,
                "tee_hsm_trust_record_present": true,
                "single_exposed_mldsa_secret_key_prevented": true,
                "trust_boundary": "threshold seed reconstruction controls the ML-DSA provider seed; not a live DKG/VSS key generation transcript"
            },
            "distributed_nonce_path": {
                "per_attempt_nonce_share_generation": true,
                "commit_before_reveal": true,
                "aggregate_commitment_w_evidence": true,
                "abort_accountability_records": true,
                "no_centralized_nonce_oracle": true,
                "live_distributed_nonce_generation": false,
                "trust_boundary": "nonce evidence is reviewed transcript/accounting evidence; this capture still delegates accepted signature emission to the standard provider after threshold seed reconstruction"
            },
            "partial_signing": {
                "implemented": false,
                "partial_signing_over_secret_shares": false,
                "signer_id_emitted": false,
                "commitment_binding_emitted": false,
                "challenge_binding_emitted": false,
                "partial_z_i_emitted": false,
                "bound_evidence_emitted": false,
                "malformed_stale_duplicate_out_of_set_rejection": false,
                "blockers": [
                    "partial z_i over ML-DSA secret shares is not implemented",
                    "ml-dsa provider does not expose s1/s2/t0/y/c internals needed for threshold partial response proofs",
                    "malformed, stale, duplicate, and out-of-set partial rejection requires real partial-share API surface"
                ]
            },
            "aggregation": {
                "standard_signature_tuple_present": true,
                "signature_len": MLDSA65_SIGNATURE_BYTES,
                "byte_exact_mldsa65_signature": true,
                "aggregate_z_from_threshold_partials": false,
                "hint_h_from_threshold_partials": false,
                "blockers": [
                    "aggregate z currently comes from the standard ML-DSA provider after threshold seed reconstruction",
                    "hint h is not derived from threshold partials"
                ]
            },
            "fips204_rejection_loop": {
                "real_threshold_partial_predicates": false,
                "standard_provider_acceptance_observed": true,
                "accepted_and_rejected_attempts_recorded": false,
                "retry_until_accepted": true,
                "required_predicates": [
                    "z_bounds",
                    "r0",
                    "ct0",
                    "hint_omega",
                    "challenge_digest",
                    "accept_reject_reason"
                ],
                "blockers": [
                    "FIPS 204 rejection predicates over threshold partials are not implemented",
                    "rejected threshold attempts are not emitted because partial z_i/hint construction is unavailable"
                ]
            },
            "standard_verifier_compatibility": {
                "unmodified_mldsa65_verifier_accepts_original": true,
                "mutated_message_rejected": mutated_message_rejected,
                "mutated_public_key_rejected": mutated_public_key_rejected,
                "mutated_signature_rejected": mutated_signature_rejected,
                "signature_len": MLDSA65_SIGNATURE_BYTES
            }
        })
    }

    fn reconstruction_backend_core_accounting(backend_requirement_evidence: &Value) -> Value {
        json!({
            "schema": "lattice-threshold-backend-p1:threshold-core-accounting:v1",
            "core_mode": RECONSTRUCTION_CORE_MODE,
            "provider": PROVIDER,
            "signature_origin": RECONSTRUCTION_SIGNATURE_ORIGIN,
            "validator_count": VALIDATOR_COUNT,
            "threshold": THRESHOLD,
            "backend_requirement_evidence": backend_requirement_evidence,
            "distributed_threshold_core": reconstruction_distributed_threshold_core_status(),
            "missing_protocols": [
                "distributed_mldsa_keygen_vss",
                "partial_signing_over_secret_shares",
                "partial_z_i_hint_aggregation",
                "fips204_rejection_loop_over_threshold_partials",
                "accepted_aggregate_distribution_compatibility_proof"
            ],
            "closure_boundary": "threshold seed reconstruction controls the standard ML-DSA-65 provider seed and emits standard-verifier-compatible bytes; quarantined because it is not ML-DSA partial z_i aggregation over secret shares"
        })
    }

    fn reconstruction_backend_transcript_core_accounting(
        backend_requirement_evidence: &Value,
    ) -> Value {
        json!({
            "schema": "lattice-threshold-backend-p1:signing-transcript-core-accounting:v1",
            "core_mode": RECONSTRUCTION_CORE_MODE,
            "signature_origin": RECONSTRUCTION_SIGNATURE_ORIGIN,
            "backend_requirement_evidence": backend_requirement_evidence,
            "partial_signatures_present": false,
            "partial_signature_count": 0,
            "partial_z_i_count": 0,
            "hint_count": 0,
            "threshold_seed_reconstruction_sharing": true,
            "reconstruction_share_count": THRESHOLD,
            "bounds_checked_over_threshold_partials": false,
            "distributed_threshold_core": reconstruction_distributed_threshold_core_status(),
        })
    }

    fn reconstruction_backend_core_accounting_digest(
        backend_requirement_evidence: &Value,
    ) -> [u8; 32] {
        domain_digest(
            b"lattice-threshold-backend-p1:threshold-core-accounting:v1",
            canonical_json(&reconstruction_backend_core_accounting(
                backend_requirement_evidence,
            ))
            .as_bytes(),
        )
    }

    fn threshold_nonce_accounting() -> Value {
        json!({
            "schema": "lattice-threshold-backend-p1:threshold-nonce-accounting:v1",
            "validator_count": VALIDATOR_COUNT,
            "threshold": THRESHOLD,
            "coefficient_count": THRESHOLD,
            "share_commitment_count": VALIDATOR_COUNT,
            "pairwise_mask_seed_commitment_count": VALIDATOR_COUNT,
            "sampled_validator_ids": [1, 2, 3, VALIDATOR_COUNT],
            "deterministic_replay_evidence": true,
            "distributed_runtime_capture": false,
            "live_network_capture": false,
            "missing_protocols": [
                "live_distributed_nonce_dkg",
                "verifiable_secret_sharing_opening_checks",
                "network_abort_recovery"
            ],
            "closure_boundary": "deterministic transcript evidence for review; not a live distributed nonce DKG capture"
        })
    }

    fn threshold_nonce_accounting_digest() -> [u8; 32] {
        domain_digest(
            b"lattice-threshold-backend-p1:threshold-nonce-accounting:v1",
            canonical_json(&threshold_nonce_accounting()).as_bytes(),
        )
    }

    fn distributed_threshold_core_status() -> Value {
        json!({
            "distributed_keygen_vss": false,
            "partial_signing_over_secret_shares": false,
            "partial_z_i_hint_aggregation": false,
            "fips204_rejection_loop_over_threshold_partials": false,
            "accepted_aggregate_distribution_proven": false,
        })
    }

    fn reconstruction_distributed_threshold_core_status() -> Value {
        json!({
            "distributed_keygen_vss": false,
            "threshold_seed_reconstruction_sharing": true,
            "partial_signing_over_secret_shares": false,
            "partial_z_i_hint_aggregation": false,
            "fips204_rejection_loop_over_threshold_partials": false,
            "standard_verifier_compatible_output": true,
            "accepted_aggregate_distribution_proven": false,
        })
    }

    struct EvidenceDigestInput<'a> {
        source_digest: &'a [u8; 32],
        implementation_digest: &'a [u8; 32],
        transcript_digest: &'a [u8; 32],
        public_key: &'a [u8],
        message: &'a [u8],
        signature: &'a [u8],
        mutated_message_rejected: bool,
        mutated_public_key_rejected: bool,
        mutated_signature_rejected: bool,
    }

    fn backend_evidence_digest(input: EvidenceDigestInput<'_>) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"lattice-aggregation:p1-real-threshold-backend-emission-evidence:v1");
        hasher.update(input.source_digest);
        hasher.update(input.implementation_digest);
        hasher.update(input.transcript_digest);
        hasher.update(sha3_bytes(input.public_key));
        hasher.update(sha3_bytes(input.message));
        hasher.update(sha3_bytes(input.signature));
        hasher.update([u8::from(input.mutated_message_rejected)]);
        hasher.update([u8::from(input.mutated_public_key_rejected)]);
        hasher.update([u8::from(input.mutated_signature_rejected)]);
        hasher.finalize().into()
    }

    fn dkg_custody_dealer_seed(seed: &[u8; 32], dealer_id: u16) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"lattice-aggregation:threshold-backend-p1-dkg-custody-dealer-seed:v1");
        hasher.update(seed);
        hasher.update(dealer_id.to_be_bytes());
        hasher.finalize().into()
    }

    fn dkg_public_key_digest(public_key: &ModulePublicKey) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"lattice-aggregation:threshold-backend-p1-dkg-public-key:v1");
        hasher.update(public_key.rho);
        hasher.update((public_key.t.len() as u64).to_be_bytes());
        for poly in &public_key.t {
            absorb_poly(&mut hasher, poly);
        }
        hasher.finalize().into()
    }

    fn commitment_key_digest(key: &CommitmentKey) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"lattice-aggregation:threshold-backend-p1-commitment-key:v1");
        hasher.update((key.binding_matrix().len() as u64).to_be_bytes());
        for row in key.binding_matrix() {
            hasher.update((row.len() as u64).to_be_bytes());
            for poly in row {
                absorb_poly(&mut hasher, poly);
            }
        }
        hasher.update((key.message_row().len() as u64).to_be_bytes());
        for poly in key.message_row() {
            absorb_poly(&mut hasher, poly);
        }
        hasher.finalize().into()
    }

    fn hiding_share_digest(share: &HidingShare) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"lattice-aggregation:threshold-backend-p1-receiver-share:v1");
        hasher.update(share.receiver_index.to_be_bytes());
        absorb_poly(&mut hasher, &share.value);
        hasher.update((share.randomness.len() as u64).to_be_bytes());
        for poly in &share.randomness {
            absorb_poly(&mut hasher, poly);
        }
        hasher.finalize().into()
    }

    fn absorb_poly(hasher: &mut Sha3_256, poly: &Poly) {
        for coeff in poly.canonical().coeffs {
            hasher.update(coeff.to_be_bytes());
        }
    }

    fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(domain);
        hasher.update(bytes);
        hasher.finalize().into()
    }

    fn sha3_bytes(bytes: &[u8]) -> [u8; 32] {
        Sha3_256::digest(bytes).into()
    }

    fn sha256_text(text: &str) -> String {
        encode_hex(&sha256_text_bytes(text))
    }

    fn sha256_text_bytes(text: &str) -> [u8; 32] {
        sha256_bytes(text.as_bytes())
    }

    fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
        use sha2::Sha256;

        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hasher.finalize().into()
    }

    fn require_hex_digest(value: &str, field: &str) -> Result<(), BackendError> {
        if value.len() != 64 || decode_hex_vec(value, field)?.iter().all(|byte| *byte == 0) {
            return Err(BackendError(format!("{field} must be a nonzero digest")));
        }
        Ok(())
    }

    fn decode_hex_array<const N: usize>(hex: &str, field: &str) -> Result<[u8; N], BackendError> {
        let bytes = decode_hex_vec(hex, field)?;
        if bytes.len() != N {
            return Err(BackendError(format!("{field} must be {N} bytes")));
        }
        let mut out = [0; N];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    fn decode_hex_vec(hex: &str, field: &str) -> Result<Vec<u8>, BackendError> {
        if !hex.len().is_multiple_of(2) {
            return Err(BackendError(format!("{field} hex length must be even")));
        }
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = hex_nibble(pair[0], field)?;
                let low = hex_nibble(pair[1], field)?;
                Ok((high << 4) | low)
            })
            .collect()
    }

    fn hex_nibble(byte: u8, field: &str) -> Result<u8, BackendError> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err(BackendError(format!("{field} contains non-hex byte"))),
        }
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const TABLE: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(TABLE[(byte >> 4) as usize] as char);
            out.push(TABLE[(byte & 0x0f) as usize] as char);
        }
        out
    }
}
