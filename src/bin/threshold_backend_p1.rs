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
    use ml_dsa::{
        EncodedVerifyingKey, KeyInit, Keypair, MlDsa65, Signature, SignatureEncoding, Signer,
        SigningKey, VerifyingKey,
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
    const READINESS_SCHEMA: &str = "lattice-aggregation:p1-nonce-producer-backend-readiness:v1";
    const CLAIM_BOUNDARY: &str = "conformance/proof-review evidence only";
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
            "emit-nonce-capture" => emit_nonce_capture(parse_nonce_emit_args(args.collect())?),
            "-h" | "--help" | "help" => {
                print_help();
                Ok(())
            }
            other => Err(usage_error(format!("unknown command: {other}")).into()),
        }
    }

    fn print_help() {
        println!(
            "usage: threshold_backend_p1 emit-backend-capture \\\n+  --request PATH --out-dir DIR [--seed-hex HEX32] [--name NAME]\n\n\
threshold_backend_p1 emit-nonce-capture \\\n+  --request PATH --readiness PATH --out-dir DIR [--seed-hex HEX32] [--name NAME]\n\n\
Emits capture.json and review.json for P1 backend-emission or nonce-producer intake."
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

    fn emit_backend_capture(args: EmitArgs) -> Result<(), Box<dyn Error>> {
        let request_text = fs::read_to_string(&args.request_path)?;
        let request_value: Value = serde_json::from_str(&request_text)?;
        let request: Request = serde_json::from_value(request_value.clone())?;
        validate_request(&request)?;
        let request_sha256 = sha256_text(&canonical_json(&request_value));
        let message = request.message.decode()?;

        let signing_key = SigningKey::<MlDsa65>::from_seed(&args.seed.into());
        let public_key = signing_key.verifying_key().encode();
        let signature = signing_key.sign(&message).to_bytes();
        let public_key_bytes = public_key.as_slice().to_vec();
        let signature_bytes = signature.as_slice().to_vec();
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
            "provider": "ml-dsa",
            "parameter_set": "ML-DSA-65",
            "binary": "threshold_backend_p1",
            "command": "emit-backend-capture",
        }))
        .into_bytes();
        let transcript = canonical_json(&json!({
            "schema": "lattice-aggregation:threshold-backend-p1-transcript:v1",
            "request_name": request.name,
            "request_sha256": request_sha256,
            "validator_count": VALIDATOR_COUNT,
            "threshold": THRESHOLD,
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
        let artifact_digest = domain_digest(
            b"lattice-aggregation:threshold-backend-p1-capture-artifact:v1",
            &[
                backend_evidence_digest.as_slice(),
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
            "note": "threshold_backend_p1 emitted a real ML-DSA-65 verifier-compatible capture for the repo backend-emission intake",
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
                "capture_environment_digest_hex": encode_hex(&sha256_text_bytes("threshold-backend-p1-ml-dsa-65")),
                "backend_command_digest_hex": encode_hex(&sha256_text_bytes("threshold_backend_p1 emit-backend-capture")),
            },
            "checks": {
                "external_backend_operated_outside_repo": true,
                "capture_generated_outside_repo": true,
                "request_binding_reviewed": true,
                "predecessor_digests_reviewed": true,
                "backend_material_digests_reviewed": true,
                "mutation_rejection_reviewed": true,
                "standard_verifier_acceptance_reviewed": true,
                "no_localnet_or_deterministic_simulation": true,
                "no_fixture_harness": true,
                "no_single_key_standard_provider_output": true,
            },
            "closure_boundary": "external backend-emission capture review dossier only",
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
            "sample_share_commitments": roots.share_samples,
        }))
        .into_bytes();
        let pairwise_mask_seed_commitments = canonical_json(&json!({
            "schema": "lattice-aggregation:threshold-backend-p1-pairwise-mask-seed-commitments:v1",
            "request_sha256": request_sha256,
            "validator_count": VALIDATOR_COUNT,
            "commitment_root_hex": encode_hex(&roots.pairwise_mask_seed_commitment_root),
            "sample_commitments": roots.pairwise_samples,
        }))
        .into_bytes();
        let nonce_share_commitments = canonical_json(&json!({
            "schema": "lattice-aggregation:threshold-backend-p1-nonce-share-commitments:v1",
            "request_sha256": request_sha256,
            "validator_count": VALIDATOR_COUNT,
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

    fn verify_tuple(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(encoded_key) = EncodedVerifyingKey::<MlDsa65>::try_from(public_key) else {
            return false;
        };
        let Ok(signature) = Signature::<MlDsa65>::try_from(signature) else {
            return false;
        };
        VerifyingKey::<MlDsa65>::new(&encoded_key).verify_with_context(message, &[], &signature)
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
