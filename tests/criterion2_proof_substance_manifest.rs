use serde_json::Value;
use std::path::Path;

const CRITERION2_MANIFEST: &str =
    include_str!("../docs/cryptography/criterion-2-proof-substance.json");

fn manifest() -> Value {
    serde_json::from_str(CRITERION2_MANIFEST)
        .expect("criterion-2 proof-substance manifest is valid JSON")
}

fn string_array_contains(value: &Value, needle: &str) -> bool {
    value
        .as_array()
        .expect("expected array")
        .iter()
        .any(|entry| {
            entry
                .as_str()
                .expect("array entry is a string")
                .contains(needle)
        })
}

#[test]
fn criterion2_manifest_defines_open_proof_payload_scope() {
    let manifest = manifest();

    assert_eq!(
        manifest["schema"],
        "lattice-aggregation.criterion-2-proof-substance.v1"
    );
    assert_eq!(manifest["criterion_id"], "aggregate_rejection_equivalence");
    assert_eq!(manifest["status"], "formalized_open_proof_payload");
    assert_eq!(
        manifest["selected_profile"]["name"],
        "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
    );
    assert_eq!(
        manifest["selected_profile"]["feature_gate"],
        "production-mldsa65-coordinator"
    );
    assert_eq!(
        manifest["selected_profile"]["output_target"],
        "one standard-sized ML-DSA-65 signature if proven"
    );
}

#[test]
fn criterion2_manifest_preserves_non_claim_boundary() {
    let manifest = manifest();
    let boundary = manifest["claim_boundary"]
        .as_object()
        .expect("claim_boundary is an object");

    assert_eq!(boundary["scope"], "criterion-2 proof payload only");
    for key in [
        "claims_theorem_closure",
        "claims_criterion_met",
        "claims_selected_backend_proof_closure",
        "claims_standard_verifier_compatibility_complete",
        "claims_rejection_distribution_preservation",
        "claims_cavp_acvts_validation",
        "claims_fips_validation",
        "claims_production_threshold_mldsa_security",
    ] {
        assert_eq!(boundary[key], false, "{key} must remain false");
    }
}

#[test]
fn criterion2_manifest_pins_required_artifact_slots() {
    let manifest = manifest();
    let slots = manifest["proof_payload"]["required_artifact_slots"]
        .as_array()
        .expect("required_artifact_slots is an array");
    let slot_ids = slots
        .iter()
        .map(|slot| slot["id"].as_str().expect("slot id"))
        .collect::<Vec<_>>();

    for required in [
        "threshold_output_certificate_digest",
        "real_recomputation_evidence_digest",
        "distributed_nonce_producer_artifact_digest",
        "standard_verifier_compatibility_artifact_digest",
        "real_threshold_backend_emission_artifact_digest",
        "external_backend_cryptographic_closure_candidate",
        "external_backend_evidence_attempt",
        "theorem_closure_blocker_requests",
        "rejection_distribution_review_digest",
        "theorem_linkage_artifact_digest",
        "full_kat_validation_artifact_digest",
        "norm_bound_artifact_digest",
        "hint_bound_artifact_digest",
        "challenge_bound_artifact_digest",
        "transcript_binding_evidence_digest",
        "external_review_digest",
    ] {
        assert!(
            slot_ids.contains(&required),
            "criterion-2 proof payload must require {required}"
        );
    }
    let evidence_present = [
        (
            "threshold_output_certificate_digest",
            "p1_criterion2_threshold_output_certificate_artifact_gate",
            "p1_criterion2_proof_slot_artifact_package",
        ),
        (
            "real_recomputation_evidence_digest",
            "p1_criterion2_real_recomputation_evidence_artifact_gate",
            "p1_criterion2_proof_slot_artifact_package",
        ),
        (
            "distributed_nonce_producer_artifact_digest",
            "p1_criterion2_distributed_nonce_producer_artifact_gate",
            "p1_criterion2_proof_slot_artifact_package",
        ),
        (
            "standard_verifier_compatibility_artifact_digest",
            "p1_standard_verifier_compatibility_artifact_gate",
            "p1_standard_verifier_compatibility_artifact_package",
        ),
        (
            "real_threshold_backend_emission_artifact_digest",
            "p1_real_threshold_backend_output_gate",
            "p1_real_threshold_backend_emission_artifact_package",
        ),
        (
            "external_backend_cryptographic_closure_candidate",
            "p1_external_backend_cryptographic_closure_candidate_gate",
            "p1_external_backend_cryptographic_closure_candidate_package",
        ),
        (
            "external_backend_evidence_attempt",
            "p1_external_backend_evidence_attempt_gate",
            "p1_external_backend_evidence_attempt_artifact",
        ),
        (
            "theorem_closure_blocker_requests",
            "p1_theorem_closure_blocker_request_gate",
            "p1_theorem_closure_blocker_request_artifact",
        ),
        (
            "rejection_distribution_review_digest",
            "p1_criterion2_rejection_distribution_review_artifact_gate",
            "p1_criterion2_proof_slot_artifact_package",
        ),
        (
            "theorem_linkage_artifact_digest",
            "p1_criterion2_theorem_linkage_artifact_gate",
            "p1_criterion2_proof_slot_artifact_package",
        ),
        (
            "full_kat_validation_artifact_digest",
            "p1_criterion2_full_kat_validation_artifact_gate",
            "p1_criterion2_proof_slot_artifact_package",
        ),
        (
            "norm_bound_artifact_digest",
            "p1_criterion2_norm_bound_artifact_gate",
            "p1_criterion2_proof_slot_artifact_package",
        ),
        (
            "hint_bound_artifact_digest",
            "p1_criterion2_hint_bound_artifact_gate",
            "p1_criterion2_proof_slot_artifact_package",
        ),
        (
            "challenge_bound_artifact_digest",
            "p1_criterion2_challenge_bound_artifact_gate",
            "p1_criterion2_proof_slot_artifact_package",
        ),
        (
            "transcript_binding_evidence_digest",
            "p1_criterion2_transcript_binding_artifact_gate",
            "p1_criterion2_proof_slot_artifact_package",
        ),
        (
            "external_review_digest",
            "p1_criterion2_external_review_artifact_gate",
            "p1_criterion2_proof_slot_artifact_package",
        ),
    ];
    let mut evidence_present_slots = Vec::new();
    for slot in slots {
        let slot_id = slot["id"].as_str().expect("slot id");
        if let Some((_, source, package)) = evidence_present
            .iter()
            .find(|(expected_slot, _, _)| expected_slot == &slot_id)
        {
            let expected_status = if slot_id == "theorem_closure_blocker_requests" {
                "blocker_inputs_satisfied"
            } else {
                "evidence_present_unclosed"
            };
            assert_eq!(slot["current_status"], expected_status);
            assert_eq!(slot["evidence_source"], *source);
            assert_eq!(slot["artifact_package"], *package);
            if slot_id == "real_threshold_backend_emission_artifact_digest" {
                assert_eq!(
                    slot["backend_capture_schema"],
                    "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1"
                );
                assert_eq!(
                    slot["backend_emission_request_artifact"],
                    "artifacts/backend-emission-request/latest/request.json"
                );
                assert_eq!(
                    slot["backend_emission_request_manifest"],
                    "artifacts/backend-emission-request/latest/manifest.json"
                );
                assert_eq!(
                    slot["backend_emission_request_sha256"],
                    "804a2549a04010dace167d8f5647635f57a2465520dd087b6c80cc9ae3108ec1"
                );
                assert_eq!(
                    slot["backend_emission_capture_file_intake"],
                    "scripts/stage_external_backend_emission_capture.py"
                );
                assert_eq!(
                    slot["backend_emission_capture_file_origin_required"],
                    "outside_repo_capture_file"
                );
                assert_eq!(
                    slot["backend_emission_capture_file_intake_mode"],
                    "preexisting_external_capture_file"
                );
                assert_eq!(
                    slot["backend_emission_capture_review_schema"],
                    "lattice-aggregation:p1-external-backend-emission-capture-review:v1"
                );
                assert_eq!(
                    slot["backend_emission_capture_review_manifest_origin_required"],
                    "outside_repo_review_manifest"
                );
                assert_eq!(
                    slot["backend_emission_capture_review_status_required"],
                    "reviewed_external_backend_emission_capture_ready"
                );
                assert_eq!(
                    slot["backend_capture_importer"],
                    "derive_p1_verified_real_threshold_backend_emission_artifact_package_from_capture"
                );
                assert_eq!(
                    slot["backend_capture_fixture_path"],
                    "tests/fixtures/p1_real_threshold_backend_emission_capture_schema_fixture.json"
                );
            }
            if slot_id == "external_backend_cryptographic_closure_candidate" {
                assert_eq!(
                    slot["artifact_schema"],
                    "lattice-aggregation:p1-external-backend-cryptographic-closure-candidate:v1"
                );
                assert_eq!(
                    slot["artifact_path"],
                    "artifacts/p1-external-backend-cryptographic-closure-candidate/latest/manifest.json"
                );
                assert_eq!(
                    slot["builder"],
                    "scripts/build_p1_external_backend_cryptographic_closure_candidate.py"
                );
                assert_eq!(slot["close_candidate"], true);
                assert_eq!(slot["claims_theorem_closure"], false);
                assert_eq!(slot["claims_rejection_distribution_preservation"], false);
                assert_eq!(slot["claims_selected_backend_proof_closure"], false);
            }
            if slot_id == "external_backend_evidence_attempt" {
                assert_eq!(
                    slot["artifact_schema"],
                    "lattice-aggregation:p1-external-backend-evidence-attempt:v1"
                );
                assert_eq!(
                    slot["artifact_path"],
                    "artifacts/p1-external-backend-evidence-attempt/latest/manifest.json"
                );
                assert_eq!(
                    slot["runner"],
                    "scripts/run_p1_external_backend_evidence_attempt.py"
                );
                assert_eq!(
                    slot["attempt_status"],
                    "external_evidence_close_candidate_ready"
                );
                assert_eq!(slot["close_candidate"], true);
                assert_eq!(slot["source_exclusion_passed"], true);
                assert_eq!(
                    slot["review_package_schema"],
                    "lattice-aggregation:p1-external-backend-evidence-package-review:v1"
                );
                assert_eq!(
                    slot["review_package_path"],
                    "artifacts/p1-external-backend-evidence-package-review/latest/manifest.json"
                );
                assert_eq!(slot["review_package_present"], true);
                assert_eq!(slot["review_package_binds_inputs"], true);
                assert_eq!(slot["review_package_claim_boundary_passed"], true);
                assert_eq!(slot["review_package_source_exclusions_passed"], true);
                assert_eq!(slot["review_package_review_digests_present"], true);
                assert_eq!(slot["claims_theorem_closure"], false);
                assert_eq!(slot["claims_rejection_distribution_preservation"], false);
                assert_eq!(slot["claims_selected_backend_proof_closure"], false);
            }
            let expected_boundary = if slot_id == "theorem_closure_blocker_requests" {
                "readiness preflight only; external proof and validation packages present"
            } else {
                "conformance/proof-review evidence"
            };
            assert_eq!(slot["claim_boundary"], expected_boundary);
            evidence_present_slots.push(slot_id);
        } else {
            assert_eq!(
                slot["current_status"], "required_unclosed",
                "{slot_id} must remain open"
            );
        }
    }
    for (slot_id, accessor, surface, evidence_surface) in [
        (
            "threshold_output_certificate_digest",
            "threshold_output_certificate_artifact_digest",
            "p1_selected_backend_proof_closure_artifact_certificate",
            "P1SelectedBackendProofClosureArtifactCertificate",
        ),
        (
            "real_recomputation_evidence_digest",
            "real_recomputation_evidence_artifact_digest",
            "p1_selected_backend_proof_closure_artifact_certificate",
            "P1SelectedBackendProofClosureArtifactCertificate",
        ),
        (
            "distributed_nonce_producer_artifact_digest",
            "distributed_nonce_producer_artifact_digest",
            "p1_selected_backend_proof_closure_artifact_certificate",
            "P1SelectedBackendProofClosureArtifactCertificate",
        ),
        (
            "external_backend_cryptographic_closure_candidate",
            "candidate_artifact_digest",
            "p1_external_backend_cryptographic_closure_candidate_certificate",
            "P1ExternalBackendCryptographicClosureCandidateCertificate",
        ),
    ] {
        let slot = slots
            .iter()
            .find(|slot| slot["id"].as_str() == Some(slot_id))
            .expect("durable predecessor slot is present");
        assert_eq!(slot["certificate_surface"], surface);
        assert_eq!(slot["certificate_accessor"], accessor);
        let durable_certificate_evidence = manifest["proof_payload"]
            ["durable_certificate_evidence"]
            .as_array()
            .expect("durable_certificate_evidence is an array");
        let entry = durable_certificate_evidence
            .iter()
            .find(|entry| entry["slot_id"].as_str() == Some(slot_id))
            .expect("durable predecessor certificate evidence is present");
        assert_eq!(entry["certificate_surface"], evidence_surface);
        assert_eq!(entry["certificate_accessor"], accessor);
        assert_eq!(entry["current_status"], "evidence_present_unclosed");
        assert_eq!(entry["claim_boundary"], "conformance/proof-review evidence");
    }
    assert_eq!(
        evidence_present_slots,
        evidence_present
            .iter()
            .map(|(slot_id, _, _)| *slot_id)
            .collect::<Vec<_>>(),
        "only the Criterion 2 evidence-present allowlist may have evidence present"
    );
    let nonce_producer_slot = slots
        .iter()
        .find(|slot| slot["id"].as_str() == Some("distributed_nonce_producer_artifact_digest"))
        .expect("distributed nonce producer slot is present");
    assert_eq!(
        nonce_producer_slot["current_status"],
        "evidence_present_unclosed"
    );
    assert_eq!(
        nonce_producer_slot["evidence_source"],
        "p1_criterion2_distributed_nonce_producer_artifact_gate"
    );
    assert_eq!(
        nonce_producer_slot["artifact_package"],
        "p1_criterion2_proof_slot_artifact_package"
    );
    assert_eq!(
        nonce_producer_slot["replacement_target"],
        "derive_mldsa65_centralized_nonce_prf_output_from_expanded_secret_key"
    );
    assert_eq!(
        nonce_producer_slot["backend_output_adapter"],
        "derive_p1_distributed_nonce_producer_artifact_package_from_backend_output"
    );
    assert_eq!(
        nonce_producer_slot["backend_output_material"],
        "Mldsa65DistributedNonceProducerArtifact"
    );
    assert_eq!(
        nonce_producer_slot["backend_capture_schema"],
        "lattice-aggregation:p1-distributed-nonce-producer-capture:v1"
    );
    assert_eq!(
        nonce_producer_slot["backend_capture_request_schema"],
        "lattice-aggregation:p1-distributed-nonce-producer-request:v1"
    );
    assert_eq!(
        nonce_producer_slot["backend_capture_importer"],
        "derive_p1_distributed_nonce_producer_artifact_package_from_capture"
    );
    assert_eq!(
        nonce_producer_slot["backend_capture_status"],
        "evidence_present_unclosed"
    );
    assert_eq!(
        nonce_producer_slot["backend_capture_binding"],
        "capture embeds request schema, request name, request_sha256, predecessor certificate digests, decoded material classes, and expected package digests"
    );
    assert_eq!(
        nonce_producer_slot["backend_capture_request_builder"],
        "scripts/build_nonce_producer_request.py"
    );
    assert_eq!(
        nonce_producer_slot["backend_capture_runner"],
        "scripts/run_nonce_producer_capture.py"
    );
    assert_eq!(
        nonce_producer_slot["backend_capture_runner_status"],
        "evidence_present_unclosed"
    );
    assert!(string_array_contains(
        &nonce_producer_slot["backend_output_required_digests"],
        "backend_implementation_digest",
    ));
}

#[test]
fn criterion2_manifest_links_theorem_obligations() {
    let manifest = manifest();
    let theorem_links = &manifest["proof_payload"]["theorem_links"];

    for theorem_link in [
        "Correctness Lemma 7",
        "Correctness Lemma 8",
        "Noise Lemma D",
        "Noise Lemma F",
        "Noise Lemma H",
        "FST-L5",
        "FST-L7",
    ] {
        assert!(
            string_array_contains(theorem_links, theorem_link),
            "criterion-2 payload must cite {theorem_link}"
        );
    }
}

#[test]
fn criterion2_manifest_keeps_assessment_partial() {
    let manifest = manifest();
    let assessment = &manifest["assessment"];

    assert_eq!(assessment["criterion_status"], "partially_met");
    assert_eq!(assessment["overall_verdict"], "partially_proven");
    assert_eq!(assessment["does_not_change_overall_verdict"], true);
    assert_eq!(
        assessment["report_status"],
        "criterion2_proof_payload_formalized"
    );
}

#[test]
fn criterion2_manifest_links_existing_evidence_surfaces() {
    let manifest = manifest();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let evidence_refs = manifest["evidence_refs"]
        .as_array()
        .expect("evidence_refs is an array");

    for evidence_ref in evidence_refs {
        let relative = evidence_ref.as_str().expect("evidence ref is a string");
        assert!(
            root.join(relative).exists(),
            "criterion-2 evidence ref is missing: {relative}"
        );
    }
    for required in [
        "scripts/stage_external_backend_emission_capture.py",
        "script_tests/test_stage_external_backend_emission_capture.py",
    ] {
        assert!(
            string_array_contains(&serde_json::Value::Array(evidence_refs.clone()), required),
            "Criterion 2 evidence refs must link {required}"
        );
    }
}

#[test]
fn criterion2_manifest_links_repo_evidence_pipeline_and_capture_provenance() {
    let manifest = manifest();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let pipeline = &manifest["repo_evidence_pipeline"];

    assert_eq!(
        pipeline["schema"],
        "lattice-aggregation.repo-evidence-pipeline.v1"
    );
    assert_eq!(pipeline["status"], "evidence_present_unclosed");
    assert_eq!(pipeline["claim_boundary"], "research scaffold evidence");
    assert_eq!(
        manifest["assessment"]["theorem_closure_readiness_status"],
        "ready_for_theorem_closure_assessment"
    );
    assert_eq!(
        manifest["assessment"]["theorem_closure_assessment_ready"],
        true
    );
    for artifact in [
        "artifacts/hypothesis/latest/assessment.json",
        "artifacts/hypothesis/latest/assessment.md",
        "artifacts/hypothesis/latest/closure-dashboard.json",
        "artifacts/hypothesis/latest/closure-dashboard.md",
        "artifacts/p1-external-backend-cryptographic-closure-candidate/latest/manifest.json",
        "artifacts/p1-external-backend-cryptographic-closure-candidate/latest/summary.md",
        "artifacts/p1-external-backend-cryptographic-closure-candidate/latest/SHA256SUMS",
        "artifacts/p1-external-backend-evidence-attempt/latest/manifest.json",
        "artifacts/p1-external-backend-evidence-attempt/latest/summary.md",
        "artifacts/p1-external-backend-evidence-attempt/latest/SHA256SUMS",
        "artifacts/theorem-closure-readiness/latest/manifest.json",
        "artifacts/theorem-closure-readiness/latest/summary.md",
        "artifacts/theorem-closure-readiness/latest/SHA256SUMS",
        "artifacts/backend-emission-request/latest/request.json",
        "artifacts/backend-emission-request/latest/manifest.json",
        "artifacts/backend-emission-request/latest/summary.md",
        "artifacts/backend-emission-request/latest/SHA256SUMS",
    ] {
        assert_eq!(pipeline["artifacts"][artifact], artifact);
        assert!(
            root.join(artifact).exists(),
            "repo evidence artifact is missing: {artifact}"
        );
    }

    let provenance_requirements = manifest["external_capture_provenance_requirements"]
        .as_array()
        .expect("external_capture_provenance_requirements is an array");
    for required in [
        "request_sha256",
        "capture_sha256",
        "backend_command_sha256",
        "evidence_class",
        "runner_status",
        "claim_boundary",
        "expected_digest_fields",
        "metadata_fields",
        "cargo_lock_sha256",
        "actual_external_nonce_capture_manifest_sha256",
        "real_threshold_backend_emission_capture_sha256",
        "rejection_distribution_batch_sha256",
        "closure_candidate_manifest_sha256",
        "external_backend_evidence_attempt_manifest_sha256",
        "source_exclusion_passed",
        "review_package_binds_inputs",
        "review_package_review_digests_present",
    ] {
        assert!(
            string_array_contains(
                &serde_json::Value::Array(provenance_requirements.clone()),
                required,
            ),
            "Criterion 2 must require external capture provenance field {required}"
        );
    }

    let nonce_slot = manifest["proof_payload"]["required_artifact_slots"]
        .as_array()
        .expect("required_artifact_slots is an array")
        .iter()
        .find(|entry| entry["id"].as_str() == Some("distributed_nonce_producer_artifact_digest"))
        .expect("distributed nonce-producer slot is present");
    for path_field in [
        "backend_cli_contract",
        "backend_handoff_replay",
        "backend_handoff_replay_artifact",
        "backend_handoff_replay_request",
        "backend_handoff_replay_capture",
    ] {
        let relative = nonce_slot[path_field]
            .as_str()
            .unwrap_or_else(|| panic!("{path_field} is a string"));
        assert!(
            root.join(relative).exists(),
            "distributed nonce-producer handoff ref is missing: {relative}"
        );
    }
    assert_eq!(
        nonce_slot["backend_handoff_replay_status"],
        "evidence_present_unclosed"
    );
    assert_eq!(
        nonce_slot["backend_handoff_replay_importer_test"],
        "checked_nonce_producer_handoff_replay_capture_json_feeds_rust_importer"
    );
}

#[test]
fn criterion2_manifest_links_checked_fixture_refs() {
    let manifest = manifest();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture_refs = manifest["proof_payload"]["artifact_fixture_refs"]
        .as_array()
        .expect("artifact_fixture_refs is an array");

    for (slot_id, fixture_path, schema, current_status) in [
        (
            "threshold_output_certificate_digest",
            "tests/fixtures/p1_threshold_output_certificate_artifact_fixture.json",
            "lattice-aggregation:p1-threshold-output-certificate-artifact:v1",
            "evidence_present_unclosed",
        ),
        (
            "real_recomputation_evidence_digest",
            "tests/fixtures/p1_real_recomputation_artifact_fixture.json",
            "lattice-aggregation:p1-real-recomputation-artifact:v1",
            "evidence_present_unclosed",
        ),
        (
            "standard_verifier_compatibility_artifact_digest",
            "tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json",
            "lattice-aggregation:p1-standard-verifier-compatibility-artifact:v1",
            "evidence_present_unclosed",
        ),
        (
            "real_threshold_backend_emission_artifact_digest",
            "tests/fixtures/p1_real_threshold_backend_emission_artifact_fixture.json",
            "lattice-aggregation:p1-real-threshold-backend-emission-artifact:v1",
            "evidence_present_unclosed",
        ),
        (
            "external_backend_cryptographic_closure_candidate",
            "artifacts/p1-external-backend-cryptographic-closure-candidate/latest/manifest.json",
            "lattice-aggregation:p1-external-backend-cryptographic-closure-candidate:v1",
            "evidence_present_unclosed",
        ),
        (
            "external_backend_evidence_attempt",
            "artifacts/p1-external-backend-evidence-attempt/latest/manifest.json",
            "lattice-aggregation:p1-external-backend-evidence-attempt:v1",
            "external_evidence_close_candidate_ready",
        ),
        (
            "theorem_closure_blocker_requests",
            "artifacts/theorem-closure-blocker-requests/latest/manifest.json",
            "lattice-aggregation:theorem-closure-blocker-requests:v1",
            "blocker_inputs_satisfied",
        ),
        (
            "rejection_distribution_review_digest",
            "tests/fixtures/p1_rejection_distribution_review_artifact_fixture.json",
            "lattice-aggregation:p1-rejection-distribution-review-artifact:v1",
            "evidence_present_unclosed",
        ),
        (
            "theorem_linkage_artifact_digest",
            "tests/fixtures/p1_theorem_linkage_artifact_fixture.json",
            "lattice-aggregation:p1-theorem-linkage-artifact:v1",
            "evidence_present_unclosed",
        ),
        (
            "theorem_linkage_artifact_digest",
            "artifacts/p1-theorem-linkage-review/latest/manifest.json",
            "lattice-aggregation:p1-theorem-linkage-review:v1",
            "reviewed_theorem_linkage_ready",
        ),
    ] {
        let fixture_ref = fixture_refs
            .iter()
            .find(|entry| {
                entry["slot_id"].as_str() == Some(slot_id)
                    && entry["fixture_path"].as_str() == Some(fixture_path)
            })
            .unwrap_or_else(|| panic!("{slot_id} has a checked fixture reference"));

        assert_eq!(fixture_ref["fixture_path"], fixture_path);
        assert_eq!(fixture_ref["schema"], schema);
        let expected_boundary = if slot_id == "theorem_closure_blocker_requests" {
            "readiness preflight only; external proof and validation packages present"
        } else {
            "conformance/proof-review evidence"
        };
        assert_eq!(fixture_ref["claim_boundary"], expected_boundary);
        assert_eq!(fixture_ref["current_status"], current_status);
        if slot_id == "external_backend_cryptographic_closure_candidate" {
            assert_eq!(fixture_ref["close_candidate"], true);
        }
        if slot_id == "external_backend_evidence_attempt" {
            assert_eq!(
                fixture_ref["current_status"],
                "external_evidence_close_candidate_ready"
            );
            assert_eq!(fixture_ref["close_candidate"], true);
            assert_eq!(fixture_ref["source_exclusion_passed"], true);
        }
        assert!(
            root.join(
                fixture_ref["fixture_path"]
                    .as_str()
                    .expect("fixture_path is a string")
            )
            .exists(),
            "{fixture_path} must be checked in"
        );
    }

    let capture_fixture_ref = fixture_refs
        .iter()
        .find(|entry| {
            entry["fixture_path"].as_str()
                == Some(
                    "tests/fixtures/p1_real_threshold_backend_emission_capture_schema_fixture.json",
                )
        })
        .expect("real-threshold backend emission capture schema fixture is linked");
    assert_eq!(
        capture_fixture_ref["slot_id"],
        "real_threshold_backend_emission_artifact_digest"
    );
    assert_eq!(
        capture_fixture_ref["schema"],
        "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1"
    );
    assert_eq!(
        capture_fixture_ref["current_status"],
        "checked_capture_schema_fixture_blocked_until_actual_backend_evidence"
    );
    assert_eq!(
        capture_fixture_ref["claim_boundary"],
        "conformance/proof-review evidence"
    );
    assert!(
        root.join(
            capture_fixture_ref["fixture_path"]
                .as_str()
                .expect("capture fixture_path is a string")
        )
        .exists(),
        "capture schema fixture must be checked in"
    );

    let nonce_handoff_ref = fixture_refs
        .iter()
        .find(|entry| {
            entry["fixture_path"].as_str()
                == Some("artifacts/nonce-producer-handoff/latest/capture/capture.json")
        })
        .expect("distributed nonce-producer checked handoff replay is linked");
    assert_eq!(
        nonce_handoff_ref["slot_id"],
        "distributed_nonce_producer_artifact_digest"
    );
    assert_eq!(
        nonce_handoff_ref["schema"],
        "lattice-aggregation:p1-distributed-nonce-producer-capture:v1"
    );
    assert_eq!(
        nonce_handoff_ref["current_status"],
        "checked_handoff_replay_importable_until_actual_backend_evidence"
    );
    assert_eq!(
        nonce_handoff_ref["claim_boundary"],
        "conformance/proof-review evidence"
    );
    assert!(
        root.join(
            nonce_handoff_ref["fixture_path"]
                .as_str()
                .expect("nonce handoff fixture_path is a string")
        )
        .exists(),
        "distributed nonce-producer checked handoff capture must be checked in"
    );
}
