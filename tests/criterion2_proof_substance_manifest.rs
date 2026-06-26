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
        "standard_verifier_compatibility_artifact_digest",
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
            "standard_verifier_compatibility_artifact_digest",
            "p1_standard_verifier_compatibility_artifact_gate",
            "p1_standard_verifier_compatibility_artifact_package",
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
            assert_eq!(slot["current_status"], "evidence_present_unclosed");
            assert_eq!(slot["evidence_source"], *source);
            assert_eq!(slot["artifact_package"], *package);
            assert_eq!(
                slot["claim_boundary"],
                "conformance/proof-review evidence only"
            );
            evidence_present_slots.push(slot_id);
        } else {
            assert_eq!(
                slot["current_status"], "required_unclosed",
                "{slot_id} must remain open"
            );
        }
    }
    for (slot_id, accessor) in [
        (
            "threshold_output_certificate_digest",
            "threshold_output_certificate_artifact_digest",
        ),
        (
            "real_recomputation_evidence_digest",
            "real_recomputation_evidence_artifact_digest",
        ),
    ] {
        let slot = slots
            .iter()
            .find(|slot| slot["id"].as_str() == Some(slot_id))
            .expect("durable predecessor slot is present");
        assert_eq!(
            slot["certificate_surface"],
            "p1_selected_backend_proof_closure_artifact_certificate"
        );
        assert_eq!(slot["certificate_accessor"], accessor);
    }
    let durable_certificate_evidence = manifest["proof_payload"]["durable_certificate_evidence"]
        .as_array()
        .expect("durable_certificate_evidence is an array");
    for (slot_id, accessor) in [
        (
            "threshold_output_certificate_digest",
            "threshold_output_certificate_artifact_digest",
        ),
        (
            "real_recomputation_evidence_digest",
            "real_recomputation_evidence_artifact_digest",
        ),
    ] {
        let entry = durable_certificate_evidence
            .iter()
            .find(|entry| entry["slot_id"].as_str() == Some(slot_id))
            .expect("durable predecessor certificate evidence is present");
        assert_eq!(
            entry["certificate_surface"],
            "P1SelectedBackendProofClosureArtifactCertificate"
        );
        assert_eq!(entry["certificate_accessor"], accessor);
        assert_eq!(entry["current_status"], "evidence_present_unclosed");
        assert_eq!(
            entry["claim_boundary"],
            "conformance/proof-review evidence only"
        );
    }
    assert_eq!(
        evidence_present_slots,
        evidence_present
            .iter()
            .map(|(slot_id, _, _)| *slot_id)
            .collect::<Vec<_>>(),
        "only the Criterion 2 evidence-present allowlist may have evidence present"
    );
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
}

#[test]
fn criterion2_manifest_links_checked_fixture_refs() {
    let manifest = manifest();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture_refs = manifest["proof_payload"]["artifact_fixture_refs"]
        .as_array()
        .expect("artifact_fixture_refs is an array");

    for (slot_id, fixture_path, schema) in [
        (
            "threshold_output_certificate_digest",
            "tests/fixtures/p1_threshold_output_certificate_artifact_fixture.json",
            "lattice-aggregation:p1-threshold-output-certificate-artifact:v1",
        ),
        (
            "real_recomputation_evidence_digest",
            "tests/fixtures/p1_real_recomputation_artifact_fixture.json",
            "lattice-aggregation:p1-real-recomputation-artifact:v1",
        ),
        (
            "standard_verifier_compatibility_artifact_digest",
            "tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json",
            "lattice-aggregation:p1-standard-verifier-compatibility-artifact:v1",
        ),
        (
            "rejection_distribution_review_digest",
            "tests/fixtures/p1_rejection_distribution_review_artifact_fixture.json",
            "lattice-aggregation:p1-rejection-distribution-review-artifact:v1",
        ),
    ] {
        let fixture_ref = fixture_refs
            .iter()
            .find(|entry| entry["slot_id"].as_str() == Some(slot_id))
            .unwrap_or_else(|| panic!("{slot_id} has a checked fixture reference"));

        assert_eq!(fixture_ref["fixture_path"], fixture_path);
        assert_eq!(fixture_ref["schema"], schema);
        assert_eq!(
            fixture_ref["claim_boundary"],
            "conformance/proof-review evidence only"
        );
        assert_eq!(fixture_ref["current_status"], "evidence_present_unclosed");
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
}
