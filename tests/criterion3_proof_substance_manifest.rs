use serde_json::Value;
use std::path::Path;

const CRITERION3_MANIFEST: &str =
    include_str!("../docs/cryptography/criterion-3-proof-substance.json");

fn manifest() -> Value {
    serde_json::from_str(CRITERION3_MANIFEST)
        .expect("criterion-3 proof-substance manifest is valid JSON")
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
fn criterion3_manifest_defines_open_abort_retry_payload_scope() {
    let manifest = manifest();

    assert_eq!(
        manifest["schema"],
        "lattice-aggregation.criterion-3-proof-substance.v1"
    );
    assert_eq!(manifest["criterion_id"], "abort_retry_bias");
    assert_eq!(manifest["status"], "formalized_open_proof_payload");
    assert_eq!(
        manifest["selected_profile"]["name"],
        "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
    );
    assert_eq!(
        manifest["proof_payload"]["retry_domain"],
        "session_id + attempt_id + retry_counter"
    );
    assert_eq!(
        manifest["proof_payload"]["accepted_signature_target"],
        "accepted threshold signatures remain unbiased under the reviewed abort and retry policy"
    );
}

#[test]
fn criterion3_manifest_preserves_non_claim_boundary() {
    let manifest = manifest();
    let boundary = manifest["claim_boundary"]
        .as_object()
        .expect("claim_boundary is an object");

    assert_eq!(boundary["scope"], "criterion-3 proof payload only");
    for key in [
        "claims_criterion_met",
        "claims_abort_retry_bias_proven",
        "claims_selected_backend_proof_closure",
        "claims_accepted_signature_distribution",
        "claims_cavp_acvts_validation",
        "claims_fips_validation",
        "claims_production_threshold_mldsa_security",
    ] {
        assert_eq!(boundary[key], false, "{key} must remain false");
    }
}

#[test]
fn criterion3_manifest_pins_required_artifact_slots_as_open() {
    let manifest = manifest();
    let slots = manifest["proof_payload"]["required_artifact_slots"]
        .as_array()
        .expect("required_artifact_slots is an array");
    let slot_ids = slots
        .iter()
        .map(|slot| slot["id"].as_str().expect("slot id"))
        .collect::<Vec<_>>();

    for required in [
        "retry_domain_separation_proof_digest",
        "formal_abort_leakage_model_digest",
        "accepted_signature_distribution_proof_digest",
        "adversarial_abort_policy_corpus_digest",
        "sample_size_bucket_rationale_digest",
        "timeout_retry_policy_digest",
        "external_review_digest",
    ] {
        assert!(
            slot_ids.contains(&required),
            "criterion-3 proof payload must require {required}"
        );
    }

    for slot in slots {
        assert_eq!(slot["current_status"], "required_unclosed");
        assert_eq!(slot["claim_boundary"], "conformance/proof-review evidence");
    }
}

#[test]
fn criterion3_manifest_links_abort_retry_theorem_obligations() {
    let manifest = manifest();
    let theorem_links = &manifest["proof_payload"]["theorem_links"];

    for theorem_link in ["Noise Lemma G", "Noise Lemma H", "FST-L7", "FST-L9"] {
        assert!(
            string_array_contains(theorem_links, theorem_link),
            "criterion-3 payload must cite {theorem_link}"
        );
    }
}

#[test]
fn criterion3_manifest_keeps_assessment_partial() {
    let manifest = manifest();
    let assessment = &manifest["assessment"];

    assert_eq!(assessment["criterion_status"], "partially_met");
    assert_eq!(assessment["overall_verdict"], "partially_proven");
    assert_eq!(assessment["does_not_change_overall_verdict"], true);
    assert_eq!(
        assessment["report_status"],
        "criterion3_proof_payload_formalized"
    );
}

#[test]
fn criterion3_manifest_links_existing_evidence_surfaces() {
    let manifest = manifest();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let evidence_refs = manifest["evidence_refs"]
        .as_array()
        .expect("evidence_refs is an array");

    for evidence_ref in evidence_refs {
        let relative = evidence_ref.as_str().expect("evidence ref is a string");
        assert!(
            root.join(relative).exists(),
            "criterion-3 evidence ref is missing: {relative}"
        );
    }
}

#[test]
fn criterion3_manifest_links_repo_evidence_pipeline_artifacts() {
    let manifest = manifest();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let pipeline = &manifest["repo_evidence_pipeline"];

    assert_eq!(
        pipeline["schema"],
        "lattice-aggregation.repo-evidence-pipeline.v1"
    );
    assert_eq!(pipeline["status"], "evidence_present_unclosed");
    assert_eq!(pipeline["claim_boundary"], "research scaffold evidence");
    for artifact in [
        "artifacts/hypothesis/latest/assessment.json",
        "artifacts/hypothesis/latest/assessment.md",
        "artifacts/hypothesis/latest/closure-dashboard.json",
        "artifacts/hypothesis/latest/closure-dashboard.md",
    ] {
        assert_eq!(pipeline["artifacts"][artifact], artifact);
        assert!(
            root.join(artifact).exists(),
            "repo evidence artifact is missing: {artifact}"
        );
    }
}
