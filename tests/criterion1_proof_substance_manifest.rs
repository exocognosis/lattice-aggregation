use serde_json::Value;
use std::path::Path;

const CRITERION1_MANIFEST: &str =
    include_str!("../docs/cryptography/criterion-1-proof-substance.json");

fn manifest() -> Value {
    serde_json::from_str(CRITERION1_MANIFEST)
        .expect("criterion-1 proof-substance manifest is valid JSON")
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
fn criterion1_manifest_defines_open_mask_distribution_payload_scope() {
    let manifest = manifest();

    assert_eq!(
        manifest["schema"],
        "lattice-aggregation.criterion-1-proof-substance.v1"
    );
    assert_eq!(manifest["criterion_id"], "aggregate_mask_distribution");
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
        manifest["proof_payload"]["distance_measure"],
        "Renyi divergence bound for epsilon_mask"
    );
}

#[test]
fn criterion1_manifest_preserves_non_claim_boundary() {
    let manifest = manifest();
    let boundary = manifest["claim_boundary"]
        .as_object()
        .expect("claim_boundary is an object");

    assert_eq!(boundary["scope"], "criterion-1 proof payload only");
    for key in [
        "claims_criterion_met",
        "claims_mask_distribution_proven",
        "claims_selected_backend_proof_closure",
        "claims_rejection_distribution_preservation",
        "claims_cavp_acvts_validation",
        "claims_fips_validation",
        "claims_production_threshold_mldsa_security",
    ] {
        assert_eq!(boundary[key], false, "{key} must remain false");
    }
}

#[test]
fn criterion1_manifest_pins_required_artifact_slots_as_open() {
    let manifest = manifest();
    let slots = manifest["proof_payload"]["required_artifact_slots"]
        .as_array()
        .expect("required_artifact_slots is an array");
    let slot_ids = slots
        .iter()
        .map(|slot| slot["id"].as_str().expect("slot id"))
        .collect::<Vec<_>>();

    for required in [
        "selected_mask_construction_digest",
        "centralized_distribution_artifact_digest",
        "aggregate_distribution_artifact_digest",
        "renyi_bound_proof_digest",
        "min_entropy_review_digest",
        "parameter_selection_digest",
        "external_review_digest",
    ] {
        assert!(
            slot_ids.contains(&required),
            "criterion-1 proof payload must require {required}"
        );
    }

    for slot in slots {
        assert_eq!(slot["current_status"], "required_unclosed");
        assert_eq!(
            slot["claim_boundary"],
            "conformance/proof-review evidence only"
        );
    }
}

#[test]
fn criterion1_manifest_links_mask_theorem_obligations() {
    let manifest = manifest();
    let theorem_links = &manifest["proof_payload"]["theorem_links"];

    for theorem_link in [
        "Noise Lemma B",
        "Noise Lemma H",
        "Correctness Lemma 8",
        "FST-L7",
    ] {
        assert!(
            string_array_contains(theorem_links, theorem_link),
            "criterion-1 payload must cite {theorem_link}"
        );
    }
}

#[test]
fn criterion1_manifest_keeps_assessment_partial() {
    let manifest = manifest();
    let assessment = &manifest["assessment"];

    assert_eq!(assessment["criterion_status"], "partially_met");
    assert_eq!(assessment["overall_verdict"], "partially_proven");
    assert_eq!(assessment["does_not_change_overall_verdict"], true);
    assert_eq!(
        assessment["report_status"],
        "criterion1_proof_payload_formalized"
    );
}

#[test]
fn criterion1_manifest_links_existing_evidence_surfaces() {
    let manifest = manifest();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let evidence_refs = manifest["evidence_refs"]
        .as_array()
        .expect("evidence_refs is an array");

    for evidence_ref in evidence_refs {
        let relative = evidence_ref.as_str().expect("evidence ref is a string");
        assert!(
            root.join(relative).exists(),
            "criterion-1 evidence ref is missing: {relative}"
        );
    }
}

#[test]
fn criterion1_manifest_links_repo_evidence_pipeline_artifacts() {
    let manifest = manifest();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let pipeline = &manifest["repo_evidence_pipeline"];

    assert_eq!(
        pipeline["schema"],
        "lattice-aggregation.repo-evidence-pipeline.v1"
    );
    assert_eq!(pipeline["status"], "evidence_present_unclosed");
    assert_eq!(pipeline["claim_boundary"], "research scaffold only");
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
