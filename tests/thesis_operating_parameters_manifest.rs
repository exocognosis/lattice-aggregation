use serde_json::Value;
use std::path::Path;

const THESIS_MANIFEST: &str = include_str!("../docs/cryptography/thesis-operating-parameters.json");

fn manifest() -> Value {
    serde_json::from_str(THESIS_MANIFEST)
        .expect("thesis operating parameters manifest is valid JSON")
}

fn array_contains(value: &Value, needle: &str) -> bool {
    value
        .as_array()
        .expect("expected string array")
        .iter()
        .any(|entry| {
            entry
                .as_str()
                .expect("array entry is a string")
                .contains(needle)
        })
}

#[test]
fn thesis_manifest_defines_native_threshold_mldsa_p1_scope() {
    let manifest = manifest();

    assert_eq!(
        manifest["schema"],
        "lattice-aggregation.thesis-operating-parameters.v1"
    );
    assert_eq!(
        manifest["thesis_id"],
        "native-threshold-mldsa65-aggregation-p1"
    );
    assert_eq!(manifest["status"], "research_scaffold_partially_proven");
    assert_eq!(
        manifest["selected_profile"]["name"],
        "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
    );
    assert_eq!(manifest["selected_profile"]["parameter_set"], "ML-DSA-65");
    assert_eq!(
        manifest["selected_profile"]["feature_gate"],
        "production-mldsa65-coordinator"
    );
    assert_eq!(
        manifest["selected_profile"]["coordinator_assumption"],
        "TEE/HSM"
    );
    assert_eq!(
        manifest["selected_profile"]["standard_verifier_compatibility"],
        "target"
    );
    assert_eq!(manifest["selected_profile"]["signature_bytes"], 3309);
    assert_eq!(manifest["selected_profile"]["public_key_bytes"], 1952);
    assert_eq!(
        manifest["selected_profile"]["aggregate_output_shape"],
        "one standard-sized ML-DSA-65 signature if proven"
    );
}

#[test]
fn thesis_manifest_preserves_research_claim_boundary() {
    let manifest = manifest();
    let boundary = manifest["claim_boundary"]
        .as_object()
        .expect("claim_boundary is an object");

    assert_eq!(boundary["scope"], "research scaffold evidence");
    for key in [
        "claims_production_threshold_mldsa_security",
        "claims_selected_backend_proof_closure",
        "claims_standard_verifier_compatibility_complete",
        "claims_rejection_distribution_preservation",
        "claims_cavp_acvts_validation",
        "claims_fips_validation",
    ] {
        assert_eq!(boundary[key], false, "{key} must remain false");
    }
}

#[test]
fn thesis_manifest_pins_operating_parameters() {
    let manifest = manifest();
    let operating = &manifest["operating_parameters"];

    assert_eq!(operating["security_parameter"], "lambda");
    assert_eq!(operating["validator_count"], "n");
    assert_eq!(operating["threshold"], "t");
    assert_eq!(operating["validator_set"], "V");
    assert_eq!(operating["threshold_range"], "1 <= t <= n");
    assert_eq!(
        operating["static_corruption_bound"],
        "at most t - 1 validators"
    );
    assert_eq!(
        operating["retry_domain"],
        "session_id + attempt_id + retry_counter"
    );
    assert_eq!(
        operating["rejection_sampling_domain"],
        "centralized ML-DSA-65 acceptance distribution"
    );
    assert_eq!(
        operating["batch4_dependency"],
        "selected-backend proof-closure artifact package gate"
    );
    assert_eq!(operating["boundary"], "conformance/proof-review evidence");
}

#[test]
fn thesis_manifest_pins_all_five_promotion_criteria_as_partial() {
    let manifest = manifest();
    let criteria = manifest["criterion_promotion"]
        .as_array()
        .expect("criterion_promotion is an array");
    let ids = criteria
        .iter()
        .map(|criterion| {
            (
                criterion["id"].as_str().expect("criterion id"),
                criterion["current_status"]
                    .as_str()
                    .expect("criterion status"),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        ids,
        vec![
            ("aggregate_mask_distribution", "partially_met"),
            ("aggregate_rejection_equivalence", "partially_met"),
            ("abort_retry_bias", "partially_met"),
            ("partial_contribution_soundness", "partially_met"),
            ("unauthorized_aggregate_reduction", "partially_met"),
        ]
    );
    for criterion in criteria {
        assert!(
            criterion["promotion_requires"].as_array().unwrap().len() >= 3,
            "{} must name concrete promotion requirements",
            criterion["id"]
        );
        assert!(
            criterion["failure_criteria"].as_array().unwrap().len() >= 2,
            "{} must name concrete failure criteria",
            criterion["id"]
        );
    }
}

#[test]
fn thesis_manifest_names_concrete_promotion_and_failure_anchors() {
    let manifest = manifest();
    let criteria = manifest["criterion_promotion"]
        .as_array()
        .expect("criterion_promotion is an array");

    for criterion in criteria {
        let id = criterion["id"].as_str().expect("criterion id");
        let (promotion_needles, failure_needles): (&[&str], &[&str]) = match id {
            "aggregate_mask_distribution" => (
                &[
                    "selected-backend mask-generation",
                    "Renyi divergence",
                    "distribution comparison",
                ],
                &["distinguishable", "selected profile"],
            ),
            "aggregate_rejection_equivalence" => (
                &[
                    "real threshold aggregate recomputation",
                    "standard-verifier compatibility",
                    "rejection-distribution review",
                ],
                &[
                    "fail standard ML-DSA-65 verification",
                    "centralized ML-DSA-65 predicates",
                ],
            ),
            "abort_retry_bias" => (
                &[
                    "retry transcript domain separation",
                    "selective-abort leakage",
                    "accepted-signature distribution",
                ],
                &["retry timing", "attempt identifiers"],
            ),
            "partial_contribution_soundness" => (
                &[
                    "production LocalAccept",
                    "VSS/DKG binding and hiding",
                    "context-binding and leakage review",
                ],
                &[
                    "cross-context partial contributions",
                    "accepted partial evidence leaks",
                ],
            ),
            "unauthorized_aggregate_reduction" => (
                &[
                    "threshold unforgeability reduction",
                    "base ML-DSA theorem dependency",
                    "simulator and hybrid-bound",
                ],
                &["named assumption", "validator-set binding"],
            ),
            other => panic!("unexpected criterion id {other}"),
        };

        for needle in promotion_needles {
            assert!(
                array_contains(&criterion["promotion_requires"], needle),
                "{id} promotion requirements must contain {needle}"
            );
        }
        for needle in failure_needles {
            assert!(
                array_contains(&criterion["failure_criteria"], needle),
                "{id} failure criteria must contain {needle}"
            );
        }
    }
}

#[test]
fn thesis_manifest_links_to_required_evidence_surfaces() {
    let manifest = manifest();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let criteria = manifest["criterion_promotion"]
        .as_array()
        .expect("criterion_promotion is an array");

    for criterion in criteria {
        let evidence_refs = criterion["evidence_refs"]
            .as_array()
            .expect("criterion evidence_refs is an array");
        assert!(
            evidence_refs.len() >= 3,
            "{} must link reviewer evidence surfaces",
            criterion["id"]
        );
        for evidence_ref in evidence_refs {
            let relative = evidence_ref.as_str().expect("evidence ref is a string");
            assert!(
                root.join(relative).exists(),
                "{} links missing evidence surface {relative}",
                criterion["id"]
            );
        }
    }
}

#[test]
fn thesis_manifest_defines_plan_b_as_evaluate_only() {
    let manifest = manifest();
    let fallback = &manifest["fallback"];

    assert_eq!(
        fallback["architecture"],
        "Falcon/LaBRADOR-style proof aggregation"
    );
    assert_eq!(fallback["status"], "evaluate_only");
    assert_eq!(fallback["claims_selected_backend"], false);
    assert_eq!(fallback["pivot_requires"].as_array().unwrap().len(), 5);
}
