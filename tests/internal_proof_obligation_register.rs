use serde_json::Value;
use std::fs;
use std::process::Command;

const REGISTER: &str = include_str!("../docs/cryptography/internal-proof-obligation-register.json");

fn register() -> Value {
    serde_json::from_str(REGISTER).expect("internal proof-obligation register is valid JSON")
}

#[test]
fn register_separates_proof_review_and_independent_validation() {
    let register = register();
    assert_eq!(
        register["schema"],
        "lattice-aggregation.internal-proof-obligation-register.v1"
    );
    assert_eq!(
        register["scope"]["internal_milestone"],
        "internally_closed_pending_independent_review"
    );

    for criterion in register["criteria"]
        .as_array()
        .expect("criteria is an array")
    {
        assert!(criterion["substantive_proof"]["status"].is_string());
        assert!(criterion["internal_review"]["status"].is_string());
        assert!(criterion["independent_validation"]["status"].is_string());
    }
}

#[test]
fn current_register_does_not_claim_theorem_closure() {
    let register = register();
    let claims = register["claim_boundary"]
        .as_object()
        .expect("claim boundary is an object");

    for key in [
        "claims_internal_theorem_closure",
        "claims_independent_validation",
        "claims_theorem_closure",
        "claims_production_threshold_mldsa_security",
        "claims_no_single_holder_threshold_signing",
    ] {
        assert_eq!(claims[key], false, "{key} must remain false");
    }
}

#[test]
fn keygen_public_output_is_separated_from_distributed_keygen_closure() {
    let register = register();
    let boundary = register["implementation_capability_boundary"]
        .as_object()
        .expect("implementation capability boundary is an object");
    let public_key = &boundary["fips204_exact_public_key_from_supplied_shares"];
    assert_eq!(public_key["status"], "engineering_guard_only");
    assert_eq!(public_key["implemented"], true);
    assert_eq!(public_key["reveals_combined_t_and_t0"], true);
    assert_eq!(public_key["model_permits_public_t_and_t0"], true);
    assert_eq!(
        public_key["establishes_exact_joint_secret_distribution"],
        false
    );
    assert_eq!(
        public_key["evidence"]["implementation_path"],
        "src/crypto/fips_public_key.rs"
    );
    assert_eq!(
        public_key["evidence"]["test_path"],
        "tests/fips_keygen_conformance.rs"
    );
    assert_eq!(
        public_key["evidence"]["type_surface_test_path"],
        "tests/fips_keygen_type_surface.rs"
    );

    for capability in [
        "fips204_exact_joint_expand_s_secret_sampling",
        "joint_unbiasable_rho_generation",
        "ceremony_context_construction_and_authentication",
        "distributed_secret_k_generation",
        "fips204_retained_t0_signing_state",
        "production_pq_private_share_transport",
        "process_isolated_private_share_custody",
        "persistent_receiver_replay_state",
        "malicious_secure_dkg_proof",
        "secret_share_vss_and_shortness_proof",
        "public_secret_relation_proof",
        "authenticated_complaint_and_recovery",
        "fips204_shared_signing_state",
        "fips204_exact_distributed_key_generation",
    ] {
        assert_eq!(boundary[capability]["status"], "open", "{capability}");
        assert_eq!(boundary[capability]["implemented"], false, "{capability}");
        assert!(boundary[capability]["blocker"].is_string(), "{capability}");
    }

    assert_eq!(
        boundary["criterion_promotion"]["promoted_by_this_batch"],
        false
    );

    let custody = &boundary["encrypted_receiver_custody_seam"];
    assert_eq!(custody["status"], "engineering_guard_only");
    assert_eq!(custody["implemented"], true);
    assert_eq!(custody["establishes_process_isolation"], false);
    assert_eq!(
        custody["establishes_pq_key_exchange_or_production_aead"],
        false
    );
    assert_eq!(
        custody["evidence"]["implementation_path"],
        "src/crypto/receiver_custody.rs"
    );
    assert_eq!(
        custody["evidence"]["test_path"],
        "tests/receiver_custody.rs"
    );
}

#[test]
fn register_covers_all_assessor_criteria_and_core_theorem_obligations() {
    let register = register();
    let criterion_ids = register["criteria"]
        .as_array()
        .expect("criteria is an array")
        .iter()
        .map(|criterion| criterion["id"].as_str().expect("criterion id"))
        .collect::<Vec<_>>();
    assert_eq!(
        criterion_ids,
        vec![
            "aggregate_mask_distribution",
            "aggregate_rejection_equivalence",
            "abort_retry_bias",
            "partial_contribution_soundness",
            "unauthorized_aggregate_reduction",
        ]
    );

    let obligation_ids = register["obligations"]
        .as_array()
        .expect("obligations is an array")
        .iter()
        .map(|obligation| obligation["id"].as_str().expect("obligation id"))
        .collect::<Vec<_>>();
    for required in [
        "FST-T1", "FST-T2", "FST-T3", "FST-T4", "FST-L1", "FST-L2", "FST-L3", "FST-L4", "FST-L5",
        "FST-L6", "FST-L7", "FST-L8", "FST-L9",
    ] {
        assert!(
            obligation_ids.contains(&required),
            "missing obligation {required}"
        );
    }
}

#[test]
fn validator_accepts_the_current_conservative_register() {
    let root = env!("CARGO_MANIFEST_DIR");
    let output = Command::new("python3")
        .args([
            "scripts/validate_internal_proof_obligation_register.py",
            "--root",
            root,
            "--json",
        ])
        .current_dir(root)
        .output()
        .expect("run proof-obligation register validator");

    assert!(
        output.status.success(),
        "validator failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).expect("validator returns JSON");
    assert_eq!(result["valid"], true);
    assert_eq!(result["errors"].as_array().unwrap().len(), 0);
}

#[test]
fn validator_rejects_internal_closure_overclaim() {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut overclaim = register();
    overclaim["claim_boundary"]["claims_internal_theorem_closure"] = Value::Bool(true);
    let path = std::env::temp_dir().join(format!(
        "lattice-proof-register-overclaim-{}.json",
        std::process::id()
    ));
    fs::write(
        &path,
        serde_json::to_vec_pretty(&overclaim).expect("serialize overclaim fixture"),
    )
    .expect("write overclaim fixture");

    let output = Command::new("python3")
        .args([
            "scripts/validate_internal_proof_obligation_register.py",
            "--root",
            root,
            "--register",
            path.to_str().expect("temporary path is UTF-8"),
            "--json",
        ])
        .current_dir(root)
        .output()
        .expect("run proof-obligation register validator");
    fs::remove_file(&path).expect("remove overclaim fixture");

    assert_eq!(output.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&output.stdout).expect("validator returns JSON");
    assert_eq!(result["valid"], false);
    assert!(result["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|error| error
            .as_str()
            .unwrap()
            .contains("internal theorem closure is claimed")));
}

#[test]
fn validator_rejects_keygen_capability_overclaim() {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut overclaim = register();
    overclaim["implementation_capability_boundary"]["fips204_exact_distributed_key_generation"]
        ["status"] = Value::String("engineering_guard_only".to_owned());
    overclaim["implementation_capability_boundary"]["fips204_exact_distributed_key_generation"]
        ["implemented"] = Value::Bool(true);
    let path = std::env::temp_dir().join(format!(
        "lattice-keygen-register-overclaim-{}.json",
        std::process::id()
    ));
    fs::write(
        &path,
        serde_json::to_vec_pretty(&overclaim).expect("serialize keygen overclaim fixture"),
    )
    .expect("write keygen overclaim fixture");

    let output = Command::new("python3")
        .args([
            "scripts/validate_internal_proof_obligation_register.py",
            "--root",
            root,
            "--register",
            path.to_str().expect("temporary path is UTF-8"),
            "--json",
        ])
        .current_dir(root)
        .output()
        .expect("run proof-obligation register validator");
    fs::remove_file(&path).expect("remove keygen overclaim fixture");

    assert_eq!(output.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&output.stdout).expect("validator returns JSON");
    assert_eq!(result["valid"], false);
    assert!(result["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|error| error
            .as_str()
            .unwrap()
            .contains("fips204_exact_distributed_key_generation must remain open")));
}
