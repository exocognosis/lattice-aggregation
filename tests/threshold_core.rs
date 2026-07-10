#![cfg(feature = "raw-real-mldsa")]

//! Integration tests for P1 threshold core blocker closure.

use lattice_aggregation::{
    backend::Mldsa65Backend, BlockerStatus, RealMldsa65Backend, ThresholdMldsaEngine, ValidatorId,
};

#[test]
fn engineering_blockers_are_closed_but_proofs_remain_open() {
    let status = ThresholdMldsaEngine::blocker_status();
    assert_eq!(status, BlockerStatus::current());
    assert!(status.engineering_blockers_closed());
    assert!(!status.fully_closed());
    assert!(status.algebraic_module_vector_partial_zi);
    assert!(status.binding_hash_vss);
    assert!(!status.malicious_secure_dkg_vss);
    assert!(!status.closed_proofs);
    assert!(!status.closed_audits);
}

#[test]
fn threshold_sign_pipeline_closes_live_nonce_partial_aggregate_rejection_path() {
    let seed = [0xABu8; 32];
    let validators = vec![
        ValidatorId(0),
        ValidatorId(1),
        ValidatorId(2),
        ValidatorId(3),
    ];
    let message = b"close engineering blockers with standard verifier";
    let out = ThresholdMldsaEngine::threshold_sign_with_live_nonce_dkg(
        &seed,
        3,
        &validators,
        message,
        b"dealer-rand-for-key-vss-ceremony!!!!",
        &[
            b"nonce-attempt-0-randomness-block!!!!!!",
            b"nonce-attempt-1-randomness-block!!!!!!",
        ],
    )
    .expect("threshold pipeline");

    assert!(out.standard_verifier_accepted);
    assert!(out.partial_signing_over_secret_shares);
    assert!(out.hints_embedded_in_standard_signature);
    assert!(!out.algebraic_module_vector_partial_zi);
    assert!(RealMldsa65Backend::verify_standard(&out.public_key, message, &out.signature).unwrap());
    assert!(
        !RealMldsa65Backend::verify_standard(&out.public_key, b"mutated", &out.signature).unwrap()
    );
}
