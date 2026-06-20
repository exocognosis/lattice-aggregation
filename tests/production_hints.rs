#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::{
    production::{
        hints::{HintRoutingDecision, HintRoutingRequest, HintRoutingResponse},
        types::AttemptId,
    },
    ValidatorId,
};

#[test]
fn hint_routing_request_binds_public_context() {
    let request = HintRoutingRequest::new([1; 32], AttemptId([2; 32]), [3; 32], [4; 32], [5; 32]);
    assert_eq!(request.session_id(), &[1; 32]);
    assert_eq!(request.attempt_id(), AttemptId([2; 32]));
    assert_eq!(request.active_set_digest(), &[3; 32]);
    assert_eq!(request.challenge_digest(), &[4; 32]);
    assert_eq!(request.near_boundary_commitment_digest(), &[5; 32]);
}

#[test]
fn hint_routing_response_binds_validator_without_raw_hint_material() {
    let response = HintRoutingResponse::new(ValidatorId(9), [8; 32]);
    assert_eq!(response.validator(), ValidatorId(9));
    assert_eq!(response.response_digest(), &[8; 32]);
}

#[test]
fn hint_routing_decision_records_complete_or_abort() {
    assert!(HintRoutingDecision::Completed.hint_routing_completed());
    assert!(!HintRoutingDecision::AbortBeforeShareRelease.hint_routing_completed());
}
