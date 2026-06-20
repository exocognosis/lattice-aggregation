#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::adapter::production_wire::{ProductionWireDecodeError, ProductionWireMsg};

#[test]
fn coordinator_challenge_wire_encoding_is_golden() {
    let msg = ProductionWireMsg::CoordinatorChallenge {
        session_id: [1; 32],
        epoch: 7,
        attempt_id: [2; 32],
        active_set_digest: [3; 32],
        challenge_digest: [4; 32],
    };
    let encoded = msg.encode();
    assert_eq!(encoded[0], 2);
    assert_eq!(encoded[1], 3);
    assert_eq!(encoded.len(), 138);
    assert_eq!(&encoded[2..34], &[1; 32]);
    assert_eq!(&encoded[34..42], &7u64.to_be_bytes());
    assert_eq!(&encoded[42..74], &[2; 32]);
    assert_eq!(&encoded[74..106], &[3; 32]);
    assert_eq!(&encoded[106..138], &[4; 32]);
    assert_eq!(ProductionWireMsg::decode(&encoded).unwrap(), msg);
}

#[test]
fn coordinator_abort_wire_encoding_is_golden() {
    let msg = ProductionWireMsg::CoordinatorAbort {
        session_id: [1; 32],
        epoch: 7,
        attempt_id: [2; 32],
        reason_code: 9,
    };
    let encoded = msg.encode();
    assert_eq!(encoded[0], 2);
    assert_eq!(encoded[1], 4);
    assert_eq!(encoded.len(), 76);
    assert_eq!(&encoded[2..34], &[1; 32]);
    assert_eq!(&encoded[34..42], &7u64.to_be_bytes());
    assert_eq!(&encoded[42..74], &[2; 32]);
    assert_eq!(&encoded[74..76], &9u16.to_be_bytes());
    assert_eq!(ProductionWireMsg::decode(&encoded).unwrap(), msg);
}

#[test]
fn prefilter_pass_wire_encoding_is_golden() {
    let msg = ProductionWireMsg::PreFilterPass {
        session_id: [1; 32],
        epoch: 7,
        attempt_id: [2; 32],
        clearance_boundary: 100,
        aggregate_infinity_norm: 45,
    };
    let encoded = msg.encode();
    assert_eq!(encoded[0], 2);
    assert_eq!(encoded[1], 6);
    assert_eq!(encoded.len(), 82);
    assert_eq!(&encoded[2..34], &[1; 32]);
    assert_eq!(&encoded[34..42], &7u64.to_be_bytes());
    assert_eq!(&encoded[42..74], &[2; 32]);
    assert_eq!(&encoded[74..78], &100u32.to_be_bytes());
    assert_eq!(&encoded[78..82], &45u32.to_be_bytes());
    assert_eq!(ProductionWireMsg::decode(&encoded).unwrap(), msg);
}

#[test]
fn prefilter_abort_wire_encoding_is_golden() {
    let msg = ProductionWireMsg::PreFilterAbort {
        session_id: [1; 32],
        epoch: 7,
        attempt_id: [2; 32],
        reason_code: 11,
        aggregate_infinity_norm: 101,
    };
    let encoded = msg.encode();
    assert_eq!(encoded[0], 2);
    assert_eq!(encoded[1], 5);
    assert_eq!(encoded.len(), 80);
    assert_eq!(&encoded[2..34], &[1; 32]);
    assert_eq!(&encoded[34..42], &7u64.to_be_bytes());
    assert_eq!(&encoded[42..74], &[2; 32]);
    assert_eq!(&encoded[74..76], &11u16.to_be_bytes());
    assert_eq!(&encoded[76..80], &101u32.to_be_bytes());
    assert_eq!(ProductionWireMsg::decode(&encoded).unwrap(), msg);
}

#[test]
fn hint_routing_request_wire_encoding_is_golden() {
    let msg = ProductionWireMsg::HintRoutingRequest {
        session_id: [1; 32],
        epoch: 7,
        attempt_id: [2; 32],
        active_set_digest: [3; 32],
        challenge_digest: [4; 32],
        near_boundary_commitment_digest: [5; 32],
    };
    let encoded = msg.encode();
    assert_eq!(encoded[0], 2);
    assert_eq!(encoded[1], 7);
    assert_eq!(encoded.len(), 170);
    assert_eq!(&encoded[2..34], &[1; 32]);
    assert_eq!(&encoded[34..42], &7u64.to_be_bytes());
    assert_eq!(&encoded[42..74], &[2; 32]);
    assert_eq!(&encoded[74..106], &[3; 32]);
    assert_eq!(&encoded[106..138], &[4; 32]);
    assert_eq!(&encoded[138..170], &[5; 32]);
    assert_eq!(ProductionWireMsg::decode(&encoded).unwrap(), msg);
}

#[test]
fn hint_routing_response_wire_encoding_is_golden() {
    let msg = ProductionWireMsg::HintRoutingResponse {
        session_id: [1; 32],
        epoch: 7,
        attempt_id: [2; 32],
        validator_index: 9,
        response_digest: [8; 32],
    };
    let encoded = msg.encode();
    assert_eq!(encoded[0], 2);
    assert_eq!(encoded[1], 8);
    assert_eq!(encoded.len(), 108);
    assert_eq!(&encoded[2..34], &[1; 32]);
    assert_eq!(&encoded[34..42], &7u64.to_be_bytes());
    assert_eq!(&encoded[42..74], &[2; 32]);
    assert_eq!(&encoded[74..76], &9u16.to_be_bytes());
    assert_eq!(&encoded[76..108], &[8; 32]);
    assert_eq!(ProductionWireMsg::decode(&encoded).unwrap(), msg);
}

#[test]
fn production_wire_rejects_short_or_unknown_headers() {
    assert_eq!(
        ProductionWireMsg::decode(&[]).unwrap_err(),
        ProductionWireDecodeError::InvalidLength
    );
    assert_eq!(
        ProductionWireMsg::decode(&[2]).unwrap_err(),
        ProductionWireDecodeError::InvalidLength
    );
    assert_eq!(
        ProductionWireMsg::decode(&[1, 3]).unwrap_err(),
        ProductionWireDecodeError::UnsupportedVersion
    );
    assert_eq!(
        ProductionWireMsg::decode(&[2, 99]).unwrap_err(),
        ProductionWireDecodeError::UnknownMessageType
    );
}

#[test]
fn production_wire_rejects_truncated_frames() {
    let mut challenge = ProductionWireMsg::CoordinatorChallenge {
        session_id: [1; 32],
        epoch: 7,
        attempt_id: [2; 32],
        active_set_digest: [3; 32],
        challenge_digest: [4; 32],
    }
    .encode();
    challenge.pop();
    assert_eq!(
        ProductionWireMsg::decode(&challenge).unwrap_err(),
        ProductionWireDecodeError::InvalidLength
    );

    let mut abort = ProductionWireMsg::CoordinatorAbort {
        session_id: [1; 32],
        epoch: 7,
        attempt_id: [2; 32],
        reason_code: 9,
    }
    .encode();
    abort.pop();
    assert_eq!(
        ProductionWireMsg::decode(&abort).unwrap_err(),
        ProductionWireDecodeError::InvalidLength
    );
}

#[test]
fn production_wire_rejects_trailing_bytes() {
    let mut frame = ProductionWireMsg::CoordinatorAbort {
        session_id: [1; 32],
        epoch: 7,
        attempt_id: [2; 32],
        reason_code: 9,
    }
    .encode();
    frame.push(0);
    assert_eq!(
        ProductionWireMsg::decode(&frame).unwrap_err(),
        ProductionWireDecodeError::InvalidLength
    );

    let mut challenge = ProductionWireMsg::CoordinatorChallenge {
        session_id: [1; 32],
        epoch: 7,
        attempt_id: [2; 32],
        active_set_digest: [3; 32],
        challenge_digest: [4; 32],
    }
    .encode();
    challenge.push(0);
    assert_eq!(
        ProductionWireMsg::decode(&challenge).unwrap_err(),
        ProductionWireDecodeError::InvalidLength
    );

    let mut hint = ProductionWireMsg::HintRoutingRequest {
        session_id: [1; 32],
        epoch: 7,
        attempt_id: [2; 32],
        active_set_digest: [3; 32],
        challenge_digest: [4; 32],
        near_boundary_commitment_digest: [5; 32],
    }
    .encode();
    hint.push(0);
    assert_eq!(
        ProductionWireMsg::decode(&hint).unwrap_err(),
        ProductionWireDecodeError::InvalidLength
    );
}
