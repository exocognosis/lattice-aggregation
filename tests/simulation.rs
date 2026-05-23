use dytallix_pq_threshold::{
    adapter,
    adapter::evidence::{EvidenceKind, SlashingEvidence},
    adapter::wire::{
        PqcThresholdWireMsg, WireDecodeError, MAX_DKG_SHARE_BYTES, MAX_PARTIAL_SHARE_BYTES,
    },
    ValidatorId,
};

#[test]
fn adapter_module_is_exported() {
    let _ = core::any::type_name::<adapter::wire::PqcThresholdWireMsg>();
}

#[test]
fn slashing_evidence_keeps_attributable_validator_and_frame() {
    let evidence = SlashingEvidence::new(
        [7; 32],
        ValidatorId(2),
        EvidenceKind::InvalidPartialSignature,
        Some(vec![1, 2, 3]),
        "invalid partial share",
    );

    assert_eq!(evidence.session_id, [7; 32]);
    assert_eq!(evidence.validator, ValidatorId(2));
    assert_eq!(evidence.kind, EvidenceKind::InvalidPartialSignature);
    assert_eq!(evidence.wire_frame.as_deref(), Some(&[1, 2, 3][..]));
    assert_eq!(evidence.details, "invalid partial share");
}

#[test]
fn sign_commit_wire_encoding_is_golden() {
    let msg = PqcThresholdWireMsg::SignCommit {
        session_id: [0x11; 32],
        block_height: 0x0102_0304_0506_0708,
        validator_index: 0x1234,
        commitment: [0xAA; 32],
    };

    let encoded = msg.encode();

    assert_eq!(encoded.len(), 76);
    assert_eq!(encoded[0], 1);
    assert_eq!(encoded[1], 3);
    assert_eq!(&encoded[2..34], &[0x11; 32]);
    assert_eq!(&encoded[34..42], &0x0102_0304_0506_0708u64.to_be_bytes());
    assert_eq!(&encoded[42..44], &0x1234u16.to_be_bytes());
    assert_eq!(&encoded[44..76], &[0xAA; 32]);
    assert_eq!(PqcThresholdWireMsg::decode(&encoded).unwrap(), msg);
}

#[test]
fn dkg_commit_wire_encoding_round_trips() {
    let msg = PqcThresholdWireMsg::DkgCommit {
        session_id: [0x22; 32],
        validator_index: 0x0102,
        commitment_hash: [0xBB; 32],
    };

    let encoded = msg.encode();

    assert_eq!(encoded.len(), 68);
    assert_eq!(encoded[0], 1);
    assert_eq!(encoded[1], 1);
    assert_eq!(&encoded[2..34], &[0x22; 32]);
    assert_eq!(&encoded[34..36], &0x0102u16.to_be_bytes());
    assert_eq!(&encoded[36..68], &[0xBB; 32]);
    assert_eq!(PqcThresholdWireMsg::decode(&encoded).unwrap(), msg);
}

#[test]
fn dkg_share_exchange_wire_encoding_round_trips() {
    let msg = PqcThresholdWireMsg::DkgShareExchange {
        session_id: [0x33; 32],
        target_validator_index: 0x0203,
        encrypted_share: vec![1, 2, 3],
    };

    let encoded = msg.encode();

    assert_eq!(encoded.len(), 43);
    assert_eq!(encoded[0], 1);
    assert_eq!(encoded[1], 2);
    assert_eq!(&encoded[2..34], &[0x33; 32]);
    assert_eq!(&encoded[34..36], &0x0203u16.to_be_bytes());
    assert_eq!(&encoded[36..40], &3u32.to_be_bytes());
    assert_eq!(&encoded[40..43], &[1, 2, 3]);
    assert_eq!(PqcThresholdWireMsg::decode(&encoded).unwrap(), msg);
}

#[test]
fn partial_signature_wire_encoding_round_trips() {
    let msg = PqcThresholdWireMsg::PartialSignature {
        session_id: [0x44; 32],
        validator_index: 0x0304,
        partial_sig_share: vec![4, 5, 6, 7],
    };

    let encoded = msg.encode();

    assert_eq!(encoded.len(), 44);
    assert_eq!(encoded[0], 1);
    assert_eq!(encoded[1], 4);
    assert_eq!(&encoded[2..34], &[0x44; 32]);
    assert_eq!(&encoded[34..36], &0x0304u16.to_be_bytes());
    assert_eq!(&encoded[36..40], &4u32.to_be_bytes());
    assert_eq!(&encoded[40..44], &[4, 5, 6, 7]);
    assert_eq!(PqcThresholdWireMsg::decode(&encoded).unwrap(), msg);
}

#[test]
fn wire_decode_rejects_oversized_variable_payloads() {
    let msg = PqcThresholdWireMsg::PartialSignature {
        session_id: [9; 32],
        validator_index: 2,
        partial_sig_share: vec![7; MAX_PARTIAL_SHARE_BYTES + 1],
    };

    assert_eq!(
        PqcThresholdWireMsg::decode(&msg.encode()),
        Err(WireDecodeError::PayloadTooLarge)
    );
}

#[test]
fn wire_decode_rejects_oversized_dkg_share_payloads() {
    let msg = PqcThresholdWireMsg::DkgShareExchange {
        session_id: [8; 32],
        target_validator_index: 3,
        encrypted_share: vec![5; MAX_DKG_SHARE_BYTES + 1],
    };

    assert_eq!(
        PqcThresholdWireMsg::decode(&msg.encode()),
        Err(WireDecodeError::PayloadTooLarge)
    );
}

#[test]
fn wire_decode_rejects_malformed_frames() {
    assert_eq!(
        PqcThresholdWireMsg::decode(&[1]),
        Err(WireDecodeError::InvalidLength)
    );
    assert_eq!(
        PqcThresholdWireMsg::decode(&[2, 1]),
        Err(WireDecodeError::UnsupportedVersion)
    );
    assert_eq!(
        PqcThresholdWireMsg::decode(&[1, 99]),
        Err(WireDecodeError::UnknownMessageType)
    );

    let mut fixed_with_trailing = PqcThresholdWireMsg::DkgCommit {
        session_id: [1; 32],
        validator_index: 1,
        commitment_hash: [2; 32],
    }
    .encode();
    fixed_with_trailing.push(0);
    assert_eq!(
        PqcThresholdWireMsg::decode(&fixed_with_trailing),
        Err(WireDecodeError::InvalidLength)
    );

    let mut truncated_variable = PqcThresholdWireMsg::PartialSignature {
        session_id: [3; 32],
        validator_index: 4,
        partial_sig_share: vec![9, 9, 9],
    }
    .encode();
    truncated_variable.pop();
    assert_eq!(
        PqcThresholdWireMsg::decode(&truncated_variable),
        Err(WireDecodeError::InvalidLength)
    );
}
