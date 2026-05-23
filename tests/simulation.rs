use dytallix_pq_threshold::{
    adapter,
    adapter::evidence::{EvidenceKind, SlashingEvidence},
    adapter::wire::{PqcThresholdWireMsg, WireDecodeError, MAX_PARTIAL_SHARE_BYTES},
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
