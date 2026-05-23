use dytallix_pq_threshold::{
    adapter,
    adapter::evidence::{EvidenceKind, SlashingEvidence},
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
