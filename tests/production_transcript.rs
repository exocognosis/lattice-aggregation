#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::production::types::{
    ActiveSignerSet, AttemptId, DkgTranscriptDigest, EpochId, KeyId, MessageBinding,
    ProtocolProfile, ValidatorSetDigest,
};
use lattice_aggregation::ValidatorId;

#[test]
fn production_context_types_have_stable_bytes() {
    assert_eq!(
        ProtocolProfile::coordinator_assisted_v1().as_bytes(),
        b"mldsa65-coordinator-v1"
    );
    assert_eq!(EpochId(7).to_be_bytes(), 7u64.to_be_bytes());
    assert_eq!(KeyId([1; 32]).as_bytes(), &[1; 32]);
    assert_eq!(AttemptId([2; 32]).as_bytes(), &[2; 32]);
    assert_eq!(ValidatorSetDigest([3; 32]).as_bytes(), &[3; 32]);
    assert_eq!(DkgTranscriptDigest([4; 32]).as_bytes(), &[4; 32]);
    assert_eq!(MessageBinding([5; 64]).as_bytes(), &[5; 64]);
}

#[test]
fn active_signer_set_is_canonical() {
    let active =
        ActiveSignerSet::new(vec![ValidatorId(3), ValidatorId(1), ValidatorId(2)]).unwrap();
    assert_eq!(
        active.as_slice(),
        &[ValidatorId(1), ValidatorId(2), ValidatorId(3)]
    );
}

#[test]
fn active_signer_set_rejects_duplicates() {
    let err = ActiveSignerSet::new(vec![ValidatorId(1), ValidatorId(1)]).unwrap_err();
    assert!(err.to_string().contains("duplicate validator 1"));
}
