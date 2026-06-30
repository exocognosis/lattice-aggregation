use lattice_aggregation::{
    Commitment, CommitmentSet, Mldsa65Backend, PartialShareSet, PartialSignatureShare,
    SigningTranscript, SimulatedBackend, ThresholdError, ThresholdPublicKey, ValidatorId,
    MLDSA65_PUBLICKEY_BYTES, MLDSA65_SIGNATURE_BYTES,
};

const VALIDATOR_COUNT: u16 = 10_000;
const THRESHOLD: u16 = 6_667;
const MESSAGE: &[u8] = b"lattice-aggregation 10000-validator standard-verifier gate";

#[test]
fn simulated_10000_validator_aggregate_is_standard_sized_but_verifier_blocked() {
    let (public_key, aggregate_signature) = simulated_10000_validator_aggregate();

    assert_eq!(aggregate_signature.0.len(), MLDSA65_SIGNATURE_BYTES);
    assert_eq!(
        SimulatedBackend::verify_standard(&public_key, MESSAGE, &aggregate_signature).unwrap_err(),
        ThresholdError::BackendUnavailable {
            reason: "simulation backend does not implement standard ML-DSA verification",
        }
    );
}

#[cfg(feature = "hazmat-real-mldsa")]
#[test]
fn hazmat_standard_verifier_rejects_simulated_10000_validator_aggregate() {
    use lattice_aggregation::production::provider::{
        HazmatMldsa65Provider, StandardMldsa65Provider,
    };

    let (public_key, aggregate_signature) = simulated_10000_validator_aggregate();

    assert!(
        !HazmatMldsa65Provider::verify(&public_key, MESSAGE, &aggregate_signature).unwrap(),
        "deterministic simulated bytes must not satisfy standard ML-DSA verification"
    );
}

fn simulated_10000_validator_aggregate(
) -> (ThresholdPublicKey, lattice_aggregation::ThresholdSignature) {
    let validators = validators();
    let public_key = threshold_public_key();
    let commitments = CommitmentSet::new(
        validators.clone(),
        THRESHOLD,
        (1..=THRESHOLD)
            .map(|validator| (ValidatorId(validator), commitment_for(validator)))
            .collect(),
    )
    .expect("10,000-validator commitment set should be valid");
    let transcript = SigningTranscript::new(
        session_id(),
        THRESHOLD,
        validators.clone(),
        public_key.clone(),
        MESSAGE,
        commitments,
    )
    .expect("10,000-validator transcript should be valid");
    let shares = PartialShareSet::new(
        validators,
        THRESHOLD,
        (1..=THRESHOLD).map(partial_share_for).collect(),
    )
    .expect("10,000-validator partial share set should be valid");
    let signature =
        SimulatedBackend::aggregate(&public_key, &transcript, shares).expect("aggregate succeeds");

    (public_key, signature)
}

fn validators() -> Vec<ValidatorId> {
    (1..=VALIDATOR_COUNT).map(ValidatorId).collect()
}

fn threshold_public_key() -> ThresholdPublicKey {
    let mut bytes = [0u8; MLDSA65_PUBLICKEY_BYTES];
    bytes[0..2].copy_from_slice(&VALIDATOR_COUNT.to_be_bytes());
    bytes[2..4].copy_from_slice(&THRESHOLD.to_be_bytes());
    ThresholdPublicKey(bytes)
}

fn session_id() -> [u8; 32] {
    let mut bytes = [0xA5; 32];
    bytes[0..2].copy_from_slice(&VALIDATOR_COUNT.to_be_bytes());
    bytes[2..4].copy_from_slice(&THRESHOLD.to_be_bytes());
    bytes
}

fn commitment_for(validator: u16) -> Commitment {
    let mut bytes = [0u8; 32];
    bytes[0..2].copy_from_slice(&validator.to_be_bytes());
    bytes[2] = 0xC3;
    Commitment(bytes)
}

fn partial_share_for(validator: u16) -> PartialSignatureShare {
    let mut bytes = vec![(validator % 251) as u8; 64];
    bytes[0..2].copy_from_slice(&validator.to_be_bytes());
    PartialSignatureShare {
        signer: ValidatorId(validator),
        bytes,
    }
}
