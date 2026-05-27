#![cfg(feature = "hazmat-real-mldsa")]

use std::time::Duration;

#[cfg(feature = "experimental-vss")]
use dytallix_pq_threshold::crypto::vss::{
    verify_experimental_vss_complaint_evidence, ExperimentalVssComplaintEvidence,
};
use dytallix_pq_threshold::{
    adapter::{
        actor::{
            production_contribution_statement_digest_from_scaffold, ActorConfig, ActorEvent,
            HazmatMldsa65ActorSession, ThresholdActor,
        },
        evidence::SlashingEvidence,
        traits::{ConsensusStateAdapter, P2pNetworkAdapter},
        wire::{
            PqcThresholdWireMsg, WireDecodeError, MAX_HAZMAT_MLDSA65_MASKING_CONTRIBUTION_BYTES,
            MAX_HAZMAT_MLDSA65_SECRET_CONTRIBUTION_BYTES,
        },
    },
    crypto::contribution_proof::{
        prove_contribution, ContributionProof, ContributionStatement, ContributionWitness,
        CONTRIBUTION_PROOF_BYTES,
    },
    mldsa65::{
        aggregate_mldsa65_masking_contributions, decode_mldsa65_masking_contribution,
        decode_mldsa65_secret_contribution, derive_mldsa65_challenge_from_aggregated_masking,
        derive_mldsa65_expanded_secret_key_from_seed,
        derive_mldsa65_masking_contribution_from_share,
        derive_mldsa65_public_key_from_expanded_secret_key,
        derive_mldsa65_secret_contribution_from_share, encode_mldsa65_masking_contribution,
        encode_mldsa65_secret_contribution, finalize_mldsa65_threshold_signature_attempt,
        masking_commitment_digest, reconstruct_mldsa65_secret_contribution_from_shares,
        secret_commitment_digest, split_mldsa65_expanded_secret_key, verify_mldsa65_internal_mu,
        MLDSA65_CHALLENGE_BYTES, MLDSA65_MU_BYTES,
    },
    PrivateKeyShare, ThresholdError, ThresholdPublicKey, ThresholdSignature, ValidatorId,
    MLDSA65_SIGNATURE_BYTES, Q,
};
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc;

type BroadcastRecords = Arc<Mutex<Vec<PqcThresholdWireMsg>>>;
type FinalizedRecords = Arc<Mutex<Vec<(u64, Vec<u8>)>>>;
type EvidenceRecords = Arc<Mutex<Vec<SlashingEvidence>>>;

#[derive(Clone, Default)]
struct RecordingNetwork {
    broadcasts: BroadcastRecords,
}

#[async_trait::async_trait]
impl P2pNetworkAdapter for RecordingNetwork {
    type Error = Infallible;

    async fn broadcast(&self, msg: PqcThresholdWireMsg) -> Result<(), Self::Error> {
        self.broadcasts.lock().unwrap().push(msg);
        Ok(())
    }

    async fn send_to(&self, _target: u16, msg: PqcThresholdWireMsg) -> Result<(), Self::Error> {
        self.broadcasts.lock().unwrap().push(msg);
        Ok(())
    }
}

#[derive(Clone, Default)]
struct RecordingConsensus {
    finalized: FinalizedRecords,
    evidence: EvidenceRecords,
}

#[async_trait::async_trait]
impl ConsensusStateAdapter for RecordingConsensus {
    type Error = Infallible;

    async fn on_signature_finalized(
        &self,
        block_height: u64,
        signature: Vec<u8>,
    ) -> Result<(), Self::Error> {
        self.finalized
            .lock()
            .unwrap()
            .push((block_height, signature));
        Ok(())
    }

    async fn submit_slashing_evidence(
        &self,
        evidence: SlashingEvidence,
    ) -> Result<(), Self::Error> {
        self.evidence.lock().unwrap().push(evidence);
        Ok(())
    }

    async fn update_gas_baseline(&self, _block_height: u64) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[test]
fn hazmat_mldsa65_wire_frames_round_trip_with_stable_layout() {
    let masking = PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
        session_id: [0xA1; 32],
        block_height: 0x0102_0304_0506_0708,
        attempt: 0x090A,
        validator_index: 0x0B0C,
        payload: vec![0x55, 0x66],
    };
    let encoded = masking.encode();
    assert_eq!(encoded.len(), 52);
    assert_eq!(encoded[0], 1);
    assert_eq!(encoded[1], 5);
    assert_eq!(&encoded[2..34], &[0xA1; 32]);
    assert_eq!(&encoded[34..42], &0x0102_0304_0506_0708u64.to_be_bytes());
    assert_eq!(&encoded[42..44], &0x090Au16.to_be_bytes());
    assert_eq!(&encoded[44..46], &0x0B0Cu16.to_be_bytes());
    assert_eq!(&encoded[46..50], &2u32.to_be_bytes());
    assert_eq!(&encoded[50..52], &[0x55, 0x66]);
    assert_eq!(PqcThresholdWireMsg::decode(&encoded).unwrap(), masking);

    let challenge = PqcThresholdWireMsg::HazmatMldsa65Challenge {
        session_id: [0xA2; 32],
        block_height: 77,
        attempt: 2,
        challenge: [0xCC; MLDSA65_CHALLENGE_BYTES],
    };
    let encoded = challenge.encode();
    assert_eq!(encoded.len(), 92);
    assert_eq!(encoded[1], 6);
    assert_eq!(PqcThresholdWireMsg::decode(&encoded).unwrap(), challenge);

    let commitment = PqcThresholdWireMsg::HazmatMldsa65MaskingCommitment {
        session_id: [0xA4; 32],
        block_height: 99,
        attempt: 4,
        validator_index: 5,
        commitment: [0xEE; 32],
    };
    let encoded = commitment.encode();
    assert_eq!(encoded.len(), 78);
    assert_eq!(encoded[1], 8);
    assert_eq!(PqcThresholdWireMsg::decode(&encoded).unwrap(), commitment);

    let secret = PqcThresholdWireMsg::HazmatMldsa65SecretContribution {
        session_id: [0xA3; 32],
        block_height: 88,
        attempt: 3,
        validator_index: 4,
        challenge: [0xDD; MLDSA65_CHALLENGE_BYTES],
        payload: vec![0x77, 0x88, 0x99],
    };
    let encoded = secret.encode();
    assert_eq!(encoded.len(), 101);
    assert_eq!(encoded[1], 7);
    assert_eq!(PqcThresholdWireMsg::decode(&encoded).unwrap(), secret);

    let secret_commitment = PqcThresholdWireMsg::HazmatMldsa65SecretCommitment {
        session_id: [0xA5; 32],
        block_height: 100,
        attempt: 5,
        validator_index: 6,
        challenge: [0xF1; MLDSA65_CHALLENGE_BYTES],
        commitment: [0xF2; 32],
    };
    let encoded = secret_commitment.encode();
    assert_eq!(encoded.len(), 126);
    assert_eq!(encoded[1], 9);
    assert_eq!(
        PqcThresholdWireMsg::decode(&encoded).unwrap(),
        secret_commitment
    );

    let proof_bound = fixture_proof_bound_secret_wire_msg(vec![0x11, 0x22, 0x33]);
    let encoded = proof_bound.encode();
    assert_eq!(encoded.len(), 297);
    assert_eq!(encoded[1], 10);
    assert_eq!(PqcThresholdWireMsg::decode(&encoded).unwrap(), proof_bound);
}

#[test]
fn hazmat_actor_session_requires_masking_precommitment_in_strict_mode() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(31).wrapping_add(9));
    let secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret");
    let shares =
        split_mldsa65_expanded_secret_key(secret.as_bytes(), 2, 3).expect("split secret key");
    let session_id = [0x91; 32];
    let block_height = 55;
    let mut actor_session = HazmatMldsa65ActorSession::new_with_masking_precommitments(
        session_id,
        block_height,
        2,
        3,
        [0x92; MLDSA65_MU_BYTES],
        Duration::from_secs(2),
    )
    .expect("create strict actor session");
    let contribution =
        derive_mldsa65_masking_contribution_from_share(&shares[0], &[0x93; MLDSA65_MU_BYTES], 0)
            .expect("derive masking");
    let payload = encode_mldsa65_masking_contribution(&contribution);
    let opening = PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
        session_id,
        block_height,
        attempt: 0,
        validator_index: contribution.receiver_index(),
        payload: payload.clone(),
    };

    let err = actor_session
        .submit_masking_wire_message(&opening)
        .expect_err("strict mode requires precommitment");
    assert!(matches!(err, ThresholdError::TranscriptMismatch));

    let bad_commitment = PqcThresholdWireMsg::HazmatMldsa65MaskingCommitment {
        session_id,
        block_height,
        attempt: 0,
        validator_index: contribution.receiver_index(),
        commitment: [0xAA; 32],
    };
    actor_session
        .submit_masking_commitment_wire_message(&bad_commitment)
        .expect("commitment frame is accepted before opening");
    let err = actor_session
        .submit_masking_wire_message(&opening)
        .expect_err("opening must match precommitment");
    assert!(matches!(
        err,
        ThresholdError::CommitmentVerificationFailed {
            validator: ValidatorId(1)
        }
    ));

    let mut actor_session = HazmatMldsa65ActorSession::new_with_masking_precommitments(
        session_id,
        block_height,
        2,
        3,
        [0x92; MLDSA65_MU_BYTES],
        Duration::from_secs(2),
    )
    .expect("create strict actor session");
    let commitment = PqcThresholdWireMsg::HazmatMldsa65MaskingCommitment {
        session_id,
        block_height,
        attempt: 0,
        validator_index: contribution.receiver_index(),
        commitment: masking_commitment_digest(
            &session_id,
            block_height,
            0,
            contribution.receiver_index(),
            &payload,
        ),
    };
    actor_session
        .submit_masking_commitment_wire_message(&commitment)
        .expect("valid commitment should be recorded");
    assert!(actor_session
        .submit_masking_wire_message(&opening)
        .expect("valid opening should match commitment")
        .is_none());
}

#[test]
fn hazmat_actor_session_requires_secret_precommitment_in_strict_mode() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(37).wrapping_add(13));
    let secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret");
    let shares =
        split_mldsa65_expanded_secret_key(secret.as_bytes(), 2, 3).expect("split secret key");
    let session_id = [0x94; 32];
    let block_height = 56;
    let mut actor_session = HazmatMldsa65ActorSession::new_with_precommitments(
        session_id,
        block_height,
        2,
        3,
        [0x95; MLDSA65_MU_BYTES],
        Duration::from_secs(2),
    )
    .expect("create strict actor session");

    let premature_commitment = PqcThresholdWireMsg::HazmatMldsa65SecretCommitment {
        session_id,
        block_height,
        attempt: 0,
        validator_index: 1,
        challenge: [0xFE; MLDSA65_CHALLENGE_BYTES],
        commitment: [0xFD; 32],
    };
    let err = actor_session
        .submit_secret_commitment_wire_message(&premature_commitment)
        .expect_err("secret commitment before fixed challenge must be rejected");
    assert!(matches!(err, ThresholdError::TranscriptMismatch));

    let masking_contributions = [
        derive_mldsa65_masking_contribution_from_share(&shares[0], &[0x96; MLDSA65_MU_BYTES], 0)
            .expect("derive first masking"),
        derive_mldsa65_masking_contribution_from_share(&shares[1], &[0x96; MLDSA65_MU_BYTES], 0)
            .expect("derive second masking"),
    ];
    for contribution in masking_contributions {
        let payload = encode_mldsa65_masking_contribution(&contribution);
        let commitment = PqcThresholdWireMsg::HazmatMldsa65MaskingCommitment {
            session_id,
            block_height,
            attempt: 0,
            validator_index: contribution.receiver_index(),
            commitment: masking_commitment_digest(
                &session_id,
                block_height,
                0,
                contribution.receiver_index(),
                &payload,
            ),
        };
        actor_session
            .submit_masking_commitment_wire_message(&commitment)
            .expect("submit masking commitment");
        let opening = PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
            session_id,
            block_height,
            attempt: 0,
            validator_index: contribution.receiver_index(),
            payload,
        };
        let _ = actor_session
            .submit_masking_wire_message(&opening)
            .expect("submit masking opening");
    }
    let challenge = actor_session
        .derive_challenge()
        .expect_err("challenge should already be fixed by quorum");
    assert!(matches!(challenge, ThresholdError::TranscriptMismatch));

    let challenge = {
        let mut fresh = HazmatMldsa65ActorSession::new_with_precommitments(
            session_id,
            block_height,
            2,
            3,
            [0x95; MLDSA65_MU_BYTES],
            Duration::from_secs(2),
        )
        .expect("create strict actor session");
        let mut fixed = None;
        for contribution in masking_contributions {
            let payload = encode_mldsa65_masking_contribution(&contribution);
            let commitment = PqcThresholdWireMsg::HazmatMldsa65MaskingCommitment {
                session_id,
                block_height,
                attempt: 0,
                validator_index: contribution.receiver_index(),
                commitment: masking_commitment_digest(
                    &session_id,
                    block_height,
                    0,
                    contribution.receiver_index(),
                    &payload,
                ),
            };
            fresh
                .submit_masking_commitment_wire_message(&commitment)
                .expect("submit masking commitment");
            let opening = PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
                session_id,
                block_height,
                attempt: 0,
                validator_index: contribution.receiver_index(),
                payload,
            };
            fixed = fresh
                .submit_masking_wire_message(&opening)
                .expect("submit masking opening")
                .or(fixed);
        }
        fixed.expect("masking quorum fixes challenge")
    };

    let mut actor_session = HazmatMldsa65ActorSession::new_with_precommitments(
        session_id,
        block_height,
        2,
        3,
        [0x95; MLDSA65_MU_BYTES],
        Duration::from_secs(2),
    )
    .expect("create strict actor session");
    for contribution in masking_contributions {
        let payload = encode_mldsa65_masking_contribution(&contribution);
        let commitment = PqcThresholdWireMsg::HazmatMldsa65MaskingCommitment {
            session_id,
            block_height,
            attempt: 0,
            validator_index: contribution.receiver_index(),
            commitment: masking_commitment_digest(
                &session_id,
                block_height,
                0,
                contribution.receiver_index(),
                &payload,
            ),
        };
        actor_session
            .submit_masking_commitment_wire_message(&commitment)
            .expect("submit masking commitment");
        let opening = PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
            session_id,
            block_height,
            attempt: 0,
            validator_index: contribution.receiver_index(),
            payload,
        };
        let _ = actor_session
            .submit_masking_wire_message(&opening)
            .expect("submit masking opening");
    }

    let contribution = derive_mldsa65_secret_contribution_from_share(&shares[0], &challenge)
        .expect("derive secret contribution");
    let payload = encode_mldsa65_secret_contribution(&contribution);
    let opening = PqcThresholdWireMsg::HazmatMldsa65SecretContribution {
        session_id,
        block_height,
        attempt: 0,
        validator_index: contribution.receiver_index(),
        challenge,
        payload: payload.clone(),
    };
    let err = actor_session
        .submit_secret_wire_message(&opening)
        .expect_err("strict mode requires secret precommitment");
    assert!(matches!(err, ThresholdError::TranscriptMismatch));

    let mut wrong_challenge = challenge;
    wrong_challenge[0] ^= 0x01;
    let stale_commitment = PqcThresholdWireMsg::HazmatMldsa65SecretCommitment {
        session_id,
        block_height,
        attempt: 0,
        validator_index: contribution.receiver_index(),
        challenge: wrong_challenge,
        commitment: secret_commitment_digest(
            &session_id,
            block_height,
            0,
            contribution.receiver_index(),
            &wrong_challenge,
            &payload,
        ),
    };
    let err = actor_session
        .submit_secret_commitment_wire_message(&stale_commitment)
        .expect_err("secret commitment must bind the fixed challenge");
    assert!(matches!(err, ThresholdError::TranscriptMismatch));

    let bad_commitment = PqcThresholdWireMsg::HazmatMldsa65SecretCommitment {
        session_id,
        block_height,
        attempt: 0,
        validator_index: contribution.receiver_index(),
        challenge,
        commitment: [0xFA; 32],
    };
    actor_session
        .submit_secret_commitment_wire_message(&bad_commitment)
        .expect("record bad secret commitment");
    let err = actor_session
        .submit_secret_wire_message(&opening)
        .expect_err("secret opening must match precommitment");
    assert!(matches!(
        err,
        ThresholdError::CommitmentVerificationFailed {
            validator: ValidatorId(1)
        }
    ));

    let mut actor_session = HazmatMldsa65ActorSession::new_with_precommitments(
        session_id,
        block_height,
        2,
        3,
        [0x95; MLDSA65_MU_BYTES],
        Duration::from_secs(2),
    )
    .expect("create strict actor session");
    for contribution in masking_contributions {
        let payload = encode_mldsa65_masking_contribution(&contribution);
        actor_session
            .submit_masking_commitment_wire_message(
                &PqcThresholdWireMsg::HazmatMldsa65MaskingCommitment {
                    session_id,
                    block_height,
                    attempt: 0,
                    validator_index: contribution.receiver_index(),
                    commitment: masking_commitment_digest(
                        &session_id,
                        block_height,
                        0,
                        contribution.receiver_index(),
                        &payload,
                    ),
                },
            )
            .expect("submit masking commitment");
        let _ = actor_session
            .submit_masking_wire_message(&PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
                session_id,
                block_height,
                attempt: 0,
                validator_index: contribution.receiver_index(),
                payload,
            })
            .expect("submit masking opening");
    }
    let commitment = PqcThresholdWireMsg::HazmatMldsa65SecretCommitment {
        session_id,
        block_height,
        attempt: 0,
        validator_index: contribution.receiver_index(),
        challenge,
        commitment: secret_commitment_digest(
            &session_id,
            block_height,
            0,
            contribution.receiver_index(),
            &challenge,
            &payload,
        ),
    };
    actor_session
        .submit_secret_commitment_wire_message(&commitment)
        .expect("record valid secret commitment");
    assert!(actor_session
        .submit_secret_wire_message(&opening)
        .expect("valid secret opening should match commitment")
        .is_none());
}

#[test]
fn hazmat_actor_session_accepts_proof_bound_secret_opening() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(41).wrapping_add(17));
    let secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret");
    let shares =
        split_mldsa65_expanded_secret_key(secret.as_bytes(), 2, 3).expect("split secret key");
    let session_id = [0xA6; 32];
    let block_height = 57;
    let mut actor_session = HazmatMldsa65ActorSession::new(
        session_id,
        block_height,
        2,
        3,
        [0xA7; MLDSA65_MU_BYTES],
        Duration::from_secs(2),
    )
    .expect("create actor session");
    assert_ne!(actor_session.dkg_commitment_digest(), [0; 32]);

    let mut challenge = None;
    for share in [&shares[0], &shares[1]] {
        let contribution =
            derive_mldsa65_masking_contribution_from_share(share, &[0xA8; MLDSA65_MU_BYTES], 0)
                .expect("derive masking");
        let frame = PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
            session_id,
            block_height,
            attempt: 0,
            validator_index: contribution.receiver_index(),
            payload: encode_mldsa65_masking_contribution(&contribution),
        };
        challenge = actor_session
            .submit_masking_wire_message(&frame)
            .expect("submit masking")
            .or(challenge);
    }
    let challenge = challenge.expect("masking quorum fixes challenge");
    let contribution = derive_mldsa65_secret_contribution_from_share(&shares[0], &challenge)
        .expect("derive secret contribution");
    let payload = encode_mldsa65_secret_contribution(&contribution);
    let statement = fixture_contribution_statement_with_dkg_digest(
        session_id,
        block_height,
        0,
        contribution.receiver_index(),
        challenge,
        &payload,
        actor_session.dkg_commitment_digest(),
    );
    let proof = prove_contribution(
        &statement,
        &ContributionWitness::from_payload(payload.clone()),
    )
    .expect("build contribution proof");
    let frame = PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
        session_id,
        block_height,
        attempt: 0,
        validator_index: contribution.receiver_index(),
        challenge,
        masking_commitment_digest: statement.masking_commitment_digest,
        secret_commitment_digest: statement.secret_commitment_digest,
        dkg_commitment_digest: statement.dkg_commitment_digest,
        production_statement_digest: actor_session
            .production_contribution_statement_digest(
                contribution.receiver_index(),
                &challenge,
                &payload,
            )
            .expect("derive production statement digest"),
        proof,
        payload,
    };

    assert!(actor_session
        .submit_secret_wire_message(&frame)
        .expect("proof-bound secret opening should verify")
        .is_none());
}

#[test]
fn hazmat_actor_session_rejects_proof_bound_secret_tampering() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(43).wrapping_add(19));
    let secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret");
    let shares =
        split_mldsa65_expanded_secret_key(secret.as_bytes(), 2, 3).expect("split secret key");
    let session_id = [0xA9; 32];
    let block_height = 58;

    let make_secret_frame = |session_id, block_height| {
        let mut actor_session = HazmatMldsa65ActorSession::new(
            session_id,
            block_height,
            2,
            3,
            [0xAA; MLDSA65_MU_BYTES],
            Duration::from_secs(2),
        )
        .expect("create actor session");
        let mut challenge = None;
        for share in [&shares[0], &shares[1]] {
            let contribution =
                derive_mldsa65_masking_contribution_from_share(share, &[0xAB; MLDSA65_MU_BYTES], 0)
                    .expect("derive masking");
            let frame = PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
                session_id,
                block_height,
                attempt: 0,
                validator_index: contribution.receiver_index(),
                payload: encode_mldsa65_masking_contribution(&contribution),
            };
            challenge = actor_session
                .submit_masking_wire_message(&frame)
                .expect("submit masking")
                .or(challenge);
        }
        let challenge = challenge.expect("masking quorum fixes challenge");
        let contribution = derive_mldsa65_secret_contribution_from_share(&shares[0], &challenge)
            .expect("derive secret contribution");
        let payload = encode_mldsa65_secret_contribution(&contribution);
        let statement = fixture_contribution_statement_with_dkg_digest(
            session_id,
            block_height,
            0,
            contribution.receiver_index(),
            challenge,
            &payload,
            actor_session.dkg_commitment_digest(),
        );
        let proof = prove_contribution(
            &statement,
            &ContributionWitness::from_payload(payload.clone()),
        )
        .expect("build contribution proof");
        let frame = PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
            session_id,
            block_height,
            attempt: 0,
            validator_index: contribution.receiver_index(),
            challenge,
            masking_commitment_digest: statement.masking_commitment_digest,
            secret_commitment_digest: statement.secret_commitment_digest,
            dkg_commitment_digest: statement.dkg_commitment_digest,
            production_statement_digest: actor_session
                .production_contribution_statement_digest(
                    contribution.receiver_index(),
                    &challenge,
                    &payload,
                )
                .expect("derive production statement digest"),
            proof,
            payload,
        };
        (actor_session, frame)
    };

    let (mut actor_session, mut frame) = make_secret_frame(session_id, block_height);
    if let PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
        masking_commitment_digest,
        ..
    } = &mut frame
    {
        masking_commitment_digest[0] ^= 0x01;
    }
    let err = actor_session
        .submit_secret_wire_message(&frame)
        .expect_err("statement tampering must be rejected");
    assert!(matches!(
        err,
        ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(1)
        }
    ));

    let (mut actor_session, mut frame) = make_secret_frame([0xAE; 32], block_height);
    if let PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
        secret_commitment_digest: wire_secret_commitment_digest,
        ..
    } = &mut frame
    {
        wire_secret_commitment_digest[0] ^= 0x01;
    }
    let err = actor_session
        .submit_secret_wire_message(&frame)
        .expect_err("secret commitment digest tampering must be rejected");
    assert!(matches!(
        err,
        ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(1)
        }
    ));

    let (mut actor_session, mut frame) = make_secret_frame([0xAD; 32], block_height);
    if let PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
        dkg_commitment_digest,
        ..
    } = &mut frame
    {
        dkg_commitment_digest[0] ^= 0x01;
    }
    let err = actor_session
        .submit_secret_wire_message(&frame)
        .expect_err("DKG commitment tampering must be rejected");
    assert!(matches!(
        err,
        ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(1)
        }
    ));

    let (mut actor_session, mut frame) = make_secret_frame([0xAF; 32], block_height);
    if let PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution { challenge, .. } =
        &mut frame
    {
        challenge[0] ^= 0x01;
    }
    let err = actor_session
        .submit_secret_wire_message(&frame)
        .expect_err("stale challenge binding must be rejected");
    assert!(matches!(
        err,
        ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(1)
        }
    ));

    let (mut actor_session, mut frame) = make_secret_frame([0xAC; 32], block_height);
    if let PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution { proof, .. } = &mut frame
    {
        proof.proof_digest[0] ^= 0x01;
    }
    let err = actor_session
        .submit_secret_wire_message(&frame)
        .expect_err("proof tampering must be rejected");
    assert!(matches!(
        err,
        ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(1)
        }
    ));

    let (mut actor_session, mut frame) = make_secret_frame([0xB2; 32], block_height);
    if let PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
        production_statement_digest,
        ..
    } = &mut frame
    {
        production_statement_digest[0] ^= 0x01;
    }
    let err = actor_session
        .submit_secret_wire_message(&frame)
        .expect_err("production statement digest tampering must be rejected");
    assert!(matches!(
        err,
        ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(1)
        }
    ));

    let (mut actor_session, mut frame) = make_secret_frame([0xB1; 32], block_height);
    if let PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
        session_id,
        block_height,
        attempt,
        validator_index,
        challenge,
        secret_commitment_digest: wire_secret_commitment_digest,
        payload,
        ..
    } = &mut frame
    {
        let first_coeff_offset = 2 + 2 + 2 + MLDSA65_CHALLENGE_BYTES;
        let mut coeff = [0u8; 4];
        coeff.copy_from_slice(&payload[first_coeff_offset..first_coeff_offset + 4]);
        let replacement = (i32::from_be_bytes(coeff) + 1) % Q;
        payload[first_coeff_offset..first_coeff_offset + 4]
            .copy_from_slice(&replacement.to_be_bytes());
        *wire_secret_commitment_digest = secret_commitment_digest(
            session_id,
            *block_height,
            *attempt,
            *validator_index,
            challenge,
            payload,
        );
    }
    let err = actor_session
        .submit_secret_wire_message(&frame)
        .expect_err("same-validator payload mutation after proof generation must be rejected");
    assert!(matches!(
        err,
        ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(1)
        }
    ));

    let (mut actor_session, mut frame) = make_secret_frame([0xB0; 32], block_height);
    if let PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
        challenge,
        validator_index,
        payload,
        ..
    } = &mut frame
    {
        let replayed_contribution =
            derive_mldsa65_secret_contribution_from_share(&shares[1], challenge)
                .expect("derive replay payload");
        *validator_index = replayed_contribution.receiver_index();
        *payload = encode_mldsa65_secret_contribution(&replayed_contribution);
    }
    let err = actor_session
        .submit_secret_wire_message(&frame)
        .expect_err("validator replay with another payload must be rejected");
    assert!(matches!(
        err,
        ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(2)
        }
    ));
}

#[test]
fn hazmat_actor_session_rejects_cross_session_and_cross_height_opening_replay() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(29).wrapping_add(11));
    let secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret");
    let shares =
        split_mldsa65_expanded_secret_key(secret.as_bytes(), 2, 3).expect("split secret key");
    let session_id = [0xBB; 32];
    let block_height = 61;
    let mut actor_session = HazmatMldsa65ActorSession::new(
        session_id,
        block_height,
        2,
        3,
        [0xBC; MLDSA65_MU_BYTES],
        Duration::from_secs(2),
    )
    .expect("create actor session");
    let mut challenge = None;
    for share in [&shares[0], &shares[1]] {
        let contribution =
            derive_mldsa65_masking_contribution_from_share(share, &[0xBD; MLDSA65_MU_BYTES], 0)
                .expect("derive masking");
        let frame = PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
            session_id,
            block_height,
            attempt: 0,
            validator_index: contribution.receiver_index(),
            payload: encode_mldsa65_masking_contribution(&contribution),
        };
        challenge = actor_session
            .submit_masking_wire_message(&frame)
            .expect("submit masking")
            .or(challenge);
    }
    let challenge = challenge.expect("masking quorum fixes challenge");
    let contribution = derive_mldsa65_secret_contribution_from_share(&shares[0], &challenge)
        .expect("derive secret contribution");
    let payload = encode_mldsa65_secret_contribution(&contribution);
    let valid_frame = PqcThresholdWireMsg::HazmatMldsa65SecretContribution {
        session_id,
        block_height,
        attempt: 0,
        validator_index: contribution.receiver_index(),
        challenge,
        payload,
    };

    let mut replayed_session = valid_frame.clone();
    if let PqcThresholdWireMsg::HazmatMldsa65SecretContribution { session_id, .. } =
        &mut replayed_session
    {
        session_id[0] ^= 0x01;
    }
    assert_eq!(
        actor_session
            .submit_secret_wire_message(&replayed_session)
            .expect_err("cross-session replay must be rejected"),
        ThresholdError::TranscriptMismatch
    );

    let mut replayed_height = valid_frame.clone();
    if let PqcThresholdWireMsg::HazmatMldsa65SecretContribution { block_height, .. } =
        &mut replayed_height
    {
        *block_height += 1;
    }
    assert_eq!(
        actor_session
            .submit_secret_wire_message(&replayed_height)
            .expect_err("cross-height replay must be rejected"),
        ThresholdError::TranscriptMismatch
    );

    let mut replayed_attempt = valid_frame;
    if let PqcThresholdWireMsg::HazmatMldsa65SecretContribution { attempt, .. } =
        &mut replayed_attempt
    {
        *attempt += 1;
    }
    assert_eq!(
        actor_session
            .submit_secret_wire_message(&replayed_attempt)
            .expect_err("cross-attempt replay must be rejected"),
        ThresholdError::TranscriptMismatch
    );
}

#[test]
fn hazmat_actor_session_accepts_legacy_secret_opening() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(43).wrapping_add(19));
    let secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret");
    let shares =
        split_mldsa65_expanded_secret_key(secret.as_bytes(), 2, 3).expect("split secret key");
    let session_id = [0xAD; 32];
    let block_height = 59;
    let mut actor_session = HazmatMldsa65ActorSession::new(
        session_id,
        block_height,
        2,
        3,
        [0xAE; MLDSA65_MU_BYTES],
        Duration::from_secs(2),
    )
    .expect("create actor session");
    let mut challenge = None;
    for share in [&shares[0], &shares[1]] {
        let contribution =
            derive_mldsa65_masking_contribution_from_share(share, &[0xAF; MLDSA65_MU_BYTES], 0)
                .expect("derive masking");
        let frame = PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
            session_id,
            block_height,
            attempt: 0,
            validator_index: contribution.receiver_index(),
            payload: encode_mldsa65_masking_contribution(&contribution),
        };
        challenge = actor_session
            .submit_masking_wire_message(&frame)
            .expect("submit masking")
            .or(challenge);
    }
    let challenge = challenge.expect("masking quorum fixes challenge");
    let contribution = derive_mldsa65_secret_contribution_from_share(&shares[0], &challenge)
        .expect("derive secret contribution");
    let frame = PqcThresholdWireMsg::HazmatMldsa65SecretContribution {
        session_id,
        block_height,
        attempt: 0,
        validator_index: contribution.receiver_index(),
        challenge,
        payload: encode_mldsa65_secret_contribution(&contribution),
    };

    assert!(actor_session
        .submit_secret_wire_message(&frame)
        .expect("legacy secret opening should still verify")
        .is_none());
}

#[test]
fn hazmat_proof_bound_secret_wire_rejects_oversized_payload() {
    let mut msg = fixture_proof_bound_secret_wire_msg(vec![
        0;
        MAX_HAZMAT_MLDSA65_SECRET_CONTRIBUTION_BYTES
            + 1
    ]);
    if let PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
        proof, payload, ..
    } = &mut msg
    {
        proof.payload_len = payload.len() as u32;
    }

    assert_eq!(
        PqcThresholdWireMsg::decode(&msg.encode()),
        Err(WireDecodeError::PayloadTooLarge)
    );
}

#[test]
fn hazmat_proof_bound_secret_wire_rejects_payload_length_mismatch() {
    let mut msg = fixture_proof_bound_secret_wire_msg(vec![0x11, 0x22, 0x33, 0x44]);
    if let PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution { proof, .. } = &mut msg {
        proof.payload_len += 1;
    }

    assert_eq!(
        PqcThresholdWireMsg::decode(&msg.encode()),
        Err(WireDecodeError::InvalidLength)
    );
}

#[test]
fn hazmat_mldsa65_wire_frames_reject_oversized_payloads() {
    let masking = PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
        session_id: [1; 32],
        block_height: 1,
        attempt: 0,
        validator_index: 1,
        payload: vec![0; MAX_HAZMAT_MLDSA65_MASKING_CONTRIBUTION_BYTES + 1],
    };
    assert_eq!(
        PqcThresholdWireMsg::decode(&masking.encode()),
        Err(WireDecodeError::PayloadTooLarge)
    );

    let secret = PqcThresholdWireMsg::HazmatMldsa65SecretContribution {
        session_id: [2; 32],
        block_height: 2,
        attempt: 0,
        validator_index: 2,
        challenge: [3; MLDSA65_CHALLENGE_BYTES],
        payload: vec![0; MAX_HAZMAT_MLDSA65_SECRET_CONTRIBUTION_BYTES + 1],
    };
    assert_eq!(
        PqcThresholdWireMsg::decode(&secret.encode()),
        Err(WireDecodeError::PayloadTooLarge)
    );
}

#[test]
fn hazmat_mldsa65_contribution_payloads_round_trip() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(31).wrapping_add(9));
    let secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret");
    let shares =
        split_mldsa65_expanded_secret_key(secret.as_bytes(), 2, 3).expect("split secret key");

    let masking_seed = [0x41; MLDSA65_MU_BYTES];
    let masking = derive_mldsa65_masking_contribution_from_share(&shares[0], &masking_seed, 0)
        .expect("derive masking");
    let masking_payload = encode_mldsa65_masking_contribution(&masking);
    assert_eq!(
        decode_mldsa65_masking_contribution(&masking_payload).expect("decode masking"),
        masking
    );

    let challenge = [0x42; MLDSA65_CHALLENGE_BYTES];
    let secret_contribution = derive_mldsa65_secret_contribution_from_share(&shares[0], &challenge)
        .expect("derive secret contribution");
    let secret_payload = encode_mldsa65_secret_contribution(&secret_contribution);
    assert_eq!(
        decode_mldsa65_secret_contribution(&secret_payload).expect("decode secret contribution"),
        secret_contribution
    );
}

#[test]
fn hazmat_commitment_digests_bind_replay_context_and_payload() {
    let session_id = [0xC1; 32];
    let block_height = 70;
    let attempt = 2;
    let validator_index = 3;
    let payload = vec![0xAA, 0xBB, 0xCC];
    let challenge = [0xC2; MLDSA65_CHALLENGE_BYTES];

    let baseline_masking = masking_commitment_digest(
        &session_id,
        block_height,
        attempt,
        validator_index,
        &payload,
    );
    let mut different_session = session_id;
    different_session[0] ^= 0x01;
    assert_ne!(
        baseline_masking,
        masking_commitment_digest(
            &different_session,
            block_height,
            attempt,
            validator_index,
            &payload
        )
    );
    assert_ne!(
        baseline_masking,
        masking_commitment_digest(
            &session_id,
            block_height + 1,
            attempt,
            validator_index,
            &payload
        )
    );
    assert_ne!(
        baseline_masking,
        masking_commitment_digest(
            &session_id,
            block_height,
            attempt + 1,
            validator_index,
            &payload
        )
    );
    assert_ne!(
        baseline_masking,
        masking_commitment_digest(
            &session_id,
            block_height,
            attempt,
            validator_index + 1,
            &payload
        )
    );
    assert_ne!(
        baseline_masking,
        masking_commitment_digest(
            &session_id,
            block_height,
            attempt,
            validator_index,
            &[payload.as_slice(), &[0xDD]].concat()
        )
    );

    let baseline_secret = secret_commitment_digest(
        &session_id,
        block_height,
        attempt,
        validator_index,
        &challenge,
        &payload,
    );
    let mut different_challenge = challenge;
    different_challenge[0] ^= 0x01;
    assert_ne!(
        baseline_secret,
        secret_commitment_digest(
            &session_id,
            block_height,
            attempt,
            validator_index,
            &different_challenge,
            &payload
        )
    );
    assert_ne!(
        baseline_secret,
        secret_commitment_digest(
            &different_session,
            block_height,
            attempt,
            validator_index,
            &challenge,
            &payload
        )
    );
    assert_ne!(
        baseline_secret,
        secret_commitment_digest(
            &session_id,
            block_height + 1,
            attempt,
            validator_index,
            &challenge,
            &payload
        )
    );
    assert_ne!(
        baseline_secret,
        secret_commitment_digest(
            &session_id,
            block_height,
            attempt + 1,
            validator_index,
            &challenge,
            &payload
        )
    );
    assert_ne!(
        baseline_secret,
        secret_commitment_digest(
            &session_id,
            block_height,
            attempt,
            validator_index + 1,
            &challenge,
            &payload
        )
    );
    assert_ne!(
        baseline_secret,
        secret_commitment_digest(
            &session_id,
            block_height,
            attempt,
            validator_index,
            &challenge,
            &[payload.as_slice(), &[0xDD]].concat()
        )
    );
}

#[test]
fn hazmat_actor_session_accepts_real_wire_contributions_and_finalizes() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(47).wrapping_add(25));
    let secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret key");
    let public_key = ThresholdPublicKey(
        *derive_mldsa65_public_key_from_expanded_secret_key(secret.as_bytes())
            .expect("derive public key")
            .as_bytes(),
    );
    let shares = split_mldsa65_expanded_secret_key(secret.as_bytes(), 3, 5)
        .expect("split expanded secret key");
    let active_shares = [&shares[0], &shares[2], &shares[4]];
    let mu = [0xD1u8; MLDSA65_MU_BYTES];

    let mut accepted = None;
    for attempt_id in 0..64u8 {
        let session_id = [attempt_id; 32];
        let block_height = 99;
        let mut actor_session = HazmatMldsa65ActorSession::new(
            session_id,
            block_height,
            3,
            5,
            mu,
            Duration::from_secs(2),
        )
        .expect("create hazmat actor session");
        let masking_seed = [attempt_id; MLDSA65_MU_BYTES];
        let mut challenge = None;
        for share in active_shares {
            let contribution =
                derive_mldsa65_masking_contribution_from_share(share, &masking_seed, 0)
                    .expect("derive masking contribution");
            let frame = PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
                session_id,
                block_height,
                attempt: 0,
                validator_index: contribution.receiver_index(),
                payload: encode_mldsa65_masking_contribution(&contribution),
            };
            challenge = actor_session
                .submit_masking_wire_message(&frame)
                .expect("submit masking wire frame")
                .or(challenge);
        }
        let challenge = challenge.expect("masking quorum fixes challenge");

        for share in active_shares {
            let contribution = derive_mldsa65_secret_contribution_from_share(share, &challenge)
                .expect("derive secret contribution");
            let frame = PqcThresholdWireMsg::HazmatMldsa65SecretContribution {
                session_id,
                block_height,
                attempt: 0,
                validator_index: contribution.receiver_index(),
                challenge,
                payload: encode_mldsa65_secret_contribution(&contribution),
            };
            match actor_session.submit_secret_wire_message(&frame) {
                Ok(Some((height, signature))) => {
                    assert_eq!(height, block_height);
                    accepted = Some(signature);
                    break;
                }
                Ok(None) => {}
                Err(dytallix_pq_threshold::ThresholdError::RejectionSamplingFailed { .. }) => break,
                Err(err) => panic!("unexpected actor wire error: {err:?}"),
            }
        }
        if accepted.is_some() {
            break;
        }
    }

    let signature = accepted.expect("one actor wire retry should pass");
    assert_eq!(signature.len(), MLDSA65_SIGNATURE_BYTES);
    let signature = ThresholdSignature(signature.try_into().expect("standard signature length"));
    assert!(verify_mldsa65_internal_mu(&public_key, &mu, &signature)
        .expect("standard internal-mu verification should run"));
}

#[test]
fn hazmat_actor_session_rejects_out_of_range_contribution_index() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(13).wrapping_add(7));
    let secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret");
    let shares =
        split_mldsa65_expanded_secret_key(secret.as_bytes(), 2, 3).expect("split secret key");
    let mut contribution =
        derive_mldsa65_masking_contribution_from_share(&shares[0], &[0x21; MLDSA65_MU_BYTES], 0)
            .expect("derive masking");
    let mut payload = encode_mldsa65_masking_contribution(&contribution);
    payload[0] = 0;
    payload[1] = 0;

    let mut actor_session = HazmatMldsa65ActorSession::new(
        [0xB1; 32],
        10,
        2,
        3,
        [0xB2; MLDSA65_MU_BYTES],
        Duration::from_secs(2),
    )
    .expect("create actor session");
    let frame = PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
        session_id: [0xB1; 32],
        block_height: 10,
        attempt: 0,
        validator_index: 0,
        payload,
    };

    let err = actor_session
        .submit_masking_wire_message(&frame)
        .expect_err("index zero must be rejected");
    assert!(matches!(
        err,
        ThresholdError::UnknownValidator {
            validator: ValidatorId(0)
        }
    ));

    contribution =
        derive_mldsa65_masking_contribution_from_share(&shares[0], &[0x22; MLDSA65_MU_BYTES], 0)
            .expect("derive masking");
    let mut payload = encode_mldsa65_masking_contribution(&contribution);
    payload[0] = 0;
    payload[1] = 4;
    let frame = PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
        session_id: [0xB1; 32],
        block_height: 10,
        attempt: 0,
        validator_index: 4,
        payload,
    };
    let err = actor_session
        .submit_masking_wire_message(&frame)
        .expect_err("index above total nodes must be rejected");
    assert!(matches!(
        err,
        ThresholdError::UnknownValidator {
            validator: ValidatorId(4)
        }
    ));
}

#[test]
fn hazmat_actor_session_rejects_masking_payload_with_inconsistent_w() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(17).wrapping_add(3));
    let secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret");
    let shares =
        split_mldsa65_expanded_secret_key(secret.as_bytes(), 2, 3).expect("split secret key");
    let contribution =
        derive_mldsa65_masking_contribution_from_share(&shares[0], &[0x31; MLDSA65_MU_BYTES], 0)
            .expect("derive masking");
    let mut payload = encode_mldsa65_masking_contribution(&contribution);
    let last = payload.last_mut().expect("payload is non-empty");
    *last ^= 0x01;

    let mut actor_session = HazmatMldsa65ActorSession::new(
        [0xC1; 32],
        11,
        2,
        3,
        [0xC2; MLDSA65_MU_BYTES],
        Duration::from_secs(2),
    )
    .expect("create actor session");
    let frame = PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
        session_id: [0xC1; 32],
        block_height: 11,
        attempt: 0,
        validator_index: contribution.receiver_index(),
        payload,
    };

    let err = actor_session
        .submit_masking_wire_message(&frame)
        .expect_err("tampered w must be rejected");
    assert!(matches!(
        err,
        ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(1)
        }
    ));
}

#[tokio::test]
async fn threshold_actor_routes_hazmat_mldsa65_wire_flow_to_consensus() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(19).wrapping_add(5));
    let secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret");
    let public_key = ThresholdPublicKey(
        *derive_mldsa65_public_key_from_expanded_secret_key(secret.as_bytes())
            .expect("derive public key")
            .as_bytes(),
    );
    let shares =
        split_mldsa65_expanded_secret_key(secret.as_bytes(), 2, 3).expect("split secret key");
    let network = RecordingNetwork::default();
    let consensus = RecordingConsensus::default();
    let (tx, rx) = mpsc::channel(16);
    let config = ActorConfig::new(
        ValidatorId(1),
        vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)],
        2,
        public_key.clone(),
        PrivateKeyShare::new(ValidatorId(1), b"sim-share".to_vec()),
        Duration::from_secs(2),
        8,
    )
    .with_hazmat_mldsa65_share(shares[0].clone());
    let actor =
        ThresholdActor::new(config, network.clone(), consensus.clone(), rx).expect("actor config");
    let handle = tokio::spawn(actor.run());

    let session_id = [0xD1; 32];
    let block_height = 12;
    let mu = [0xD2; MLDSA65_MU_BYTES];
    let masking_seed = [0xD3; MLDSA65_MU_BYTES];

    tx.send(ActorEvent::TriggerHazmatMldsa65SigningRound {
        session_id,
        block_height,
        mu,
        masking_seed,
    })
    .await
    .unwrap();
    wait_for_broadcasts(&network, 2).await;

    let remote_masking =
        derive_mldsa65_masking_contribution_from_share(&shares[1], &masking_seed, 0)
            .expect("derive remote masking");
    let remote_masking_payload = encode_mldsa65_masking_contribution(&remote_masking);
    let remote_masking_digest = masking_commitment_digest(
        &session_id,
        block_height,
        0,
        remote_masking.receiver_index(),
        &remote_masking_payload,
    );
    tx.send(ActorEvent::IncomingNetworkMessage(
        PqcThresholdWireMsg::HazmatMldsa65MaskingCommitment {
            session_id,
            block_height,
            attempt: 0,
            validator_index: remote_masking.receiver_index(),
            commitment: remote_masking_digest,
        },
    ))
    .await
    .unwrap();
    tx.send(ActorEvent::IncomingNetworkMessage(
        PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
            session_id,
            block_height,
            attempt: 0,
            validator_index: remote_masking.receiver_index(),
            payload: remote_masking_payload,
        },
    ))
    .await
    .unwrap();
    wait_for_broadcasts(&network, 4).await;

    let challenge = network
        .broadcasts
        .lock()
        .unwrap()
        .iter()
        .find_map(|msg| {
            if let PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
                challenge,
                ..
            } = msg
            {
                Some(*challenge)
            } else {
                None
            }
        })
        .expect("actor should broadcast local secret contribution");
    let remote_secret = derive_mldsa65_secret_contribution_from_share(&shares[1], &challenge)
        .expect("derive remote secret");
    let remote_secret_payload = encode_mldsa65_secret_contribution(&remote_secret);
    let remote_secret_digest = secret_commitment_digest(
        &session_id,
        block_height,
        0,
        remote_secret.receiver_index(),
        &challenge,
        &remote_secret_payload,
    );
    tx.send(ActorEvent::IncomingNetworkMessage(
        PqcThresholdWireMsg::HazmatMldsa65SecretCommitment {
            session_id,
            block_height,
            attempt: 0,
            validator_index: remote_secret.receiver_index(),
            challenge,
            commitment: remote_secret_digest,
        },
    ))
    .await
    .unwrap();
    let remote_statement = ContributionStatement {
        session_id,
        block_height,
        attempt: 0,
        validator_index: remote_secret.receiver_index(),
        challenge,
        masking_commitment_digest: remote_masking_digest,
        secret_commitment_digest: remote_secret_digest,
        dkg_commitment_digest: shares[1].dkg_public_commitment_digest(),
    };
    let remote_proof = prove_contribution(
        &remote_statement,
        &ContributionWitness::from_payload(remote_secret_payload.clone()),
    )
    .expect("build remote proof-bound contribution proof");
    tx.send(ActorEvent::IncomingNetworkMessage(
        PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
            session_id,
            block_height,
            attempt: 0,
            validator_index: remote_secret.receiver_index(),
            challenge,
            masking_commitment_digest: remote_statement.masking_commitment_digest,
            secret_commitment_digest: remote_statement.secret_commitment_digest,
            dkg_commitment_digest: remote_statement.dkg_commitment_digest,
            production_statement_digest: production_contribution_statement_digest_from_scaffold(
                &remote_statement,
                2,
                3,
                &mu,
                &remote_secret_payload,
            )
            .expect("derive remote production statement digest"),
            proof: remote_proof,
            payload: remote_secret_payload,
        },
    ))
    .await
    .unwrap();

    wait_for_finalized(&consensus).await;
    drop(tx);
    handle.await.unwrap();

    let finalized = consensus.finalized.lock().unwrap();
    assert_eq!(finalized.len(), 1);
    assert_eq!(finalized[0].0, block_height);
    assert_eq!(finalized[0].1.len(), MLDSA65_SIGNATURE_BYTES);
    let signature = ThresholdSignature(finalized[0].1.clone().try_into().unwrap());
    assert!(verify_mldsa65_internal_mu(&public_key, &mu, &signature)
        .expect("standard verification should run"));
}

#[tokio::test]
async fn threshold_actor_does_not_slash_honest_rejection_sampling_abort() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(41).wrapping_add(19));
    let secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret");
    let public_key = ThresholdPublicKey(
        *derive_mldsa65_public_key_from_expanded_secret_key(secret.as_bytes())
            .expect("derive public key")
            .as_bytes(),
    );
    let shares =
        split_mldsa65_expanded_secret_key(secret.as_bytes(), 3, 5).expect("split secret key");
    let active_share_indices = [0usize, 2, 4];
    let mu = [0x66u8; MLDSA65_MU_BYTES];
    let masking_seed = (0..64u8)
        .map(|attempt| [attempt; MLDSA65_MU_BYTES])
        .find(|masking_seed| {
            let masking_contributions = active_share_indices
                .iter()
                .map(|index| {
                    derive_mldsa65_masking_contribution_from_share(&shares[*index], masking_seed, 0)
                        .expect("derive masking contribution")
                })
                .collect::<Vec<_>>();
            let aggregate = aggregate_mldsa65_masking_contributions(&masking_contributions)
                .expect("aggregate masking contributions");
            let challenge = derive_mldsa65_challenge_from_aggregated_masking(&mu, &aggregate);
            let secret_contributions = active_share_indices
                .iter()
                .map(|index| {
                    derive_mldsa65_secret_contribution_from_share(&shares[*index], &challenge)
                        .expect("derive secret contribution")
                })
                .collect::<Vec<_>>();
            let reconstructed =
                reconstruct_mldsa65_secret_contribution_from_shares(&secret_contributions)
                    .expect("reconstruct secret contribution");
            matches!(
                finalize_mldsa65_threshold_signature_attempt(&aggregate, &mu, &reconstructed),
                Err(ThresholdError::RejectionSamplingFailed { .. })
            )
        })
        .expect("deterministic masking retry should produce a rejection abort");

    let network = RecordingNetwork::default();
    let consensus = RecordingConsensus::default();
    let (tx, rx) = mpsc::channel(32);
    let config = ActorConfig::new(
        ValidatorId(1),
        vec![
            ValidatorId(1),
            ValidatorId(2),
            ValidatorId(3),
            ValidatorId(4),
            ValidatorId(5),
        ],
        3,
        public_key,
        PrivateKeyShare::new(ValidatorId(1), b"sim-share".to_vec()),
        Duration::from_secs(2),
        8,
    )
    .with_hazmat_mldsa65_share(shares[0].clone());
    let actor =
        ThresholdActor::new(config, network.clone(), consensus.clone(), rx).expect("actor config");
    let handle = tokio::spawn(actor.run());

    let session_id = [0xE1; 32];
    let block_height = 13;
    tx.send(ActorEvent::TriggerHazmatMldsa65SigningRound {
        session_id,
        block_height,
        mu,
        masking_seed,
    })
    .await
    .unwrap();
    wait_for_broadcasts(&network, 2).await;

    let mut remote_masking_digests = Vec::new();
    for share_index in [2usize, 4] {
        let remote_masking =
            derive_mldsa65_masking_contribution_from_share(&shares[share_index], &masking_seed, 0)
                .expect("derive remote masking");
        let remote_masking_payload = encode_mldsa65_masking_contribution(&remote_masking);
        let remote_masking_digest = masking_commitment_digest(
            &session_id,
            block_height,
            0,
            remote_masking.receiver_index(),
            &remote_masking_payload,
        );
        remote_masking_digests.push((
            share_index,
            remote_masking.receiver_index(),
            remote_masking_digest,
        ));
        tx.send(ActorEvent::IncomingNetworkMessage(
            PqcThresholdWireMsg::HazmatMldsa65MaskingCommitment {
                session_id,
                block_height,
                attempt: 0,
                validator_index: remote_masking.receiver_index(),
                commitment: remote_masking_digest,
            },
        ))
        .await
        .unwrap();
        tx.send(ActorEvent::IncomingNetworkMessage(
            PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
                session_id,
                block_height,
                attempt: 0,
                validator_index: remote_masking.receiver_index(),
                payload: remote_masking_payload,
            },
        ))
        .await
        .unwrap();
    }
    wait_for_broadcasts(&network, 4).await;

    let challenge = network
        .broadcasts
        .lock()
        .unwrap()
        .iter()
        .find_map(|msg| {
            if let PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
                challenge,
                ..
            } = msg
            {
                Some(*challenge)
            } else {
                None
            }
        })
        .expect("actor should broadcast local secret contribution");

    for (share_index, validator_index, masking_digest) in remote_masking_digests {
        let remote_secret =
            derive_mldsa65_secret_contribution_from_share(&shares[share_index], &challenge)
                .expect("derive remote secret");
        let remote_secret_payload = encode_mldsa65_secret_contribution(&remote_secret);
        let remote_secret_digest = secret_commitment_digest(
            &session_id,
            block_height,
            0,
            validator_index,
            &challenge,
            &remote_secret_payload,
        );
        tx.send(ActorEvent::IncomingNetworkMessage(
            PqcThresholdWireMsg::HazmatMldsa65SecretCommitment {
                session_id,
                block_height,
                attempt: 0,
                validator_index,
                challenge,
                commitment: remote_secret_digest,
            },
        ))
        .await
        .unwrap();
        let statement = ContributionStatement {
            session_id,
            block_height,
            attempt: 0,
            validator_index,
            challenge,
            masking_commitment_digest: masking_digest,
            secret_commitment_digest: remote_secret_digest,
            dkg_commitment_digest: shares[share_index].dkg_public_commitment_digest(),
        };
        let remote_proof = prove_contribution(
            &statement,
            &ContributionWitness::from_payload(remote_secret_payload.clone()),
        )
        .expect("build remote proof-bound contribution proof");
        tx.send(ActorEvent::IncomingNetworkMessage(
            PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
                session_id,
                block_height,
                attempt: 0,
                validator_index,
                challenge,
                masking_commitment_digest: statement.masking_commitment_digest,
                secret_commitment_digest: statement.secret_commitment_digest,
                dkg_commitment_digest: statement.dkg_commitment_digest,
                production_statement_digest:
                    production_contribution_statement_digest_from_scaffold(
                        &statement,
                        3,
                        5,
                        &mu,
                        &remote_secret_payload,
                    )
                    .expect("derive remote production statement digest"),
                proof: remote_proof,
                payload: remote_secret_payload,
            },
        ))
        .await
        .unwrap();
    }

    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    drop(tx);
    handle.await.unwrap();

    assert!(
        consensus.finalized.lock().unwrap().is_empty(),
        "rejected attempt must not finalize a signature"
    );
    assert!(
        consensus.evidence.lock().unwrap().is_empty(),
        "honest rejection-sampling aborts are retry events, not slashing evidence"
    );
}

#[cfg(feature = "experimental-vss")]
#[tokio::test]
async fn threshold_actor_attaches_experimental_vss_complaint_evidence_for_invalid_hazmat_share() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(23).wrapping_add(17));
    let secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret");
    let public_key = ThresholdPublicKey(
        *derive_mldsa65_public_key_from_expanded_secret_key(secret.as_bytes())
            .expect("derive public key")
            .as_bytes(),
    );
    let shares =
        split_mldsa65_expanded_secret_key(secret.as_bytes(), 2, 3).expect("split secret key");
    let network = RecordingNetwork::default();
    let consensus = RecordingConsensus::default();
    let (tx, rx) = mpsc::channel(16);
    let config = ActorConfig::new(
        ValidatorId(1),
        vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)],
        2,
        public_key,
        PrivateKeyShare::new(ValidatorId(1), b"sim-share".to_vec()),
        Duration::from_secs(2),
        8,
    )
    .with_hazmat_mldsa65_share(shares[0].clone());
    let actor =
        ThresholdActor::new(config, network.clone(), consensus.clone(), rx).expect("actor config");
    let handle = tokio::spawn(actor.run());

    let session_id = [0xE4; 32];
    let block_height = 33;
    let mu = [0xE5; MLDSA65_MU_BYTES];
    let masking_seed = [0xE6; MLDSA65_MU_BYTES];

    tx.send(ActorEvent::TriggerHazmatMldsa65SigningRound {
        session_id,
        block_height,
        mu,
        masking_seed,
    })
    .await
    .unwrap();
    wait_for_broadcasts(&network, 2).await;

    let remote_masking =
        derive_mldsa65_masking_contribution_from_share(&shares[1], &masking_seed, 0)
            .expect("derive remote masking");
    let remote_masking_payload = encode_mldsa65_masking_contribution(&remote_masking);
    tx.send(ActorEvent::IncomingNetworkMessage(
        PqcThresholdWireMsg::HazmatMldsa65MaskingCommitment {
            session_id,
            block_height,
            attempt: 0,
            validator_index: remote_masking.receiver_index(),
            commitment: [0xA7; 32],
        },
    ))
    .await
    .unwrap();
    tx.send(ActorEvent::IncomingNetworkMessage(
        PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
            session_id,
            block_height,
            attempt: 0,
            validator_index: remote_masking.receiver_index(),
            payload: remote_masking_payload,
        },
    ))
    .await
    .unwrap();

    wait_for_evidence(&consensus).await;
    drop(tx);
    handle.await.unwrap();

    let evidence = consensus.evidence.lock().unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].validator, ValidatorId(2));
    let complaint_bytes = evidence[0]
        .experimental_vss_complaint_evidence
        .as_deref()
        .expect("invalid hazmat share should carry experimental VSS complaint evidence bytes");
    let complaint = ExperimentalVssComplaintEvidence::from_canonical_bytes(complaint_bytes)
        .expect("actor should emit canonical experimental VSS complaint evidence");
    verify_experimental_vss_complaint_evidence(&complaint)
        .expect("actor complaint evidence should be structurally valid");
    assert_eq!(complaint.statement.dealer_index, 2);
    assert_eq!(complaint.opening.receiver_index, 2);
    let production_statement_digest = evidence[0]
        .production_vss_relation_statement_digest
        .expect("invalid hazmat share should carry production VSS relation statement digest");
    assert_ne!(production_statement_digest, [0; 32]);
}

async fn wait_for_broadcasts(network: &RecordingNetwork, count: usize) {
    for _ in 0..128 {
        if network.broadcasts.lock().unwrap().len() >= count {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("timed out waiting for {count} broadcasts");
}

async fn wait_for_finalized(consensus: &RecordingConsensus) {
    for _ in 0..128 {
        if !consensus.finalized.lock().unwrap().is_empty() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("timed out waiting for finalized signature");
}

#[cfg(feature = "experimental-vss")]
async fn wait_for_evidence(consensus: &RecordingConsensus) {
    for _ in 0..128 {
        if !consensus.evidence.lock().unwrap().is_empty() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("timed out waiting for evidence");
}

fn fixture_proof_bound_secret_wire_msg(payload: Vec<u8>) -> PqcThresholdWireMsg {
    let session_id = [0xF1; 32];
    let block_height = 0x0102_0304_0506_0708;
    let attempt = 0x090A;
    let validator_index = 0x0B0C;
    let challenge = [0xF2; MLDSA65_CHALLENGE_BYTES];
    let statement = fixture_contribution_statement(
        session_id,
        block_height,
        attempt,
        validator_index,
        challenge,
        &payload,
    );
    let proof = if payload.is_empty() {
        ContributionProof {
            payload_len: 0,
            payload_digest: [0; 32],
            proof_digest: [0; 32],
        }
    } else {
        prove_contribution(
            &statement,
            &ContributionWitness::from_payload(payload.clone()),
        )
        .expect("build contribution proof")
    };
    assert_eq!(proof.to_canonical_bytes().len(), CONTRIBUTION_PROOF_BYTES);

    PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
        session_id,
        block_height,
        attempt,
        validator_index,
        challenge,
        masking_commitment_digest: statement.masking_commitment_digest,
        secret_commitment_digest: statement.secret_commitment_digest,
        dkg_commitment_digest: statement.dkg_commitment_digest,
        production_statement_digest: [0xF3; 32],
        proof,
        payload,
    }
}

fn fixture_contribution_statement(
    session_id: [u8; 32],
    block_height: u64,
    attempt: u16,
    validator_index: u16,
    challenge: [u8; MLDSA65_CHALLENGE_BYTES],
    payload: &[u8],
) -> ContributionStatement {
    fixture_contribution_statement_with_dkg_digest(
        session_id,
        block_height,
        attempt,
        validator_index,
        challenge,
        payload,
        [0; 32],
    )
}

fn fixture_contribution_statement_with_dkg_digest(
    session_id: [u8; 32],
    block_height: u64,
    attempt: u16,
    validator_index: u16,
    challenge: [u8; MLDSA65_CHALLENGE_BYTES],
    payload: &[u8],
    dkg_commitment_digest: [u8; 32],
) -> ContributionStatement {
    ContributionStatement {
        session_id,
        block_height,
        attempt,
        validator_index,
        challenge,
        masking_commitment_digest: masking_commitment_digest(
            &session_id,
            block_height,
            attempt,
            validator_index,
            &[],
        ),
        secret_commitment_digest: secret_commitment_digest(
            &session_id,
            block_height,
            attempt,
            validator_index,
            &challenge,
            payload,
        ),
        dkg_commitment_digest,
    }
}
