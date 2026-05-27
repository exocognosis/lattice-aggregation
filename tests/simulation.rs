use dytallix_pq_threshold::{
    adapter,
    adapter::actor::{ActorConfig, ActorEvent, ThresholdActor},
    adapter::evidence::{EvidenceKind, SlashingEvidence},
    adapter::traits::{ConsensusStateAdapter, P2pNetworkAdapter},
    adapter::wire::{
        PqcThresholdWireMsg, WireDecodeError, MAX_DKG_SHARE_BYTES, MAX_PARTIAL_SHARE_BYTES,
    },
    PrivateKeyShare, ThresholdPublicKey, ValidatorId, MLDSA65_SIGNATURE_BYTES,
};
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;

type FinalizedRecords = Arc<Mutex<Vec<(u64, Vec<u8>)>>>;
type EvidenceRecords = Arc<Mutex<Vec<SlashingEvidence>>>;
type GasUpdates = Arc<Mutex<Vec<u64>>>;

#[derive(Clone, Default)]
struct RecordingNetwork {
    broadcasts: Arc<Mutex<Vec<PqcThresholdWireMsg>>>,
    direct_sends: Arc<Mutex<Vec<(u16, PqcThresholdWireMsg)>>>,
}

#[async_trait::async_trait]
impl P2pNetworkAdapter for RecordingNetwork {
    type Error = Infallible;

    async fn broadcast(&self, msg: PqcThresholdWireMsg) -> Result<(), Self::Error> {
        self.broadcasts.lock().unwrap().push(msg);
        Ok(())
    }

    async fn send_to(&self, target: u16, msg: PqcThresholdWireMsg) -> Result<(), Self::Error> {
        self.direct_sends.lock().unwrap().push((target, msg));
        Ok(())
    }
}

#[derive(Clone, Default)]
struct RecordingConsensus {
    finalized: FinalizedRecords,
    evidence: EvidenceRecords,
    gas_updates: GasUpdates,
}

fn actor_config(max_sessions: usize) -> ActorConfig {
    actor_config_with_timeout(max_sessions, Duration::from_millis(50))
}

fn actor_config_with_timeout(max_sessions: usize, round_timeout: Duration) -> ActorConfig {
    ActorConfig::new(
        ValidatorId(1),
        vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)],
        2,
        ThresholdPublicKey([4; 1952]),
        PrivateKeyShare::new(ValidatorId(1), b"share-1".to_vec()),
        round_timeout,
        max_sessions,
    )
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

    async fn update_gas_baseline(&self, block_height: u64) -> Result<(), Self::Error> {
        self.gas_updates.lock().unwrap().push(block_height);
        Ok(())
    }
}

#[test]
fn adapter_module_is_exported() {
    let _ = core::any::type_name::<adapter::wire::PqcThresholdWireMsg>();
}

#[tokio::test]
async fn adapter_traits_can_be_mocked_in_memory() {
    let network = RecordingNetwork::default();
    let consensus = RecordingConsensus::default();
    let sign_commit = PqcThresholdWireMsg::SignCommit {
        session_id: [1; 32],
        block_height: 42,
        validator_index: 7,
        commitment: [2; 32],
    };
    let dkg_share = PqcThresholdWireMsg::DkgShareExchange {
        session_id: [3; 32],
        target_validator_index: 9,
        encrypted_share: vec![4, 5, 6],
    };
    let evidence = SlashingEvidence::new(
        [8; 32],
        ValidatorId(9),
        EvidenceKind::CommitmentWithoutPartial,
        Some(vec![0xAA]),
        "validator committed without partial",
    );

    network.broadcast(sign_commit.clone()).await.unwrap();
    network.send_to(9, dkg_share.clone()).await.unwrap();
    consensus
        .on_signature_finalized(42, vec![0x11, 0x22])
        .await
        .unwrap();
    consensus
        .submit_slashing_evidence(evidence.clone())
        .await
        .unwrap();
    consensus.update_gas_baseline(42).await.unwrap();

    assert_eq!(
        network.broadcasts.lock().unwrap().as_slice(),
        &[sign_commit]
    );
    assert_eq!(
        network.direct_sends.lock().unwrap().as_slice(),
        &[(9, dkg_share)]
    );
    assert_eq!(
        consensus.finalized.lock().unwrap().as_slice(),
        &[(42, vec![0x11, 0x22])]
    );
    assert_eq!(consensus.evidence.lock().unwrap().as_slice(), &[evidence]);
    assert_eq!(consensus.gas_updates.lock().unwrap().as_slice(), &[42]);
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

#[tokio::test]
async fn actor_rejects_sessions_past_capacity() {
    let (tx, rx) = mpsc::channel(8);
    let network = RecordingNetwork::default();
    let consensus = RecordingConsensus::default();
    let actor = ThresholdActor::new(actor_config(1), network.clone(), consensus.clone(), rx)
        .expect("actor config should be valid");

    assert_eq!(actor.active_session_count(), 0);
    let handle = tokio::spawn(actor.run());

    tx.send(ActorEvent::TriggerSigningRound {
        session_id: [1; 32],
        block_height: 1,
        message_hash: [9; 32],
    })
    .await
    .unwrap();
    tx.send(ActorEvent::TriggerSigningRound {
        session_id: [2; 32],
        block_height: 2,
        message_hash: [8; 32],
    })
    .await
    .unwrap();
    drop(tx);

    handle.await.unwrap();

    let broadcasts = network.broadcasts.lock().unwrap();
    let gas_updates = consensus.gas_updates.lock().unwrap();
    assert_eq!(broadcasts.len(), 1);
    assert_eq!(gas_updates.as_slice(), &[1]);
    assert!(matches!(
        &broadcasts[0],
        PqcThresholdWireMsg::SignCommit {
            session_id,
            block_height: 1,
            validator_index: 1,
            ..
        } if session_id == &[1; 32]
    ));
}

#[tokio::test]
async fn actor_finalizes_ideal_threshold_signature() {
    let (tx, rx) = mpsc::channel(8);
    let network = RecordingNetwork::default();
    let consensus = RecordingConsensus::default();
    let actor = ThresholdActor::new(
        actor_config_with_timeout(4, Duration::ZERO),
        network.clone(),
        consensus.clone(),
        rx,
    )
    .expect("actor config should be valid");
    let handle = tokio::spawn(actor.run());

    tx.send(ActorEvent::TriggerSigningRound {
        session_id: [3; 32],
        block_height: 44,
        message_hash: [0x44; 32],
    })
    .await
    .unwrap();
    tx.send(ActorEvent::IncomingNetworkMessage(
        PqcThresholdWireMsg::SignCommit {
            session_id: [3; 32],
            block_height: 44,
            validator_index: 2,
            commitment: [0x22; 32],
        },
    ))
    .await
    .unwrap();
    tx.send(ActorEvent::IncomingNetworkMessage(
        PqcThresholdWireMsg::PartialSignature {
            session_id: [3; 32],
            validator_index: 2,
            partial_sig_share: vec![0xAB; 64],
        },
    ))
    .await
    .unwrap();
    drop(tx);

    handle.await.unwrap();

    let finalized = consensus.finalized.lock().unwrap();
    assert_eq!(finalized.len(), 1);
    assert_eq!(finalized[0].0, 44);
    assert_eq!(finalized[0].1.len(), MLDSA65_SIGNATURE_BYTES);
}

#[tokio::test]
async fn actor_submits_evidence_for_poisoned_partial_share() {
    let (tx, rx) = mpsc::channel(8);
    let network = RecordingNetwork::default();
    let consensus = RecordingConsensus::default();
    let actor = ThresholdActor::new(
        actor_config_with_timeout(4, Duration::ZERO),
        network.clone(),
        consensus.clone(),
        rx,
    )
    .expect("actor config should be valid");
    let handle = tokio::spawn(actor.run());

    tx.send(ActorEvent::TriggerSigningRound {
        session_id: [4; 32],
        block_height: 45,
        message_hash: [0x45; 32],
    })
    .await
    .unwrap();
    tx.send(ActorEvent::IncomingNetworkMessage(
        PqcThresholdWireMsg::SignCommit {
            session_id: [4; 32],
            block_height: 45,
            validator_index: 2,
            commitment: [0x23; 32],
        },
    ))
    .await
    .unwrap();
    tx.send(ActorEvent::IncomingNetworkMessage(
        PqcThresholdWireMsg::PartialSignature {
            session_id: [4; 32],
            validator_index: 2,
            partial_sig_share: b"poison-share".to_vec(),
        },
    ))
    .await
    .unwrap();
    drop(tx);

    handle.await.unwrap();

    let evidence = consensus.evidence.lock().unwrap();
    assert!(evidence.iter().any(|record| {
        record.kind == EvidenceKind::InvalidPartialSignature
            && record.validator == ValidatorId(2)
            && record.session_id == [4; 32]
    }));
    assert!(consensus.finalized.lock().unwrap().is_empty());
}

#[tokio::test]
async fn actor_submits_liveness_evidence_for_commitment_without_partial() {
    let (tx, rx) = mpsc::channel(8);
    let network = RecordingNetwork::default();
    let consensus = RecordingConsensus::default();
    let actor = ThresholdActor::new(
        actor_config_with_timeout(4, Duration::ZERO),
        network.clone(),
        consensus.clone(),
        rx,
    )
    .expect("actor config should be valid");
    let handle = tokio::spawn(actor.run());

    tx.send(ActorEvent::TriggerSigningRound {
        session_id: [5; 32],
        block_height: 46,
        message_hash: [0x46; 32],
    })
    .await
    .unwrap();
    tx.send(ActorEvent::IncomingNetworkMessage(
        PqcThresholdWireMsg::SignCommit {
            session_id: [5; 32],
            block_height: 46,
            validator_index: 2,
            commitment: [0x24; 32],
        },
    ))
    .await
    .unwrap();
    while network.broadcasts.lock().unwrap().is_empty() {
        tokio::task::yield_now().await;
    }
    tx.send(ActorEvent::TimeoutCheck).await.unwrap();
    drop(tx);

    handle.await.unwrap();

    let evidence = consensus.evidence.lock().unwrap();
    assert!(evidence.iter().any(|record| {
        record.kind == EvidenceKind::CommitmentWithoutPartial
            && record.validator == ValidatorId(2)
            && record.session_id == [5; 32]
    }));
}
