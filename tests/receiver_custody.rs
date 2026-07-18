//! Adversarial contract tests for private per-receiver share custody.

use lattice_aggregation::crypto::{
    bdlop::CommitmentKey,
    mldsa_module::{deal_secret_key, sample_secret_key},
    receiver_custody::{
        seal_shared_secret_key, ComponentKind, CoordinatorCustodyBundle, CustodyContext,
        ReceiverCustodyError, ReceiverEndpoint, ReceiverShareVault,
    },
    share_transport::{ReceiverKey, Shake256Transport},
};

const DEALER_ID: u16 = 7;

struct Fixture {
    context: CustodyContext,
    commitment_key: CommitmentKey,
    receiver_keys: [ReceiverKey; 2],
    bundle: CoordinatorCustodyBundle,
}

fn fixture() -> Fixture {
    let context = CustodyContext::new([0x11; 32], [0x22; 32], 2, 2).unwrap();
    let commitment_key = CommitmentKey::from_seed(b"receiver-custody-public-commitment-key");
    let secret = sample_secret_key(&[0x33; 32]);
    let (shared_key, _proofs) = deal_secret_key(
        &secret,
        context.threshold(),
        context.total_nodes(),
        &[0x44; 32],
        &commitment_key,
    )
    .unwrap();
    let receiver_keys = [
        ReceiverKey::from_bytes([0x51; 32]),
        ReceiverKey::from_bytes([0x52; 32]),
    ];
    let endpoints = vec![
        ReceiverEndpoint::new(1, receiver_keys[0].clone()),
        ReceiverEndpoint::new(2, receiver_keys[1].clone()),
    ];
    let bundle = seal_shared_secret_key(
        shared_key,
        context,
        DEALER_ID,
        endpoints,
        &[0x61; 32],
        &Shake256Transport,
    )
    .unwrap();
    Fixture {
        context,
        commitment_key,
        receiver_keys,
        bundle,
    }
}

#[test]
fn coordinator_bundle_contains_ciphertexts_and_receiver_validates_only_its_share() {
    let fixture = fixture();
    assert_eq!(fixture.bundle.envelopes.len(), 2);
    assert!(fixture
        .bundle
        .envelopes
        .iter()
        .flat_map(|envelope| envelope.sealed_s1.iter().chain(&envelope.sealed_s2))
        .all(|sealed| !sealed.ciphertext.is_empty()));
    assert_eq!(
        fixture.bundle.bundle_digest,
        fixture.bundle.compute_digest()
    );

    let mut vault = ReceiverShareVault::new(
        fixture.context,
        1,
        DEALER_ID,
        fixture.receiver_keys[0].clone(),
        Shake256Transport,
    )
    .unwrap();
    vault
        .import(&fixture.bundle, &fixture.commitment_key)
        .unwrap();
    assert_eq!(vault.loaded_dealers(), vec![DEALER_ID]);
    let receiver = vault
        .with_component_share(DEALER_ID, ComponentKind::S1, 0, |share| {
            share.receiver_index
        })
        .unwrap();
    assert_eq!(receiver, 1);
}

#[test]
fn wrong_receiver_key_and_wrong_session_or_rho_fail_closed() {
    let fixture = fixture();
    let mut wrong_receiver_key = ReceiverShareVault::new(
        fixture.context,
        2,
        DEALER_ID,
        fixture.receiver_keys[0].clone(),
        Shake256Transport,
    )
    .unwrap();
    assert_eq!(
        wrong_receiver_key.import(&fixture.bundle, &fixture.commitment_key),
        Err(ReceiverCustodyError::AuthenticationFailed)
    );

    let forged_dealer_id = DEALER_ID + 1;
    let mut relabeled = fixture.bundle.clone();
    relabeled.dealer_id = forged_dealer_id;
    relabeled.bundle_digest = relabeled.compute_digest();
    let mut dealer_b_vault = ReceiverShareVault::new(
        fixture.context,
        1,
        forged_dealer_id,
        ReceiverKey::from_bytes([0xa2; 32]),
        Shake256Transport,
    )
    .unwrap();
    assert_eq!(
        dealer_b_vault.import(&relabeled, &fixture.commitment_key),
        Err(ReceiverCustodyError::AuthenticationFailed),
        "dealer A ciphertext must not authenticate under dealer B's receiver key"
    );
    assert_eq!(
        dealer_b_vault.add_dealer_key(forged_dealer_id, ReceiverKey::from_bytes([0xa3; 32]),),
        Err(ReceiverCustodyError::DuplicateDealerKey {
            dealer_id: forged_dealer_id,
        })
    );

    for wrong_context in [
        CustodyContext::new([0x12; 32], [0x22; 32], 2, 2).unwrap(),
        CustodyContext::new([0x11; 32], [0x23; 32], 2, 2).unwrap(),
    ] {
        let mut vault = ReceiverShareVault::new(
            wrong_context,
            1,
            DEALER_ID,
            fixture.receiver_keys[0].clone(),
            Shake256Transport,
        )
        .unwrap();
        assert_eq!(
            vault.import(&fixture.bundle, &fixture.commitment_key),
            Err(ReceiverCustodyError::ContextMismatch)
        );
    }
}

#[test]
fn ciphertext_tag_tamper_and_replay_are_rejected() {
    let fixture = fixture();
    let mut tampered_ciphertext = fixture.bundle.clone();
    tampered_ciphertext.envelopes[0].sealed_s1[0].ciphertext[0] ^= 1;
    let mut vault = ReceiverShareVault::new(
        fixture.context,
        1,
        DEALER_ID,
        fixture.receiver_keys[0].clone(),
        Shake256Transport,
    )
    .unwrap();
    assert_eq!(
        vault.import(&tampered_ciphertext, &fixture.commitment_key),
        Err(ReceiverCustodyError::BundleDigestMismatch)
    );

    let mut tampered_tag = fixture.bundle.clone();
    tampered_tag.envelopes[0].sealed_s2[0].tag[0] ^= 1;
    assert_eq!(
        vault.import(&tampered_tag, &fixture.commitment_key),
        Err(ReceiverCustodyError::BundleDigestMismatch)
    );

    vault
        .import(&fixture.bundle, &fixture.commitment_key)
        .unwrap();
    assert_eq!(
        vault.import(&fixture.bundle, &fixture.commitment_key),
        Err(ReceiverCustodyError::ReplayDetected)
    );
}

#[test]
fn dealer_sealing_rejects_duplicate_and_missing_receiver_endpoints() {
    let context = CustodyContext::new([0x71; 32], [0x72; 32], 2, 2).unwrap();
    let commitment_key = CommitmentKey::from_seed(b"duplicate-receiver-test");
    let secret = sample_secret_key(&[0x73; 32]);
    let make_shared = || {
        deal_secret_key(&secret, 2, 2, &[0x74; 32], &commitment_key)
            .unwrap()
            .0
    };

    let duplicate = vec![
        ReceiverEndpoint::new(1, ReceiverKey::from_bytes([0x75; 32])),
        ReceiverEndpoint::new(1, ReceiverKey::from_bytes([0x76; 32])),
    ];
    assert_eq!(
        seal_shared_secret_key(
            make_shared(),
            context,
            DEALER_ID,
            duplicate,
            &[0x77; 32],
            &Shake256Transport,
        ),
        Err(ReceiverCustodyError::DuplicateReceiver { receiver_index: 1 })
    );

    let missing = vec![ReceiverEndpoint::new(
        1,
        ReceiverKey::from_bytes([0x78; 32]),
    )];
    assert_eq!(
        seal_shared_secret_key(
            make_shared(),
            context,
            DEALER_ID,
            missing,
            &[0x79; 32],
            &Shake256Transport,
        ),
        Err(ReceiverCustodyError::MissingReceiver { receiver_index: 2 })
    );
}
