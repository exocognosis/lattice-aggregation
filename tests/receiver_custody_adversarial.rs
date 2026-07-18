use lattice_aggregation::crypto::{
    bdlop::CommitmentKey,
    mldsa_module::{deal_secret_key, sample_secret_key, SharedSecretKey},
    receiver_custody::{
        seal_shared_secret_key, ComponentKind, CoordinatorCustodyBundle, CustodyContext,
        ReceiverCustodyError, ReceiverEndpoint, ReceiverShareVault,
    },
    share_transport::{ReceiverKey, SealedShare, Shake256Transport, ShareTransport, KEY_BYTES},
};
use std::sync::OnceLock;

const THRESHOLD: u16 = 6;
const RECEIVERS: u16 = 8;
const DEALER_ID: u16 = 17;
const RECEIVER: u16 = 3;

#[test]
fn receiver_imports_only_its_verified_share_and_rejects_replay() {
    let (bundle, commitment_key, keys, context) = fixture();
    let mut vault = ReceiverShareVault::new(
        context,
        RECEIVER,
        DEALER_ID,
        keys[usize::from(RECEIVER - 1)].clone(),
        Shake256Transport,
    )
    .unwrap();

    vault
        .import(&bundle, &commitment_key)
        .expect("the addressed receiver must import every verified component");
    assert_eq!(vault.loaded_dealers(), vec![DEALER_ID]);
    assert_eq!(
        vault
            .with_component_share(DEALER_ID, ComponentKind::S1, 0, |share| {
                share.receiver_index
            })
            .unwrap(),
        RECEIVER
    );
    assert_eq!(
        vault
            .with_aggregated_component_share(ComponentKind::S2, 0, |share| { share.receiver_index })
            .unwrap(),
        RECEIVER
    );
    assert_eq!(
        vault.import(&bundle, &commitment_key),
        Err(ReceiverCustodyError::ReplayDetected)
    );

    let debug = format!("{vault:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("coeffs"));
}

#[test]
fn receiver_rejects_wrong_session_rho_key_and_dealer_rebinding() {
    let (bundle, commitment_key, keys, context) = fixture();
    let receiver_key = keys[usize::from(RECEIVER - 1)].clone();

    for wrong_context in [
        CustodyContext::new([0x72; 32], *context.rho(), THRESHOLD, RECEIVERS).unwrap(),
        CustodyContext::new(*context.session_id(), [0x73; 32], THRESHOLD, RECEIVERS).unwrap(),
    ] {
        let mut vault = ReceiverShareVault::new(
            wrong_context,
            RECEIVER,
            DEALER_ID,
            receiver_key.clone(),
            Shake256Transport,
        )
        .unwrap();
        assert_eq!(
            vault.import(&bundle, &commitment_key),
            Err(ReceiverCustodyError::ContextMismatch)
        );
    }

    let mut wrong_key_vault = ReceiverShareVault::new(
        context,
        RECEIVER,
        DEALER_ID,
        ReceiverKey::from_bytes([0xff; KEY_BYTES]),
        Shake256Transport,
    )
    .unwrap();
    assert_eq!(
        wrong_key_vault.import(&bundle, &commitment_key),
        Err(ReceiverCustodyError::AuthenticationFailed)
    );

    let mut rebound_dealer = bundle.clone();
    let forged_dealer_id = DEALER_ID + 1;
    rebound_dealer.dealer_id = forged_dealer_id;
    rebound_dealer.bundle_digest = rebound_dealer.compute_digest();
    let mut vault = ReceiverShareVault::new(
        context,
        RECEIVER,
        DEALER_ID,
        receiver_key,
        Shake256Transport,
    )
    .unwrap();
    assert_eq!(
        vault.import(&rebound_dealer, &commitment_key),
        Err(ReceiverCustodyError::UnknownDealerKey {
            dealer_id: forged_dealer_id,
        })
    );
    vault
        .add_dealer_key(forged_dealer_id, ReceiverKey::from_bytes([0xbe; KEY_BYTES]))
        .unwrap();
    assert_eq!(
        vault.import(&rebound_dealer, &commitment_key),
        Err(ReceiverCustodyError::AuthenticationFailed),
        "the dealer id must be authenticated as ciphertext associated data"
    );
}

#[test]
fn receiver_rejects_ciphertext_tag_missing_and_duplicate_envelope_tamper() {
    let (bundle, commitment_key, keys, context) = fixture();

    let mut ciphertext_tamper = bundle.clone();
    ciphertext_tamper.envelopes[usize::from(RECEIVER - 1)].sealed_s1[0].ciphertext[0] ^= 1;
    ciphertext_tamper.bundle_digest = ciphertext_tamper.compute_digest();
    assert_import_error(
        &ciphertext_tamper,
        &commitment_key,
        &keys,
        context,
        ReceiverCustodyError::EnvelopeDigestMismatch,
    );

    let mut tag_tamper = bundle.clone();
    tag_tamper.envelopes[usize::from(RECEIVER - 1)].sealed_s2[0].tag[0] ^= 1;
    tag_tamper.bundle_digest = tag_tamper.compute_digest();
    assert_import_error(
        &tag_tamper,
        &commitment_key,
        &keys,
        context,
        ReceiverCustodyError::EnvelopeDigestMismatch,
    );

    let mut duplicate = bundle.clone();
    duplicate
        .envelopes
        .push(duplicate.envelopes[usize::from(RECEIVER - 1)].clone());
    duplicate.bundle_digest = duplicate.compute_digest();
    assert_import_error(
        &duplicate,
        &commitment_key,
        &keys,
        context,
        ReceiverCustodyError::DuplicateReceiver {
            receiver_index: RECEIVER,
        },
    );

    let mut missing = bundle;
    missing
        .envelopes
        .retain(|envelope| envelope.receiver_index != RECEIVER);
    missing.bundle_digest = missing.compute_digest();
    assert_import_error(
        &missing,
        &commitment_key,
        &keys,
        context,
        ReceiverCustodyError::MissingReceiver {
            receiver_index: RECEIVER,
        },
    );
}

#[test]
fn receiver_rejects_authenticated_malformed_and_vss_invalid_plaintext() {
    let malformed_transport = MalformedOpenTransport;
    let (malformed_bundle, commitment_key, malformed_keys, context) = fixture();
    let mut malformed_vault = ReceiverShareVault::new(
        context,
        RECEIVER,
        DEALER_ID,
        malformed_keys[usize::from(RECEIVER - 1)].clone(),
        malformed_transport,
    )
    .unwrap();
    assert_eq!(
        malformed_vault.import(&malformed_bundle, &commitment_key),
        Err(ReceiverCustodyError::MalformedPlaintext)
    );

    let invalid_transport = InvalidShareOpenTransport;
    let (invalid_bundle, commitment_key, invalid_keys, context) = fixture();
    let mut invalid_vault = ReceiverShareVault::new(
        context,
        RECEIVER,
        DEALER_ID,
        invalid_keys[usize::from(RECEIVER - 1)].clone(),
        invalid_transport,
    )
    .unwrap();
    assert_eq!(
        invalid_vault.import(&invalid_bundle, &commitment_key),
        Err(ReceiverCustodyError::ShareVerificationFailed {
            kind: ComponentKind::S1,
            component_index: 0,
        })
    );
}

fn fixture() -> (
    CoordinatorCustodyBundle,
    CommitmentKey,
    Vec<ReceiverKey>,
    CustodyContext,
) {
    static FIXTURE: OnceLock<(
        CoordinatorCustodyBundle,
        CommitmentKey,
        Vec<ReceiverKey>,
        CustodyContext,
    )> = OnceLock::new();
    let (bundle, commitment_key, keys, context) = FIXTURE.get_or_init(|| {
        let context = custody_context();
        let commitment_key = CommitmentKey::from_seed(b"receiver-custody-test-commitment-key");
        let keys = receiver_keys();
        let bundle = seal_shared_secret_key(
            shared_key(&commitment_key),
            context,
            DEALER_ID,
            receiver_endpoints(&keys),
            &[0x90; 32],
            &Shake256Transport,
        )
        .expect("complete receiver set must seal");
        (bundle, commitment_key, keys, context)
    });
    (
        bundle.clone(),
        commitment_key.clone(),
        keys.clone(),
        *context,
    )
}

fn custody_context() -> CustodyContext {
    CustodyContext::new([0x70; 32], [0x71; 32], THRESHOLD, RECEIVERS).unwrap()
}

fn shared_key(commitment_key: &CommitmentKey) -> SharedSecretKey {
    let secret = sample_secret_key(&[0x74; 32]);
    deal_secret_key(&secret, THRESHOLD, RECEIVERS, &[0x75; 32], commitment_key)
        .expect("valid committee-8 sharing")
        .0
}

fn receiver_keys() -> Vec<ReceiverKey> {
    (1..=RECEIVERS)
        .map(|receiver| {
            ReceiverKey::from_channel_secret(b"receiver-custody-test-channel", receiver)
        })
        .collect()
}

fn receiver_endpoints(keys: &[ReceiverKey]) -> Vec<ReceiverEndpoint> {
    keys.iter()
        .enumerate()
        .map(|(index, key)| ReceiverEndpoint::new(index as u16 + 1, key.clone()))
        .collect()
}

fn assert_import_error(
    bundle: &CoordinatorCustodyBundle,
    commitment_key: &CommitmentKey,
    keys: &[ReceiverKey],
    context: CustodyContext,
    expected: ReceiverCustodyError,
) {
    let mut vault = ReceiverShareVault::new(
        context,
        RECEIVER,
        DEALER_ID,
        keys[usize::from(RECEIVER - 1)].clone(),
        Shake256Transport,
    )
    .unwrap();
    assert_eq!(vault.import(bundle, commitment_key), Err(expected));
}

#[derive(Clone, Copy, Debug)]
struct MalformedOpenTransport;

impl ShareTransport for MalformedOpenTransport {
    fn seal(
        &self,
        key: &ReceiverKey,
        nonce: &[u8],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> SealedShare {
        Shake256Transport.seal(key, nonce, associated_data, plaintext)
    }

    fn open(
        &self,
        _key: &ReceiverKey,
        _associated_data: &[u8],
        _sealed: &SealedShare,
    ) -> Option<Vec<u8>> {
        Some(vec![0])
    }
}

#[derive(Clone, Copy, Debug)]
struct InvalidShareOpenTransport;

impl ShareTransport for InvalidShareOpenTransport {
    fn seal(
        &self,
        key: &ReceiverKey,
        nonce: &[u8],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> SealedShare {
        Shake256Transport.seal(key, nonce, associated_data, plaintext)
    }

    fn open(
        &self,
        key: &ReceiverKey,
        associated_data: &[u8],
        sealed: &SealedShare,
    ) -> Option<Vec<u8>> {
        let mut plaintext = Shake256Transport.open(key, associated_data, sealed)?;
        let value = i32::from_be_bytes(plaintext[6..10].try_into().ok()?);
        plaintext[6..10].copy_from_slice(&(value + 1).rem_euclid(8_380_417).to_be_bytes());
        Some(plaintext)
    }
}
