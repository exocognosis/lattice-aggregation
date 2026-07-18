//! Encrypted, private-per-receiver custody for ML-DSA module-key shares.
//!
//! This module is the dealer/receiver seam around
//! [`crate::crypto::share_transport`]. Dealer-side code consumes a clear
//! [`SharedSecretKey`](crate::crypto::mldsa_module::SharedSecretKey), seals each
//! `s1` and `s2` component to its intended receiver, and emits a
//! [`CoordinatorCustodyBundle`]. That coordinator-visible bundle contains only
//! public context, public VSS commitments, digests, and authenticated
//! ciphertexts. A [`ReceiverShareVault`] opens only the envelope addressed to
//! its receiver and verifies every decrypted component against those public
//! commitments before retaining it.
//!
//! ## Security boundary
//!
//! This is an **in-process API and ciphertext-custody boundary**, not physical
//! isolation. It demonstrates that coordinator-facing Rust objects need not
//! contain plaintext shares and that a receiver can fail closed on replay,
//! wrong-receiver, wrong-session, tamper, and invalid-share inputs. It does not
//! prove that separate operating-system processes were used, that memory was
//! never copied, or that a production HSM protects the vault. The current
//! [`Shake256Transport`] is a pre-shared symmetric-key reference construction,
//! not ML-KEM, and provides neither key exchange nor forward secrecy. Dealer
//! code necessarily sees the clear shares it creates before this seam seals
//! and wipes its temporary serialization. Vault keys are scoped per
//! `(dealer, receiver)`, preventing one dealer from authenticating ciphertexts
//! as another under this interface, but there are no signed dealer frames or
//! non-repudiable complaints. Replay memory is in-process only; a production
//! receiver must persist accepted ceremony/dealer sequence state across restarts.
//!
//! A vault exposes one receiver's component share only through a scoped
//! callback. It has no reconstruction or complete-secret export operation.
//! Since this is an ordinary in-process Rust API, a malicious callback could
//! still copy the one receiver share it is given; process/HSM enforcement is a
//! later boundary.

use std::collections::{BTreeMap, BTreeSet};

use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{
    bdlop::{Commitment, CommitmentKey},
    mldsa_module::{ReceiverCustodyMaterial, SharedSecretKey, MODULE_K, MODULE_L},
    poly::{Poly, N, Q},
    share_transport::{ReceiverKey, SealedShare, ShareTransport},
    vss_bdlop::{self, HidingShare},
};

const CONTEXT_LABEL: &[u8] = b"lattice-aggregation/receiver-custody/context/v1";
const COMMITMENTS_LABEL: &[u8] = b"lattice-aggregation/receiver-custody/commitments/v1";
const ENVELOPE_LABEL: &[u8] = b"lattice-aggregation/receiver-custody/envelope/v1";
const BUNDLE_LABEL: &[u8] = b"lattice-aggregation/receiver-custody/bundle/v1";
const ASSOCIATED_DATA_LABEL: &[u8] = b"lattice-aggregation/receiver-custody/ad/v1";
const NONCE_LABEL: &[u8] = b"lattice-aggregation/receiver-custody/nonce/v1";
const PAYLOAD_VERSION: u8 = 1;

/// Public DKG context to which every encrypted share is bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustodyContext {
    session_id: [u8; 32],
    rho: [u8; 32],
    threshold: u16,
    total_nodes: u16,
}

impl CustodyContext {
    /// Construct a session binding for a public matrix and threshold profile.
    ///
    /// `session_id` remains caller supplied; constructing and authenticating a
    /// canonical epoch/validator-set transcript is a separate open obligation.
    pub fn new(
        session_id: [u8; 32],
        rho: [u8; 32],
        threshold: u16,
        total_nodes: u16,
    ) -> Result<Self, ReceiverCustodyError> {
        if threshold == 0 || total_nodes < threshold {
            return Err(ReceiverCustodyError::InvalidContext);
        }
        Ok(Self {
            session_id,
            rho,
            threshold,
            total_nodes,
        })
    }

    /// Session identifier bound into every ciphertext.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// ML-DSA public matrix seed bound into every ciphertext.
    pub const fn rho(&self) -> &[u8; 32] {
        &self.rho
    }

    /// DKG reconstruction threshold.
    pub const fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Number of receivers in the DKG.
    pub const fn total_nodes(&self) -> u16 {
        self.total_nodes
    }

    fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(CONTEXT_LABEL);
        hasher.update(self.session_id);
        hasher.update(self.rho);
        hasher.update(self.threshold.to_be_bytes());
        hasher.update(self.total_nodes.to_be_bytes());
        hasher.finalize().into()
    }
}

/// Dealer-side receiver address and its already-established transport key.
///
/// The key is an input assumption; this type does not perform key exchange.
pub struct ReceiverEndpoint {
    receiver_index: u16,
    key: ReceiverKey,
}

impl ReceiverEndpoint {
    /// Bind a one-based receiver index to its pre-shared transport key.
    pub fn new(receiver_index: u16, key: ReceiverKey) -> Self {
        Self {
            receiver_index,
            key,
        }
    }
}

/// Secret-key vector to which a component share belongs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentKind {
    /// An `s1` component.
    S1,
    /// An `s2` component.
    S2,
}

impl ComponentKind {
    const fn code(self) -> u8 {
        match self {
            Self::S1 => 1,
            Self::S2 => 2,
        }
    }
}

/// Public VSS commitments for every `s1` and `s2` component.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicShareCommitments {
    /// Per-component coefficient commitments for `s1`.
    pub s1: Vec<Vec<Commitment>>,
    /// Per-component coefficient commitments for `s2`.
    pub s2: Vec<Vec<Commitment>>,
}

impl PublicShareCommitments {
    /// Domain-separated digest binding the complete public commitment set.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(COMMITMENTS_LABEL);
        absorb_commitment_components(&mut hasher, &self.s1);
        absorb_commitment_components(&mut hasher, &self.s2);
        hasher.finalize().into()
    }

    fn validate_shape(&self, threshold: u16) -> bool {
        self.s1.len() == MODULE_L
            && self.s2.len() == MODULE_K
            && self
                .s1
                .iter()
                .chain(self.s2.iter())
                .all(|component| component.len() == usize::from(threshold))
    }

    fn component(&self, kind: ComponentKind, index: usize) -> Option<&[Commitment]> {
        match kind {
            ComponentKind::S1 => self.s1.get(index),
            ComponentKind::S2 => self.s2.get(index),
        }
        .map(Vec::as_slice)
    }
}

/// Authenticated ciphertexts addressed to one receiver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiverShareEnvelope {
    /// One-based receiver index; also authenticated as associated data.
    pub receiver_index: u16,
    /// One ciphertext for each `s1` component.
    pub sealed_s1: Vec<SealedShare>,
    /// One ciphertext for each `s2` component.
    pub sealed_s2: Vec<SealedShare>,
    /// Digest of the public commitments against which plaintext is verified.
    pub commitments_digest: [u8; 32],
    /// Digest binding this envelope's public metadata and ciphertexts.
    pub envelope_digest: [u8; 32],
}

impl ReceiverShareEnvelope {
    fn compute_digest(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(ENVELOPE_LABEL);
        hasher.update(self.receiver_index.to_be_bytes());
        hasher.update(self.commitments_digest);
        absorb_sealed_set(&mut hasher, &self.sealed_s1);
        absorb_sealed_set(&mut hasher, &self.sealed_s2);
        hasher.finalize().into()
    }
}

/// Dealer output safe for a coordinator to route and transcript-bind.
///
/// This type deliberately has no plaintext-share field or reconstruction API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorCustodyBundle {
    /// Public DKG/session context.
    pub context: CustodyContext,
    /// Dealer whose contribution was sealed.
    pub dealer_id: u16,
    /// Public VSS commitments used by receivers for local validation.
    pub public_commitments: PublicShareCommitments,
    /// One authenticated ciphertext envelope per receiver.
    pub envelopes: Vec<ReceiverShareEnvelope>,
    /// Digest binding context, dealer, commitments, and all ciphertexts.
    pub bundle_digest: [u8; 32],
}

impl CoordinatorCustodyBundle {
    /// Recompute the transcript digest from the bundle's current contents.
    pub fn compute_digest(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(BUNDLE_LABEL);
        hasher.update(self.context.digest());
        hasher.update(self.dealer_id.to_be_bytes());
        hasher.update(self.public_commitments.digest());
        hasher.update((self.envelopes.len() as u64).to_be_bytes());
        for envelope in &self.envelopes {
            hasher.update(envelope.compute_digest());
        }
        hasher.finalize().into()
    }
}

/// Fail-closed errors for dealer sealing and receiver import.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReceiverCustodyError {
    /// Threshold or validator count is invalid.
    #[error("invalid receiver-custody context")]
    InvalidContext,
    /// The clear sharing does not match the requested public context.
    #[error("shared-key parameters do not match receiver-custody context")]
    SharingContextMismatch,
    /// A receiver index is zero or outside the validator set.
    #[error("invalid receiver index {receiver_index}")]
    InvalidReceiver {
        /// Invalid one-based receiver index.
        receiver_index: u16,
    },
    /// A receiver endpoint or envelope appeared more than once.
    #[error("duplicate receiver index {receiver_index}")]
    DuplicateReceiver {
        /// Duplicated one-based receiver index.
        receiver_index: u16,
    },
    /// A required receiver endpoint or envelope is absent.
    #[error("missing receiver index {receiver_index}")]
    MissingReceiver {
        /// Missing one-based receiver index.
        receiver_index: u16,
    },
    /// Internal component and receiver dimensions are inconsistent.
    #[error("invalid clear-share layout")]
    InvalidShareLayout,
    /// The bundle belongs to another session, matrix, threshold, or validator set.
    #[error("receiver vault context mismatch")]
    ContextMismatch,
    /// The public commitment vectors have the wrong dimensions.
    #[error("invalid public commitment shape")]
    InvalidCommitmentShape,
    /// A public bundle digest failed to match its contents.
    #[error("coordinator bundle digest mismatch")]
    BundleDigestMismatch,
    /// An envelope digest failed to match its contents.
    #[error("receiver envelope digest mismatch")]
    EnvelopeDigestMismatch,
    /// The exact same authenticated envelope was already accepted.
    #[error("replayed receiver envelope")]
    ReplayDetected,
    /// Another contribution for the same dealer was already accepted.
    #[error("duplicate dealer contribution {dealer_id}")]
    DuplicateDealer {
        /// Dealer with an existing accepted contribution.
        dealer_id: u16,
    },
    /// No transport key is registered for this exact dealer/receiver pair.
    #[error("unknown transport key for dealer {dealer_id}")]
    UnknownDealerKey {
        /// Dealer whose receiver key was not registered.
        dealer_id: u16,
    },
    /// A transport key was already registered for this exact dealer/receiver pair.
    #[error("duplicate transport key for dealer {dealer_id}")]
    DuplicateDealerKey {
        /// Dealer whose receiver key was already registered.
        dealer_id: u16,
    },
    /// Authenticated decryption rejected the key, context, or ciphertext.
    #[error("receiver share authentication failed")]
    AuthenticationFailed,
    /// Decrypted bytes do not encode the expected component share.
    #[error("malformed receiver share plaintext")]
    MalformedPlaintext,
    /// A decrypted component failed its VSS relation.
    #[error("share verification failed for {kind:?} component {component_index}")]
    ShareVerificationFailed {
        /// Secret vector containing the rejected component.
        kind: ComponentKind,
        /// Zero-based component index.
        component_index: usize,
    },
    /// The requested dealer has not been imported.
    #[error("unknown dealer contribution {dealer_id}")]
    UnknownDealer {
        /// Requested dealer identifier.
        dealer_id: u16,
    },
    /// The requested component index is outside the module dimensions.
    #[error("unknown {kind:?} component {component_index}")]
    UnknownComponent {
        /// Requested secret vector.
        kind: ComponentKind,
        /// Requested zero-based component index.
        component_index: usize,
    },
    /// No dealer contributions are loaded, so there is nothing to aggregate.
    #[error("receiver vault has no dealer shares")]
    NoDealerShares,
}

/// Dealer-side sealing of one shared-key contribution into receiver ciphertexts.
///
/// `nonce_seed` must be fresh for this dealer and context. Reusing it with the
/// same receiver transport keys repeats `(key, nonce)` pairs and breaks the
/// reference stream construction's confidentiality. The function consumes the
/// clear sharing; its temporary plaintext encodings and the consumed share
/// arrays are zeroized.
pub fn seal_shared_secret_key<T: ShareTransport>(
    shared_key: SharedSecretKey,
    context: CustodyContext,
    dealer_id: u16,
    endpoints: Vec<ReceiverEndpoint>,
    nonce_seed: &[u8; 32],
    transport: &T,
) -> Result<CoordinatorCustodyBundle, ReceiverCustodyError> {
    let mut material = shared_key.into_receiver_custody_material();
    if material.threshold != context.threshold || material.total_nodes != context.total_nodes {
        return Err(ReceiverCustodyError::SharingContextMismatch);
    }
    validate_share_layout(&material)?;

    let mut keys = BTreeMap::new();
    for endpoint in endpoints {
        if !(1..=context.total_nodes).contains(&endpoint.receiver_index) {
            return Err(ReceiverCustodyError::InvalidReceiver {
                receiver_index: endpoint.receiver_index,
            });
        }
        if keys.insert(endpoint.receiver_index, endpoint.key).is_some() {
            return Err(ReceiverCustodyError::DuplicateReceiver {
                receiver_index: endpoint.receiver_index,
            });
        }
    }
    for receiver_index in 1..=context.total_nodes {
        if !keys.contains_key(&receiver_index) {
            return Err(ReceiverCustodyError::MissingReceiver { receiver_index });
        }
    }

    let public_commitments = PublicShareCommitments {
        s1: core::mem::take(&mut material.s1_commitments),
        s2: core::mem::take(&mut material.s2_commitments),
    };
    let commitments_digest = public_commitments.digest();
    let mut envelopes = Vec::with_capacity(usize::from(context.total_nodes));
    for receiver_index in 1..=context.total_nodes {
        let key = keys
            .remove(&receiver_index)
            .expect("complete receiver map was checked");
        let sealed_s1 = seal_components(
            &material.s1_shares,
            ComponentKind::S1,
            receiver_index,
            &context,
            dealer_id,
            commitments_digest,
            nonce_seed,
            &key,
            transport,
        )?;
        let sealed_s2 = seal_components(
            &material.s2_shares,
            ComponentKind::S2,
            receiver_index,
            &context,
            dealer_id,
            commitments_digest,
            nonce_seed,
            &key,
            transport,
        )?;
        let mut envelope = ReceiverShareEnvelope {
            receiver_index,
            sealed_s1,
            sealed_s2,
            commitments_digest,
            envelope_digest: [0; 32],
        };
        envelope.envelope_digest = envelope.compute_digest();
        envelopes.push(envelope);
    }

    let mut bundle = CoordinatorCustodyBundle {
        context,
        dealer_id,
        public_commitments,
        envelopes,
        bundle_digest: [0; 32],
    };
    bundle.bundle_digest = bundle.compute_digest();
    Ok(bundle)
}

/// In-process vault retaining only one receiver's validated component shares.
///
/// The vault is neither `Clone` nor plaintext-serializable and zeroizes retained
/// shares on drop. It deliberately provides no complete-secret reconstruction
/// method.
pub struct ReceiverShareVault<T> {
    context: CustodyContext,
    receiver_index: u16,
    dealer_keys: BTreeMap<u16, ReceiverKey>,
    transport: T,
    accepted_envelopes: BTreeSet<[u8; 32]>,
    dealer_material: BTreeMap<u16, ReceiverShareMaterial>,
}

impl<T: ShareTransport> ReceiverShareVault<T> {
    /// Create a receiver-pinned vault for one DKG context.
    pub fn new(
        context: CustodyContext,
        receiver_index: u16,
        dealer_id: u16,
        key: ReceiverKey,
        transport: T,
    ) -> Result<Self, ReceiverCustodyError> {
        if !(1..=context.total_nodes).contains(&receiver_index) {
            return Err(ReceiverCustodyError::InvalidReceiver { receiver_index });
        }
        let mut dealer_keys = BTreeMap::new();
        dealer_keys.insert(dealer_id, key);
        Ok(Self {
            context,
            receiver_index,
            dealer_keys,
            transport,
            accepted_envelopes: BTreeSet::new(),
            dealer_material: BTreeMap::new(),
        })
    }

    /// One-based receiver index pinned to this vault.
    pub const fn receiver_index(&self) -> u16 {
        self.receiver_index
    }

    /// Sorted dealer identifiers successfully imported into this vault.
    pub fn loaded_dealers(&self) -> Vec<u16> {
        self.dealer_material.keys().copied().collect()
    }

    /// Register the pre-shared transport key for another exact dealer/receiver
    /// pair before importing that dealer's contribution.
    ///
    /// A duplicate dealer id is rejected instead of replacing its key, so an
    /// attacker cannot silently change the expected origin-authentication key.
    pub fn add_dealer_key(
        &mut self,
        dealer_id: u16,
        key: ReceiverKey,
    ) -> Result<(), ReceiverCustodyError> {
        if self.dealer_keys.contains_key(&dealer_id) {
            return Err(ReceiverCustodyError::DuplicateDealerKey { dealer_id });
        }
        self.dealer_keys.insert(dealer_id, key);
        Ok(())
    }

    /// Authenticate, decrypt, and locally verify this receiver's envelope.
    pub fn import(
        &mut self,
        bundle: &CoordinatorCustodyBundle,
        commitment_key: &CommitmentKey,
    ) -> Result<(), ReceiverCustodyError> {
        if bundle.context != self.context {
            return Err(ReceiverCustodyError::ContextMismatch);
        }
        if !bundle
            .public_commitments
            .validate_shape(self.context.threshold)
        {
            return Err(ReceiverCustodyError::InvalidCommitmentShape);
        }
        if bundle.bundle_digest != bundle.compute_digest() {
            return Err(ReceiverCustodyError::BundleDigestMismatch);
        }
        validate_envelope_set(&bundle.envelopes, self.context.total_nodes)?;

        let mut matches = bundle
            .envelopes
            .iter()
            .filter(|envelope| envelope.receiver_index == self.receiver_index);
        let envelope = matches
            .next()
            .ok_or(ReceiverCustodyError::MissingReceiver {
                receiver_index: self.receiver_index,
            })?;
        if matches.next().is_some() {
            return Err(ReceiverCustodyError::DuplicateReceiver {
                receiver_index: self.receiver_index,
            });
        }
        if envelope.envelope_digest != envelope.compute_digest() {
            return Err(ReceiverCustodyError::EnvelopeDigestMismatch);
        }
        if envelope.commitments_digest != bundle.public_commitments.digest() {
            return Err(ReceiverCustodyError::EnvelopeDigestMismatch);
        }
        if self.accepted_envelopes.contains(&envelope.envelope_digest) {
            return Err(ReceiverCustodyError::ReplayDetected);
        }
        if self.dealer_material.contains_key(&bundle.dealer_id) {
            return Err(ReceiverCustodyError::DuplicateDealer {
                dealer_id: bundle.dealer_id,
            });
        }
        let dealer_key = self.dealer_keys.get(&bundle.dealer_id).ok_or(
            ReceiverCustodyError::UnknownDealerKey {
                dealer_id: bundle.dealer_id,
            },
        )?;

        let mut material = ReceiverShareMaterial::default();
        open_components(
            &self.transport,
            dealer_key,
            &self.context,
            bundle.dealer_id,
            self.receiver_index,
            ComponentKind::S1,
            &envelope.sealed_s1,
            &bundle.public_commitments,
            commitment_key,
            &mut material.s1,
        )?;
        open_components(
            &self.transport,
            dealer_key,
            &self.context,
            bundle.dealer_id,
            self.receiver_index,
            ComponentKind::S2,
            &envelope.sealed_s2,
            &bundle.public_commitments,
            commitment_key,
            &mut material.s2,
        )?;

        self.accepted_envelopes.insert(envelope.envelope_digest);
        self.dealer_material.insert(bundle.dealer_id, material);
        Ok(())
    }

    /// Use one locally validated component share without exporting a key object.
    pub fn with_component_share<R>(
        &self,
        dealer_id: u16,
        kind: ComponentKind,
        component_index: usize,
        operation: impl FnOnce(&HidingShare) -> R,
    ) -> Result<R, ReceiverCustodyError> {
        let material = self
            .dealer_material
            .get(&dealer_id)
            .ok_or(ReceiverCustodyError::UnknownDealer { dealer_id })?;
        let share = material.component(kind, component_index).ok_or(
            ReceiverCustodyError::UnknownComponent {
                kind,
                component_index,
            },
        )?;
        Ok(operation(share))
    }

    /// Use the component-wise sum of all accepted dealer shares.
    ///
    /// The temporary aggregate is zeroized immediately after the callback. It
    /// remains one receiver's threshold share, never a reconstructed secret.
    pub fn with_aggregated_component_share<R>(
        &self,
        kind: ComponentKind,
        component_index: usize,
        operation: impl FnOnce(&HidingShare) -> R,
    ) -> Result<R, ReceiverCustodyError> {
        let mut materials = self.dealer_material.values();
        let first = materials
            .next()
            .ok_or(ReceiverCustodyError::NoDealerShares)?;
        let first_share = first.component(kind, component_index).ok_or(
            ReceiverCustodyError::UnknownComponent {
                kind,
                component_index,
            },
        )?;
        let mut aggregate = EphemeralShare(first_share.clone());
        for material in materials {
            let share = material.component(kind, component_index).ok_or(
                ReceiverCustodyError::UnknownComponent {
                    kind,
                    component_index,
                },
            )?;
            aggregate.0.value.add_assign(&share.value);
            for (sum, addend) in aggregate
                .0
                .randomness
                .iter_mut()
                .zip(share.randomness.iter())
            {
                sum.add_assign(addend);
            }
        }
        Ok(operation(&aggregate.0))
    }
}

impl<T> core::fmt::Debug for ReceiverShareVault<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReceiverShareVault")
            .field("context", &self.context)
            .field("receiver_index", &self.receiver_index)
            .field("authorized_dealers", &self.dealer_keys.keys())
            .field("loaded_dealers", &self.dealer_material.keys())
            .field("secret_material", &"REDACTED")
            .finish()
    }
}

fn validate_envelope_set(
    envelopes: &[ReceiverShareEnvelope],
    total_nodes: u16,
) -> Result<(), ReceiverCustodyError> {
    let mut seen = BTreeSet::new();
    for envelope in envelopes {
        if !(1..=total_nodes).contains(&envelope.receiver_index) {
            return Err(ReceiverCustodyError::InvalidReceiver {
                receiver_index: envelope.receiver_index,
            });
        }
        if !seen.insert(envelope.receiver_index) {
            return Err(ReceiverCustodyError::DuplicateReceiver {
                receiver_index: envelope.receiver_index,
            });
        }
    }
    for receiver_index in 1..=total_nodes {
        if !seen.contains(&receiver_index) {
            return Err(ReceiverCustodyError::MissingReceiver { receiver_index });
        }
    }
    Ok(())
}

#[derive(Default)]
struct ReceiverShareMaterial {
    s1: Vec<HidingShare>,
    s2: Vec<HidingShare>,
}

impl ReceiverShareMaterial {
    fn component(&self, kind: ComponentKind, index: usize) -> Option<&HidingShare> {
        match kind {
            ComponentKind::S1 => self.s1.get(index),
            ComponentKind::S2 => self.s2.get(index),
        }
    }
}

impl Drop for ReceiverShareMaterial {
    fn drop(&mut self) {
        zeroize_shares(&mut self.s1);
        zeroize_shares(&mut self.s2);
    }
}

struct EphemeralShare(HidingShare);

impl Drop for EphemeralShare {
    fn drop(&mut self) {
        zeroize_share(&mut self.0);
    }
}

#[allow(clippy::too_many_arguments)]
fn seal_components<T: ShareTransport>(
    components: &[Vec<HidingShare>],
    kind: ComponentKind,
    receiver_index: u16,
    context: &CustodyContext,
    dealer_id: u16,
    commitments_digest: [u8; 32],
    nonce_seed: &[u8; 32],
    key: &ReceiverKey,
    transport: &T,
) -> Result<Vec<SealedShare>, ReceiverCustodyError> {
    let mut sealed = Vec::with_capacity(components.len());
    for (component_index, receiver_shares) in components.iter().enumerate() {
        let share = receiver_shares
            .get(usize::from(receiver_index - 1))
            .ok_or(ReceiverCustodyError::InvalidShareLayout)?;
        if share.receiver_index != receiver_index {
            return Err(ReceiverCustodyError::InvalidShareLayout);
        }
        let plaintext = Zeroizing::new(encode_share(kind, component_index, share));
        let associated_data = associated_data(
            context,
            dealer_id,
            receiver_index,
            kind,
            component_index,
            commitments_digest,
        );
        let nonce = component_nonce(
            nonce_seed,
            context,
            dealer_id,
            receiver_index,
            kind,
            component_index,
        );
        sealed.push(transport.seal(key, &nonce, &associated_data, plaintext.as_slice()));
    }
    Ok(sealed)
}

#[allow(clippy::too_many_arguments)]
fn open_components<T: ShareTransport>(
    transport: &T,
    key: &ReceiverKey,
    context: &CustodyContext,
    dealer_id: u16,
    receiver_index: u16,
    kind: ComponentKind,
    sealed: &[SealedShare],
    commitments: &PublicShareCommitments,
    commitment_key: &CommitmentKey,
    output: &mut Vec<HidingShare>,
) -> Result<(), ReceiverCustodyError> {
    let expected_count = match kind {
        ComponentKind::S1 => MODULE_L,
        ComponentKind::S2 => MODULE_K,
    };
    if sealed.len() != expected_count {
        return Err(ReceiverCustodyError::InvalidShareLayout);
    }
    let commitments_digest = commitments.digest();
    for (component_index, ciphertext) in sealed.iter().enumerate() {
        let associated_data = associated_data(
            context,
            dealer_id,
            receiver_index,
            kind,
            component_index,
            commitments_digest,
        );
        let plaintext = Zeroizing::new(
            transport
                .open(key, &associated_data, ciphertext)
                .ok_or(ReceiverCustodyError::AuthenticationFailed)?,
        );
        let share = decode_share(kind, component_index, receiver_index, &plaintext)?;
        let component_commitments = commitments
            .component(kind, component_index)
            .ok_or(ReceiverCustodyError::InvalidCommitmentShape)?;
        if !vss_bdlop::verify_share(&share, component_commitments, commitment_key) {
            let mut rejected = share;
            zeroize_share(&mut rejected);
            return Err(ReceiverCustodyError::ShareVerificationFailed {
                kind,
                component_index,
            });
        }
        output.push(share);
    }
    Ok(())
}

fn validate_share_layout(material: &ReceiverCustodyMaterial) -> Result<(), ReceiverCustodyError> {
    if material.s1_shares.len() != MODULE_L
        || material.s2_shares.len() != MODULE_K
        || material.s1_commitments.len() != MODULE_L
        || material.s2_commitments.len() != MODULE_K
    {
        return Err(ReceiverCustodyError::InvalidShareLayout);
    }
    let receiver_count = usize::from(material.total_nodes);
    let commitment_count = usize::from(material.threshold);
    if material
        .s1_shares
        .iter()
        .chain(material.s2_shares.iter())
        .any(|shares| shares.len() != receiver_count)
        || material
            .s1_commitments
            .iter()
            .chain(material.s2_commitments.iter())
            .any(|commitments| commitments.len() != commitment_count)
    {
        return Err(ReceiverCustodyError::InvalidShareLayout);
    }
    Ok(())
}

fn encode_share(kind: ComponentKind, component_index: usize, share: &HidingShare) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + (1 + share.randomness.len()) * N * 4);
    bytes.push(PAYLOAD_VERSION);
    bytes.push(kind.code());
    bytes.extend_from_slice(&(component_index as u16).to_be_bytes());
    bytes.extend_from_slice(&share.receiver_index.to_be_bytes());
    absorb_poly_bytes(&mut bytes, &share.value);
    bytes.extend_from_slice(&(share.randomness.len() as u16).to_be_bytes());
    for randomness in &share.randomness {
        absorb_poly_bytes(&mut bytes, randomness);
    }
    bytes
}

fn decode_share(
    expected_kind: ComponentKind,
    expected_component: usize,
    expected_receiver: u16,
    bytes: &[u8],
) -> Result<HidingShare, ReceiverCustodyError> {
    let mut cursor = 0usize;
    if take_u8(bytes, &mut cursor)? != PAYLOAD_VERSION
        || take_u8(bytes, &mut cursor)? != expected_kind.code()
        || usize::from(take_u16(bytes, &mut cursor)?) != expected_component
        || take_u16(bytes, &mut cursor)? != expected_receiver
    {
        return Err(ReceiverCustodyError::MalformedPlaintext);
    }
    let mut decoded = DecodedShareGuard {
        value: take_poly(bytes, &mut cursor)?,
        randomness: Vec::new(),
    };
    let randomness_count = usize::from(take_u16(bytes, &mut cursor)?);
    if randomness_count != crate::crypto::bdlop::K {
        return Err(ReceiverCustodyError::MalformedPlaintext);
    }
    decoded.randomness.reserve(randomness_count);
    for _ in 0..randomness_count {
        decoded.randomness.push(take_poly(bytes, &mut cursor)?);
    }
    if cursor != bytes.len() {
        return Err(ReceiverCustodyError::MalformedPlaintext);
    }
    Ok(HidingShare {
        receiver_index: expected_receiver,
        value: decoded.value,
        randomness: core::mem::take(&mut decoded.randomness),
    })
}

/// Wipes successfully decoded fields if any later payload field is malformed.
struct DecodedShareGuard {
    value: Poly,
    randomness: Vec<Poly>,
}

impl Drop for DecodedShareGuard {
    fn drop(&mut self) {
        self.value.coeffs.zeroize();
        for randomness in &mut self.randomness {
            randomness.coeffs.zeroize();
        }
    }
}

fn take_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, ReceiverCustodyError> {
    let value = *bytes
        .get(*cursor)
        .ok_or(ReceiverCustodyError::MalformedPlaintext)?;
    *cursor += 1;
    Ok(value)
}

fn take_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, ReceiverCustodyError> {
    let end = cursor
        .checked_add(2)
        .ok_or(ReceiverCustodyError::MalformedPlaintext)?;
    let raw = bytes
        .get(*cursor..end)
        .ok_or(ReceiverCustodyError::MalformedPlaintext)?;
    *cursor = end;
    Ok(u16::from_be_bytes([raw[0], raw[1]]))
}

fn take_poly(bytes: &[u8], cursor: &mut usize) -> Result<Poly, ReceiverCustodyError> {
    let mut coefficients = Zeroizing::new([0i32; N]);
    for coefficient in coefficients.iter_mut() {
        let end = cursor
            .checked_add(4)
            .ok_or(ReceiverCustodyError::MalformedPlaintext)?;
        let raw = bytes
            .get(*cursor..end)
            .ok_or(ReceiverCustodyError::MalformedPlaintext)?;
        *cursor = end;
        let value = i32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        if !(0..Q).contains(&value) {
            return Err(ReceiverCustodyError::MalformedPlaintext);
        }
        *coefficient = value;
    }
    Ok(Poly::from_coeffs(*coefficients))
}

fn associated_data(
    context: &CustodyContext,
    dealer_id: u16,
    receiver_index: u16,
    kind: ComponentKind,
    component_index: usize,
    commitments_digest: [u8; 32],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(110);
    bytes.extend_from_slice(ASSOCIATED_DATA_LABEL);
    bytes.extend_from_slice(&context.digest());
    bytes.extend_from_slice(&dealer_id.to_be_bytes());
    bytes.extend_from_slice(&receiver_index.to_be_bytes());
    bytes.push(kind.code());
    bytes.extend_from_slice(&(component_index as u16).to_be_bytes());
    bytes.extend_from_slice(&commitments_digest);
    bytes
}

fn component_nonce(
    nonce_seed: &[u8; 32],
    context: &CustodyContext,
    dealer_id: u16,
    receiver_index: u16,
    kind: ComponentKind,
    component_index: usize,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(NONCE_LABEL);
    hasher.update(nonce_seed);
    hasher.update(context.digest());
    hasher.update(dealer_id.to_be_bytes());
    hasher.update(receiver_index.to_be_bytes());
    hasher.update([kind.code()]);
    hasher.update((component_index as u16).to_be_bytes());
    hasher.finalize().into()
}

fn absorb_poly_bytes(bytes: &mut Vec<u8>, poly: &Poly) {
    for coefficient in poly.canonical().coeffs {
        bytes.extend_from_slice(&coefficient.to_be_bytes());
    }
}

fn absorb_commitment_components(hasher: &mut Sha3_256, components: &[Vec<Commitment>]) {
    hasher.update((components.len() as u64).to_be_bytes());
    for component in components {
        hasher.update((component.len() as u64).to_be_bytes());
        for commitment in component {
            for poly in commitment.t1.iter().chain(core::iter::once(&commitment.t2)) {
                for coefficient in poly.canonical().coeffs {
                    hasher.update(coefficient.to_be_bytes());
                }
            }
        }
    }
}

fn absorb_sealed_set(hasher: &mut Sha3_256, sealed: &[SealedShare]) {
    hasher.update((sealed.len() as u64).to_be_bytes());
    for share in sealed {
        hasher.update((share.nonce.len() as u64).to_be_bytes());
        hasher.update(&share.nonce);
        hasher.update((share.ciphertext.len() as u64).to_be_bytes());
        hasher.update(&share.ciphertext);
        hasher.update(share.tag);
    }
}

fn zeroize_shares(shares: &mut [HidingShare]) {
    for share in shares {
        zeroize_share(share);
    }
}

fn zeroize_share(share: &mut HidingShare) {
    share.value.coeffs.zeroize();
    for randomness in &mut share.randomness {
        randomness.coeffs.zeroize();
    }
}
