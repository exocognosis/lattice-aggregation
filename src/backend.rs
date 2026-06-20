//! Backend boundary for threshold ML-DSA-65 operations.
//!
//! The simulation backend is deterministic test machinery. It does not produce
//! real ML-DSA signatures and cannot verify standard ML-DSA signatures.

use core::fmt;

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use zeroize::Zeroize;

use crate::{
    collections::PartialShareSet,
    errors::ThresholdError,
    transcript::SigningTranscript,
    types::{
        Commitment, PartialSignatureShare, PrivateKeyShare, ThresholdPublicKey, ThresholdSignature,
        MLDSA65_SIGNATURE_BYTES,
    },
};

const COMMITMENT_LABEL: &[u8] = b"lattice-aggregation/threshold-mldsa65/simulated/commitment";
const PARTIAL_SIGNATURE_LABEL: &[u8] =
    b"lattice-aggregation/threshold-mldsa65/simulated/partial-signature";
const AGGREGATE_SIGNATURE_LABEL: &[u8] =
    b"lattice-aggregation/threshold-mldsa65/simulated/aggregate-signature";
const PARTIAL_SIGNATURE_BYTES: usize = 64;

/// Secret retained between simulated commitment derivation and partial signing.
pub struct SimulatedCommitmentSecret([u8; 32]);

impl SimulatedCommitmentSecret {
    fn zeroed() -> Self {
        Self([0u8; 32])
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn as_mut_bytes(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }
}

impl fmt::Debug for SimulatedCommitmentSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SimulatedCommitmentSecret")
            .field("redacted", &true)
            .finish()
    }
}

impl Zeroize for SimulatedCommitmentSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SimulatedCommitmentSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Backend contract for ML-DSA-65 threshold signing operations.
pub trait Mldsa65Backend {
    /// Error type returned by backend operations.
    type Error;

    /// Local key share consumed by the backend.
    type KeyShare;

    /// Secret retained between commitment derivation and partial signing.
    type CommitmentSecret;

    /// Derive a public commitment and retained local secret for one transcript.
    fn derive_commitment(
        key_share: &Self::KeyShare,
        transcript: &SigningTranscript,
    ) -> Result<(Commitment, Self::CommitmentSecret), Self::Error>;

    /// Produce a partial signature share for one transcript.
    fn partial_sign(
        share: &Self::KeyShare,
        secret: Self::CommitmentSecret,
        transcript: &SigningTranscript,
    ) -> Result<PartialSignatureShare, Self::Error>;

    /// Aggregate a canonical set of partial shares into threshold signature bytes.
    fn aggregate(
        public_key: &ThresholdPublicKey,
        transcript: &SigningTranscript,
        shares: PartialShareSet,
    ) -> Result<ThresholdSignature, Self::Error>;

    /// Verify a standard ML-DSA signature against a public key and message.
    fn verify_standard(
        public_key: &ThresholdPublicKey,
        message: &[u8],
        signature: &ThresholdSignature,
    ) -> Result<bool, Self::Error>;
}

/// Deterministic simulation backend for API and protocol tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SimulatedBackend;

impl Mldsa65Backend for SimulatedBackend {
    type Error = ThresholdError;
    type KeyShare = PrivateKeyShare;
    type CommitmentSecret = SimulatedCommitmentSecret;

    fn derive_commitment(
        key_share: &Self::KeyShare,
        transcript: &SigningTranscript,
    ) -> Result<(Commitment, Self::CommitmentSecret), Self::Error> {
        let mut hasher = Shake256::default();
        update_bytes(&mut hasher, COMMITMENT_LABEL);
        update_bytes(&mut hasher, key_share.secret());
        update_validator_id(&mut hasher, key_share.share_id);
        hasher.update(&transcript.challenge().0);

        let mut reader = hasher.finalize_xof();
        let mut commitment = [0u8; 32];
        let mut secret = SimulatedCommitmentSecret::zeroed();
        reader.read(&mut commitment);
        reader.read(secret.as_mut_bytes());

        Ok((Commitment(commitment), secret))
    }

    fn partial_sign(
        share: &Self::KeyShare,
        mut secret: Self::CommitmentSecret,
        transcript: &SigningTranscript,
    ) -> Result<PartialSignatureShare, Self::Error> {
        let mut hasher = Shake256::default();
        update_bytes(&mut hasher, PARTIAL_SIGNATURE_LABEL);
        hasher.update(secret.as_bytes());
        update_bytes(&mut hasher, share.secret());
        update_validator_id(&mut hasher, share.share_id);
        hasher.update(&transcript.challenge().0);

        let mut bytes = vec![0u8; PARTIAL_SIGNATURE_BYTES];
        hasher.finalize_xof().read(&mut bytes);
        secret.zeroize();

        Ok(PartialSignatureShare {
            signer: share.share_id,
            bytes,
        })
    }

    fn aggregate(
        public_key: &ThresholdPublicKey,
        transcript: &SigningTranscript,
        shares: PartialShareSet,
    ) -> Result<ThresholdSignature, Self::Error> {
        if public_key != transcript.public_key() {
            return Err(ThresholdError::TranscriptMismatch);
        }

        let mut hasher = Shake256::default();
        update_bytes(&mut hasher, AGGREGATE_SIGNATURE_LABEL);
        hasher.update(&public_key.0);
        update_bytes(&mut hasher, transcript.message());
        hasher.update(&transcript.challenge().0);
        for (validator, share) in shares.iter() {
            update_validator_id(&mut hasher, *validator);
            update_bytes(&mut hasher, &share.bytes);
        }

        let mut signature = [0u8; MLDSA65_SIGNATURE_BYTES];
        hasher.finalize_xof().read(&mut signature);

        Ok(ThresholdSignature(signature))
    }

    fn verify_standard(
        _public_key: &ThresholdPublicKey,
        _message: &[u8],
        _signature: &ThresholdSignature,
    ) -> Result<bool, Self::Error> {
        Err(ThresholdError::BackendUnavailable {
            reason: "simulation backend does not implement standard ML-DSA verification",
        })
    }
}

fn update_bytes(hasher: &mut Shake256, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn update_validator_id(hasher: &mut Shake256, validator: crate::types::ValidatorId) {
    hasher.update(&validator.0.to_be_bytes());
}
