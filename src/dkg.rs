//! Simulated DKG API surface.
//!
//! The simulation DKG is deterministic test machinery for exercising protocol
//! wiring. It does not implement verifiable secret sharing or a secure
//! distributed key generation protocol.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::{
    collections::ValidatedDkgShares,
    errors::ThresholdError,
    types::{Commitment, SessionId, ThresholdPublicKey, MLDSA65_PUBLICKEY_BYTES},
};

const DKG_COMMITMENT_LABEL: &[u8] =
    b"lattice-aggregation/threshold-mldsa65/simulated/dkg-commitment";
const DKG_PUBLIC_KEY_LABEL: &[u8] =
    b"lattice-aggregation/threshold-mldsa65/simulated/dkg-public-key";

/// Threshold key generation interface.
pub trait ThresholdKeyGeneration {
    /// Error returned by key generation operations.
    type Error;

    /// Generate a deterministic simulated share commitment for one session.
    fn generate_share_commitment(session: SessionId, nodes: u16)
        -> Result<Commitment, Self::Error>;

    /// Finalize a deterministic simulated threshold public key from verified shares.
    fn finalize_public_key(
        verified_shares: ValidatedDkgShares,
    ) -> Result<ThresholdPublicKey, Self::Error>;
}

/// Deterministic simulation DKG engine reserved for the DKG task.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SimulatedDkg;

impl ThresholdKeyGeneration for SimulatedDkg {
    type Error = ThresholdError;

    fn generate_share_commitment(
        session: SessionId,
        nodes: u16,
    ) -> Result<Commitment, Self::Error> {
        if nodes == 0 {
            return Err(ThresholdError::InvalidThresholdParameters {
                threshold: 1,
                total_nodes: nodes,
            });
        }

        let mut hasher = Shake256::default();
        update_bytes(&mut hasher, DKG_COMMITMENT_LABEL);
        hasher.update(&session);
        hasher.update(&nodes.to_be_bytes());

        let mut commitment = [0u8; 32];
        hasher.finalize_xof().read(&mut commitment);

        Ok(Commitment(commitment))
    }

    fn finalize_public_key(
        verified_shares: ValidatedDkgShares,
    ) -> Result<ThresholdPublicKey, Self::Error> {
        let mut hasher = Shake256::default();
        update_bytes(&mut hasher, DKG_PUBLIC_KEY_LABEL);
        hasher.update(&verified_shares.threshold().to_be_bytes());
        hasher.update(&(verified_shares.validators().len() as u16).to_be_bytes());
        for validator in verified_shares.validators() {
            hasher.update(&validator.0.to_be_bytes());
        }
        hasher.update(&(verified_shares.len() as u16).to_be_bytes());
        for (validator, commitment) in verified_shares.iter() {
            hasher.update(&validator.0.to_be_bytes());
            hasher.update(&commitment.0);
        }

        let mut public_key = [0u8; MLDSA65_PUBLICKEY_BYTES];
        hasher.finalize_xof().read(&mut public_key);

        Ok(ThresholdPublicKey(public_key))
    }
}

fn update_bytes(hasher: &mut Shake256, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}
