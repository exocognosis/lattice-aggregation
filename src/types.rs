//! Public opaque types and ML-DSA-65 constants.

use core::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// FIPS 204 ML-DSA-65 public key byte length.
pub const MLDSA65_PUBLICKEY_BYTES: usize = 1952;
/// FIPS 204 ML-DSA-65 signature byte length.
pub const MLDSA65_SIGNATURE_BYTES: usize = 3309;
/// FIPS 204 ML-DSA-65 expanded secret key byte length.
pub const MLDSA65_SECRETKEY_BYTES: usize = 4032;
/// Seed length used by polynomial commitment derivation.
pub const POLY_SEED_BYTES: usize = 32;
/// Session identifier byte length.
pub const SESSION_ID_BYTES: usize = 32;
/// Commitment digest byte length.
pub const COMMITMENT_BYTES: usize = 32;

/// Unique identity tag for a protocol session.
pub type SessionId = [u8; SESSION_ID_BYTES];

/// Stable validator identity inside one threshold validator set.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct ValidatorId(pub u16);

impl core::fmt::Display for ValidatorId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "validator {}", self.0)
    }
}

/// Joint public verification key for the threshold identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdPublicKey(pub [u8; MLDSA65_PUBLICKEY_BYTES]);

/// Standard-size ML-DSA-65 signature bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdSignature(pub [u8; MLDSA65_SIGNATURE_BYTES]);

/// Commitment to a validator's local masking contribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Commitment(pub [u8; COMMITMENT_BYTES]);

/// Transcript-derived challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Challenge(pub [u8; 32]);

/// Serialized partial signature share produced by one validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialSignatureShare {
    /// Validator that produced this partial share.
    pub signer: ValidatorId,
    /// Backend-defined share encoding.
    pub bytes: Vec<u8>,
}

/// Opaque local signing key share.
#[derive(Clone)]
pub struct PrivateKeyShare {
    /// Validator that owns this share.
    pub share_id: ValidatorId,
    /// Backend-owned secret material. The simulation backend uses deterministic bytes.
    pub(crate) secret: Vec<u8>,
}

impl PrivateKeyShare {
    /// Construct a key share for backend-owned secret bytes.
    pub fn new(share_id: ValidatorId, secret: Vec<u8>) -> Self {
        Self { share_id, secret }
    }

    /// Borrow backend-owned secret bytes.
    #[allow(dead_code)]
    pub(crate) fn secret(&self) -> &[u8] {
        &self.secret
    }
}

impl Drop for PrivateKeyShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for PrivateKeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKeyShare")
            .field("share_id", &self.share_id.to_string())
            .field("secret_len", &self.secret.len())
            .finish()
    }
}

impl Zeroize for PrivateKeyShare {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}
