//! Standard ML-DSA-65 provider boundary.

use crate::{ThresholdError, ThresholdPublicKey, ThresholdSignature};

#[cfg(feature = "hazmat-real-mldsa")]
use ml_dsa::{EncodedVerifyingKey, KeyInit, MlDsa65, Signature, VerifyingKey};

/// Standard ML-DSA-65 verification provider.
pub trait StandardMldsa65Provider {
    /// Verify a standard ML-DSA-65 signature over the original application message.
    ///
    /// The `message` argument is not a transcript-internal `mu` or prehash. A
    /// provider that verifies a prehashed representative must use a different
    /// boundary and cannot satisfy this trait.
    fn verify(
        public_key: &ThresholdPublicKey,
        message: &[u8],
        signature: &ThresholdSignature,
    ) -> Result<bool, ThresholdError>;
}

/// Fail-closed provider used when real ML-DSA is not enabled.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UnavailableMldsa65Provider;

impl StandardMldsa65Provider for UnavailableMldsa65Provider {
    fn verify(
        _public_key: &ThresholdPublicKey,
        _message: &[u8],
        _signature: &ThresholdSignature,
    ) -> Result<bool, ThresholdError> {
        Err(ThresholdError::BackendUnavailable {
            reason: "standard ML-DSA provider is not enabled",
        })
    }
}

/// Hazmat provider wrapper for optional ML-DSA-65 KAT and smoke compatibility checks.
#[cfg(feature = "hazmat-real-mldsa")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HazmatMldsa65Provider;

#[cfg(feature = "hazmat-real-mldsa")]
impl StandardMldsa65Provider for HazmatMldsa65Provider {
    fn verify(
        public_key: &ThresholdPublicKey,
        message: &[u8],
        signature: &ThresholdSignature,
    ) -> Result<bool, ThresholdError> {
        Self::verify_with_context(public_key, message, &[], signature)
    }
}

#[cfg(feature = "hazmat-real-mldsa")]
impl HazmatMldsa65Provider {
    /// Verify a standard ML-DSA-65 signature over an application message and
    /// FIPS 204 context string.
    pub fn verify_with_context(
        public_key: &ThresholdPublicKey,
        message: &[u8],
        context: &[u8],
        signature: &ThresholdSignature,
    ) -> Result<bool, ThresholdError> {
        let Some((verifying_key, signature)) = decode_verifier_inputs(public_key, signature) else {
            return Ok(false);
        };

        Ok(verifying_key.verify_with_context(message, context, &signature))
    }
}

#[cfg(feature = "hazmat-real-mldsa")]
fn decode_verifier_inputs(
    public_key: &ThresholdPublicKey,
    signature: &ThresholdSignature,
) -> Option<(VerifyingKey<MlDsa65>, Signature<MlDsa65>)> {
    let encoded_key = EncodedVerifyingKey::<MlDsa65>::try_from(public_key.0.as_slice()).ok()?;
    let signature = Signature::<MlDsa65>::try_from(signature.0.as_slice()).ok()?;

    Some((VerifyingKey::<MlDsa65>::new(&encoded_key), signature))
}
