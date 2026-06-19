//! Standard ML-DSA-65 provider boundary.

use crate::{ThresholdError, ThresholdPublicKey, ThresholdSignature};

/// Standard ML-DSA-65 verification provider.
pub trait StandardMldsa65Provider {
    /// Verify a standard ML-DSA-65 signature.
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

/// Hazmat provider wrapper for the optional ML-DSA implementation.
#[cfg(feature = "hazmat-real-mldsa")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HazmatMldsa65Provider;

#[cfg(feature = "hazmat-real-mldsa")]
impl StandardMldsa65Provider for HazmatMldsa65Provider {
    fn verify(
        _public_key: &ThresholdPublicKey,
        _message: &[u8],
        _signature: &ThresholdSignature,
    ) -> Result<bool, ThresholdError> {
        Err(ThresholdError::BackendUnavailable {
            reason: "hazmat ML-DSA provider wrapper requires KAT-backed implementation",
        })
    }
}
