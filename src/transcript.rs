//! Placeholder transcript API surface for a later implementation task.

/// Signing transcript interface reserved for the transcript task.
#[allow(private_bounds)]
pub trait SigningTranscript: sealed::Sealed {}

/// Canonical threshold signing transcript reserved for the transcript task.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ThresholdSigningTranscript;

impl SigningTranscript for ThresholdSigningTranscript {}

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::ThresholdSigningTranscript {}
}
