//! Placeholder transcript API surface for a later implementation task.

/// Signing transcript interface reserved for the transcript task.
pub trait SigningTranscript {}

/// Canonical threshold signing transcript reserved for the transcript task.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ThresholdSigningTranscript;
