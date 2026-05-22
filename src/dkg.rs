//! Placeholder DKG API surface for a later implementation task.

/// Threshold key generation interface reserved for the DKG task.
pub trait ThresholdKeyGeneration {}

/// Deterministic simulation DKG engine reserved for the DKG task.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SimulatedDkg;
