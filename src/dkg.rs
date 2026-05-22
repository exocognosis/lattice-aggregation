//! Placeholder DKG API surface for a later implementation task.

/// Threshold key generation interface reserved for the DKG task.
#[allow(private_bounds)]
pub trait ThresholdKeyGeneration: sealed::Sealed {}

/// Deterministic simulation DKG engine reserved for the DKG task.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SimulatedDkg;

impl ThresholdKeyGeneration for SimulatedDkg {}

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::SimulatedDkg {}
}
