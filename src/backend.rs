//! Placeholder backend API surface for a later implementation task.

/// ML-DSA-65 backend interface reserved for the backend task.
#[allow(private_bounds)]
pub trait Mldsa65Backend: sealed::Sealed {}

/// Deterministic simulation backend reserved for the backend task.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SimulatedBackend;

impl Mldsa65Backend for SimulatedBackend {}

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::SimulatedBackend {}
}
