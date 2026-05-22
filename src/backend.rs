//! Placeholder backend API surface for a later implementation task.

/// ML-DSA-65 backend interface reserved for the backend task.
pub trait Mldsa65Backend {}

/// Deterministic simulation backend reserved for the backend task.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SimulatedBackend;
