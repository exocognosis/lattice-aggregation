//! Cryptographic scaffolding modules built on low-level arithmetic.
//!
//! These modules are research and simulation infrastructure. They do not
//! implement a complete threshold ML-DSA protocol.

/// Polynomial primitives used by crypto scaffolding.
pub mod poly {
    pub use crate::low_level::poly::{Poly, N, Q};
}

pub mod contribution_proof;
pub mod interpolation;
pub mod production_policy;
pub mod vss;
