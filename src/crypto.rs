//! Cryptographic scaffolding modules built on low-level arithmetic.
//!
//! These modules are research and simulation infrastructure. They do not
//! implement a complete threshold ML-DSA protocol.

/// Polynomial primitives used by crypto scaffolding.
pub mod poly {
    pub use crate::low_level::poly::{Poly, N, Q};
}

pub mod feldman_vss;
pub mod interpolation;
pub mod vss;
pub mod vss_real;
