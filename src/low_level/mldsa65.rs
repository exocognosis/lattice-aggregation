//! Hazmat ML-DSA-65 internals gated behind `hazmat-real-mldsa`.
//!
//! This module captures the local FIPS 204 ML-DSA-65 parameter surface and
//! arithmetic boundary needed by threshold experiments. It is intentionally not
//! a complete signing or verification implementation yet; callers must treat
//! every item here as low-level cryptographic construction material.

use crate::{
    errors::ThresholdError,
    low_level::poly::{Poly, Q},
    types::{
        ThresholdPublicKey, ThresholdSignature, MLDSA65_PUBLICKEY_BYTES, MLDSA65_SIGNATURE_BYTES,
    },
};

/// ML-DSA-65 matrix row dimension `k`.
pub const MLDSA65_K: usize = 6;
/// ML-DSA-65 matrix column dimension `l`.
pub const MLDSA65_L: usize = 5;
/// ML-DSA-65 private key coefficient range parameter `eta`.
pub const MLDSA65_ETA: i32 = 4;
/// ML-DSA-65 challenge sparsity parameter `tau`.
pub const MLDSA65_TAU: i32 = 49;
/// ML-DSA-65 rejection-bound slack `beta = tau * eta`.
pub const MLDSA65_BETA: i32 = MLDSA65_TAU * MLDSA65_ETA;
/// ML-DSA-65 masking-vector range parameter `gamma_1`.
pub const MLDSA65_GAMMA1: i32 = 1 << 19;
/// ML-DSA-65 low-order rounding range parameter `gamma_2`.
pub const MLDSA65_GAMMA2: i32 = (Q - 1) / 32;
/// ML-DSA-65 hint weight bound `omega`.
pub const MLDSA65_OMEGA: usize = 55;
/// ML-DSA-65 secret key byte length.
pub const MLDSA65_SECRETKEY_BYTES: usize = 4032;

const HAZMAT_VERIFIER_UNAVAILABLE: &str =
    "hazmat-real-mldsa verifier requires FIPS 204 KAT-backed implementation";

/// Fixed-size byte wrapper for an ML-DSA-65 public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mldsa65PublicKeyBytes([u8; MLDSA65_PUBLICKEY_BYTES]);

impl Mldsa65PublicKeyBytes {
    /// Construct a public key byte wrapper from exactly-sized bytes.
    pub const fn new(bytes: [u8; MLDSA65_PUBLICKEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// Borrow the encoded public key bytes.
    pub fn as_bytes(&self) -> &[u8; MLDSA65_PUBLICKEY_BYTES] {
        &self.0
    }
}

impl From<Mldsa65PublicKeyBytes> for ThresholdPublicKey {
    fn from(value: Mldsa65PublicKeyBytes) -> Self {
        Self(value.0)
    }
}

/// Fixed-size byte wrapper for an ML-DSA-65 signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mldsa65SignatureBytes([u8; MLDSA65_SIGNATURE_BYTES]);

impl Mldsa65SignatureBytes {
    /// Construct a signature byte wrapper from exactly-sized bytes.
    pub const fn new(bytes: [u8; MLDSA65_SIGNATURE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Borrow the encoded signature bytes.
    pub fn as_bytes(&self) -> &[u8; MLDSA65_SIGNATURE_BYTES] {
        &self.0
    }
}

impl From<Mldsa65SignatureBytes> for ThresholdSignature {
    fn from(value: Mldsa65SignatureBytes) -> Self {
        Self(value.0)
    }
}

/// Fixed-length ML-DSA polynomial vector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolyVec<const LEN: usize> {
    polys: [Poly; LEN],
}

impl<const LEN: usize> PolyVec<LEN> {
    /// Return the zero polynomial vector.
    pub const fn zero() -> Self {
        Self {
            polys: [Poly::zero(); LEN],
        }
    }

    /// Construct a vector from raw polynomials.
    pub const fn from_polys(polys: [Poly; LEN]) -> Self {
        Self { polys }
    }

    /// Borrow the vector polynomials.
    pub fn polys(&self) -> &[Poly; LEN] {
        &self.polys
    }

    /// Borrow mutable vector polynomials.
    pub fn polys_mut(&mut self) -> &mut [Poly; LEN] {
        &mut self.polys
    }
}

impl<const LEN: usize> Default for PolyVec<LEN> {
    fn default() -> Self {
        Self::zero()
    }
}

/// ML-DSA-65 `k`-dimension polynomial vector.
pub type VectorK = PolyVec<MLDSA65_K>;
/// ML-DSA-65 `l`-dimension polynomial vector.
pub type VectorL = PolyVec<MLDSA65_L>;

/// Return a canonical representative in `[0, Q)` for a signed integer.
pub fn reduce_mod_q(value: i64) -> i32 {
    let modulus = Q as i64;
    let mut reduced = value % modulus;
    if reduced < 0 {
        reduced += modulus;
    }
    reduced as i32
}

/// Add two canonical field elements modulo `Q`.
pub fn add_mod_q(lhs: i32, rhs: i32) -> i32 {
    reduce_mod_q(lhs as i64 + rhs as i64)
}

/// Subtract two canonical field elements modulo `Q`.
pub fn sub_mod_q(lhs: i32, rhs: i32) -> i32 {
    reduce_mod_q(lhs as i64 - rhs as i64)
}

/// Multiply two canonical field elements modulo `Q`.
pub fn mul_mod_q(lhs: i32, rhs: i32) -> i32 {
    reduce_mod_q(lhs as i64 * rhs as i64)
}

/// Check that all polynomial coefficients are strictly below the given bound.
pub fn check_poly_bound(poly: &Poly, bound: i32) -> bool {
    poly.check_noise_bounds(bound)
}

/// Verify a standard ML-DSA-65 signature.
///
/// This function is a deliberate hard stop until the local implementation is
/// completed against FIPS 204 known-answer tests.
pub fn verify_standard_mldsa65(
    _public_key: &ThresholdPublicKey,
    _message: &[u8],
    _signature: &ThresholdSignature,
) -> Result<bool, ThresholdError> {
    Err(ThresholdError::BackendUnavailable {
        reason: HAZMAT_VERIFIER_UNAVAILABLE,
    })
}
