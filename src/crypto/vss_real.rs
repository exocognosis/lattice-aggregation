//! Real verifiable secret sharing over the negacyclic ring `R_q`.
//!
//! This module implements Increment 1 of the real threshold key material
//! build-out (`docs/superpowers/plans/2026-07-10-real-threshold-key-material-vss.md`).
//! Unlike [`crate::crypto::vss`], the sharing polynomial's non-constant
//! coefficients are sampled with a SHAKE256-based CSPRNG expansion (not toy
//! deterministic masks), and each dealt share is *verifiable* against public
//! Feldman-style coefficient commitments `C_j = g * c_j`.
//!
//! ## What this provides
//!
//! - CSPRNG-seeded Shamir sharing of a secret ring element with degree
//!   `< threshold`.
//! - Homomorphic share verification: a receiver can check its share against the
//!   dealer's public commitments without learning the other coefficients.
//! - Reconstruction of the secret from any `threshold` verified shares.
//!
//! ## What this does NOT yet provide (claim boundary)
//!
//! The commitment map `c -> g * c` is **perfectly binding** relative to `g`
//! (which is invertible in `R_q` with overwhelming probability) but is **not
//! hiding**: it leaks `g * c_j`. A computationally hiding module-SIS
//! (Ajtai/BDLOP) commitment with selected parameters is Increment 2. This
//! module therefore does not close any hypothesis criterion, does not implement
//! encrypted per-receiver shares, complaints, or a malicious-secure DKG, and
//! makes no production threshold ML-DSA security claim.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::{
    crypto::{
        interpolation::reconstruct_secret_poly,
        poly::{Poly, N, Q},
    },
    errors::ThresholdError,
};

const UNIFORM_SAMPLE_LABEL: &[u8] = b"lattice-aggregation/vss-real/uniform-sample";
const COMMITMENT_GENERATOR_LABEL: &[u8] = b"lattice-aggregation/vss-real/commitment-generator";

/// Public Feldman-style coefficient commitments for one dealer polynomial.
///
/// Entry `j` is `C_j = g * c_j`, ordered from the constant term (`j = 0`, the
/// shared secret) upward. The number of entries equals the threshold `tau`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoefficientCommitments {
    commitments: Vec<Poly>,
}

impl CoefficientCommitments {
    /// Number of committed coefficients (equal to the threshold `tau`).
    pub fn len(&self) -> usize {
        self.commitments.len()
    }

    /// Return `true` when no coefficients are committed.
    pub fn is_empty(&self) -> bool {
        self.commitments.is_empty()
    }

    /// Iterate coefficient commitments from the constant term upward.
    pub fn iter(&self) -> impl Iterator<Item = &Poly> {
        self.commitments.iter()
    }
}

/// A secret share `P(receiver_index)` issued to one receiver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VssShare {
    /// One-based receiver index, used as the polynomial evaluation point.
    pub receiver_index: u16,
    /// Polynomial evaluation `P(receiver_index)` in `R_q`.
    pub value: Poly,
}

/// Return the public commitment generator `g`, derived deterministically from a
/// fixed domain-separated label.
///
/// `g` is a uniform `R_q` element and is invertible with overwhelming
/// probability, which is what makes the commitment map `c -> g * c` binding.
pub fn commitment_generator() -> Poly {
    sample_uniform_poly(COMMITMENT_GENERATOR_LABEL, 0)
}

/// Deal a secret ring element into `total_nodes` verifiable shares.
///
/// The constant term of the sharing polynomial is `secret`; the non-constant
/// coefficients `c_1..c_{threshold-1}` are sampled from `dealer_seed` via
/// SHAKE256 rejection sampling, giving a degree-`< threshold` polynomial. The
/// returned shares are the evaluations at receiver indices `1..=total_nodes`,
/// alongside the public Feldman-style commitments to every coefficient.
///
/// Returns [`ThresholdError::InvalidThresholdParameters`] when `threshold` is
/// zero or exceeds `total_nodes`.
pub fn deal_secret(
    secret: &Poly,
    threshold: u16,
    total_nodes: u16,
    dealer_seed: &[u8; 32],
    generator: &Poly,
) -> Result<(Vec<VssShare>, CoefficientCommitments), ThresholdError> {
    if threshold == 0 || total_nodes < threshold {
        return Err(ThresholdError::InvalidThresholdParameters {
            threshold,
            total_nodes,
        });
    }

    // Coefficient 0 is the shared secret; coefficients 1..threshold are
    // CSPRNG-sampled so the sharing polynomial has degree `< threshold`.
    let mut coefficients = Vec::with_capacity(usize::from(threshold));
    coefficients.push(secret.canonical());
    for degree in 1..threshold {
        coefficients.push(sample_uniform_poly(dealer_seed, u32::from(degree)));
    }

    let commitments = coefficients
        .iter()
        .map(|coeff| generator.mul(coeff))
        .collect();

    let mut shares = Vec::with_capacity(usize::from(total_nodes));
    for receiver_index in 1..=total_nodes {
        shares.push(VssShare {
            receiver_index,
            value: evaluate_poly(&coefficients, receiver_index),
        });
    }

    Ok((shares, CoefficientCommitments { commitments }))
}

/// Verify a share against the dealer's public coefficient commitments.
///
/// Checks the homomorphic Feldman relation `g * P(i) == sum_j C_j * i^j`. A
/// share that was tampered with (or issued for a different polynomial) fails
/// this check because `g` is invertible.
pub fn verify_share(
    share: &VssShare,
    commitments: &CoefficientCommitments,
    generator: &Poly,
) -> bool {
    let lhs = generator.mul(&share.value);

    let q = i64::from(Q);
    let point = i64::from(share.receiver_index);
    let mut power = 1i64; // point^0
    let mut rhs = Poly::zero();
    for commitment in commitments.iter() {
        rhs.add_assign(&commitment.scalar_mul(power));
        power = (power * point) % q;
    }

    lhs.canonical() == rhs.canonical()
}

/// Reconstruct the shared secret `P(0)` from a set of shares.
///
/// Reconstruction uses Lagrange interpolation at `x = 0` over the supplied
/// evaluation points. Callers should first verify each share with
/// [`verify_share`]; supplying at least `threshold` valid shares recovers the
/// dealt secret, while fewer shares interpolate a different value.
pub fn reconstruct(shares: &[VssShare]) -> Poly {
    let points: Vec<(u16, Poly)> = shares
        .iter()
        .map(|share| (share.receiver_index, share.value))
        .collect();
    reconstruct_secret_poly(&points)
}

/// Evaluate `P(x) = sum_j coefficients[j] * x^j` at integer point `x` via
/// Horner's method over the ring. Coefficients are assumed canonical.
fn evaluate_poly(coefficients: &[Poly], x: u16) -> Poly {
    let point = i64::from(x);
    let mut result = Poly::zero();
    for coeff in coefficients.iter().rev() {
        result = result.scalar_mul(point);
        result.add_assign(coeff);
    }
    result
}

/// Sample a uniform `R_q` element from a seed using SHAKE256 rejection
/// sampling: each coefficient is a 23-bit candidate accepted only when it is
/// below `Q` (FIPS 204 uniform-sampling style).
fn sample_uniform_poly(seed: &[u8], nonce: u32) -> Poly {
    let mut hasher = Shake256::default();
    absorb(&mut hasher, UNIFORM_SAMPLE_LABEL);
    absorb(&mut hasher, seed);
    hasher.update(&nonce.to_be_bytes());
    let mut reader = hasher.finalize_xof();

    let mut coeffs = [0i32; N];
    let mut filled = 0usize;
    let mut buf = [0u8; 3];
    while filled < N {
        reader.read(&mut buf);
        let candidate = (u32::from(buf[0]) | (u32::from(buf[1]) << 8) | (u32::from(buf[2]) << 16))
            & 0x007f_ffff;
        if (candidate as i32) < Q {
            coeffs[filled] = candidate as i32;
            filled += 1;
        }
    }
    Poly::from_coeffs(coeffs)
}

fn absorb(hasher: &mut Shake256, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod vss_real_tests {
    use super::*;

    fn secret_fixture() -> Poly {
        let mut coeffs = [0i32; N];
        for (index, coeff) in coeffs.iter_mut().enumerate() {
            *coeff = ((index as i32) * 12_345 + 678) % Q;
        }
        Poly::from_coeffs(coeffs)
    }

    #[test]
    fn deal_and_reconstruct_recovers_secret() {
        let generator = commitment_generator();
        let secret = secret_fixture();
        let (shares, _commitments) = deal_secret(&secret, 3, 5, &[7u8; 32], &generator).unwrap();

        let subset = [shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = reconstruct(&subset);
        assert_eq!(recovered.canonical().coeffs, secret.canonical().coeffs);
    }

    #[test]
    fn different_threshold_subsets_agree() {
        let generator = commitment_generator();
        let secret = secret_fixture();
        let (shares, _commitments) = deal_secret(&secret, 3, 6, &[9u8; 32], &generator).unwrap();

        let first = reconstruct(&[shares[0].clone(), shares[1].clone(), shares[2].clone()]);
        let second = reconstruct(&[shares[3].clone(), shares[4].clone(), shares[5].clone()]);
        assert_eq!(first.canonical().coeffs, second.canonical().coeffs);
    }

    #[test]
    fn valid_shares_verify() {
        let generator = commitment_generator();
        let secret = secret_fixture();
        let (shares, commitments) = deal_secret(&secret, 4, 7, &[3u8; 32], &generator).unwrap();
        for share in &shares {
            assert!(verify_share(share, &commitments, &generator));
        }
    }

    #[test]
    fn tampered_share_fails_verification() {
        let generator = commitment_generator();
        let secret = secret_fixture();
        let (mut shares, commitments) = deal_secret(&secret, 3, 5, &[1u8; 32], &generator).unwrap();

        shares[0].value.coeffs[0] = (shares[0].value.coeffs[0] + 1) % Q;
        assert!(!verify_share(&shares[0], &commitments, &generator));
    }

    #[test]
    fn sub_threshold_does_not_recover_secret() {
        let generator = commitment_generator();
        let secret = secret_fixture();
        let (shares, _commitments) = deal_secret(&secret, 3, 5, &[42u8; 32], &generator).unwrap();

        let recovered = reconstruct(&[shares[0].clone(), shares[1].clone()]);
        assert_ne!(recovered.canonical().coeffs, secret.canonical().coeffs);
    }

    #[test]
    fn rejects_invalid_parameters() {
        let generator = commitment_generator();
        let secret = secret_fixture();
        assert!(deal_secret(&secret, 0, 5, &[0u8; 32], &generator).is_err());
        assert!(deal_secret(&secret, 4, 3, &[0u8; 32], &generator).is_err());
    }
}
