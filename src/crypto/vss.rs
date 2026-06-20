//! Verifiable-secret-sharing arithmetic scaffold for polynomial shares.
//!
//! This module models Shamir-style polynomial evaluation over ML-DSA
//! coefficient polynomials. The masking coefficients are deterministic test
//! fixtures, not cryptographic randomness.

use crate::crypto::poly::{Poly, Q};

/// Point-evaluation share sent to one validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareContribution {
    /// Receiver validator index, using one-based epoch ordering.
    pub receiver_index: u16,
    /// Polynomial share `P(receiver_index)`.
    pub polynomial_share: Poly,
}

/// Evaluate a polynomial with `Poly` coefficients at integer point `x`.
///
/// Uses Horner's method over each coefficient lane:
/// `P(x) = c_0 + c_1*x + c_2*x^2 ... mod Q`.
pub fn evaluate_polynomial_at(coefficients: &[Poly], x: u16) -> Poly {
    let mut result = Poly::zero();
    let x_i64 = i64::from(x);
    let q_i64 = i64::from(Q);

    for poly_coeff in coefficients.iter().rev() {
        let mut scaled = Poly::zero();
        for (out, coeff) in scaled.coeffs.iter_mut().zip(result.coeffs.iter()) {
            let mut product = (i64::from(*coeff) * x_i64) % q_i64;
            if product < 0 {
                product += q_i64;
            }
            *out = product as i32;
        }
        result = scaled;
        result.add_assign(poly_coeff);
    }

    result
}

/// Split a secret polynomial into deterministic Shamir-style shares.
///
/// The upper polynomial coefficients are deterministic masks so tests can
/// validate algebraic plumbing. Production DKG must replace this with
/// cryptographically sampled coefficient polynomials and commitments.
pub fn split_secret_poly(
    secret: &Poly,
    threshold: u16,
    total_nodes: u16,
) -> Vec<ShareContribution> {
    let mut poly_coefficients = vec![*secret];

    for degree in 1..threshold {
        let mut mask = Poly::zero();
        for (index, coeff) in mask.coeffs.iter_mut().enumerate() {
            *coeff = (((index as i32) + i32::from(degree)) * 42) % Q;
        }
        poly_coefficients.push(mask);
    }

    let mut shares = Vec::with_capacity(usize::from(total_nodes));
    for receiver_index in 1..=total_nodes {
        shares.push(ShareContribution {
            receiver_index,
            polynomial_share: evaluate_polynomial_at(&poly_coefficients, receiver_index),
        });
    }

    shares
}

#[cfg(test)]
mod vss_academic_tests {
    use super::*;
    use crate::crypto::poly::N;

    #[test]
    fn test_secret_polynomial_sharing_evaluation() {
        let mut secret = Poly::zero();
        for (index, coeff) in secret.coeffs.iter_mut().enumerate() {
            *coeff = index as i32;
        }

        let threshold = 2;
        let total_nodes = 3;

        let shares = split_secret_poly(&secret, threshold, total_nodes);

        assert_eq!(shares.len(), 3);
        assert_eq!(shares[0].receiver_index, 1);
        assert_ne!(shares[0].polynomial_share.coeffs, secret.coeffs);
    }

    #[test]
    fn polynomial_evaluation_horner_matches_linear_case() {
        let constant = Poly::from_coeffs([3; N]);
        let slope = Poly::from_coeffs([7; N]);

        let evaluated = evaluate_polynomial_at(&[constant, slope], 5);

        assert_eq!(evaluated, Poly::from_coeffs([38; N]));
    }
}
