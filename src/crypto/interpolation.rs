//! Lagrange interpolation scaffold for polynomial shares.
//!
//! The routines reconstruct coefficient-domain polynomial shares at `x = 0`
//! over the ML-DSA modulus. They are deterministic math plumbing for tests and
//! integration scaffolding, not an audited constant-time field implementation.

use crate::crypto::poly::{Poly, Q};

/// Calculate a modular inverse modulo `Q`.
///
/// The exponent is fixed at `Q - 2`, so the loop shape is independent of the
/// input value. This is still a scaffold and not a formal timing guarantee.
pub fn modular_inverse(base: i32) -> i32 {
    let mut result = 1i64;
    let mut factor = canonical_i64(base);
    let mut exponent = Q - 2;
    let q = i64::from(Q);

    while exponent > 0 {
        if exponent % 2 == 1 {
            result = (result * factor) % q;
        }
        factor = (factor * factor) % q;
        exponent /= 2;
    }

    result as i32
}

/// Compute the Lagrange coefficient at `x = 0` for `current_index`.
///
/// `lambda_i = PROD_{j != i} (x_j / (x_j - x_i)) mod Q`.
pub fn compute_lagrange_coefficient(active_indices: &[u16], current_index: u16) -> i32 {
    let mut numerator = 1i64;
    let mut denominator = 1i64;
    let current = i32::from(current_index);
    let q = i64::from(Q);

    for &index in active_indices {
        if index == current_index {
            continue;
        }

        let peer = i32::from(index);
        numerator = (numerator * i64::from(peer)) % q;
        denominator = (denominator * canonical_i64(peer - current)) % q;
    }

    let inverse = modular_inverse(denominator as i32);
    ((numerator * i64::from(inverse)) % q) as i32
}

/// Reconstruct the secret polynomial at `x = 0` from active shares.
pub fn reconstruct_secret_poly(active_shares: &[(u16, Poly)]) -> Poly {
    let active_indices = active_shares
        .iter()
        .map(|(index, _)| *index)
        .collect::<Vec<_>>();
    let mut master_poly = Poly::zero();
    let q = i64::from(Q);

    for (node_index, share_poly) in active_shares {
        let lambda = compute_lagrange_coefficient(&active_indices, *node_index);
        let mut scaled_poly = Poly::zero();
        for (out, coeff) in scaled_poly.coeffs.iter_mut().zip(share_poly.coeffs.iter()) {
            let mut product = (i64::from(*coeff) * i64::from(lambda)) % q;
            if product < 0 {
                product += q;
            }
            *out = product as i32;
        }

        master_poly.add_assign(&scaled_poly);
    }

    master_poly
}

fn canonical_i64(value: i32) -> i64 {
    let q = i64::from(Q);
    let mut out = i64::from(value) % q;
    if out < 0 {
        out += q;
    }
    out
}

#[cfg(test)]
mod interpolation_tests {
    use super::*;
    use crate::crypto::{
        poly::{N, Q},
        vss::split_secret_poly,
    };

    #[test]
    fn test_modular_inverse_soundness() {
        let test_val = 4231;
        let inv = modular_inverse(test_val);
        let identity = (i64::from(test_val) * i64::from(inv)) % i64::from(Q);

        assert_eq!(identity, 1);
    }

    #[test]
    fn test_end_to_end_vss_interpolation_reconstruction() {
        let mut original_secret = Poly::zero();
        for (index, coeff) in original_secret.coeffs.iter_mut().enumerate() {
            *coeff = ((index as i32) * 7) % Q;
        }

        let shares = split_secret_poly(&original_secret, 2, 3);
        let received_shares = vec![
            (shares[0].receiver_index, shares[0].polynomial_share),
            (shares[2].receiver_index, shares[2].polynomial_share),
        ];

        let reconstructed_secret = reconstruct_secret_poly(&received_shares);

        assert_eq!(
            reconstructed_secret.coeffs, original_secret.coeffs,
            "Lattice polynomial interpolation failure: reconstructed data does not match origin secret."
        );
        assert_eq!(reconstructed_secret.coeffs.len(), N);
    }
}
