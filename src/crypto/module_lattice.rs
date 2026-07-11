//! Module-lattice arithmetic and sampling over `R_q = Z_q[X]/(X^256 + 1)`.
//!
//! Internal plumbing for the BDLOP commitment (`crate::crypto::bdlop`) and the
//! hiding verifiable secret sharing built on it. Operations act on vectors of
//! [`Poly`] (`R_q^k`) and matrices (`R_q^{rows x cols}`). All results are
//! canonical in `[0, Q)`; short samples are returned in signed centered form so
//! their infinity norm can be checked directly.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::crypto::poly::{Poly, N, Q};

const UNIFORM_SAMPLE_LABEL: &[u8] = b"lattice-aggregation/module-lattice/uniform";
const SHORT_SAMPLE_LABEL: &[u8] = b"lattice-aggregation/module-lattice/short";

/// Inner product `sum_i a[i] * b[i]` over `R_q`.
///
/// The two slices are expected to have equal length; extra elements of the
/// longer slice are ignored.
pub(crate) fn inner_product(a: &[Poly], b: &[Poly]) -> Poly {
    let mut acc = Poly::zero();
    for (lhs, rhs) in a.iter().zip(b.iter()) {
        acc.add_assign(&lhs.mul(rhs));
    }
    acc
}

/// Matrix-vector product `matrix * vector` over `R_q`.
///
/// Each matrix row is dotted with `vector`; row length is expected to match the
/// vector length.
pub(crate) fn matrix_vec_mul(matrix: &[Vec<Poly>], vector: &[Poly]) -> Vec<Poly> {
    matrix
        .iter()
        .map(|row| inner_product(row, vector))
        .collect()
}

/// Component-wise sum of two equal-length vectors over `R_q`.
pub(crate) fn vec_add(a: &[Poly], b: &[Poly]) -> Vec<Poly> {
    a.iter()
        .zip(b.iter())
        .map(|(lhs, rhs)| {
            let mut sum = *lhs;
            sum.add_assign(rhs);
            sum
        })
        .collect()
}

/// Multiply every component of a vector by an integer scalar modulo `Q`.
pub(crate) fn vec_scalar_mul(vector: &[Poly], scalar: i64) -> Vec<Poly> {
    vector.iter().map(|poly| poly.scalar_mul(scalar)).collect()
}

/// Expand a uniform `R_q^{rows x cols}` matrix from a public seed.
pub(crate) fn sample_uniform_matrix(seed: &[u8], rows: usize, cols: usize) -> Vec<Vec<Poly>> {
    (0..rows)
        .map(|row| {
            (0..cols)
                .map(|col| uniform_poly(seed, (row * cols + col) as u32))
                .collect()
        })
        .collect()
}

/// Sample a length-`len` vector of short `R_q` elements (coefficients in
/// `{-1, 0, 1}`) from a seed and domain separator.
pub(crate) fn sample_short_vec(seed: &[u8], domain: u32, len: usize) -> Vec<Poly> {
    (0..len)
        .map(|index| short_poly(seed, domain, index as u32))
        .collect()
}

/// Sample a uniform `R_q` element from a seed via SHAKE256 rejection sampling
/// (23-bit candidates, reject `>= Q`, FIPS 204 uniform style).
pub(crate) fn uniform_poly(seed: &[u8], nonce: u32) -> Poly {
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

/// Sample a short `R_q` element with coefficients uniform over `{-1, 0, 1}`,
/// returned in signed centered form.
fn short_poly(seed: &[u8], domain: u32, index: u32) -> Poly {
    let mut hasher = Shake256::default();
    absorb(&mut hasher, SHORT_SAMPLE_LABEL);
    absorb(&mut hasher, seed);
    hasher.update(&domain.to_be_bytes());
    hasher.update(&index.to_be_bytes());
    let mut reader = hasher.finalize_xof();

    let mut coeffs = [0i32; N];
    let mut filled = 0usize;
    let mut buf = [0u8; 1];
    while filled < N {
        reader.read(&mut buf);
        match buf[0] & 0x03 {
            0 => {
                coeffs[filled] = 0;
                filled += 1;
            }
            1 => {
                coeffs[filled] = 1;
                filled += 1;
            }
            2 => {
                coeffs[filled] = -1;
                filled += 1;
            }
            _ => {} // value 3: reject and resample
        }
    }
    Poly::from_coeffs(coeffs)
}

fn absorb(hasher: &mut Shake256, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod module_lattice_tests {
    use super::*;

    #[test]
    fn inner_product_distributes_over_vector_addition() {
        let a = vec![uniform_poly(b"a", 0), uniform_poly(b"a", 1)];
        let b = vec![uniform_poly(b"b", 0), uniform_poly(b"b", 1)];
        let c = vec![uniform_poly(b"c", 0), uniform_poly(b"c", 1)];

        let lhs = inner_product(&a, &vec_add(&b, &c));

        let mut rhs = inner_product(&a, &b);
        rhs.add_assign(&inner_product(&a, &c));

        assert_eq!(lhs.canonical().coeffs, rhs.canonical().coeffs);
    }

    #[test]
    fn matrix_vec_mul_is_linear_in_the_vector() {
        let matrix = sample_uniform_matrix(b"seed", 3, 2);
        let r1 = sample_short_vec(b"r1", 0, 2);
        let r2 = sample_short_vec(b"r2", 0, 2);

        let lhs = matrix_vec_mul(&matrix, &vec_add(&r1, &r2));

        let sum_products = vec_add(&matrix_vec_mul(&matrix, &r1), &matrix_vec_mul(&matrix, &r2));

        for (l, r) in lhs.iter().zip(sum_products.iter()) {
            assert_eq!(l.canonical().coeffs, r.canonical().coeffs);
        }
    }

    #[test]
    fn short_samples_have_infinity_norm_one() {
        for index in 0..8 {
            let poly = short_poly(b"seed", 7, index);
            assert!(
                poly.check_noise_bounds(2),
                "coefficients must be in {{-1,0,1}}"
            );
        }
    }

    #[test]
    fn scalar_mul_matches_repeated_vector_addition() {
        let vector = sample_uniform_matrix(b"s", 1, 3).remove(0);
        let scaled = vec_scalar_mul(&vector, 3);
        let repeated = vec_add(&vec_add(&vector, &vector), &vector);
        for (s, r) in scaled.iter().zip(repeated.iter()) {
            assert_eq!(s.canonical().coeffs, r.canonical().coeffs);
        }
    }
}
