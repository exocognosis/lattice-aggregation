//! Polynomial arithmetic over the ML-DSA coefficient ring.
//!
//! These helpers model coefficient-domain arithmetic for
//! `Z_q[X] / (X^256 + 1)` with the ML-DSA modulus. They are deliberately
//! small building blocks for threshold-protocol experiments, not an NTT
//! implementation and not a production ML-DSA backend.
//!
//! The multiplication path is a negacyclic (`X^256 = -1`) schoolbook product
//! used by the verifiable secret sharing layer. It is a correct reference
//! implementation, not a constant-time NTT.

/// Number of coefficients in an ML-DSA polynomial.
pub const N: usize = 256;
/// ML-DSA prime modulus `q`.
pub const Q: i32 = 8_380_417;

/// Raw polynomial coefficients.
///
/// Coefficients are expected to be canonical representatives in `[0, Q)` for
/// modular addition. Noise-bound checks interpret coefficients as signed
/// centered values supplied by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Poly {
    /// Coefficients in coefficient or NTT domain, depending on caller context.
    pub coeffs: [i32; N],
}

impl Poly {
    /// Return the zero polynomial.
    pub const fn zero() -> Self {
        Self { coeffs: [0; N] }
    }

    /// Construct a polynomial from raw coefficients.
    pub const fn from_coeffs(coeffs: [i32; N]) -> Self {
        Self { coeffs }
    }

    /// Add another polynomial modulo `Q`.
    ///
    /// This operation performs no allocation and uses a branch-free reduction
    /// path for canonical inputs in `[0, Q)`.
    pub fn add_assign(&mut self, rhs: &Self) {
        for (lhs, rhs) in self.coeffs.iter_mut().zip(rhs.coeffs.iter()) {
            let sum = *lhs + *rhs;
            let reduced = sum - Q;
            let underflow_mask = reduced >> 31;
            *lhs = reduced + (Q & underflow_mask);
        }
    }

    /// Return `true` when every coefficient has absolute value below `bound`.
    ///
    /// The comparison uses branch-free absolute value for the expected ML-DSA
    /// coefficient range. It is test infrastructure, not a formal timing proof.
    pub fn check_noise_bounds(&self, bound: i32) -> bool {
        if bound <= 0 {
            return false;
        }

        let mut within_bounds = true;
        for coeff in self.coeffs {
            let sign = coeff >> 31;
            let abs = (coeff ^ sign).wrapping_sub(sign);
            within_bounds &= abs < bound;
        }

        within_bounds
    }

    /// Return a copy with every coefficient reduced to the canonical range
    /// `[0, Q)`.
    ///
    /// Accepts arbitrary `i32` inputs and maps them to their canonical
    /// representative modulo `Q`.
    pub fn canonical(&self) -> Self {
        let q = i64::from(Q);
        let mut coeffs = [0i32; N];
        for (out, &value) in coeffs.iter_mut().zip(self.coeffs.iter()) {
            let mut reduced = i64::from(value) % q;
            if reduced < 0 {
                reduced += q;
            }
            *out = reduced as i32;
        }
        Self { coeffs }
    }

    /// Subtract another polynomial modulo `Q`.
    ///
    /// Both operands are expected to hold canonical coefficients in `[0, Q)`;
    /// the result is canonical.
    pub fn sub_assign(&mut self, rhs: &Self) {
        for (lhs, rhs) in self.coeffs.iter_mut().zip(rhs.coeffs.iter()) {
            let diff = *lhs - *rhs;
            let underflow_mask = diff >> 31;
            *lhs = diff + (Q & underflow_mask);
        }
    }

    /// Multiply every coefficient by an integer scalar modulo `Q`.
    ///
    /// The scalar is reduced modulo `Q` first, so any `i64` value is accepted.
    pub fn scalar_mul(&self, scalar: i64) -> Self {
        let q = i64::from(Q);
        let mut factor = scalar % q;
        if factor < 0 {
            factor += q;
        }

        let mut coeffs = [0i32; N];
        for (out, &value) in coeffs.iter_mut().zip(self.coeffs.iter()) {
            let mut reduced = (i64::from(value) * factor) % q;
            if reduced < 0 {
                reduced += q;
            }
            *out = reduced as i32;
        }
        Self { coeffs }
    }

    /// Multiply by another polynomial in the negacyclic ring
    /// `R_q = Z_q[X] / (X^256 + 1)`.
    ///
    /// This is a schoolbook `O(N^2)` product with the reduction `X^256 = -1`.
    /// Inputs are canonicalized first, so any `i32` coefficients are accepted;
    /// the result is canonical in `[0, Q)`. It is a correct reference
    /// multiplication, not a constant-time NTT.
    pub fn mul(&self, rhs: &Self) -> Self {
        let lhs = self.canonical();
        let rhs = rhs.canonical();
        let q = i64::from(Q);

        let mut acc = [0i64; N];
        for (i, &a) in lhs.coeffs.iter().enumerate() {
            if a == 0 {
                continue;
            }
            let a = i64::from(a);
            for (j, &b) in rhs.coeffs.iter().enumerate() {
                let product = a * i64::from(b);
                let k = i + j;
                if k < N {
                    acc[k] += product;
                } else {
                    acc[k - N] -= product;
                }
            }
        }

        let mut coeffs = [0i32; N];
        for (out, &value) in coeffs.iter_mut().zip(acc.iter()) {
            let mut reduced = value % q;
            if reduced < 0 {
                reduced += q;
            }
            *out = reduced as i32;
        }
        Self { coeffs }
    }
}

impl Default for Poly {
    fn default() -> Self {
        Self::zero()
    }
}

#[cfg(test)]
mod poly_ring_tests {
    use super::*;

    fn monomial(degree: usize, coeff: i32) -> Poly {
        let mut poly = Poly::zero();
        poly.coeffs[degree] = coeff;
        poly
    }

    fn sample(seed: i32) -> Poly {
        let mut poly = Poly::zero();
        for (index, coeff) in poly.coeffs.iter_mut().enumerate() {
            *coeff = ((index as i32).wrapping_mul(seed).wrapping_add(seed)).rem_euclid(Q);
        }
        poly
    }

    #[test]
    fn multiplicative_identity() {
        let one = monomial(0, 1);
        let poly = sample(31);
        assert_eq!(poly.mul(&one).coeffs, poly.canonical().coeffs);
    }

    #[test]
    fn negacyclic_wraparound_maps_x_pow_n_to_minus_one() {
        // X^128 * X^128 = X^256 = -1 in R_q.
        let x_128 = monomial(128, 1);
        let product = x_128.mul(&x_128);

        let mut expected = Poly::zero();
        expected.coeffs[0] = Q - 1; // -1 mod Q
        assert_eq!(product.coeffs, expected.coeffs);
    }

    #[test]
    fn multiplication_is_commutative() {
        let a = sample(7);
        let b = sample(13);
        assert_eq!(a.mul(&b).coeffs, b.mul(&a).coeffs);
    }

    #[test]
    fn multiplication_distributes_over_addition() {
        let a = sample(5);
        let b = sample(9);
        let c = sample(17);

        let mut b_plus_c = b;
        b_plus_c.add_assign(&c);
        let lhs = a.mul(&b_plus_c);

        let mut rhs = a.mul(&b);
        rhs.add_assign(&a.mul(&c));

        assert_eq!(lhs.coeffs, rhs.coeffs);
    }

    #[test]
    fn subtraction_inverts_addition() {
        let a = sample(3);
        let b = sample(11);

        let mut sum = a;
        sum.add_assign(&b);
        sum.sub_assign(&b);

        assert_eq!(sum.coeffs, a.canonical().coeffs);
    }

    #[test]
    fn scalar_multiplication_matches_repeated_addition() {
        let a = sample(23);
        let scaled = a.scalar_mul(3);

        let mut repeated = a;
        repeated.add_assign(&a);
        repeated.add_assign(&a);

        assert_eq!(scaled.coeffs, repeated.canonical().coeffs);
    }
}
