//! Polynomial arithmetic over the ML-DSA coefficient ring.
//!
//! These helpers model coefficient-domain arithmetic for
//! `Z_q[X] / (X^256 + 1)` with the ML-DSA modulus. They are deliberately
//! small building blocks for threshold-protocol experiments, not an NTT
//! implementation and not a production ML-DSA backend.

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
}

impl Default for Poly {
    fn default() -> Self {
        Self::zero()
    }
}
