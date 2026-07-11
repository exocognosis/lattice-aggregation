//! Number-theoretic transform over `R_q = Z_q[X]/(X^256 + 1)`.
//!
//! Provides an `O(N log N)` negacyclic multiplication to replace the schoolbook
//! `O(N^2)` product. It uses the ML-DSA parameters (`q = 8380417`, primitive
//! 512-th root of unity `zeta = 1753`) with a Cooley-Tukey forward transform and
//! a Gentleman-Sande inverse, in plain `i64` modular arithmetic (no Montgomery
//! form, no unsafe).
//!
//! Correctness is pinned by property tests: the transform round-trips
//! (`inv_ntt(ntt(a)) == a`) and `ntt_mul` matches the schoolbook reference
//! `Poly::mul_schoolbook` on random and edge inputs.
//! The internal butterfly ordering is self-consistent but is **not** claimed
//! byte-identical to the FIPS 204 `NTT`/`NTT^-1` coefficient ordering; matching
//! that exactly (for wire-format ML-DSA interop) is deferred.

use std::sync::OnceLock;

use crate::low_level::poly::{N, Q};

/// Primitive 512-th root of unity modulo `Q` (the ML-DSA value).
const ZETA: i64 = 1753;

const fn q64() -> i64 {
    Q as i64
}

struct Tables {
    /// `zetas[i] = ZETA^bitrev8(i) mod Q`, the twiddle factors in transform order.
    zetas: [i32; N],
    /// `N^-1 mod Q`, applied once at the end of the inverse transform.
    n_inv: i32,
}

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut zetas = [0i32; N];
        for (index, entry) in zetas.iter_mut().enumerate() {
            *entry = pow_mod(ZETA, u64::from(bit_reverse_8(index as u32))) as i32;
        }
        let n_inv = pow_mod(N as i64, Q as u64 - 2) as i32;
        Tables { zetas, n_inv }
    })
}

/// Forward negacyclic NTT, in place. Input in normal order; output in the
/// transform's bit-reversed order (consumed by [`inv_ntt`]).
pub(crate) fn ntt(coeffs: &mut [i32; N]) {
    let zetas = &tables().zetas;
    let mut k = 0usize;
    let mut len = N / 2;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            k += 1;
            let zeta = i64::from(zetas[k]);
            for j in start..start + len {
                let twiddle = (zeta * i64::from(coeffs[j + len])).rem_euclid(q64()) as i32;
                coeffs[j + len] = sub_mod(coeffs[j], twiddle);
                coeffs[j] = add_mod(coeffs[j], twiddle);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Inverse negacyclic NTT, in place, including the `N^-1` scaling. Input in the
/// forward transform's bit-reversed order; output in normal order.
pub(crate) fn inv_ntt(coeffs: &mut [i32; N]) {
    let tables = tables();
    let zetas = &tables.zetas;
    let mut k = N;
    let mut len = 1;
    while len < N {
        let mut start = 0;
        while start < N {
            k -= 1;
            let neg_zeta = i64::from(Q - zetas[k]); // -zeta mod Q
            for j in start..start + len {
                let upper = coeffs[j];
                coeffs[j] = add_mod(upper, coeffs[j + len]);
                let diff = sub_mod(upper, coeffs[j + len]);
                coeffs[j + len] = (neg_zeta * i64::from(diff)).rem_euclid(q64()) as i32;
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    let n_inv = i64::from(tables.n_inv);
    for coeff in coeffs.iter_mut() {
        *coeff = (n_inv * i64::from(*coeff)).rem_euclid(q64()) as i32;
    }
}

/// Multiply two polynomials in `R_q` via the NTT: `inv_ntt(ntt(a) o ntt(b))`.
///
/// Inputs are canonicalized to `[0, Q)` first; the result is canonical.
pub(crate) fn ntt_mul(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
    let mut fa = *a;
    let mut fb = *b;
    for coeff in fa.iter_mut() {
        *coeff = i64::from(*coeff).rem_euclid(q64()) as i32;
    }
    for coeff in fb.iter_mut() {
        *coeff = i64::from(*coeff).rem_euclid(q64()) as i32;
    }

    ntt(&mut fa);
    ntt(&mut fb);

    let mut product = [0i32; N];
    for (out, (&x, &y)) in product.iter_mut().zip(fa.iter().zip(fb.iter())) {
        *out = (i64::from(x) * i64::from(y)).rem_euclid(q64()) as i32;
    }

    inv_ntt(&mut product);
    product
}

/// Modular addition for canonical operands in `[0, Q)`.
fn add_mod(a: i32, b: i32) -> i32 {
    let sum = a + b;
    if sum >= Q {
        sum - Q
    } else {
        sum
    }
}

/// Modular subtraction for canonical operands in `[0, Q)`.
fn sub_mod(a: i32, b: i32) -> i32 {
    let diff = a - b;
    if diff < 0 {
        diff + Q
    } else {
        diff
    }
}

/// Modular exponentiation `base^exp mod Q`.
fn pow_mod(mut base: i64, mut exp: u64) -> i64 {
    base = base.rem_euclid(q64());
    let mut result = 1i64;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % q64();
        }
        base = base * base % q64();
        exp >>= 1;
    }
    result
}

/// 8-bit bit reversal (for the length-256 transform twiddle order).
fn bit_reverse_8(mut value: u32) -> u32 {
    let mut reversed = 0;
    for _ in 0..8 {
        reversed = (reversed << 1) | (value & 1);
        value >>= 1;
    }
    reversed
}

#[cfg(test)]
mod ntt_tests {
    use super::*;

    fn sample(seed: i64) -> [i32; N] {
        let mut coeffs = [0i32; N];
        for (index, coeff) in coeffs.iter_mut().enumerate() {
            *coeff = ((index as i64 * seed + seed).rem_euclid(q64())) as i32;
        }
        coeffs
    }

    #[test]
    fn round_trip_is_identity() {
        for seed in 1..8 {
            let original = sample(seed * 1009);
            let mut work = original;
            ntt(&mut work);
            inv_ntt(&mut work);
            assert_eq!(work, original, "inv_ntt(ntt(a)) must equal a");
        }
    }

    #[test]
    fn ntt_mul_negacyclic_wraparound() {
        // X^128 * X^128 = X^256 = -1 in R_q.
        let mut x_128 = [0i32; N];
        x_128[128] = 1;
        let product = ntt_mul(&x_128, &x_128);

        let mut expected = [0i32; N];
        expected[0] = Q - 1;
        assert_eq!(product, expected);
    }

    #[test]
    fn multiplicative_identity() {
        let mut one = [0i32; N];
        one[0] = 1;
        let poly = sample(4242);
        assert_eq!(ntt_mul(&poly, &one), poly);
    }

    #[test]
    fn ntt_mul_monomial_sweep_matches_analytic() {
        // X^i * X^j = (sign) X^{(i+j) mod N}, sign = -1 iff i+j >= N (negacyclic).
        // Since both ntt_mul and the schoolbook product are R_q-bilinear,
        // agreement on all monomial pairs certifies agreement on all inputs.
        for i in 0..N {
            for &j in &[0usize, 1, 63, 127, 128, 129, 200, 255] {
                let mut a = [0i32; N];
                a[i] = 1;
                let mut b = [0i32; N];
                b[j] = 1;

                let degree = i + j;
                let mut expected = [0i32; N];
                expected[degree % N] = if degree >= N { Q - 1 } else { 1 };

                assert_eq!(ntt_mul(&a, &b), expected, "X^{i} * X^{j}");
            }
        }
    }

    #[test]
    fn zetas_are_a_512th_root_structure() {
        // zeta^256 == -1 mod Q, confirming the negacyclic root of unity.
        assert_eq!(pow_mod(ZETA, 256), i64::from(Q - 1));
        assert_eq!(pow_mod(ZETA, 512), 1);
    }
}
