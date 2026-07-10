//! Coefficient-domain arithmetic in `R_q = Z_q[X] / (X^256 + 1)`.
//!
//! Provides schoolbook negacyclic multiplication used by module-vector partial
//! responses. This is algebraically correct for `R_q` but is not a constant-time
//! NTT implementation and is not claimed side-channel safe.

use super::poly::{Poly, N, Q};

/// Reduce into canonical `[0, Q)`.
#[inline]
pub fn canonical(mut x: i64) -> i32 {
    let q = i64::from(Q);
    x %= q;
    if x < 0 {
        x += q;
    }
    x as i32
}

/// Centered representative in `(-Q/2, Q/2]`.
#[inline]
pub fn centered(x: i32) -> i32 {
    let q = Q;
    let mut c = x % q;
    if c < 0 {
        c += q;
    }
    if c > q / 2 {
        c -= q;
    }
    c
}

/// Infinity norm using centered representatives.
pub fn infinity_norm(poly: &Poly) -> i32 {
    let mut max = 0i32;
    for coeff in poly.coeffs {
        let a = centered(coeff).unsigned_abs() as i32;
        if a > max {
            max = a;
        }
    }
    max
}

/// Return true when every centered coefficient has absolute value `< bound`.
pub fn check_centered_bound(poly: &Poly, bound: i32) -> bool {
    if bound <= 0 {
        return false;
    }
    infinity_norm(poly) < bound
}

/// `out = a + b` in `R_q`.
pub fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let mut out = *a;
    out.add_assign(b);
    out
}

/// `out = a - b` in `R_q`.
pub fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    let mut out = Poly::zero();
    for i in 0..N {
        out.coeffs[i] = canonical(i64::from(a.coeffs[i]) - i64::from(b.coeffs[i]));
    }
    out
}

/// Negacyclic schoolbook product in `R_q = Z_q[X]/(X^n+1)`.
#[allow(clippy::needless_range_loop)]
pub fn poly_mul(a: &Poly, b: &Poly) -> Poly {
    let q = i64::from(Q);
    let mut acc = [0i64; N];
    for i in 0..N {
        let ai = i64::from(a.coeffs[i]);
        if ai == 0 {
            continue;
        }
        for j in 0..N {
            let bj = i64::from(b.coeffs[j]);
            if bj == 0 {
                continue;
            }
            let k = i + j;
            let product = ai * bj;
            if k < N {
                acc[k] += product;
            } else {
                // X^n ≡ -1
                acc[k - N] -= product;
            }
        }
    }
    let mut out = Poly::zero();
    for i in 0..N {
        out.coeffs[i] = canonical(acc[i] % q);
    }
    out
}

/// Scale polynomial by an integer scalar in `Z_q`.
pub fn poly_scale(poly: &Poly, scalar: i32) -> Poly {
    let s = i64::from(scalar);
    let mut out = Poly::zero();
    for i in 0..N {
        out.coeffs[i] = canonical(i64::from(poly.coeffs[i]) * s);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_by_one_is_identity() {
        let mut a = Poly::zero();
        a.coeffs[0] = 1;
        a.coeffs[3] = 5;
        let one = {
            let mut o = Poly::zero();
            o.coeffs[0] = 1;
            o
        };
        assert_eq!(poly_mul(&a, &one).coeffs, a.coeffs);
    }

    #[test]
    fn x_pow_n_is_minus_one() {
        let mut x = Poly::zero();
        x.coeffs[1] = 1; // X
        let mut p = {
            let mut o = Poly::zero();
            o.coeffs[0] = 1;
            o
        };
        for _ in 0..N {
            p = poly_mul(&p, &x);
        }
        // X^n = -1 = Q-1
        assert_eq!(p.coeffs[0], Q - 1);
        for c in p.coeffs.iter().skip(1) {
            assert_eq!(*c, 0);
        }
    }
}
