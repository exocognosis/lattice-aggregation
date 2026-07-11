//! ML-DSA-65 signing primitives: rounding/decomposition, challenge sampling,
//! and mask sampling.
//!
//! These are the FIPS 204 building blocks the threshold signing path needs
//! regardless of the distributed-protocol design: `w1 = HighBits(w)` for the
//! challenge input, `c = SampleInBall(c_tilde)` for the challenge, and the
//! decomposition bounds used by the rejection loop.
//!
//! ## Fidelity boundary
//!
//! The functions implement the FIPS 204 **semantics** (`Power2Round`,
//! `Decompose`/`HighBits`/`LowBits`, `SampleInBall`, and a `gamma1` mask
//! sampler) over `R_q` with the ML-DSA-65 parameters, and are checked by
//! algebraic property tests (decomposition reconstruction, coefficient bounds,
//! challenge weight/signs). They are **not** asserted byte-identical to the
//! FIPS 204 reference via known-answer tests, and the `gamma1` sampler uses a
//! simple 20-bit unpack rather than the exact `ExpandMask` bit-packing. KAT/CAVP
//! validation and byte-exact packing are deferred. No hypothesis criterion is
//! closed here.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::crypto::poly::{Poly, N, Q};

/// Dropped-bits parameter for `Power2Round`.
pub const D: u32 = 13;
/// Mask range parameter: coefficients are sampled in `(-GAMMA1, GAMMA1]`.
pub const GAMMA1: i32 = 1 << 19;
/// Low-order rounding range parameter (`(q - 1) / 32`).
pub const GAMMA2: i32 = (Q - 1) / 32;
/// Challenge Hamming weight (number of nonzero `+-1` coefficients).
pub const TAU: usize = 49;
/// Rejection-bound slack `beta = TAU * eta` (`eta = 4` for ML-DSA-65).
pub const BETA: i32 = 196;
/// Maximum number of `+-1` hint coefficients.
pub const OMEGA: usize = 55;

/// Centered representative of `r` modulo `alpha`: the unique `r0` with
/// `r0 == r (mod alpha)` and `-alpha/2 < r0 <= alpha/2`.
pub fn mod_pm(r: i32, alpha: i32) -> i32 {
    debug_assert!(alpha > 0, "alpha must be positive");
    let mut r0 = r.rem_euclid(alpha);
    if r0 > alpha / 2 {
        r0 -= alpha;
    }
    r0
}

/// `Power2Round(r)`: split `r mod q` as `r1 * 2^D + r0` with `r0` centered
/// modulo `2^D`. Returns `(r1, r0)`.
pub fn power2round(r: i32) -> (i32, i32) {
    let r = r.rem_euclid(Q);
    let r0 = mod_pm(r, 1 << D);
    let r1 = (r - r0) / (1 << D);
    (r1, r0)
}

/// `Decompose(r)`: split `r mod q` into high and low parts relative to
/// `alpha = 2 * GAMMA2`, with the FIPS 204 boundary correction. Returns
/// `(r1, r0)` where `r1 * alpha + r0 == r (mod q)`.
pub fn decompose(r: i32) -> (i32, i32) {
    let r = r.rem_euclid(Q);
    let alpha = 2 * GAMMA2;
    let mut r0 = mod_pm(r, alpha);
    let r1;
    if r - r0 == Q - 1 {
        r1 = 0;
        r0 -= 1;
    } else {
        r1 = (r - r0) / alpha;
    }
    (r1, r0)
}

/// `HighBits(r)`: the high part from [`decompose`].
pub fn high_bits(r: i32) -> i32 {
    decompose(r).0
}

/// `LowBits(r)`: the low (centered) part from [`decompose`].
pub fn low_bits(r: i32) -> i32 {
    decompose(r).1
}

/// Apply [`high_bits`] coefficient-wise to a polynomial.
pub fn high_bits_poly(poly: &Poly) -> Poly {
    let mut coeffs = [0i32; N];
    for (out, &value) in coeffs.iter_mut().zip(poly.coeffs.iter()) {
        *out = high_bits(value);
    }
    Poly::from_coeffs(coeffs)
}

/// `SampleInBall(seed)`: sample a challenge polynomial with exactly [`TAU`]
/// nonzero coefficients, each `+-1`, via the FIPS 204 inside-out shuffle seeded
/// by SHAKE256.
pub fn sample_in_ball(seed: &[u8]) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();

    let mut sign_bytes = [0u8; 8];
    reader.read(&mut sign_bytes);
    let mut signs = u64::from_le_bytes(sign_bytes);

    let mut coeffs = [0i32; N];
    let mut byte = [0u8; 1];
    for i in (N - TAU)..N {
        let j = loop {
            reader.read(&mut byte);
            let candidate = usize::from(byte[0]);
            if candidate <= i {
                break candidate;
            }
        };
        coeffs[i] = coeffs[j];
        coeffs[j] = 1 - 2 * ((signs & 1) as i32);
        signs >>= 1;
    }
    Poly::from_coeffs(coeffs)
}

/// Sample a mask polynomial with coefficients uniform in `(-GAMMA1, GAMMA1]`.
///
/// Uses a 20-bit unpack (`2 * GAMMA1 == 2^20`, so no rejection is needed), which
/// matches the distribution but not the exact `ExpandMask` bit-packing.
pub fn sample_gamma1_poly(seed: &[u8], nonce: u16) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(&(seed.len() as u64).to_be_bytes());
    hasher.update(seed);
    hasher.update(&nonce.to_be_bytes());
    let mut reader = hasher.finalize_xof();

    let mut coeffs = [0i32; N];
    let mut buf = [0u8; 3];
    for coeff in coeffs.iter_mut() {
        reader.read(&mut buf);
        let value = (i32::from(buf[0]) | (i32::from(buf[1]) << 8) | (i32::from(buf[2]) << 16))
            & 0x000f_ffff;
        *coeff = GAMMA1 - value; // (-GAMMA1, GAMMA1]
    }
    Poly::from_coeffs(coeffs)
}

#[cfg(test)]
mod mldsa_primitives_tests {
    use super::*;

    fn samples() -> Vec<i32> {
        let mut values = vec![0, 1, Q - 1, GAMMA2, GAMMA2 + 1, 2 * GAMMA2, Q / 2];
        for seed in 0..64 {
            values.push(((seed * 131_071 + 7) as i64).rem_euclid(i64::from(Q)) as i32);
        }
        values
    }

    #[test]
    fn decompose_reconstructs_modulo_q() {
        let alpha = 2 * GAMMA2;
        for r in samples() {
            let (r1, r0) = decompose(r);
            let reconstructed =
                (i64::from(r1) * i64::from(alpha) + i64::from(r0)).rem_euclid(i64::from(Q));
            assert_eq!(reconstructed, i64::from(r.rem_euclid(Q)), "r = {r}");
            assert!(r0.abs() <= GAMMA2, "|r0| <= GAMMA2 for r = {r}");
            assert!((0..16).contains(&r1), "r1 in [0,16) for r = {r}");
        }
    }

    #[test]
    fn power2round_reconstructs_modulo_q() {
        let scale = 1i64 << D;
        for r in samples() {
            let (r1, r0) = power2round(r);
            let reconstructed = (i64::from(r1) * scale + i64::from(r0)).rem_euclid(i64::from(Q));
            assert_eq!(reconstructed, i64::from(r.rem_euclid(Q)), "r = {r}");
            assert!(r0.abs() <= (1 << (D - 1)), "|r0| <= 2^(D-1) for r = {r}");
        }
    }

    #[test]
    fn mod_pm_is_centered() {
        let alpha = 2 * GAMMA2;
        for r in samples() {
            let r0 = mod_pm(r, alpha);
            assert!(r0 > -alpha / 2 && r0 <= alpha / 2);
            assert_eq!((r - r0).rem_euclid(alpha), 0);
        }
    }

    #[test]
    fn sample_in_ball_has_weight_tau_and_signs() {
        for seed in 0..8u8 {
            let challenge = sample_in_ball(&[seed; 32]);
            let nonzero = challenge.coeffs.iter().filter(|&&c| c != 0).count();
            assert_eq!(nonzero, TAU, "exactly TAU nonzero coefficients");
            assert!(
                challenge
                    .coeffs
                    .iter()
                    .all(|&c| c == 0 || c == 1 || c == -1),
                "nonzero coefficients are +-1"
            );
        }
    }

    #[test]
    fn sample_in_ball_is_deterministic() {
        assert_eq!(
            sample_in_ball(&[3u8; 32]).coeffs,
            sample_in_ball(&[3u8; 32]).coeffs
        );
    }

    #[test]
    fn gamma1_mask_is_within_bound() {
        for nonce in 0..8 {
            let mask = sample_gamma1_poly(b"seed", nonce);
            for &c in &mask.coeffs {
                assert!(
                    c > -GAMMA1 && c <= GAMMA1,
                    "coefficient in (-GAMMA1, GAMMA1]"
                );
            }
        }
    }
}
