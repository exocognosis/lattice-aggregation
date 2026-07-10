//! Algebraic partial-response composition over `R_q` polynomials.
//!
//! # Goal
//!
//! Close the gap between **seed-layer partials** and **NTT-domain module-vector
//! partial `z_i`** by implementing the correct algebraic share relation on the
//! repository's coefficient-domain [`Poly`] type:
//!
//! ```text
//! z_i = y_i + c · s_i   (in R_q)
//! z   = Σ λ_i z_i = y + c · s
//! ```
//!
//! # Claim boundary
//!
//! - Implements single-polynomial partial composition and Lagrange aggregation.
//! - Includes local infinity-norm rejection checks on partial/aggregate `z`.
//! - Single-poly path lives here; full ML-DSA-65 module vectors (`R_q^L`) live in
//!   [`super::module_partial`].
//! - Does **not** produce a FIPS 204 wire signature by itself.
//! - Status: `algebraic_poly_partial_zi = true`; see `module_partial` for
//!   module-vector status.

use crate::{
    crypto::interpolation::{compute_lagrange_coefficient, modular_inverse},
    errors::ThresholdError,
    low_level::poly::{Poly, N, Q},
    types::ValidatorId,
};

/// Status of the algebraic partial path relative to full ML-DSA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlgebraicPartialStatus {
    /// Coefficient-domain partial `z_i = y_i + c·s_i` on a single `Poly`.
    pub algebraic_poly_partial_zi: bool,
    /// Full module-vector ML-DSA partials (`R_q^ℓ`) with NTT and hints.
    pub algebraic_module_vector_partial_zi: bool,
    /// Produces a standard FIPS 204 signature without a seed-reconstruction bridge.
    pub fips204_wire_signature_from_algebraic_partials: bool,
}

impl AlgebraicPartialStatus {
    /// Current engineering status.
    pub const fn current() -> Self {
        Self {
            algebraic_poly_partial_zi: true,
            // Module-vector composition is implemented in `module_partial`.
            algebraic_module_vector_partial_zi: true,
            // Via fips_wire: provider pack + threshold share of wire z (not s1/y-only pack).
            fips204_wire_signature_from_algebraic_partials: true,
        }
    }
}

/// One party's algebraic partial response over `R_q`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlgebraicPartialZi {
    /// Signer identity / evaluation point owner.
    pub signer: ValidatorId,
    /// Evaluation point `x_i` (nonzero).
    pub x: u16,
    /// Partial response `z_i = y_i + c · s_i`.
    pub z_i: Poly,
    /// Local nonce share `y_i` (retained for diagnostics; zeroize in production paths).
    pub y_i: Poly,
    /// Local secret share `s_i`.
    pub s_i: Poly,
}

/// Aggregated algebraic response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlgebraicAggregateZ {
    /// Reconstructed `z = y + c·s`.
    pub z: Poly,
    /// Active signer evaluation points.
    pub active_xs: Vec<u16>,
    /// Challenge scalar used (canonical representative in `0..Q`).
    pub challenge_scalar: i32,
    /// Whether aggregate infinity-norm check passed.
    pub infinity_norm_ok: bool,
}

/// Derive a challenge scalar in `Z_q` from 32 challenge bytes (research mapping).
pub fn challenge_scalar_from_digest(challenge: &[u8; 32]) -> i32 {
    let mut acc = 0i64;
    for chunk in challenge.chunks_exact(4).take(2) {
        let word = i32::from_le_bytes(chunk.try_into().expect("4 bytes"));
        acc = (acc + i64::from(word).rem_euclid(i64::from(Q))) % i64::from(Q);
    }
    acc as i32
}

/// Emit algebraic partial `z_i = y_i + c · s_i` with local bound check.
pub fn emit_algebraic_partial_zi(
    signer: ValidatorId,
    x: u16,
    s_i: &Poly,
    y_i: &Poly,
    challenge_scalar: i32,
    local_z_bound: i32,
) -> Result<AlgebraicPartialZi, ThresholdError> {
    if x == 0 {
        return Err(ThresholdError::BackendUnavailable {
            reason: "algebraic partial requires nonzero evaluation point",
        });
    }
    let mut z_i = *y_i;
    let mut cs = scale_poly(s_i, challenge_scalar);
    z_i.add_assign(&cs);
    // Best-effort wipe of temporary.
    cs = Poly::zero();
    let _ = cs;

    if !z_i.check_noise_bounds(local_z_bound) {
        return Err(ThresholdError::RejectionSamplingFailed { validator: signer });
    }

    Ok(AlgebraicPartialZi {
        signer,
        x,
        z_i,
        y_i: *y_i,
        s_i: *s_i,
    })
}

/// Aggregate algebraic partials via Lagrange at zero: `z = Σ λ_i z_i`.
pub fn aggregate_algebraic_partials(
    partials: &[AlgebraicPartialZi],
    challenge_scalar: i32,
    aggregate_z_bound: i32,
) -> Result<AlgebraicAggregateZ, ThresholdError> {
    if partials.is_empty() {
        return Err(ThresholdError::InsufficientPartialShares {
            required: 1,
            received: 0,
        });
    }

    let mut xs = Vec::with_capacity(partials.len());
    let mut seen = std::collections::BTreeSet::new();
    for partial in partials {
        if partial.x == 0 {
            return Err(ThresholdError::BackendUnavailable {
                reason: "algebraic aggregate saw zero evaluation point",
            });
        }
        if !seen.insert(partial.x) {
            return Err(ThresholdError::DuplicateValidator {
                validator: partial.signer,
            });
        }
        xs.push(partial.x);
    }

    let mut z = Poly::zero();
    for partial in partials {
        let lambda = compute_lagrange_coefficient(&xs, partial.x);
        let scaled = scale_poly(&partial.z_i, lambda);
        z.add_assign(&scaled);
    }

    let infinity_norm_ok = z.check_noise_bounds(aggregate_z_bound);
    if !infinity_norm_ok {
        return Err(ThresholdError::RejectionSamplingFailed {
            validator: partials[0].signer,
        });
    }

    Ok(AlgebraicAggregateZ {
        z,
        active_xs: xs,
        challenge_scalar,
        infinity_norm_ok,
    })
}

/// Split a secret polynomial into Shamir shares over coefficient lanes.
///
/// Higher-degree coefficients are derived from `mask_seed` (research RNG input).
pub fn split_secret_poly_shamir(
    secret: &Poly,
    threshold: u16,
    receivers: &[(ValidatorId, u16)],
    mask_seed: &[u8],
) -> Result<Vec<(ValidatorId, u16, Poly)>, ThresholdError> {
    if threshold == 0 || receivers.len() < threshold as usize {
        return Err(ThresholdError::InvalidThresholdParameters {
            threshold,
            total_nodes: receivers.len() as u16,
        });
    }

    // coeffs[degree][coeff_index]
    let degree = threshold as usize;
    let mut coeffs = vec![*secret];
    for d in 1..degree {
        coeffs.push(derive_mask_poly(mask_seed, d as u16));
    }

    let mut shares = Vec::with_capacity(receivers.len());
    for &(validator, x) in receivers {
        if x == 0 {
            return Err(ThresholdError::BackendUnavailable {
                reason: "share evaluation point must be nonzero",
            });
        }
        let mut share = Poly::zero();
        let mut x_pow = 1i64;
        let q = i64::from(Q);
        for (degree_idx, poly_coeff) in coeffs.iter().enumerate() {
            if degree_idx > 0 {
                x_pow = (x_pow * i64::from(x)) % q;
            }
            for (out, coeff) in share.coeffs.iter_mut().zip(poly_coeff.coeffs.iter()) {
                let mut term = (i64::from(*coeff) * x_pow) % q;
                if term < 0 {
                    term += q;
                }
                let mut sum = i64::from(*out) + term;
                sum %= q;
                if sum < 0 {
                    sum += q;
                }
                *out = sum as i32;
            }
        }
        shares.push((validator, x, share));
    }
    Ok(shares)
}

/// Reconstruct secret poly at 0 from shares (test helper).
pub fn reconstruct_secret_poly(shares: &[(u16, Poly)]) -> Poly {
    crate::crypto::interpolation::reconstruct_secret_poly(shares)
}

fn scale_poly(poly: &Poly, scalar: i32) -> Poly {
    let q = i64::from(Q);
    let s = i64::from(scalar).rem_euclid(q);
    let mut out = Poly::zero();
    for (dst, src) in out.coeffs.iter_mut().zip(poly.coeffs.iter()) {
        let mut product = (i64::from(*src) * s) % q;
        if product < 0 {
            product += q;
        }
        *dst = product as i32;
    }
    out
}

fn derive_mask_poly(mask_seed: &[u8], degree: u16) -> Poly {
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    let mut hasher = Shake256::default();
    hasher.update(b"lattice-aggregation/algebraic-partial/mask-poly/v1");
    hasher.update(&degree.to_be_bytes());
    hasher.update(mask_seed);
    let mut reader = hasher.finalize_xof();
    let mut coeffs = [0i32; N];
    for coeff in &mut coeffs {
        let mut word = [0u8; 4];
        reader.read(&mut word);
        let raw = u32::from_le_bytes(word) % (Q as u32);
        *coeff = raw as i32;
    }
    Poly::from_coeffs(coeffs)
}

/// Ensure modular inverse is linked for callers that scale by inverses.
#[allow(dead_code)]
fn _inverse_smoke(value: i32) -> i32 {
    modular_inverse(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algebraic_partial_round_trip_reconstructs_y_plus_cs() {
        let status = AlgebraicPartialStatus::current();
        assert!(status.algebraic_poly_partial_zi);
        assert!(status.algebraic_module_vector_partial_zi);

        let mut secret = Poly::zero();
        for (i, c) in secret.coeffs.iter_mut().enumerate() {
            *c = (i as i32 * 3) % Q;
        }
        let receivers = vec![
            (ValidatorId(0), 1u16),
            (ValidatorId(1), 2u16),
            (ValidatorId(2), 3u16),
        ];
        let s_shares = split_secret_poly_shamir(&secret, 2, &receivers, b"s-mask").unwrap();

        let mut y_secret = Poly::zero();
        for (i, c) in y_secret.coeffs.iter_mut().enumerate() {
            *c = (i as i32 * 7 + 1) % Q;
        }
        let y_shares = split_secret_poly_shamir(&y_secret, 2, &receivers, b"y-mask").unwrap();

        let challenge = [0x11u8; 32];
        let c = challenge_scalar_from_digest(&challenge);
        // Use a loose bound for random-ish polys in tests.
        let bound = Q;

        let mut partials = Vec::new();
        for i in 0..2 {
            let (validator, x, s_i) = &s_shares[i];
            let (_, _, y_i) = &y_shares[i];
            partials.push(emit_algebraic_partial_zi(*validator, *x, s_i, y_i, c, bound).unwrap());
        }

        let agg = aggregate_algebraic_partials(&partials, c, bound).unwrap();
        assert!(agg.infinity_norm_ok);

        // z should equal y + c*s
        let mut expected = y_secret;
        expected.add_assign(&scale_poly(&secret, c));
        assert_eq!(agg.z.coeffs, expected.coeffs);
    }

    #[test]
    fn local_bound_rejection_fires() {
        let s = Poly::from_coeffs([1000; N]);
        let y = Poly::from_coeffs([1000; N]);
        let err = emit_algebraic_partial_zi(ValidatorId(1), 1, &s, &y, 2, 10).unwrap_err();
        assert!(matches!(
            err,
            ThresholdError::RejectionSamplingFailed { .. }
        ));
    }
}
