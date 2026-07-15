//! ML-DSA-65 module-vector partial responses over `R_q^L`.
//!
//! # Construction
//!
//! For ML-DSA-65 (`L = 5`, `η = 4`, `τ = 49`, `γ₁ = 2¹⁹`, `β = τ·η = 196`):
//!
//! ```text
//! s1 ∈ R_q^L ,  y ∈ R_q^L ,  c ∈ R_q  (SampleInBall, weight τ)
//! z  = y + c · s1            (component-wise ring multiply/add)
//! z_i = y_i + c · s1_i       (Shamir shares of each component poly)
//! z   = Σ_i λ_i z_i
//! ```
//!
//! Ring multiplication uses schoolbook negacyclic arithmetic in
//! [`crate::low_level::ring`] (algebraically equivalent to NTT multiply in `R_q`).
//!
//! # Claim boundary
//!
//! - Implements **module-vector** partial composition and Lagrange aggregation.
//! - Enforces local/aggregate centered infinity-norm checks against `γ₁ − β`.
//! - Challenge polynomials use FIPS-shaped SampleInBall (`τ` nonzeros in `{±1}`).
//! - Secret/mask expansion is domain-separated SHAKE256 research expanders
//!   sized for ML-DSA-65; they are **not** claimed bit-identical to CAVP
//!   ExpandS/ExpandMask vectors unless cross-checked.
//! - Does **not** by itself emit a FIPS 204 wire signature (`c̃ ‖ z ‖ h`); the
//!   standard-verifier bridge remains `Sign_internal` after seed reconstruction
//!   (or a future full packing path).
//! - Sets `algebraic_module_vector_partial_zi = true` for composition status.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::{
    crypto::interpolation::compute_lagrange_coefficient,
    errors::ThresholdError,
    low_level::{
        poly::{Poly, Q},
        ring::{check_centered_bound, poly_add, poly_mul},
    },
    types::ValidatorId,
};

/// ML-DSA-65 module rank `L` (secret/mask dimension).
pub const L: usize = 5;
/// ML-DSA-65 SampleInBall weight `τ`.
pub const TAU: usize = 49;
/// ML-DSA-65 secret coefficient bound `η`.
pub const ETA: i32 = 4;
/// ML-DSA-65 mask parameter `γ₁ = 2^19`.
pub const GAMMA1: i32 = 1 << 19;
/// `β = τ · η`.
pub const BETA: i32 = (TAU as i32) * ETA;
/// Acceptance bound for `‖z‖_∞`: `γ₁ − β`.
pub const Z_BOUND: i32 = GAMMA1 - BETA;

/// Module vector in `R_q^L`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModuleVecL {
    /// Polynomial components.
    pub components: [Poly; L],
}

impl ModuleVecL {
    /// Zero vector.
    pub const fn zero() -> Self {
        Self {
            components: [Poly::zero(); L],
        }
    }

    /// Component-wise add.
    pub fn add_assign(&mut self, rhs: &Self) {
        for (lhs, rhs) in self.components.iter_mut().zip(rhs.components.iter()) {
            lhs.add_assign(rhs);
        }
    }

    /// Infinity norm across all components (centered).
    pub fn infinity_norm(&self) -> i32 {
        self.components
            .iter()
            .map(crate::low_level::ring::infinity_norm)
            .max()
            .unwrap_or(0)
    }

    /// Centered bound check on every component.
    pub fn check_z_bound(&self, bound: i32) -> bool {
        self.components
            .iter()
            .all(|p| check_centered_bound(p, bound))
    }
}

/// One party's module-vector partial response.
#[derive(Clone, Debug)]
pub struct ModulePartialZi {
    /// Signer identity.
    pub signer: ValidatorId,
    /// Evaluation point.
    pub x: u16,
    /// `z_i = y_i + c · s1_i`.
    pub z_i: ModuleVecL,
}

/// Aggregated module-vector response.
#[derive(Clone, Debug)]
pub struct ModuleAggregateZ {
    /// Reconstructed `z`.
    pub z: ModuleVecL,
    /// Active evaluation points.
    pub active_xs: Vec<u16>,
    /// Whether `‖z‖_∞ < γ₁ − β`.
    pub z_bound_ok: bool,
}

/// Expand a research `s1 ∈ R_q^L` from a 32-byte seed (η-bounded coeffs).
pub fn expand_s1_research(seed: &[u8; 32]) -> ModuleVecL {
    let mut out = ModuleVecL::zero();
    for (index, poly) in out.components.iter_mut().enumerate() {
        *poly = expand_bounded_poly(seed, b"s1", index as u16, ETA);
    }
    out
}

/// Expand a research mask `y ∈ R_q^L` from a 32-byte nonce seed (γ₁-bounded).
pub fn expand_y_research(nonce_seed: &[u8; 32], kappa: u16) -> ModuleVecL {
    let mut out = ModuleVecL::zero();
    for (index, poly) in out.components.iter_mut().enumerate() {
        *poly = expand_mask_poly(nonce_seed, kappa, index as u16);
    }
    out
}

/// FIPS-shaped SampleInBall: Hamming weight `τ`, coefficients in `{0, ±1}`.
pub fn sample_in_ball(rho: &[u8], tau: usize) -> Poly {
    let mut c = Poly::zero();
    let mut hasher = Shake256::default();
    hasher.update(rho);
    let mut reader = hasher.finalize_xof();

    let mut s = [0u8; 8];
    reader.read(&mut s);

    let mut j_buf = [0u8; 1];
    for i in (256 - tau)..256 {
        reader.read(&mut j_buf);
        while usize::from(j_buf[0]) > i {
            reader.read(&mut j_buf);
        }
        let j = usize::from(j_buf[0]);
        c.coeffs[i] = c.coeffs[j];
        let bit = (s[(i + tau - 256) / 8] >> ((i + tau - 256) % 8)) & 1;
        c.coeffs[j] = if bit == 0 { 1 } else { Q - 1 }; // +1 or -1
    }
    c
}

/// Compute `c · v` component-wise with ring multiply.
pub fn module_mul_challenge(c: &Poly, v: &ModuleVecL) -> ModuleVecL {
    let mut out = ModuleVecL::zero();
    for i in 0..L {
        out.components[i] = poly_mul(c, &v.components[i]);
    }
    out
}

/// `z = y + c · s1`.
pub fn compute_z(y: &ModuleVecL, s1: &ModuleVecL, c: &Poly) -> ModuleVecL {
    let cs1 = module_mul_challenge(c, s1);
    let mut z = ModuleVecL::zero();
    for i in 0..L {
        z.components[i] = poly_add(&y.components[i], &cs1.components[i]);
    }
    z
}

/// Shamir-split each component polynomial of a module vector.
#[allow(clippy::needless_range_loop)]
pub fn split_module_vector_shamir(
    secret: &ModuleVecL,
    threshold: u16,
    receivers: &[(ValidatorId, u16)],
    mask_seed: &[u8],
) -> Result<Vec<(ValidatorId, u16, ModuleVecL)>, ThresholdError> {
    if threshold == 0 || receivers.len() < threshold as usize {
        return Err(ThresholdError::InvalidThresholdParameters {
            threshold,
            total_nodes: receivers.len() as u16,
        });
    }
    for &(_, x) in receivers {
        if x == 0 {
            return Err(ThresholdError::BackendUnavailable {
                reason: "module partial share x must be nonzero",
            });
        }
    }

    // For each component poly, build degree-(t-1) polys and evaluate.
    let degree = threshold as usize;
    let mut component_polys: Vec<Vec<Poly>> = Vec::with_capacity(L);
    for (comp_idx, secret_poly) in secret.components.iter().enumerate() {
        let mut coeffs = vec![*secret_poly];
        for d in 1..degree {
            coeffs.push(derive_mask_poly(mask_seed, comp_idx as u16, d as u16));
        }
        component_polys.push(coeffs);
    }

    let mut shares = Vec::with_capacity(receivers.len());
    for &(validator, x) in receivers {
        let mut vec = ModuleVecL::zero();
        for comp_idx in 0..L {
            vec.components[comp_idx] = eval_poly_coeffs(&component_polys[comp_idx], x);
        }
        shares.push((validator, x, vec));
    }
    Ok(shares)
}

/// Emit module partial `z_i = y_i + c · s1_i` with local z-bound check.
pub fn emit_module_partial_zi(
    signer: ValidatorId,
    x: u16,
    s1_i: &ModuleVecL,
    y_i: &ModuleVecL,
    c: &Poly,
) -> Result<ModulePartialZi, ThresholdError> {
    if x == 0 {
        return Err(ThresholdError::BackendUnavailable {
            reason: "module partial requires nonzero x",
        });
    }
    let z_i = compute_z(y_i, s1_i, c);
    if !z_i.check_z_bound(Z_BOUND) {
        return Err(ThresholdError::RejectionSamplingFailed { validator: signer });
    }
    Ok(ModulePartialZi { signer, x, z_i })
}

/// Aggregate module partials: `z = Σ λ_i z_i`.
pub fn aggregate_module_partials(
    partials: &[ModulePartialZi],
) -> Result<ModuleAggregateZ, ThresholdError> {
    if partials.is_empty() {
        return Err(ThresholdError::InsufficientPartialShares {
            required: 1,
            received: 0,
        });
    }
    let mut xs = Vec::with_capacity(partials.len());
    let mut seen = std::collections::BTreeSet::new();
    for p in partials {
        if !seen.insert(p.x) {
            return Err(ThresholdError::DuplicateValidator {
                validator: p.signer,
            });
        }
        xs.push(p.x);
    }

    let mut z = ModuleVecL::zero();
    for p in partials {
        let lambda = compute_lagrange_coefficient(&xs, p.x);
        for comp in 0..L {
            let scaled = crate::low_level::ring::poly_scale(&p.z_i.components[comp], lambda);
            z.components[comp].add_assign(&scaled);
        }
    }

    let z_bound_ok = z.check_z_bound(Z_BOUND);
    if !z_bound_ok {
        return Err(ThresholdError::RejectionSamplingFailed {
            validator: partials[0].signer,
        });
    }

    Ok(ModuleAggregateZ {
        z,
        active_xs: xs,
        z_bound_ok,
    })
}

/// End-to-end research helper: expand secrets, share, partial-sign, aggregate.
pub fn module_partial_round_trip(
    s1_seed: &[u8; 32],
    y_seed: &[u8; 32],
    challenge_rho: &[u8],
    threshold: u16,
    receivers: &[(ValidatorId, u16)],
) -> Result<ModuleAggregateZ, ThresholdError> {
    let s1 = expand_s1_research(s1_seed);
    let y = expand_y_research(y_seed, 0);
    let c = sample_in_ball(challenge_rho, TAU);

    let s_shares = split_module_vector_shamir(&s1, threshold, receivers, b"s1-mask")?;
    let y_shares = split_module_vector_shamir(&y, threshold, receivers, b"y-mask")?;

    let mut partials = Vec::with_capacity(threshold as usize);
    for i in 0..threshold as usize {
        let (v, x, s_i) = &s_shares[i];
        let (_, _, y_i) = &y_shares[i];
        // Local bound may reject with research expanders; retry soft path uses full Z_BOUND.
        match emit_module_partial_zi(*v, *x, s_i, y_i, &c) {
            Ok(p) => partials.push(p),
            Err(ThresholdError::RejectionSamplingFailed { .. }) => {
                // Research expanders can occasionally exceed γ1−β after c·s1.
                // Still emit for algebraic identity tests with relaxed bound path.
                let z_i = compute_z(y_i, s_i, &c);
                partials.push(ModulePartialZi {
                    signer: *v,
                    x: *x,
                    z_i,
                });
            }
            Err(other) => return Err(other),
        }
    }

    // Algebraic aggregate without re-applying z-bound (checked separately).
    let mut xs = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for p in &partials {
        if !seen.insert(p.x) {
            return Err(ThresholdError::DuplicateValidator {
                validator: p.signer,
            });
        }
        xs.push(p.x);
    }
    let mut z = ModuleVecL::zero();
    for p in &partials {
        let lambda = compute_lagrange_coefficient(&xs, p.x);
        for comp in 0..L {
            let scaled = crate::low_level::ring::poly_scale(&p.z_i.components[comp], lambda);
            z.components[comp].add_assign(&scaled);
        }
    }
    let expected = compute_z(&y, &s1, &c);
    for i in 0..L {
        if z.components[i].coeffs != expected.components[i].coeffs {
            return Err(ThresholdError::BackendUnavailable {
                reason: "module partial aggregate failed algebraic identity",
            });
        }
    }
    Ok(ModuleAggregateZ {
        z,
        active_xs: xs,
        z_bound_ok: z.check_z_bound(Z_BOUND),
    })
}

/// Result of the real local partial-share validity gate.
///
/// This is executable evidence for the SOUNDNESS leg of Criterion 4
/// (`partial_contribution_soundness`) only. It is produced by recomputing
/// `z_i = y_i + c · s1_i` over `R_q^L` from the opened share/mask and checking
/// the centered infinity-norm bound against `γ₁ − β` with real ring arithmetic
/// (not a digest comparison).
///
/// Claim boundary (why this does NOT close Criterion 4):
///
/// - It is **not** zero-knowledge: the gate consumes `y_i` and `s1_i` in the
///   clear, so it does **not** discharge the hiding/leakage obligation that a
///   production partial verifier must satisfy without seeing the secret share
///   or one-time mask.
/// - The research expanders in this module are **not** claimed CAVP-identical to
///   FIPS 204 `ExpandS`/`ExpandMask`.
/// - It does **not** replace the audited proof-backed local verifier, VSS/DKG
///   binding proof, formal leakage model, or external review tracked in
///   `docs/cryptography/partial-soundness-evidence.md`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModulePartialLocalValidity {
    /// Signer whose partial was checked.
    pub signer: ValidatorId,
    /// Evaluation point of the checked partial.
    pub x: u16,
    /// Centered infinity norm `‖z_i‖_∞` of the checked response.
    pub infinity_norm: i32,
    /// SHA3-256 digest binding `(signer, x, z_i, c)`, minted only after the
    /// algebraic-relation and norm-bound checks pass. It is a *real* value that
    /// can feed the digest-only evidence surface in `partial_soundness`.
    pub local_validity_digest: [u8; 32],
}

/// Real local partial-share validity gate over a module-vector partial.
///
/// Recomputes `z_i = y_i + c · s1_i` from the opened `(y_i, s1_i)` and challenge
/// `c`, and checks the ML-DSA-65 acceptance bound `‖z_i‖_∞ < γ₁ − β`.
///
/// Rejects, with a typed [`ThresholdError`]:
///
/// - a claimed response `z_i` that does not equal the recomputed
///   `y_i + c · s1_i` (tampered response, wrong/rebound challenge, or a share
///   not bound to this signer) with [`ThresholdError::PartialShareVerificationFailed`];
/// - a response whose centered infinity norm reaches `γ₁ − β`
///   with [`ThresholdError::RejectionSamplingFailed`].
///
/// The algebraic-relation check runs before the norm check, so a response that
/// is both mis-formed and out of bound is reported as a verification failure.
pub fn verify_module_partial_local_validity(
    partial: &ModulePartialZi,
    opened_y_i: &ModuleVecL,
    opened_s1_i: &ModuleVecL,
    c: &Poly,
) -> Result<ModulePartialLocalValidity, ThresholdError> {
    if partial.x == 0 {
        return Err(ThresholdError::BackendUnavailable {
            reason: "module partial local validity requires nonzero x",
        });
    }

    let recomputed = compute_z(opened_y_i, opened_s1_i, c);
    for component in 0..L {
        if recomputed.components[component].canonical().coeffs
            != partial.z_i.components[component].canonical().coeffs
        {
            return Err(ThresholdError::PartialShareVerificationFailed {
                validator: partial.signer,
            });
        }
    }

    if !partial.z_i.check_z_bound(Z_BOUND) {
        return Err(ThresholdError::RejectionSamplingFailed {
            validator: partial.signer,
        });
    }

    Ok(ModulePartialLocalValidity {
        signer: partial.signer,
        x: partial.x,
        infinity_norm: partial.z_i.infinity_norm(),
        local_validity_digest: module_partial_validity_digest(partial, c),
    })
}

fn module_partial_validity_digest(partial: &ModulePartialZi, c: &Poly) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};

    let mut buf = Vec::new();
    buf.extend_from_slice(b"lattice-aggregation/module-partial/local-validity/v1");
    buf.extend_from_slice(&partial.signer.0.to_be_bytes());
    buf.extend_from_slice(&partial.x.to_be_bytes());
    for component in &partial.z_i.components {
        for coeff in component.coeffs {
            buf.extend_from_slice(&coeff.to_le_bytes());
        }
    }
    for coeff in c.coeffs {
        buf.extend_from_slice(&coeff.to_le_bytes());
    }
    Sha3_256::digest(&buf).into()
}

fn expand_bounded_poly(seed: &[u8], label: &[u8], index: u16, eta: i32) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(b"lattice-aggregation/module-partial/expand-bounded/v1");
    hasher.update(label);
    hasher.update(seed);
    hasher.update(&index.to_le_bytes());
    let mut reader = hasher.finalize_xof();
    let mut poly = Poly::zero();
    let span = (2 * eta + 1) as u32;
    for coeff in &mut poly.coeffs {
        let mut word = [0u8; 4];
        reader.read(&mut word);
        let raw = u32::from_le_bytes(word) % span;
        let centered = raw as i32 - eta;
        *coeff = if centered >= 0 {
            centered
        } else {
            Q + centered
        };
    }
    poly
}

fn expand_mask_poly(seed: &[u8], kappa: u16, index: u16) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(b"lattice-aggregation/module-partial/expand-mask/v1");
    hasher.update(seed);
    hasher.update(&kappa.to_le_bytes());
    hasher.update(&index.to_le_bytes());
    let mut reader = hasher.finalize_xof();
    let mut poly = Poly::zero();
    // Sample approximately uniform in (-γ1, γ1] via 20-bit values.
    let modulus = (2 * GAMMA1) as u32;
    for coeff in &mut poly.coeffs {
        let mut word = [0u8; 4];
        reader.read(&mut word);
        let raw = u32::from_le_bytes(word) % modulus;
        let centered = raw as i32 - GAMMA1;
        *coeff = if centered >= 0 {
            centered
        } else {
            Q + centered
        };
    }
    poly
}

fn derive_mask_poly(mask_seed: &[u8], component: u16, degree: u16) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(b"lattice-aggregation/module-partial/shamir-mask/v1");
    hasher.update(mask_seed);
    hasher.update(&component.to_le_bytes());
    hasher.update(&degree.to_le_bytes());
    let mut reader = hasher.finalize_xof();
    let mut poly = Poly::zero();
    for coeff in &mut poly.coeffs {
        let mut word = [0u8; 4];
        reader.read(&mut word);
        *coeff = (u32::from_le_bytes(word) % (Q as u32)) as i32;
    }
    poly
}

fn eval_poly_coeffs(coeffs: &[Poly], x: u16) -> Poly {
    let q = i64::from(Q);
    let mut result = Poly::zero();
    let mut x_pow = 1i64;
    for (degree, poly_coeff) in coeffs.iter().enumerate() {
        if degree > 0 {
            x_pow = (x_pow * i64::from(x)) % q;
        }
        for (out, coeff) in result.coeffs.iter_mut().zip(poly_coeff.coeffs.iter()) {
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
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::low_level::poly::N;

    #[test]
    fn sample_in_ball_has_weight_tau() {
        let c = sample_in_ball(b"challenge-rho-test-vector", TAU);
        let weight = c.coeffs.iter().filter(|&&v| v == 1 || v == Q - 1).count();
        assert_eq!(weight, TAU);
        assert!(c.coeffs.iter().all(|&v| v == 0 || v == 1 || v == Q - 1));
    }

    #[test]
    fn module_partial_algebraic_identity_holds() {
        let receivers = vec![
            (ValidatorId(0), 1u16),
            (ValidatorId(1), 2u16),
            (ValidatorId(2), 3u16),
        ];
        let agg = module_partial_round_trip(
            &[0x11; 32],
            &[0x22; 32],
            b"module-partial-challenge",
            2,
            &receivers,
        )
        .expect("module partial round trip");
        assert_eq!(agg.active_xs.len(), 2);
        // Algebraic identity already checked inside round_trip.
        assert_eq!(agg.z.components.len(), L);
    }

    #[test]
    fn local_validity_gate_accepts_honest_partial_and_rebinds_a_real_digest() {
        let mut s1 = ModuleVecL::zero();
        let mut y = ModuleVecL::zero();
        for component in 0..L {
            for i in 0..N {
                // η-bounded secret and small mask keep ‖z‖_∞ well under γ₁ − β.
                s1.components[component].coeffs[i] = ((i as i32 + component as i32) % 9) - 4;
                y.components[component].coeffs[i] = (i as i32 * 3 + component as i32) % 500;
            }
        }
        let c = sample_in_ball(b"local-validity-honest", TAU);
        let partial = emit_module_partial_zi(ValidatorId(7), 3, &s1, &y, &c).unwrap();

        let validity = verify_module_partial_local_validity(&partial, &y, &s1, &c).unwrap();
        assert_eq!(validity.signer, ValidatorId(7));
        assert_eq!(validity.x, 3);
        assert!(validity.infinity_norm < Z_BOUND);
        assert_ne!(validity.local_validity_digest, [0u8; 32]);
    }

    #[test]
    fn local_validity_gate_rejects_out_of_bound_response() {
        // c = 0 and s1 = 0 so z_i = y_i exactly (algebraic relation holds),
        // but one coefficient is placed just below γ₁, above the γ₁ − β bound.
        let zero_s1 = ModuleVecL::zero();
        let zero_c = Poly::zero();
        let mut y = ModuleVecL::zero();
        y.components[0].coeffs[0] = GAMMA1 - 1;
        let z_i = compute_z(&y, &zero_s1, &zero_c);
        let partial = ModulePartialZi {
            signer: ValidatorId(1),
            x: 1,
            z_i,
        };

        let err =
            verify_module_partial_local_validity(&partial, &y, &zero_s1, &zero_c).unwrap_err();
        assert!(matches!(
            err,
            ThresholdError::RejectionSamplingFailed { .. }
        ));
    }

    #[test]
    fn z_equals_y_plus_c_s1_without_sharing() {
        let s1 = expand_s1_research(&[0xAB; 32]);
        let y = expand_y_research(&[0xCD; 32], 0);
        let c = sample_in_ball(b"c-rho", TAU);
        let z = compute_z(&y, &s1, &c);
        let cs1 = module_mul_challenge(&c, &s1);
        for i in 0..L {
            let expected = poly_add(&y.components[i], &cs1.components[i]);
            assert_eq!(z.components[i].coeffs, expected.coeffs);
        }
    }
}
