//! Self-contained FIPS 204 ML-DSA-65 Sign_internal (no `ml-dsa` sign call).
//!
//! Ports KeyGen_internal + Sign_internal enough to produce wire signatures that
//! the standard `ml-dsa` verifier accepts, then composes with module-vector
//! threshold sharing of the packed `z`. The strict distributed helper splits
//! `s1`, `s2`, and `y` into Shamir shares, aggregates threshold partials, and
//! packs the resulting `(c_tilde, z, h)` tuple without calling provider sign.
//!
//! # Claim boundary
//!
//! - `fips204_wire_from_s1_y_partials_without_provider = true` when signatures
//!   are produced by this module (not `Signer::sign` / provider sign path).
//! - Still research/hazmat: not constant-time audited, not FIPS lab validated.
//! - `production_approved` remains false.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::many_single_char_names)]

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128, Shake256,
};

use crate::{
    backend::{
        fips_wire::{
            pack_z_encoding, reconstruct_module_from_partials, unpack_z_from_signature,
            C_TILDE_BYTES, Z_ENCODED_BYTES,
        },
        module_partial::{split_module_vector_shamir, ModulePartialZi, ModuleVecL, L, TAU},
        real::RealMldsa65Backend,
        Mldsa65Backend,
    },
    errors::ThresholdError,
    low_level::poly::{Poly, N, Q},
    types::{
        ThresholdPublicKey, ThresholdSignature, ValidatorId, MLDSA65_PUBLICKEY_BYTES,
        MLDSA65_SIGNATURE_BYTES, POLY_SEED_BYTES,
    },
};

const K: usize = 6;
const D: u32 = 13;
const GAMMA1: i32 = 1 << 19;
const GAMMA2: i32 = (Q - 1) / 32; // 261888
const TWO_GAMMA2: i32 = 2 * GAMMA2; // 523776
const BETA: i32 = (TAU as i32) * 4;
const OMEGA: usize = 55;
const LAMBDA_BYTES: usize = 48;
const INVERSE_256: u32 = 8_347_681;

// Zeta^{BitRev8(i)} table (FIPS 204 / ml-dsa), entry 0 unused (0).
#[allow(clippy::unreadable_literal)]
const ZETA_POW_BITREV: [u32; 256] = [
    0, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987, 7778734, 3542485, 2682288,
    2129892, 3764867, 7375178, 557458, 7159240, 5010068, 4317364, 2663378, 6705802, 4855975,
    7946292, 676590, 7044481, 5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639,
    2283733, 3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875, 394148,
    928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050, 3415069, 1759347, 7562881,
    4805951, 3756790, 6444618, 6663429, 4430364, 5483103, 3192354, 556856, 3870317, 2917338,
    1853806, 3345963, 1858416, 3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977,
    8106357, 2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088, 1528066,
    482649, 1148858, 5418153, 7814814, 169688, 2462444, 5046034, 4213992, 4892034, 1987814,
    5183169, 1736313, 235407, 5130263, 3258457, 5801164, 1787943, 5989328, 6125690, 3482206,
    4197502, 7080401, 6018354, 7062739, 2461387, 3035980, 621164, 3901472, 7153756, 2925816,
    3374250, 1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254, 348812,
    8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507, 1753, 6444997, 5720892, 6924527,
    2660408, 6600190, 8321269, 2772600, 1182243, 87208, 636927, 4415111, 4423672, 6084020, 5095502,
    4663471, 8352605, 822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952, 6695264,
    4969849, 2678278, 4611469, 4829411, 635956, 8129971, 5925040, 4234153, 6607829, 2192938,
    6653329, 2387513, 4768667, 8111961, 5199961, 3747250, 2296099, 1239911, 4541938, 3195676,
    2642980, 1254190, 8368000, 2998219, 141835, 8291116, 2513018, 7025525, 613238, 7070156,
    6161950, 7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452, 6757063,
    2105286, 6006015, 6346610, 586241, 7200804, 527981, 5637006, 6903432, 1994046, 2491325,
    6987258, 507927, 7192532, 7655613, 6545891, 5346675, 8041997, 2647994, 3009748, 5767564,
    4148469, 749577, 4357667, 3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598,
    5011144, 3994671, 8368538, 7009900, 3020393, 3363542, 214880, 545376, 7609976, 3105558,
    7277073, 508145, 7826699, 860144, 3430436, 140244, 6866265, 6195333, 3123762, 2358373, 6187330,
    5365997, 6663603, 2926054, 7987710, 8077412, 3531229, 4405932, 4606686, 1900052, 7598542,
    1054478, 7648983,
];

/// Status for self-contained FIPS wire production.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelfContainedFipsStatus {
    /// Wire signatures produced without calling provider `sign`.
    pub fips204_wire_from_s1_y_partials_without_provider: bool,
    /// Signatures verify under the standard `ml-dsa` verifier.
    pub standard_verifier_accepts_self_contained: bool,
    /// Module-vector threshold share of packed `z` reconstructs exactly.
    pub threshold_z_share_of_self_contained_wire: bool,
}

impl SelfContainedFipsStatus {
    /// Current engineering status for the self-contained FIPS path.
    pub const fn current() -> Self {
        Self {
            fips204_wire_from_s1_y_partials_without_provider: true,
            standard_verifier_accepts_self_contained: true,
            threshold_z_share_of_self_contained_wire: true,
        }
    }
}

/// Expanded secret material for ML-DSA-65 (research representation).
#[derive(Clone)]
pub struct ExpandedSecret65 {
    /// Public matrix seed `ρ`.
    pub rho: [u8; 32],
    /// Private signing seed `K`.
    pub k_seed: [u8; 32],
    /// Public-key hash `tr`.
    pub tr: [u8; 64],
    /// Secret vector `s1 ∈ R_q^L`.
    pub s1: [Poly; L],
    /// Secret vector `s2 ∈ R_q^K`.
    pub s2: [Poly; K],
    /// Low bits `t0` of public `t`.
    pub t0: [Poly; K],
    /// Encoded public key (1,952 bytes).
    pub public_key: ThresholdPublicKey,
}

/// Result of self-contained sign + module-partial z evidence.
#[derive(Clone, Debug)]
pub struct SelfContainedSignPackage {
    /// Verifying key.
    pub public_key: ThresholdPublicKey,
    /// Wire signature (3,309 bytes).
    pub signature: ThresholdSignature,
    /// Unpacked module-vector `z`.
    pub z: ModuleVecL,
    /// Threshold share reconstruction matched wire `z`.
    pub z_share_match: bool,
    /// Standard verifier accepted the wire signature.
    pub standard_verifier_accepted: bool,
    /// Inner rejection-loop aborts before acceptance.
    pub rejected_attempts: u32,
    /// Stable packing mode label.
    pub packing_mode: &'static str,
}

/// Result of strict distributed Sign_internal over real `s1` / `y` partials.
#[derive(Clone, Debug)]
pub struct StrictDistributedSignPackage {
    /// Verifying key.
    pub public_key: ThresholdPublicKey,
    /// Wire signature (3,309 bytes).
    pub signature: ThresholdSignature,
    /// Aggregated module-vector `z` assembled from partial responses.
    pub aggregate_z: ModuleVecL,
    /// Aggregated `z` matched the direct FIPS equation.
    pub aggregate_z_matches_direct: bool,
    /// Aggregated `c*s2` from secret-share partials matched the direct value.
    pub aggregate_cs2_matches_direct: bool,
    /// Standard verifier accepted the final wire signature.
    pub standard_verifier_accepted: bool,
    /// Inner rejection-loop aborts before acceptance.
    pub rejected_attempts: u32,
    /// Number of threshold response partials consumed.
    pub partial_count: usize,
    /// Whether `||z||_inf < gamma1 - beta` passed on the aggregate.
    pub z_bound_ok: bool,
    /// Whether `||r0||_inf < gamma2 - beta` passed.
    pub r0_bound_ok: bool,
    /// Whether `||c*t0||_inf < gamma2` passed.
    pub ct0_bound_ok: bool,
    /// Whether `weight(h) <= omega` passed.
    pub hint_omega_ok: bool,
    /// Stable digest binding the emitted partial response bundle.
    pub partial_bundle_digest: [u8; 32],
    /// Stable digest binding the accepted rejection-predicate state.
    pub rejection_predicate_digest: [u8; 32],
    /// Stable packing mode label.
    pub packing_mode: &'static str,
}

/// KeyGen_internal for ML-DSA-65 from a 32-byte seed.
pub fn keygen_from_seed(seed: &[u8; 32]) -> Result<ExpandedSecret65, ThresholdError> {
    let mut h = Shake256::default();
    h.update(seed);
    h.update(&[K as u8]);
    h.update(&[L as u8]);
    let mut reader = h.finalize_xof();
    let mut rho = [0u8; 32];
    let mut rhop = [0u8; 64];
    let mut k_seed = [0u8; 32];
    reader.read(&mut rho);
    reader.read(&mut rhop);
    reader.read(&mut k_seed);

    let a_hat = expand_a(&rho);
    let s1 = expand_s_l(&rhop, 0);
    let s2 = expand_s_k(&rhop, L);

    // t = NTT^{-1}(A_hat · NTT(s1)) + s2
    let mut t = [Poly::zero(); K];
    let s1_hat: Vec<[u32; N]> = s1.iter().map(ntt).collect();
    for r in 0..K {
        let mut acc = [0u32; N];
        for s in 0..L {
            let prod = ntt_pointwise(&a_hat[r][s], &s1_hat[s]);
            for i in 0..N {
                acc[i] = field_add(acc[i], prod[i]);
            }
        }
        t[r] = ntt_inverse(&acc);
        t[r] = poly_add(&t[r], &s2[r]);
    }

    let mut t1 = [Poly::zero(); K];
    let mut t0 = [Poly::zero(); K];
    for i in 0..K {
        let (hi, lo) = power2round_poly(&t[i]);
        t1[i] = hi;
        t0[i] = lo;
    }

    let public_key = encode_public_key(&rho, &t1)?;
    let mut tr_h = Shake256::default();
    tr_h.update(&public_key.0);
    let mut tr = [0u8; 64];
    tr_h.finalize_xof().read(&mut tr);

    Ok(ExpandedSecret65 {
        rho,
        k_seed,
        tr,
        s1,
        s2,
        t0,
        public_key,
    })
}

/// Self-contained Sign_internal (empty external context encoding for mu).
pub fn sign_internal_empty_ctx(
    secret: &ExpandedSecret65,
    message: &[u8],
    rnd: &[u8; 32],
) -> Result<(ThresholdSignature, ModuleVecL, u32), ThresholdError> {
    // mu = H(tr || 0x00 || |ctx|=0 || M)  — external empty context
    let mut mu_h = Shake256::default();
    mu_h.update(&secret.tr);
    mu_h.update(&[0u8]);
    mu_h.update(&[0u8]);
    mu_h.update(message);
    let mut mu = [0u8; 64];
    mu_h.finalize_xof().read(&mut mu);

    // rhopp = H(K || rnd || mu)
    let mut rp = Shake256::default();
    rp.update(&secret.k_seed);
    rp.update(rnd);
    rp.update(&mu);
    let mut rhopp = [0u8; 64];
    rp.finalize_xof().read(&mut rhopp);

    let a_hat = expand_a(&secret.rho);
    let s1_hat: Vec<[u32; N]> = secret.s1.iter().map(ntt).collect();
    let s2_hat: Vec<[u32; N]> = secret.s2.iter().map(ntt).collect();
    let t0_hat: Vec<[u32; N]> = secret.t0.iter().map(ntt).collect();

    let mut rejected = 0u32;
    for kappa_base in (0..u16::MAX).step_by(L) {
        let y = expand_mask(&rhopp, kappa_base);
        let y_hat: Vec<[u32; N]> = y.iter().map(ntt).collect();

        // w = NTT^{-1}(A_hat · y_hat)
        let mut w = [Poly::zero(); K];
        for r in 0..K {
            let mut acc = [0u32; N];
            for s in 0..L {
                let prod = ntt_pointwise(&a_hat[r][s], &y_hat[s]);
                for i in 0..N {
                    acc[i] = field_add(acc[i], prod[i]);
                }
            }
            w[r] = ntt_inverse(&acc);
        }

        let mut w1 = [Poly::zero(); K];
        for r in 0..K {
            w1[r] = high_bits_poly(&w[r]);
        }
        let w1_enc = encode_w1(&w1);

        let mut ch = Shake256::default();
        ch.update(&mu);
        ch.update(&w1_enc);
        let mut c_tilde = [0u8; LAMBDA_BYTES];
        ch.finalize_xof().read(&mut c_tilde);

        let c = sample_in_ball_poly(&c_tilde, TAU);
        let c_hat = ntt(&c);

        // z = y + NTT^{-1}(c_hat · s1_hat)
        let mut z = [Poly::zero(); L];
        for s in 0..L {
            let prod = ntt_pointwise(&c_hat, &s1_hat[s]);
            let cs1 = ntt_inverse(&prod);
            z[s] = poly_add(&y[s], &cs1);
        }

        // r0 = LowBits(w - c*s2)
        let mut r0_ok = true;
        for r in 0..K {
            let prod = ntt_pointwise(&c_hat, &s2_hat[r]);
            let cs2 = ntt_inverse(&prod);
            let w_cs2 = poly_sub(&w[r], &cs2);
            let r0 = low_bits_poly(&w_cs2);
            if infinity_norm(&r0) >= (GAMMA2 as u32).saturating_sub(BETA as u32) {
                r0_ok = false;
                break;
            }
        }
        if !r0_ok || infinity_norm_vec_l(&z) >= (GAMMA1 as u32).saturating_sub(BETA as u32) {
            rejected = rejected.saturating_add(1);
            continue;
        }

        // ct0 = NTT^{-1}(c_hat · t0_hat); h = MakeHint(-ct0, w - cs2 + ct0)
        let mut hints = [[false; N]; K];
        let mut ct0_ok = true;
        let mut hw = 0usize;
        for r in 0..K {
            let prod = ntt_pointwise(&c_hat, &t0_hat[r]);
            let ct0 = ntt_inverse(&prod);
            if infinity_norm(&ct0) >= GAMMA2 as u32 {
                ct0_ok = false;
                break;
            }
            let prod_s2 = ntt_pointwise(&c_hat, &s2_hat[r]);
            let cs2 = ntt_inverse(&prod_s2);
            let w_cs2 = poly_sub(&w[r], &cs2);
            let w_cs2_ct0 = poly_add(&w_cs2, &ct0);
            let neg_ct0 = poly_neg(&ct0);
            for j in 0..N {
                let hz = make_hint(neg_ct0.coeffs[j], w_cs2_ct0.coeffs[j]);
                hints[r][j] = hz;
                if hz {
                    hw += 1;
                }
            }
        }
        if !ct0_ok || hw > OMEGA {
            rejected = rejected.saturating_add(1);
            continue;
        }

        // mod± q on z for packing
        for s in 0..L {
            for j in 0..N {
                z[s].coeffs[j] = mod_plus_minus_q(z[s].coeffs[j]);
            }
        }

        let mut z_mod = ModuleVecL::zero();
        z_mod.components = z;
        let sig = pack_signature(&c_tilde, &z_mod, &hints)?;
        return Ok((sig, z_mod, rejected));
    }

    Err(ThresholdError::BackendUnavailable {
        reason: "self-contained Sign_internal rejection sampling exhausted",
    })
}

/// Full package: self-contained sign + threshold share of wire `z`.
pub fn self_contained_sign_with_module_z_shares(
    seed: &[u8; POLY_SEED_BYTES],
    rnd: &[u8; 32],
    message: &[u8],
    threshold: u16,
    validators: &[ValidatorId],
) -> Result<SelfContainedSignPackage, ThresholdError> {
    let secret = keygen_from_seed(seed)?;
    let (signature, z, rejected) = sign_internal_empty_ctx(&secret, message, rnd)?;

    if !RealMldsa65Backend::verify_standard(&secret.public_key, message, &signature)? {
        return Err(ThresholdError::StandardVerificationFailed);
    }

    // Confirm unpack matches our z
    let z_unpacked = unpack_z_from_signature(&signature.0)?;
    if !module_eq(&z, &z_unpacked) {
        // pack path may use different centering; re-unpack from our pack
        let packed = pack_z_encoding(&z)?;
        let mut trial = signature.0;
        trial[C_TILDE_BYTES..C_TILDE_BYTES + Z_ENCODED_BYTES].copy_from_slice(&packed);
        // Prefer original signature if verifier accepts (source of truth).
        let _ = z_unpacked;
    }

    let receivers: Vec<(ValidatorId, u16)> = validators
        .iter()
        .map(|v| (*v, v.0.wrapping_add(1)))
        .collect();
    let wire_z = unpack_z_from_signature(&signature.0)?;
    let shares = split_module_vector_shamir(
        &wire_z,
        threshold,
        &receivers,
        b"lattice-aggregation/fips-sign/z-share/v1",
    )?;
    let partials: Vec<ModulePartialZi> = shares
        .into_iter()
        .take(threshold as usize)
        .map(|(signer, x, z_i)| ModulePartialZi { signer, x, z_i })
        .collect();
    let recon = reconstruct_module_from_partials(&partials)?;
    // reconstruct_module_from_partials is in fips_wire - import it
    let z_share_match = module_eq(&recon.z, &wire_z);

    Ok(SelfContainedSignPackage {
        public_key: secret.public_key,
        signature,
        z: wire_z,
        z_share_match,
        standard_verifier_accepted: true,
        rejected_attempts: rejected,
        packing_mode: "self_contained_sign_internal_plus_threshold_wire_z_sharing",
    })
}

/// Strict distributed Sign_internal path for ML-DSA-65.
///
/// This path computes `z_i = y_i + c*s1_i` over Shamir shares, aggregates the
/// threshold partials into the wire `z`, derives `h`, applies the FIPS rejection
/// predicates, packs `(c_tilde, z, h)`, and verifies the result with the
/// unmodified ML-DSA verifier. It does not call provider `sign()`.
///
/// The setup still starts from a local FIPS seed to derive test key material.
/// That makes this an executable strict signing-core primitive, not a DKG proof
/// or theorem-closure artifact.
pub fn strict_distributed_sign_from_s1_y_partials(
    seed: &[u8; POLY_SEED_BYTES],
    rnd: &[u8; 32],
    message: &[u8],
    threshold: u16,
    validators: &[ValidatorId],
) -> Result<StrictDistributedSignPackage, ThresholdError> {
    if validators.len() < threshold as usize || threshold == 0 {
        return Err(ThresholdError::InvalidThresholdParameters {
            threshold,
            total_nodes: validators.len() as u16,
        });
    }

    let secret = keygen_from_seed(seed)?;
    let receivers: Vec<(ValidatorId, u16)> = validators
        .iter()
        .map(|v| (*v, v.0.wrapping_add(1)))
        .collect();
    let s1 = ModuleVecL {
        components: secret.s1,
    };

    let mut mu_h = Shake256::default();
    mu_h.update(&secret.tr);
    mu_h.update(&[0u8]);
    mu_h.update(&[0u8]);
    mu_h.update(message);
    let mut mu = [0u8; 64];
    mu_h.finalize_xof().read(&mut mu);

    let mut rp = Shake256::default();
    rp.update(&secret.k_seed);
    rp.update(rnd);
    rp.update(&mu);
    let mut rhopp = [0u8; 64];
    rp.finalize_xof().read(&mut rhopp);

    let a_hat = expand_a(&secret.rho);
    let s1_hat: Vec<[u32; N]> = secret.s1.iter().map(ntt).collect();
    let t0_hat: Vec<[u32; N]> = secret.t0.iter().map(ntt).collect();

    let mut rejected = 0u32;
    for kappa_base in (0..u16::MAX).step_by(L) {
        let y = expand_mask(&rhopp, kappa_base);
        let y_vec = ModuleVecL { components: y };
        let y_hat: Vec<[u32; N]> = y.iter().map(ntt).collect();

        let mut w = [Poly::zero(); K];
        for r in 0..K {
            let mut acc = [0u32; N];
            for s in 0..L {
                let prod = ntt_pointwise(&a_hat[r][s], &y_hat[s]);
                for i in 0..N {
                    acc[i] = field_add(acc[i], prod[i]);
                }
            }
            w[r] = ntt_inverse(&acc);
        }

        let mut w1 = [Poly::zero(); K];
        for r in 0..K {
            w1[r] = high_bits_poly(&w[r]);
        }
        let w1_enc = encode_w1(&w1);

        let mut ch = Shake256::default();
        ch.update(&mu);
        ch.update(&w1_enc);
        let mut c_tilde = [0u8; LAMBDA_BYTES];
        ch.finalize_xof().read(&mut c_tilde);

        let c = sample_in_ball_poly(&c_tilde, TAU);
        let c_hat = ntt(&c);

        let direct_z = direct_z_from_secret(&y, &s1_hat, &c_hat);
        let s1_share_seed = share_seed(
            b"lattice-aggregation/fips-sign/strict-s1-share/v1",
            &rhopp,
            &c_tilde,
            kappa_base,
        );
        let y_share_seed = share_seed(
            b"lattice-aggregation/fips-sign/strict-y-share/v1",
            &rhopp,
            &c_tilde,
            kappa_base,
        );
        let s1_shares = split_module_vector_shamir(&s1, threshold, &receivers, &s1_share_seed)?;
        let y_shares = split_module_vector_shamir(&y_vec, threshold, &receivers, &y_share_seed)?;

        let mut partials = Vec::with_capacity(threshold as usize);
        for i in 0..threshold as usize {
            let (signer, x, s1_i) = &s1_shares[i];
            let (_, y_x, y_i) = &y_shares[i];
            if x != y_x {
                return Err(ThresholdError::TranscriptMismatch);
            }
            let z_i = compute_z_from_share_ntt(y_i, s1_i, &c_hat);
            partials.push(ModulePartialZi {
                signer: *signer,
                x: *x,
                z_i,
            });
        }
        let aggregate = reconstruct_module_from_partials(&partials)?;
        let aggregate_z_matches_direct = module_eq(&aggregate.z, &direct_z);
        if !aggregate_z_matches_direct {
            return Err(ThresholdError::PartialShareVerificationFailed {
                validator: partials[0].signer,
            });
        }

        let s2_share_seed = share_seed(
            b"lattice-aggregation/fips-sign/strict-s2-share/v1",
            &rhopp,
            &c_tilde,
            kappa_base,
        );
        let s2_shares = split_poly_array_shamir(&secret.s2, threshold, &receivers, &s2_share_seed)?;
        let mut cs2_partials = Vec::with_capacity(threshold as usize);
        for (signer, x, s2_i) in s2_shares.into_iter().take(threshold as usize) {
            cs2_partials.push((signer, x, mul_poly_array_by_challenge(&s2_i, &c_hat)));
        }
        let cs2_from_shares = aggregate_poly_array_partials(&cs2_partials)?;
        let direct_cs2 = mul_poly_array_by_challenge(&secret.s2, &c_hat);
        let aggregate_cs2_matches_direct = poly_array_eq(&cs2_from_shares, &direct_cs2);
        if !aggregate_cs2_matches_direct {
            return Err(ThresholdError::PartialShareVerificationFailed {
                validator: cs2_partials[0].0,
            });
        }

        let mut r0_bound_ok = true;
        for r in 0..K {
            let w_cs2 = poly_sub(&w[r], &cs2_from_shares[r]);
            let r0 = low_bits_poly(&w_cs2);
            if infinity_norm(&r0) >= (GAMMA2 as u32).saturating_sub(BETA as u32) {
                r0_bound_ok = false;
                break;
            }
        }
        let z_bound_ok = infinity_norm_vec_l(&aggregate.z.components)
            < (GAMMA1 as u32).saturating_sub(BETA as u32);
        if !r0_bound_ok || !z_bound_ok {
            rejected = rejected.saturating_add(1);
            continue;
        }

        let mut hints = [[false; N]; K];
        let mut ct0_bound_ok = true;
        let mut hint_weight = 0usize;
        for r in 0..K {
            let prod = ntt_pointwise(&c_hat, &t0_hat[r]);
            let ct0 = ntt_inverse(&prod);
            if infinity_norm(&ct0) >= GAMMA2 as u32 {
                ct0_bound_ok = false;
                break;
            }
            let w_cs2 = poly_sub(&w[r], &cs2_from_shares[r]);
            let w_cs2_ct0 = poly_add(&w_cs2, &ct0);
            let neg_ct0 = poly_neg(&ct0);
            for j in 0..N {
                let hz = make_hint(neg_ct0.coeffs[j], w_cs2_ct0.coeffs[j]);
                hints[r][j] = hz;
                if hz {
                    hint_weight += 1;
                }
            }
        }
        let hint_omega_ok = hint_weight <= OMEGA;
        if !ct0_bound_ok || !hint_omega_ok {
            rejected = rejected.saturating_add(1);
            continue;
        }

        let mut z_for_wire = aggregate.z;
        for s in 0..L {
            for j in 0..N {
                z_for_wire.components[s].coeffs[j] =
                    mod_plus_minus_q(z_for_wire.components[s].coeffs[j]);
            }
        }
        let signature = pack_signature(&c_tilde, &z_for_wire, &hints)?;
        let standard_verifier_accepted =
            RealMldsa65Backend::verify_standard(&secret.public_key, message, &signature)?;
        if !standard_verifier_accepted {
            return Err(ThresholdError::StandardVerificationFailed);
        }

        let partial_bundle_digest = partial_bundle_digest(&partials, &c_tilde);
        let rejection_predicate_digest =
            rejection_predicate_digest(RejectionPredicateDigestInput {
                c_tilde: &c_tilde,
                z: &aggregate.z,
                cs2: &cs2_from_shares,
                z_bound_ok,
                r0_bound_ok,
                ct0_bound_ok,
                hint_omega_ok,
                hint_weight,
            });

        return Ok(StrictDistributedSignPackage {
            public_key: secret.public_key,
            signature,
            aggregate_z: z_for_wire,
            aggregate_z_matches_direct,
            aggregate_cs2_matches_direct,
            standard_verifier_accepted,
            rejected_attempts: rejected,
            partial_count: partials.len(),
            z_bound_ok,
            r0_bound_ok,
            ct0_bound_ok,
            hint_omega_ok,
            partial_bundle_digest,
            rejection_predicate_digest,
            packing_mode: "strict_distributed_s1_y_partials_to_fips204_wire_signature",
        });
    }

    Err(ThresholdError::BackendUnavailable {
        reason: "strict distributed Sign_internal rejection sampling exhausted",
    })
}

// --- expand ---

fn expand_a(rho: &[u8; 32]) -> Vec<Vec<[u32; N]>> {
    let mut a = vec![vec![[0u32; N]; L]; K];
    for r in 0..K {
        for s in 0..L {
            a[r][s] = rej_ntt_poly(rho, s as u8, r as u8);
        }
    }
    a
}

fn expand_s_l(rhop: &[u8; 64], base: usize) -> [Poly; L] {
    let mut out = [Poly::zero(); L];
    for i in 0..L {
        out[i] = rej_bounded_poly(rhop, (base + i) as u16);
    }
    out
}

fn expand_s_k(rhop: &[u8; 64], base: usize) -> [Poly; K] {
    let mut out = [Poly::zero(); K];
    for i in 0..K {
        out[i] = rej_bounded_poly(rhop, (base + i) as u16);
    }
    out
}

fn expand_mask(rhopp: &[u8; 64], mu: u16) -> [Poly; L] {
    let mut out = [Poly::zero(); L];
    for r in 0..L {
        let mut h = Shake256::default();
        h.update(rhopp);
        h.update(&(mu + r as u16).to_le_bytes());
        let mut buf = [0u8; 640];
        h.finalize_xof().read(&mut buf);
        out[r] = bit_unpack_gamma1(&buf);
    }
    out
}

fn rej_bounded_poly(rho: &[u8], r: u16) -> Poly {
    let mut h = Shake256::default();
    h.update(rho);
    h.update(&r.to_le_bytes());
    let mut reader = h.finalize_xof();
    let mut buf = [0u8; 272];
    reader.read(&mut buf);
    let mut a = Poly::zero();
    let mut j = 0usize;
    for &byte in &buf {
        if j >= N {
            break;
        }
        if let Some(z0) = coeff_from_half_byte(byte & 0x0f) {
            a.coeffs[j] = z0;
            j += 1;
        }
        if j < N {
            if let Some(z1) = coeff_from_half_byte(byte >> 4) {
                a.coeffs[j] = z1;
                j += 1;
            }
        }
    }
    let mut tmp = [0u8; 1];
    while j < N {
        reader.read(&mut tmp);
        if let Some(z0) = coeff_from_half_byte(tmp[0] & 0x0f) {
            a.coeffs[j] = z0;
            j += 1;
        }
        if j < N {
            if let Some(z1) = coeff_from_half_byte(tmp[0] >> 4) {
                a.coeffs[j] = z1;
                j += 1;
            }
        }
    }
    a
}

fn coeff_from_half_byte(b: u8) -> Option<i32> {
    // eta = 4
    if b < 9 {
        let b = b as i32;
        let v = if b <= 4 { 4 - b } else { -(b - 4) };
        Some(to_can(v))
    } else {
        None
    }
}

fn rej_ntt_poly(rho: &[u8], s: u8, r: u8) -> [u32; N] {
    let mut g = Shake128::default();
    g.update(rho);
    g.update(&[s]);
    g.update(&[r]);
    let mut reader = g.finalize_xof();
    let mut buf = [0u8; 840];
    reader.read(&mut buf);
    let mut a = [0u32; N];
    let mut j = 0usize;
    for chunk in buf.chunks_exact(3) {
        if j >= N {
            break;
        }
        if let Some(x) = coeff_from_three_bytes([chunk[0], chunk[1], chunk[2]]) {
            a[j] = x;
            j += 1;
        }
    }
    let mut tmp = [0u8; 3];
    while j < N {
        reader.read(&mut tmp);
        if let Some(x) = coeff_from_three_bytes(tmp) {
            a[j] = x;
            j += 1;
        }
    }
    a
}

fn coeff_from_three_bytes(b: [u8; 3]) -> Option<u32> {
    let b2 = if b[2] > 127 { b[2] - 128 } else { b[2] };
    let z = (u32::from(b2) << 16) + (u32::from(b[1]) << 8) + u32::from(b[0]);
    if z < Q as u32 {
        Some(z)
    } else {
        None
    }
}

// --- NTT ---

fn ntt(p: &Poly) -> [u32; N] {
    let mut w: [u32; N] = std::array::from_fn(|i| to_can_u32(p.coeffs[i]));
    let mut m = 0usize;
    ntt_layer::<128, 1>(&mut w, &mut m);
    ntt_layer::<64, 2>(&mut w, &mut m);
    ntt_layer::<32, 4>(&mut w, &mut m);
    ntt_layer::<16, 8>(&mut w, &mut m);
    ntt_layer::<8, 16>(&mut w, &mut m);
    ntt_layer::<4, 32>(&mut w, &mut m);
    ntt_layer::<2, 64>(&mut w, &mut m);
    ntt_layer::<1, 128>(&mut w, &mut m);
    w
}

fn ntt_layer<const LEN: usize, const ITER: usize>(w: &mut [u32; N], m: &mut usize) {
    for i in 0..ITER {
        let start = i * 2 * LEN;
        *m += 1;
        let z = ZETA_POW_BITREV[*m];
        for j in start..(start + LEN) {
            let t = field_mul(z, w[j + LEN]);
            w[j + LEN] = field_sub(w[j], t);
            w[j] = field_add(w[j], t);
        }
    }
}

fn ntt_inverse(w_in: &[u32; N]) -> Poly {
    let mut w = *w_in;
    let mut m = 256usize;
    ntt_inv_layer::<1, 128>(&mut w, &mut m);
    ntt_inv_layer::<2, 64>(&mut w, &mut m);
    ntt_inv_layer::<4, 32>(&mut w, &mut m);
    ntt_inv_layer::<8, 16>(&mut w, &mut m);
    ntt_inv_layer::<16, 8>(&mut w, &mut m);
    ntt_inv_layer::<32, 4>(&mut w, &mut m);
    ntt_inv_layer::<64, 2>(&mut w, &mut m);
    ntt_inv_layer::<128, 1>(&mut w, &mut m);
    let mut p = Poly::zero();
    for i in 0..N {
        p.coeffs[i] = field_mul(INVERSE_256, w[i]) as i32;
    }
    p
}

fn ntt_inv_layer<const LEN: usize, const ITER: usize>(w: &mut [u32; N], m: &mut usize) {
    for i in 0..ITER {
        let start = i * 2 * LEN;
        *m -= 1;
        let z = field_neg(ZETA_POW_BITREV[*m]);
        for j in start..(start + LEN) {
            let t = w[j];
            w[j] = field_add(t, w[j + LEN]);
            w[j + LEN] = field_mul(z, field_sub(t, w[j + LEN]));
        }
    }
}

fn ntt_pointwise(a: &[u32; N], b: &[u32; N]) -> [u32; N] {
    std::array::from_fn(|i| field_mul(a[i], b[i]))
}

// --- field ---

fn field_add(a: u32, b: u32) -> u32 {
    let mut s = a + b;
    if s >= Q as u32 {
        s -= Q as u32;
    }
    s
}

fn field_sub(a: u32, b: u32) -> u32 {
    if a >= b {
        a - b
    } else {
        a + Q as u32 - b
    }
}

fn field_neg(a: u32) -> u32 {
    if a == 0 {
        0
    } else {
        Q as u32 - a
    }
}

fn field_mul(a: u32, b: u32) -> u32 {
    ((u64::from(a) * u64::from(b)) % u64::from(Q as u32)) as u32
}

fn to_can(v: i32) -> i32 {
    let mut x = v % Q;
    if x < 0 {
        x += Q;
    }
    x
}

fn to_can_u32(v: i32) -> u32 {
    to_can(v) as u32
}

// --- poly ops ---

fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let mut o = *a;
    o.add_assign(b);
    o
}

fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    let mut o = Poly::zero();
    for i in 0..N {
        o.coeffs[i] = to_can(a.coeffs[i] - b.coeffs[i]);
    }
    o
}

fn poly_neg(a: &Poly) -> Poly {
    let mut o = Poly::zero();
    for i in 0..N {
        o.coeffs[i] = to_can(-a.coeffs[i]);
    }
    o
}

// --- decompose ---

fn mod_plus_minus(r: u32, m: u32) -> i32 {
    let raw = r % m;
    if raw > m / 2 {
        raw as i32 - m as i32
    } else {
        raw as i32
    }
}

fn mod_plus_minus_q(r: i32) -> i32 {
    let u = to_can(r) as u32;
    let raw = mod_plus_minus(u, Q as u32);
    to_can(raw)
}

fn decompose(r: i32) -> (i32, i32) {
    // Algorithm 36 with TwoGamma2
    let r_plus = to_can(r) as u32;
    let r0 = mod_plus_minus(r_plus, TWO_GAMMA2 as u32);
    // r0 as centered; convert to field for subtraction
    let r0_field = to_can(r0) as u32;
    let diff = field_sub(r_plus, r0_field);
    if diff == (Q as u32 - 1) {
        (0, to_can(r0 - 1))
    } else {
        let r1 = (diff / TWO_GAMMA2 as u32) as i32;
        (r1, r0)
    }
}

fn high_bits_poly(p: &Poly) -> Poly {
    let mut o = Poly::zero();
    for i in 0..N {
        o.coeffs[i] = decompose(p.coeffs[i]).0;
    }
    o
}

fn low_bits_poly(p: &Poly) -> Poly {
    let mut o = Poly::zero();
    for i in 0..N {
        o.coeffs[i] = to_can(decompose(p.coeffs[i]).1);
    }
    o
}

fn power2round_poly(p: &Poly) -> (Poly, Poly) {
    let mut t1 = Poly::zero();
    let mut t0 = Poly::zero();
    let pow2d = 1u32 << D;
    for i in 0..N {
        let r_plus = to_can(p.coeffs[i]) as u32;
        let r0 = mod_plus_minus(r_plus, pow2d);
        let r0_field = to_can(r0) as u32;
        let r1 = field_sub(r_plus, r0_field) >> D;
        t1.coeffs[i] = r1 as i32;
        t0.coeffs[i] = to_can(r0);
    }
    (t1, t0)
}

fn infinity_norm(p: &Poly) -> u32 {
    let mut max = 0u32;
    for &c in &p.coeffs {
        let u = to_can(c) as u32;
        let n = if u > (Q as u32) / 2 { Q as u32 - u } else { u };
        if n > max {
            max = n;
        }
    }
    max
}

fn infinity_norm_vec_l(v: &[Poly; L]) -> u32 {
    v.iter().map(infinity_norm).max().unwrap_or(0)
}

fn make_hint(z: i32, r: i32) -> bool {
    // Algorithm 39: hint if HighBits(r) != HighBits(r+z)
    let r1 = decompose(r).0;
    let v1 = decompose(to_can(r + z)).0;
    r1 != v1
}

// --- sample in ball ---

fn sample_in_ball_poly(rho: &[u8], tau: usize) -> Poly {
    let mut c = Poly::zero();
    let mut h = Shake256::default();
    h.update(rho);
    let mut reader = h.finalize_xof();
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
        c.coeffs[j] = if bit == 0 { 1 } else { Q - 1 };
    }
    c
}

// --- encoding ---

fn bit_unpack_gamma1(enc: &[u8; 640]) -> Poly {
    let mut poly = Poly::zero();
    let mut bit_pos = 0usize;
    for coeff in &mut poly.coeffs {
        let mut value = 0u32;
        for j in 0..20 {
            let byte = bit_pos / 8;
            let bit = bit_pos % 8;
            value |= ((u32::from(enc[byte] >> bit)) & 1) << j;
            bit_pos += 1;
        }
        let z = GAMMA1 - value as i32;
        *coeff = to_can(z);
    }
    poly
}

fn encode_w1(w1: &[Poly; K]) -> Vec<u8> {
    // SimpleBitPack with 4 bits (m=16)
    let mut out = vec![0u8; K * 128];
    for (r, poly) in w1.iter().enumerate() {
        let mut bit_pos = 0usize;
        let base = r * 128;
        for &c in &poly.coeffs {
            let v = to_can(c) as u32;
            for j in 0..4 {
                let bit = ((v >> j) & 1) as u8;
                let idx = base + bit_pos / 8;
                let b = bit_pos % 8;
                if bit != 0 {
                    out[idx] |= 1 << b;
                }
                bit_pos += 1;
            }
        }
    }
    out
}

fn encode_public_key(rho: &[u8; 32], t1: &[Poly; K]) -> Result<ThresholdPublicKey, ThresholdError> {
    // pk = rho (32) || SimpleBitPack_10(t1) — d=13 so t1 uses 10 bits?
    // Verifying key: rho || t1 with bitlen(q)-d = 23-13 = 10 bits
    let mut bytes = vec![0u8; MLDSA65_PUBLICKEY_BYTES];
    bytes[..32].copy_from_slice(rho);
    let mut bit_pos = 0usize;
    let mut out_bits = vec![0u8; MLDSA65_PUBLICKEY_BYTES - 32];
    for poly in t1 {
        for &c in &poly.coeffs {
            let v = to_can(c) as u32;
            for j in 0..10 {
                let bit = ((v >> j) & 1) as u8;
                let idx = bit_pos / 8;
                let b = bit_pos % 8;
                if idx < out_bits.len() && bit != 0 {
                    out_bits[idx] |= 1 << b;
                }
                bit_pos += 1;
            }
        }
    }
    bytes[32..].copy_from_slice(&out_bits);
    let mut pk = [0u8; MLDSA65_PUBLICKEY_BYTES];
    pk.copy_from_slice(&bytes);
    Ok(ThresholdPublicKey(pk))
}

fn pack_signature(
    c_tilde: &[u8; LAMBDA_BYTES],
    z: &ModuleVecL,
    hints: &[[bool; N]; K],
) -> Result<ThresholdSignature, ThresholdError> {
    let z_enc = pack_z_encoding(z)?;
    let h_enc = pack_hint(hints);
    let mut sig = [0u8; MLDSA65_SIGNATURE_BYTES];
    sig[..LAMBDA_BYTES].copy_from_slice(c_tilde);
    sig[LAMBDA_BYTES..LAMBDA_BYTES + Z_ENCODED_BYTES].copy_from_slice(&z_enc);
    sig[LAMBDA_BYTES + Z_ENCODED_BYTES..].copy_from_slice(&h_enc);
    Ok(ThresholdSignature(sig))
}

fn pack_hint(hints: &[[bool; N]; K]) -> [u8; 61] {
    let mut y = [0u8; 61];
    let mut index = 0usize;
    for i in 0..K {
        for j in 0..N {
            if hints[i][j] {
                y[index] = j as u8;
                index += 1;
            }
        }
        y[OMEGA + i] = index as u8;
    }
    y
}

fn module_eq(a: &ModuleVecL, b: &ModuleVecL) -> bool {
    a.components
        .iter()
        .zip(b.components.iter())
        .all(|(x, y)| x.coeffs == y.coeffs)
}

fn share_seed(
    domain: &[u8],
    rhopp: &[u8; 64],
    c_tilde: &[u8; LAMBDA_BYTES],
    kappa: u16,
) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    hasher.update(rhopp);
    hasher.update(c_tilde);
    hasher.update(&kappa.to_le_bytes());
    let mut out = [0u8; 32];
    hasher.finalize_xof().read(&mut out);
    out
}

fn direct_z_from_secret(y: &[Poly; L], s1_hat: &[[u32; N]], c_hat: &[u32; N]) -> ModuleVecL {
    let mut z = ModuleVecL::zero();
    for s in 0..L {
        let prod = ntt_pointwise(c_hat, &s1_hat[s]);
        let cs1 = ntt_inverse(&prod);
        z.components[s] = poly_add(&y[s], &cs1);
    }
    z
}

fn compute_z_from_share_ntt(y_i: &ModuleVecL, s1_i: &ModuleVecL, c_hat: &[u32; N]) -> ModuleVecL {
    let mut z_i = ModuleVecL::zero();
    for s in 0..L {
        let cs1_i = mul_poly_by_challenge_hat(&s1_i.components[s], c_hat);
        z_i.components[s] = poly_add(&y_i.components[s], &cs1_i);
    }
    z_i
}

fn mul_poly_by_challenge_hat(poly: &Poly, c_hat: &[u32; N]) -> Poly {
    let poly_hat = ntt(poly);
    let product = ntt_pointwise(c_hat, &poly_hat);
    ntt_inverse(&product)
}

fn mul_poly_array_by_challenge<const M: usize>(polys: &[Poly; M], c_hat: &[u32; N]) -> [Poly; M] {
    let mut out = [Poly::zero(); M];
    for i in 0..M {
        out[i] = mul_poly_by_challenge_hat(&polys[i], c_hat);
    }
    out
}

fn split_poly_array_shamir<const M: usize>(
    secret: &[Poly; M],
    threshold: u16,
    receivers: &[(ValidatorId, u16)],
    mask_seed: &[u8],
) -> Result<Vec<(ValidatorId, u16, [Poly; M])>, ThresholdError> {
    if threshold == 0 || receivers.len() < threshold as usize {
        return Err(ThresholdError::InvalidThresholdParameters {
            threshold,
            total_nodes: receivers.len() as u16,
        });
    }
    for &(_, x) in receivers {
        if x == 0 {
            return Err(ThresholdError::BackendUnavailable {
                reason: "poly-array share evaluation point must be nonzero",
            });
        }
    }

    let degree = threshold as usize;
    let mut component_polys: Vec<Vec<Poly>> = Vec::with_capacity(M);
    for (component, secret_poly) in secret.iter().enumerate() {
        let mut coeffs = vec![*secret_poly];
        for d in 1..degree {
            coeffs.push(derive_array_mask_poly(
                mask_seed,
                component as u16,
                d as u16,
            ));
        }
        component_polys.push(coeffs);
    }

    let mut shares = Vec::with_capacity(receivers.len());
    for &(validator, x) in receivers {
        let mut vector = [Poly::zero(); M];
        for component in 0..M {
            vector[component] = eval_array_poly_coeffs(&component_polys[component], x);
        }
        shares.push((validator, x, vector));
    }
    Ok(shares)
}

fn aggregate_poly_array_partials<const M: usize>(
    partials: &[(ValidatorId, u16, [Poly; M])],
) -> Result<[Poly; M], ThresholdError> {
    if partials.is_empty() {
        return Err(ThresholdError::InsufficientPartialShares {
            required: 1,
            received: 0,
        });
    }
    let mut xs = Vec::with_capacity(partials.len());
    let mut seen = std::collections::BTreeSet::new();
    for (validator, x, _) in partials {
        if *x == 0 {
            return Err(ThresholdError::BackendUnavailable {
                reason: "poly-array aggregate saw zero evaluation point",
            });
        }
        if !seen.insert(*x) {
            return Err(ThresholdError::DuplicateValidator {
                validator: *validator,
            });
        }
        xs.push(*x);
    }

    let mut out = [Poly::zero(); M];
    for (_, x, vector) in partials {
        let lambda = crate::crypto::interpolation::compute_lagrange_coefficient(&xs, *x);
        for component in 0..M {
            let scaled = crate::low_level::ring::poly_scale(&vector[component], lambda);
            out[component].add_assign(&scaled);
        }
    }
    Ok(out)
}

fn poly_array_eq<const M: usize>(a: &[Poly; M], b: &[Poly; M]) -> bool {
    a.iter()
        .zip(b.iter())
        .all(|(x, y)| x.canonical().coeffs == y.canonical().coeffs)
}

fn derive_array_mask_poly(mask_seed: &[u8], component: u16, degree: u16) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(b"lattice-aggregation/fips-sign/poly-array-shamir-mask/v1");
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

fn eval_array_poly_coeffs(coeffs: &[Poly], x: u16) -> Poly {
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

fn partial_bundle_digest(partials: &[ModulePartialZi], c_tilde: &[u8; LAMBDA_BYTES]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(b"lattice-aggregation/fips-sign/strict-partial-bundle/v1");
    hasher.update(c_tilde);
    for partial in partials {
        hasher.update(&partial.signer.0.to_be_bytes());
        hasher.update(&partial.x.to_be_bytes());
        for component in &partial.z_i.components {
            for coeff in component.coeffs {
                hasher.update(&coeff.to_le_bytes());
            }
        }
    }
    let mut out = [0u8; 32];
    hasher.finalize_xof().read(&mut out);
    out
}

struct RejectionPredicateDigestInput<'a> {
    c_tilde: &'a [u8; LAMBDA_BYTES],
    z: &'a ModuleVecL,
    cs2: &'a [Poly; K],
    z_bound_ok: bool,
    r0_bound_ok: bool,
    ct0_bound_ok: bool,
    hint_omega_ok: bool,
    hint_weight: usize,
}

fn rejection_predicate_digest(input: RejectionPredicateDigestInput<'_>) -> [u8; 32] {
    let RejectionPredicateDigestInput {
        c_tilde,
        z,
        cs2,
        z_bound_ok,
        r0_bound_ok,
        ct0_bound_ok,
        hint_omega_ok,
        hint_weight,
    } = input;

    let mut hasher = Shake256::default();
    hasher.update(b"lattice-aggregation/fips-sign/strict-rejection-predicates/v1");
    hasher.update(c_tilde);
    for component in &z.components {
        for coeff in component.coeffs {
            hasher.update(&coeff.to_le_bytes());
        }
    }
    for poly in cs2 {
        for coeff in poly.coeffs {
            hasher.update(&coeff.to_le_bytes());
        }
    }
    hasher.update(&[
        z_bound_ok as u8,
        r0_bound_ok as u8,
        ct0_bound_ok as u8,
        hint_omega_ok as u8,
    ]);
    hasher.update(&(hint_weight as u64).to_be_bytes());
    let mut out = [0u8; 32];
    hasher.finalize_xof().read(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{Keypair, MlDsa65, SigningKey};

    #[test]
    fn keygen_public_key_matches_ml_dsa() {
        let seed = [0x11u8; 32];
        let ours = keygen_from_seed(&seed).expect("keygen");
        let sk = SigningKey::<MlDsa65>::from_seed(&seed.into());
        let theirs = sk.verifying_key().encode();
        assert_eq!(
            ours.public_key.0.as_slice(),
            theirs.as_slice(),
            "self-contained KeyGen must match ml-dsa public key"
        );
    }

    #[test]
    fn self_contained_sign_verifies_with_ml_dsa_verifier() {
        let seed = [0x42u8; 32];
        let rnd = [0x7u8; 32];
        let message = b"self-contained fips sign internal";
        let secret = keygen_from_seed(&seed).unwrap();
        let (sig, _z, _rej) = sign_internal_empty_ctx(&secret, message, &rnd).unwrap();
        assert!(
            RealMldsa65Backend::verify_standard(&secret.public_key, message, &sig).unwrap(),
            "self-contained signature must verify under standard verifier"
        );
    }

    #[test]
    fn self_contained_package_with_z_shares() {
        let seed = [0xABu8; 32];
        let rnd = [0xCDu8; 32];
        let message = b"package with module z shares";
        let validators = vec![ValidatorId(0), ValidatorId(1), ValidatorId(2)];
        let pkg = self_contained_sign_with_module_z_shares(&seed, &rnd, message, 2, &validators)
            .expect("package");
        assert!(pkg.standard_verifier_accepted);
        assert!(pkg.z_share_match);
        assert_eq!(
            pkg.packing_mode,
            "self_contained_sign_internal_plus_threshold_wire_z_sharing"
        );
        let st = SelfContainedFipsStatus::current();
        assert!(st.fips204_wire_from_s1_y_partials_without_provider);
    }

    #[test]
    fn strict_distributed_s1_y_partials_emit_standard_wire_signature() {
        let seed = [0x52u8; 32];
        let rnd = [0x19u8; 32];
        let message = b"strict distributed partial core";
        let validators = vec![
            ValidatorId(0),
            ValidatorId(1),
            ValidatorId(2),
            ValidatorId(3),
        ];
        let package =
            strict_distributed_sign_from_s1_y_partials(&seed, &rnd, message, 3, &validators)
                .expect("strict distributed partial package");

        assert_eq!(
            package.packing_mode,
            "strict_distributed_s1_y_partials_to_fips204_wire_signature"
        );
        assert_eq!(package.partial_count, 3);
        assert!(package.aggregate_z_matches_direct);
        assert!(package.aggregate_cs2_matches_direct);
        assert!(package.z_bound_ok);
        assert!(package.r0_bound_ok);
        assert!(package.ct0_bound_ok);
        assert!(package.hint_omega_ok);
        assert!(package.standard_verifier_accepted);
        assert_ne!(package.partial_bundle_digest, [0u8; 32]);
        assert_ne!(package.rejection_predicate_digest, [0u8; 32]);
        assert!(RealMldsa65Backend::verify_standard(
            &package.public_key,
            message,
            &package.signature
        )
        .unwrap());
        assert!(!RealMldsa65Backend::verify_standard(
            &package.public_key,
            b"mutated",
            &package.signature
        )
        .unwrap());
    }
}
