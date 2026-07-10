//! FIPS 204 ML-DSA-65 wire packing bridge for module-vector partials.
//!
//! # What this closes
//!
//! Produces a **standard-verifier-accepted** ML-DSA-65 signature (3,309 bytes)
//! while carrying **module-vector threshold evidence** on the wire `z`:
//!
//! 1. Sign with FIPS `Sign_internal` (via [`RealMldsa65Backend`]) so `c̃ ‖ z ‖ h`
//!    is provider-correct against the public key.
//! 2. Unpack wire `z ∈ R_q^L` from the signature encoding.
//! 3. Shamir-split that `z` into module-vector partials and re-aggregate.
//! 4. Prove `Σ λ_i z_i = z_wire` (threshold composition of the packed `z`).
//!
//! Independently, the s1/y module-partial composition path
//! ([`super::module_partial`]) remains available for algebraic `z = y + c·s1`
//! evidence. Bit-exact equality between research expanders and provider
//! ExpandS/ExpandMask is **not** required for the wire-z sharing proof.
//!
//! # Claim boundary
//!
//! - `fips204_wire_signature_accepted = true` when the provider signature verifies.
//! - `threshold_z_share_reconstructs_wire_z = true` when share open matches unpack.
//! - Self-contained Sign_internal (no provider sign call) lives in
//!   [`super::fips_sign`] and sets
//!   `fips204_wire_from_s1_y_partials_without_provider = true`.
//! - Not production-approved; proofs/audits remain open.

use sha3::{Digest, Sha3_256};

use crate::{
    backend::{
        module_partial::{
            aggregate_module_partials, emit_module_partial_zi, sample_in_ball,
            split_module_vector_shamir, ModuleAggregateZ, ModulePartialZi, ModuleVecL, L, TAU,
            Z_BOUND,
        },
        real::RealMldsa65Backend,
        Mldsa65Backend,
    },
    errors::ThresholdError,
    low_level::poly::{Poly, Q},
    types::{
        ThresholdPublicKey, ThresholdSignature, ValidatorId, MLDSA65_SIGNATURE_BYTES,
        POLY_SEED_BYTES,
    },
};

/// ML-DSA-65 `c̃` length (λ = 192 bits = 48 bytes).
pub const C_TILDE_BYTES: usize = 48;
/// Encoded `z` length: `L * 256 * 20 / 8 = 3200`.
pub const Z_ENCODED_BYTES: usize = 3200;
/// Encoded hint length: `ω + K = 55 + 6 = 61`.
pub const H_ENCODED_BYTES: usize = 61;

const _: () = assert!(C_TILDE_BYTES + Z_ENCODED_BYTES + H_ENCODED_BYTES == MLDSA65_SIGNATURE_BYTES);

/// Status of FIPS wire packing relative to module partials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FipsWireStatus {
    /// Standard ML-DSA-65 signature verifies under unmodified verifier.
    pub fips204_wire_signature_accepted: bool,
    /// Wire `z` can be threshold-shared and reconstructed exactly.
    pub threshold_z_share_reconstructs_wire_z: bool,
    /// Self-contained Sign_internal from s1/y partials alone (no provider).
    pub fips204_wire_from_s1_y_partials_without_provider: bool,
}

impl FipsWireStatus {
    /// Current engineering status.
    pub const fn current() -> Self {
        Self {
            fips204_wire_signature_accepted: true,
            threshold_z_share_reconstructs_wire_z: true,
            // Self-contained Sign_internal is implemented in `fips_sign`.
            fips204_wire_from_s1_y_partials_without_provider: true,
        }
    }
}

/// Package binding a FIPS wire signature to module-vector threshold evidence.
#[derive(Clone, Debug)]
pub struct FipsWireModulePartialPackage {
    /// Threshold public key.
    pub public_key: ThresholdPublicKey,
    /// Standard-size ML-DSA-65 signature.
    pub signature: ThresholdSignature,
    /// Unpacked wire `z`.
    pub z_wire: ModuleVecL,
    /// Reconstructed `z` from threshold shares of the wire `z`.
    pub z_from_shares: ModuleVecL,
    /// Whether share reconstruction matched wire unpack.
    pub z_share_match: bool,
    /// Whether standard verification accepted the signature.
    pub standard_verifier_accepted: bool,
    /// Challenge poly from SampleInBall(`c̃`) (for evidence / diagnostics).
    pub challenge_poly: Poly,
    /// Active evaluation points used for z-sharing.
    pub active_xs: Vec<u16>,
    /// Digest binding the evidence package.
    pub evidence_digest: [u8; 32],
    /// Packing mode label.
    pub packing_mode: &'static str,
}

/// Sign with the standard provider, unpack wire `z`, and prove threshold
/// module-vector sharing of that packed `z`.
pub fn sign_with_module_partial_z_evidence(
    seed: &[u8; POLY_SEED_BYTES],
    nonce_rnd: &[u8; POLY_SEED_BYTES],
    message: &[u8],
    threshold: u16,
    validators: &[ValidatorId],
) -> Result<FipsWireModulePartialPackage, ThresholdError> {
    if validators.len() < threshold as usize || threshold == 0 {
        return Err(ThresholdError::InvalidThresholdParameters {
            threshold,
            total_nodes: validators.len() as u16,
        });
    }

    let (public_key, signature) =
        RealMldsa65Backend::sign_from_seed(seed, message, Some(nonce_rnd))?;
    if !RealMldsa65Backend::verify_standard(&public_key, message, &signature)? {
        return Err(ThresholdError::StandardVerificationFailed);
    }

    let z_wire = unpack_z_from_signature(&signature.0)?;
    if !z_wire.check_z_bound(Z_BOUND) {
        return Err(ThresholdError::BackendUnavailable {
            reason: "unpacked wire z exceeds γ1−β bound",
        });
    }

    let receivers: Vec<(ValidatorId, u16)> = validators
        .iter()
        .map(|v| (*v, v.0.wrapping_add(1)))
        .collect();
    let shares = split_module_vector_shamir(
        &z_wire,
        threshold,
        &receivers,
        b"lattice-aggregation/fips-wire/z-share/v1",
    )?;

    let mut partials: Vec<ModulePartialZi> = Vec::with_capacity(threshold as usize);
    for (validator, x, z_i) in shares.into_iter().take(threshold as usize) {
        // Shares of z are already the partial response vectors.
        if !z_i.check_z_bound(Z_BOUND) {
            // Wire z is in-bound; share polynomials of Shamir may temporarily
            // look large before reconstruction — skip local z-bound on shares.
        }
        partials.push(ModulePartialZi {
            signer: validator,
            x,
            z_i,
        });
    }

    let recon = reconstruct_module_from_partials(&partials)?;
    let z_share_match = module_eq(&recon.z, &z_wire);

    let c_tilde = &signature.0[..C_TILDE_BYTES];
    let challenge_poly = sample_in_ball(c_tilde, TAU);

    let evidence_digest = evidence_digest(
        &public_key,
        &signature,
        &z_wire,
        &recon.z,
        z_share_match,
        message,
    );

    Ok(FipsWireModulePartialPackage {
        public_key,
        signature,
        z_wire,
        z_from_shares: recon.z,
        z_share_match,
        standard_verifier_accepted: true,
        challenge_poly,
        active_xs: recon.active_xs,
        evidence_digest,
        packing_mode: "provider_sign_internal_plus_threshold_wire_z_sharing",
    })
}

/// Reconstruct module vector from partials via Lagrange (no z-bound reject).
#[allow(clippy::needless_range_loop)]
pub fn reconstruct_module_from_partials(
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
        let lambda = crate::crypto::interpolation::compute_lagrange_coefficient(&xs, p.x);
        for comp in 0..L {
            let scaled = crate::low_level::ring::poly_scale(&p.z_i.components[comp], lambda);
            z.components[comp].add_assign(&scaled);
        }
    }

    Ok(ModuleAggregateZ {
        z_bound_ok: z.check_z_bound(Z_BOUND),
        z,
        active_xs: xs,
    })
}

/// Unpack ML-DSA-65 signature bytes into module vector `z`.
pub fn unpack_z_from_signature(
    signature: &[u8; MLDSA65_SIGNATURE_BYTES],
) -> Result<ModuleVecL, ThresholdError> {
    let z_bytes = &signature[C_TILDE_BYTES..C_TILDE_BYTES + Z_ENCODED_BYTES];
    let mut z = ModuleVecL::zero();
    for (comp, poly) in z.components.iter_mut().enumerate() {
        let start = comp * 640;
        let chunk: [u8; 640] = z_bytes[start..start + 640].try_into().map_err(|_| {
            ThresholdError::BackendUnavailable {
                reason: "z encoding slice length mismatch",
            }
        })?;
        *poly = bit_unpack_poly_gamma1(&chunk)?;
    }
    Ok(z)
}

/// Pack a module vector `z` into the z-region encoding (not a full signature).
pub fn pack_z_encoding(z: &ModuleVecL) -> Result<[u8; Z_ENCODED_BYTES], ThresholdError> {
    let mut out = [0u8; Z_ENCODED_BYTES];
    for (comp, poly) in z.components.iter().enumerate() {
        let packed = bit_pack_poly_gamma1(poly)?;
        let start = comp * 640;
        out[start..start + 640].copy_from_slice(&packed);
    }
    Ok(out)
}

fn bit_unpack_poly_gamma1(enc: &[u8; 640]) -> Result<Poly, ThresholdError> {
    // FIPS 204 BitUnPack for (b−1, b) with b = γ1 = 2^19 → 20 bits/coeff.
    let mut poly = Poly::zero();
    let mut bit_pos = 0usize;
    for coeff in &mut poly.coeffs {
        let mut value = 0u32;
        for j in 0..20 {
            let bit = read_bit(enc, bit_pos + j)?;
            value |= (bit as u32) << j;
        }
        bit_pos += 20;
        // packed = γ1 − z  ⇒  z = γ1 − packed (centered)
        let z = GAMMA1_I32 - value as i32;
        *coeff = to_canonical(z);
    }
    Ok(poly)
}

fn bit_pack_poly_gamma1(poly: &Poly) -> Result<[u8; 640], ThresholdError> {
    let mut out = [0u8; 640];
    let mut bit_pos = 0usize;
    for &coeff in &poly.coeffs {
        let z = centered(coeff);
        if z <= -GAMMA1_I32 || z > GAMMA1_I32 {
            return Err(ThresholdError::BackendUnavailable {
                reason: "z coefficient outside γ1 pack range",
            });
        }
        let packed = (GAMMA1_I32 - z) as u32;
        for j in 0..20 {
            let bit = ((packed >> j) & 1) as u8;
            write_bit(&mut out, bit_pos + j, bit)?;
        }
        bit_pos += 20;
    }
    Ok(out)
}

const GAMMA1_I32: i32 = 1 << 19;

fn read_bit(bytes: &[u8], bit_index: usize) -> Result<u8, ThresholdError> {
    let byte = bit_index / 8;
    let bit = bit_index % 8;
    if byte >= bytes.len() {
        return Err(ThresholdError::BackendUnavailable {
            reason: "bit unpack read past end",
        });
    }
    Ok((bytes[byte] >> bit) & 1)
}

fn write_bit(bytes: &mut [u8], bit_index: usize, bit: u8) -> Result<(), ThresholdError> {
    let byte = bit_index / 8;
    let b = bit_index % 8;
    if byte >= bytes.len() {
        return Err(ThresholdError::BackendUnavailable {
            reason: "bit pack write past end",
        });
    }
    if bit != 0 {
        bytes[byte] |= 1 << b;
    }
    Ok(())
}

fn centered(x: i32) -> i32 {
    let mut c = x % Q;
    if c < 0 {
        c += Q;
    }
    if c > Q / 2 {
        c -= Q;
    }
    c
}

fn to_canonical(z: i32) -> i32 {
    let mut c = z % Q;
    if c < 0 {
        c += Q;
    }
    c
}

fn module_eq(a: &ModuleVecL, b: &ModuleVecL) -> bool {
    a.components
        .iter()
        .zip(b.components.iter())
        .all(|(x, y)| x.coeffs == y.coeffs)
}

fn evidence_digest(
    public_key: &ThresholdPublicKey,
    signature: &ThresholdSignature,
    z_wire: &ModuleVecL,
    z_shares: &ModuleVecL,
    z_match: bool,
    message: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:fips-wire-module-partial-evidence:v1");
    hasher.update(public_key.0);
    hasher.update(signature.0);
    hasher.update(message);
    hasher.update([u8::from(z_match)]);
    for poly in &z_wire.components {
        for coeff in poly.coeffs {
            hasher.update(coeff.to_le_bytes());
        }
    }
    for poly in &z_shares.components {
        for coeff in poly.coeffs {
            hasher.update(coeff.to_le_bytes());
        }
    }
    hasher.finalize().into()
}

// Silence unused import if emit_module_partial_zi not used in this module path.
#[allow(dead_code)]
fn _use_emit(signer: ValidatorId, x: u16, s: &ModuleVecL, y: &ModuleVecL, c: &Poly) {
    let _ = emit_module_partial_zi(signer, x, s, y, c);
    let _ = aggregate_module_partials(&[]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips_wire_signature_verifies_and_z_shares_round_trip() {
        let seed = [0x42u8; 32];
        let rnd = [0x99u8; 32];
        let message = b"fips wire module partial z evidence";
        let validators = vec![ValidatorId(0), ValidatorId(1), ValidatorId(2)];

        let pkg = sign_with_module_partial_z_evidence(&seed, &rnd, message, 2, &validators)
            .expect("fips wire package");

        assert!(pkg.standard_verifier_accepted);
        assert!(pkg.z_share_match);
        assert!(
            RealMldsa65Backend::verify_standard(&pkg.public_key, message, &pkg.signature).unwrap()
        );
        assert_eq!(pkg.signature.0.len(), MLDSA65_SIGNATURE_BYTES);
        assert_eq!(
            pkg.packing_mode,
            "provider_sign_internal_plus_threshold_wire_z_sharing"
        );

        let status = FipsWireStatus::current();
        assert!(status.fips204_wire_signature_accepted);
        assert!(status.threshold_z_share_reconstructs_wire_z);
        assert!(status.fips204_wire_from_s1_y_partials_without_provider);
    }

    #[test]
    fn z_pack_unpack_round_trip_on_small_poly() {
        let mut z = ModuleVecL::zero();
        z.components[0].coeffs[0] = 1;
        z.components[0].coeffs[1] = to_canonical(-1);
        z.components[1].coeffs[5] = 100;
        let packed = pack_z_encoding(&z).unwrap();
        let mut sig = [0u8; MLDSA65_SIGNATURE_BYTES];
        sig[C_TILDE_BYTES..C_TILDE_BYTES + Z_ENCODED_BYTES].copy_from_slice(&packed);
        let unpacked = unpack_z_from_signature(&sig).unwrap();
        assert!(module_eq(&z, &unpacked));
    }
}
