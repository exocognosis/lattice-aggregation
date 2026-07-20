//! Import real MP-SPDZ exact-`ExpandMask` MPC outputs into the signer's
//! additive-mask attempt type, with fail-closed equivalence against the
//! FIPS 204 oracle.
//!
//! # Binary-Output format
//!
//! An exact-`ExpandMask` MPC run (see
//! `scripts/run_exact_expandmask_mpc_equivalence.py`) writes one
//! `Binary-Output-P{p}-0` file per party. Each file holds exactly
//! `L * N = 5 * 256 = 1280` little-endian signed `int64` values: party `p`'s
//! additive share `y_p` of the ML-DSA-65 mask, flattened component-major
//! (`index = component * N + coefficient`). Summed over all parties modulo `q`,
//! the shares reconstruct the `ExpandMask` output `y`, which must equal the
//! FIPS 204 oracle.
//!
//! [`import_expandmask_attempt`] parses those bytes into [`AdditiveMaskShare65`]
//! values, reconstructs `sum_p y_p mod q`, and compares it coefficient-for-
//! coefficient against the FIPS 204 `ExpandMask` oracle recomputed here in pure
//! Rust ([`fips_expandmask_oracle`]). The resulting
//! [`AdditiveMaskAttempt65::exact_expandmask_equivalence_verified`] flag is the
//! *actual* comparison result, never a hard-coded `true`.
//!
//! # Honesty boundary
//!
//! - `exact_expandmask_equivalence_verified` is set only from the real,
//!   byte-exact reconstruction-vs-oracle comparison. A corrupted or mismatched
//!   share makes it `false`.
//! - `malicious_mpc_verified` is an **input** the caller MUST derive from real
//!   MAC-check evidence (clean MASCOT/MAMA party logs). This module never
//!   fabricates it and never defaults it to `true`.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::{
    backend::{
        fips_sign::{
            additive_mask_input_binding_digest, AdditiveMaskAttempt65, AdditiveMaskShare65,
            SigningSetMember65,
        },
        module_partial::{ModuleVecL, L},
    },
    errors::ThresholdError,
    low_level::poly::{N, Q},
};

/// ML-DSA-65 mask parameter `γ₁ = 2^19` (matches FIPS 204 `ExpandMask`).
const GAMMA1: i32 = 1 << 19;

/// Number of signed `int64` values in one `Binary-Output-P{p}-0` file:
/// `L * N = 5 * 256 = 1280` (five polynomials, 256 coefficients each).
pub const BINARY_OUTPUT_COEFF_COUNT: usize = L * N;

/// Byte length of one `Binary-Output-P{p}-0` file: `1280 * 8 = 10240`.
pub const BINARY_OUTPUT_BYTE_LEN: usize = BINARY_OUTPUT_COEFF_COUNT * 8;

/// Parse one `Binary-Output-P{p}-0` file into a signer's additive mask share.
///
/// The blob must be exactly [`BINARY_OUTPUT_BYTE_LEN`] bytes: `1280` little-
/// endian signed `int64` values, flattened component-major
/// (`index = component * N + coefficient`). Each value is reduced modulo `q`
/// into the canonical range `[0, q)`. A wrong length is rejected fail-closed.
pub fn read_binary_output_share(bytes: &[u8]) -> Result<ModuleVecL, ThresholdError> {
    if bytes.len() != BINARY_OUTPUT_BYTE_LEN {
        return Err(ThresholdError::BackendUnavailable {
            reason: "Binary-Output share must be exactly L*N=1280 little-endian int64 values",
        });
    }
    let mut out = ModuleVecL::zero();
    for (index, chunk) in bytes.chunks_exact(8).enumerate() {
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        let value = i64::from_le_bytes(word);
        let canonical = value.rem_euclid(i64::from(Q)) as i32;
        out.components[index / N].coeffs[index % N] = canonical;
    }
    Ok(out)
}

/// Recompute the FIPS 204 ML-DSA-65 `ExpandMask` output `y ∈ R_q^L` in pure Rust
/// for `(rhopp, kappa_base)`.
///
/// This mirrors, value for value, `expected_expandmask` in
/// `scripts/run_exact_expandmask_mpc_equivalence.py` and the private
/// `expand_mask` in `fips_sign`: for each component `comp ∈ [0, L)` it draws
/// `SHAKE256(rhopp || (kappa_base + comp) as u16 LE)`, unpacks 20-bit little-
/// endian words, and maps each to `(γ₁ − encoded) mod q`. It lets the importer
/// self-check equivalence without invoking the Python harness.
pub fn fips_expandmask_oracle(rhopp: &[u8; 64], kappa_base: u16) -> ModuleVecL {
    let mut out = ModuleVecL::zero();
    for component in 0..L {
        let nonce = kappa_base.wrapping_add(component as u16);
        let mut hasher = Shake256::default();
        hasher.update(rhopp);
        hasher.update(&nonce.to_le_bytes());
        // packed_bytes = (N * 20 + 7) / 8 = 640.
        let mut packed = [0u8; 640];
        hasher.finalize_xof().read(&mut packed);

        let mut bit_pos = 0usize;
        for coefficient in 0..N {
            let mut encoded = 0u32;
            for shift in 0..20 {
                let byte = bit_pos / 8;
                let bit = bit_pos % 8;
                encoded |= ((u32::from(packed[byte] >> bit)) & 1) << shift;
                bit_pos += 1;
            }
            let z = GAMMA1 - encoded as i32;
            out.components[component].coeffs[coefficient] = z.rem_euclid(Q);
        }
    }
    out
}

/// Sum additive mask shares component-wise modulo `q`.
fn reconstruct_additive_shares(shares: &[AdditiveMaskShare65]) -> ModuleVecL {
    let mut reconstructed = ModuleVecL::zero();
    for share in shares {
        for component in 0..L {
            reconstructed.components[component].add_assign(&share.mask_share.components[component]);
        }
    }
    reconstructed
}

/// Import one exact-`ExpandMask` MPC attempt from raw per-party Binary-Output
/// bytes into an [`AdditiveMaskAttempt65`], with fail-closed FIPS equivalence.
///
/// `party_binary_outputs` holds one `Binary-Output-P{p}-0` byte blob per signer,
/// ordered to match `signing_set`. Each blob becomes that signer's
/// [`AdditiveMaskShare65`] (validator / `x` taken from the matching signing-set
/// member). The attempt's `input_binding_digest` binds `rhopp`, `kappa_base`,
/// and the ordered signing set via [`additive_mask_input_binding_digest`].
///
/// Equivalence is verified for real: the shares are summed modulo `q` and
/// compared coefficient-for-coefficient against
/// [`fips_expandmask_oracle`]`(rhopp, kappa_base)`. The returned
/// `exact_expandmask_equivalence_verified` is exactly that comparison — `true`
/// only when the reconstruction is byte-identical to the oracle.
///
/// `malicious_mpc_verified` is passed through verbatim; the caller MUST derive
/// it from real MAC-check evidence (clean malicious-MPC party logs). It is never
/// defaulted to `true` here.
pub fn import_expandmask_attempt(
    signing_set: &[SigningSetMember65],
    party_binary_outputs: &[Vec<u8>],
    kappa_base: u16,
    rhopp: &[u8; 64],
    malicious_mpc_verified: bool,
) -> Result<AdditiveMaskAttempt65, ThresholdError> {
    if signing_set.is_empty() {
        return Err(ThresholdError::InsufficientPartialShares {
            required: 1,
            received: 0,
        });
    }
    if party_binary_outputs.len() != signing_set.len() {
        return Err(ThresholdError::InsufficientPartialShares {
            required: signing_set.len() as u16,
            received: party_binary_outputs.len(),
        });
    }

    let mut shares = Vec::with_capacity(signing_set.len());
    for (member, bytes) in signing_set.iter().zip(party_binary_outputs) {
        let mask_share = read_binary_output_share(bytes)?;
        shares.push(AdditiveMaskShare65 {
            validator: member.validator,
            x: member.x,
            mask_share,
        });
    }

    let input_binding_digest = additive_mask_input_binding_digest(rhopp, kappa_base, signing_set);

    // Real, byte-exact equivalence check: reconstruct sum_p y_p mod q and
    // compare it to the FIPS 204 ExpandMask oracle for (rhopp, kappa_base).
    let reconstructed = reconstruct_additive_shares(&shares);
    let oracle = fips_expandmask_oracle(rhopp, kappa_base);
    let exact_expandmask_equivalence_verified = reconstructed == oracle;

    Ok(AdditiveMaskAttempt65 {
        kappa_base,
        input_binding_digest,
        malicious_mpc_verified,
        exact_expandmask_equivalence_verified,
        shares,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ValidatorId;
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };

    fn member(validator: u16, x: u16, lagrange_weight: i32) -> SigningSetMember65 {
        SigningSetMember65 {
            validator: ValidatorId(validator),
            x,
            lagrange_weight,
        }
    }

    /// Deterministic pseudo-random coefficient in `[0, q)` from a label.
    fn pseudo_coeff(seed: &[u8]) -> i32 {
        let mut hasher = Shake256::default();
        hasher.update(seed);
        let mut word = [0u8; 8];
        hasher.finalize_xof().read(&mut word);
        (u64::from_le_bytes(word) % (Q as u64)) as i32
    }

    /// Split a known module vector into `count` additive shares mod q: the first
    /// `count - 1` shares are pseudo-random, the last absorbs the residual so the
    /// shares sum to `secret`.
    fn split_additive(secret: &ModuleVecL, count: usize, label: &[u8]) -> Vec<ModuleVecL> {
        let mut shares = vec![ModuleVecL::zero(); count];
        let mut running = ModuleVecL::zero();
        for (party, share) in shares.iter_mut().enumerate().take(count - 1) {
            for component in 0..L {
                for coefficient in 0..N {
                    let mut key = label.to_vec();
                    key.extend_from_slice(&(party as u32).to_le_bytes());
                    key.extend_from_slice(&(component as u32).to_le_bytes());
                    key.extend_from_slice(&(coefficient as u32).to_le_bytes());
                    share.components[component].coeffs[coefficient] = pseudo_coeff(&key);
                }
            }
            for component in 0..L {
                running.components[component].add_assign(&share.components[component]);
            }
        }
        let last = count - 1;
        for component in 0..L {
            for coefficient in 0..N {
                let s = i64::from(secret.components[component].coeffs[coefficient]);
                let r = i64::from(running.components[component].coeffs[coefficient]);
                shares[last].components[component].coeffs[coefficient] =
                    (s - r).rem_euclid(i64::from(Q)) as i32;
            }
        }
        shares
    }

    fn serialize_share(share: &ModuleVecL) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(BINARY_OUTPUT_BYTE_LEN);
        for component in 0..L {
            for coefficient in 0..N {
                let value = i64::from(share.components[component].coeffs[coefficient]);
                bytes.extend_from_slice(&value.to_le_bytes());
            }
        }
        bytes
    }

    #[test]
    fn imports_real_shares_and_verifies_equivalence_true() {
        let rhopp = [0x11u8; 64];
        let kappa_base = 0u16;
        let signing_set = vec![member(0, 1, 1), member(1, 2, -2), member(2, 3, 3)];
        let oracle = fips_expandmask_oracle(&rhopp, kappa_base);
        let shares = split_additive(&oracle, signing_set.len(), b"import-test-true");
        let party_bytes: Vec<Vec<u8>> = shares.iter().map(serialize_share).collect();

        let attempt =
            import_expandmask_attempt(&signing_set, &party_bytes, kappa_base, &rhopp, true)
                .expect("import succeeds");

        assert!(attempt.exact_expandmask_equivalence_verified);
        assert!(attempt.malicious_mpc_verified);
        assert_eq!(attempt.kappa_base, kappa_base);
        assert_eq!(attempt.shares.len(), 3);
        assert_eq!(attempt.shares[0].validator, ValidatorId(0));
        assert_eq!(attempt.shares[1].x, 2);
        assert_eq!(
            attempt.input_binding_digest,
            additive_mask_input_binding_digest(&rhopp, kappa_base, &signing_set)
        );
    }

    #[test]
    fn malicious_flag_is_passed_through_not_hardcoded() {
        let rhopp = [0x22u8; 64];
        let kappa_base = 10u16;
        let signing_set = vec![member(4, 5, 1), member(7, 6, -1)];
        let oracle = fips_expandmask_oracle(&rhopp, kappa_base);
        let shares = split_additive(&oracle, signing_set.len(), b"import-test-flag");
        let party_bytes: Vec<Vec<u8>> = shares.iter().map(serialize_share).collect();

        let attempt =
            import_expandmask_attempt(&signing_set, &party_bytes, kappa_base, &rhopp, false)
                .expect("import succeeds");
        // Equivalence still holds (shares sum to the oracle) ...
        assert!(attempt.exact_expandmask_equivalence_verified);
        // ... but malicious verification reflects the caller-supplied `false`.
        assert!(!attempt.malicious_mpc_verified);
    }

    #[test]
    fn corrupted_share_makes_equivalence_false() {
        let rhopp = [0x33u8; 64];
        let kappa_base = 5u16;
        let signing_set = vec![member(0, 1, 1), member(1, 2, -2), member(2, 3, 3)];
        let oracle = fips_expandmask_oracle(&rhopp, kappa_base);
        let shares = split_additive(&oracle, signing_set.len(), b"import-test-corrupt");
        let mut party_bytes: Vec<Vec<u8>> = shares.iter().map(serialize_share).collect();

        // Perturb one coefficient of party 0 (its first int64) by +1 mod q.
        let mut word = [0u8; 8];
        word.copy_from_slice(&party_bytes[0][0..8]);
        let corrupted = (i64::from_le_bytes(word) + 1).rem_euclid(i64::from(Q));
        party_bytes[0][0..8].copy_from_slice(&corrupted.to_le_bytes());

        let attempt =
            import_expandmask_attempt(&signing_set, &party_bytes, kappa_base, &rhopp, true)
                .expect("import still succeeds structurally");
        assert!(!attempt.exact_expandmask_equivalence_verified);
    }

    #[test]
    fn wrong_byte_length_is_rejected() {
        let too_short = vec![0u8; BINARY_OUTPUT_BYTE_LEN - 8];
        assert!(read_binary_output_share(&too_short).is_err());
        let too_long = vec![0u8; BINARY_OUTPUT_BYTE_LEN + 8];
        assert!(read_binary_output_share(&too_long).is_err());
        let exact = vec![0u8; BINARY_OUTPUT_BYTE_LEN];
        assert!(read_binary_output_share(&exact).is_ok());
    }

    #[test]
    fn party_count_mismatch_is_rejected() {
        let rhopp = [0x44u8; 64];
        let signing_set = vec![member(0, 1, 1), member(1, 2, -2), member(2, 3, 3)];
        // Only two party blobs for a three-member signing set.
        let party_bytes = vec![vec![0u8; BINARY_OUTPUT_BYTE_LEN]; 2];
        let result = import_expandmask_attempt(&signing_set, &party_bytes, 0, &rhopp, true);
        assert!(result.is_err());
    }

    #[test]
    fn oracle_is_deterministic_and_canonical() {
        let rhopp = [0x55u8; 64];
        let first = fips_expandmask_oracle(&rhopp, 0);
        let second = fips_expandmask_oracle(&rhopp, 0);
        assert_eq!(first, second);
        assert!(first
            .components
            .iter()
            .all(|poly| poly.coeffs.iter().all(|&c| (0..Q).contains(&c))));
    }
}
