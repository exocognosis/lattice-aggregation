//! Hazmat ML-DSA-65 internals gated behind `hazmat-real-mldsa`.
//!
//! This module captures the local FIPS 204 ML-DSA-65 parameter surface and
//! arithmetic boundary needed by threshold experiments. It is intentionally not
//! a complete signing or verification implementation yet; callers must treat
//! every item here as low-level cryptographic construction material.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::{
    errors::ThresholdError,
    low_level::poly::{Poly, N, Q},
    types::{
        ThresholdPublicKey, ThresholdSignature, MLDSA65_PUBLICKEY_BYTES, MLDSA65_SIGNATURE_BYTES,
    },
};

/// ML-DSA-65 public seed byte length for `rho`.
pub const MLDSA65_PUBLIC_SEED_BYTES: usize = 32;
/// ML-DSA-65 challenge byte length for `c_tilde`.
pub const MLDSA65_CHALLENGE_BYTES: usize = 48;
/// ML-DSA dropped-bit parameter `d`.
pub const MLDSA65_D: usize = 13;
/// ML-DSA-65 matrix row dimension `k`.
pub const MLDSA65_K: usize = 6;
/// ML-DSA-65 matrix column dimension `l`.
pub const MLDSA65_L: usize = 5;
/// ML-DSA-65 private key coefficient range parameter `eta`.
pub const MLDSA65_ETA: i32 = 4;
/// ML-DSA-65 challenge sparsity parameter `tau`.
pub const MLDSA65_TAU: i32 = 49;
/// ML-DSA-65 rejection-bound slack `beta = tau * eta`.
pub const MLDSA65_BETA: i32 = MLDSA65_TAU * MLDSA65_ETA;
/// ML-DSA-65 masking-vector range parameter `gamma_1`.
pub const MLDSA65_GAMMA1: i32 = 1 << 19;
/// ML-DSA-65 low-order rounding range parameter `gamma_2`.
pub const MLDSA65_GAMMA2: i32 = (Q - 1) / 32;
/// ML-DSA-65 hint weight bound `omega`.
pub const MLDSA65_OMEGA: usize = 55;
/// ML-DSA-65 secret key byte length.
pub const MLDSA65_SECRETKEY_BYTES: usize = 4032;
/// Packed byte length for one ML-DSA `t1` polynomial.
pub const MLDSA65_POLYT1_PACKED_BYTES: usize = 320;
/// Packed byte length for one ML-DSA-65 `z` polynomial.
pub const MLDSA65_POLYZ_PACKED_BYTES: usize = 640;
/// Packed byte length for an ML-DSA-65 hint vector.
pub const MLDSA65_HINT_PACKED_BYTES: usize = MLDSA65_OMEGA + MLDSA65_K;
/// Strict infinity norm bound for ML-DSA-65 `z`.
pub const MLDSA65_Z_NORM_BOUND: i32 = MLDSA65_GAMMA1 - MLDSA65_BETA;

const HAZMAT_VERIFIER_UNAVAILABLE: &str =
    "hazmat-real-mldsa verifier requires FIPS 204 KAT-backed implementation";
const PUBLIC_KEY_LENGTH_MISMATCH: &str = "ML-DSA-65 public key length mismatch";
const SIGNATURE_LENGTH_MISMATCH: &str = "ML-DSA-65 signature length mismatch";
const HINT_OFFSET_RANGE: &str = "ML-DSA-65 hint offset exceeds omega";
const HINT_OFFSET_MONOTONIC: &str = "ML-DSA-65 hint offsets are not monotonic";
const HINT_INDEX_ORDER: &str = "ML-DSA-65 hint indices are not strictly increasing";
const HINT_UNUSED_NONZERO: &str = "ML-DSA-65 hint encoding has nonzero unused slot";
const T1_COEFFICIENT_UNPACKABLE: &str = "ML-DSA-65 t1 coefficient cannot be packed";
const Z_COEFFICIENT_UNPACKABLE: &str = "ML-DSA-65 z coefficient cannot be packed";

/// Fixed-size byte wrapper for an ML-DSA-65 public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mldsa65PublicKeyBytes([u8; MLDSA65_PUBLICKEY_BYTES]);

impl Mldsa65PublicKeyBytes {
    /// Construct a public key byte wrapper from exactly-sized bytes.
    pub const fn new(bytes: [u8; MLDSA65_PUBLICKEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// Borrow the encoded public key bytes.
    pub fn as_bytes(&self) -> &[u8; MLDSA65_PUBLICKEY_BYTES] {
        &self.0
    }
}

impl From<Mldsa65PublicKeyBytes> for ThresholdPublicKey {
    fn from(value: Mldsa65PublicKeyBytes) -> Self {
        Self(value.0)
    }
}

/// Fixed-size byte wrapper for an ML-DSA-65 signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mldsa65SignatureBytes([u8; MLDSA65_SIGNATURE_BYTES]);

impl Mldsa65SignatureBytes {
    /// Construct a signature byte wrapper from exactly-sized bytes.
    pub const fn new(bytes: [u8; MLDSA65_SIGNATURE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Borrow the encoded signature bytes.
    pub fn as_bytes(&self) -> &[u8; MLDSA65_SIGNATURE_BYTES] {
        &self.0
    }
}

impl From<Mldsa65SignatureBytes> for ThresholdSignature {
    fn from(value: Mldsa65SignatureBytes) -> Self {
        Self(value.0)
    }
}

/// Unpacked ML-DSA-65 public key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnpackedPublicKey {
    rho: [u8; MLDSA65_PUBLIC_SEED_BYTES],
    t1: VectorK,
}

impl UnpackedPublicKey {
    /// Borrow the public matrix seed `rho`.
    pub fn rho(&self) -> &[u8; MLDSA65_PUBLIC_SEED_BYTES] {
        &self.rho
    }

    /// Borrow the unpacked `t1` vector.
    pub fn t1(&self) -> &VectorK {
        &self.t1
    }
}

/// Unpacked ML-DSA-65 hint vector metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HintVector {
    indices: [u8; MLDSA65_OMEGA],
    offsets: [u8; MLDSA65_K],
    weight: usize,
}

impl HintVector {
    /// Return an empty hint vector.
    pub const fn empty() -> Self {
        Self {
            indices: [0; MLDSA65_OMEGA],
            offsets: [0; MLDSA65_K],
            weight: 0,
        }
    }

    /// Borrow the packed hint indices.
    pub fn indices(&self) -> &[u8; MLDSA65_OMEGA] {
        &self.indices
    }

    /// Borrow the per-polynomial cumulative hint offsets.
    pub fn offsets(&self) -> &[u8; MLDSA65_K] {
        &self.offsets
    }

    /// Return the total number of hint positions used by the vector.
    pub fn weight(&self) -> usize {
        self.weight
    }
}

/// Unpacked ML-DSA-65 signature material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnpackedSignature {
    challenge: [u8; MLDSA65_CHALLENGE_BYTES],
    z: VectorL,
    hint: HintVector,
}

impl UnpackedSignature {
    /// Borrow the encoded challenge `c_tilde`.
    pub fn challenge(&self) -> &[u8; MLDSA65_CHALLENGE_BYTES] {
        &self.challenge
    }

    /// Borrow the unpacked response vector `z`.
    pub fn z(&self) -> &VectorL {
        &self.z
    }

    /// Borrow the decoded hint metadata.
    pub fn hint(&self) -> &HintVector {
        &self.hint
    }
}

/// Fixed-length ML-DSA polynomial vector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolyVec<const LEN: usize> {
    polys: [Poly; LEN],
}

impl<const LEN: usize> PolyVec<LEN> {
    /// Return the zero polynomial vector.
    pub const fn zero() -> Self {
        Self {
            polys: [Poly::zero(); LEN],
        }
    }

    /// Construct a vector from raw polynomials.
    pub const fn from_polys(polys: [Poly; LEN]) -> Self {
        Self { polys }
    }

    /// Borrow the vector polynomials.
    pub fn polys(&self) -> &[Poly; LEN] {
        &self.polys
    }

    /// Borrow mutable vector polynomials.
    pub fn polys_mut(&mut self) -> &mut [Poly; LEN] {
        &mut self.polys
    }
}

impl<const LEN: usize> Default for PolyVec<LEN> {
    fn default() -> Self {
        Self::zero()
    }
}

/// ML-DSA-65 `k`-dimension polynomial vector.
pub type VectorK = PolyVec<MLDSA65_K>;
/// ML-DSA-65 `l`-dimension polynomial vector.
pub type VectorL = PolyVec<MLDSA65_L>;

/// Pack an ML-DSA-65 public key from `rho` and `t1`.
pub fn pack_public_key(
    rho: [u8; MLDSA65_PUBLIC_SEED_BYTES],
    t1: &VectorK,
) -> Result<Mldsa65PublicKeyBytes, ThresholdError> {
    let mut bytes = [0u8; MLDSA65_PUBLICKEY_BYTES];
    bytes[..MLDSA65_PUBLIC_SEED_BYTES].copy_from_slice(&rho);

    let mut offset = MLDSA65_PUBLIC_SEED_BYTES;
    for poly in t1.polys() {
        let packed = pack_t1_poly(poly)?;
        bytes[offset..offset + MLDSA65_POLYT1_PACKED_BYTES].copy_from_slice(&packed);
        offset += MLDSA65_POLYT1_PACKED_BYTES;
    }

    Ok(Mldsa65PublicKeyBytes::new(bytes))
}

/// Pack an ML-DSA-65 signature from challenge, response, and hint material.
pub fn pack_signature(
    challenge: [u8; MLDSA65_CHALLENGE_BYTES],
    z: &VectorL,
    hint: &HintVector,
) -> Result<Mldsa65SignatureBytes, ThresholdError> {
    let mut bytes = [0u8; MLDSA65_SIGNATURE_BYTES];
    bytes[..MLDSA65_CHALLENGE_BYTES].copy_from_slice(&challenge);

    let mut offset = MLDSA65_CHALLENGE_BYTES;
    for poly in z.polys() {
        let packed = pack_z_poly(poly)?;
        bytes[offset..offset + MLDSA65_POLYZ_PACKED_BYTES].copy_from_slice(&packed);
        offset += MLDSA65_POLYZ_PACKED_BYTES;
    }

    bytes[offset..offset + MLDSA65_OMEGA].copy_from_slice(hint.indices());
    offset += MLDSA65_OMEGA;
    bytes[offset..offset + MLDSA65_K].copy_from_slice(hint.offsets());

    Ok(Mldsa65SignatureBytes::new(bytes))
}

/// Unpack an ML-DSA-65 public key into `rho` and `t1`.
pub fn unpack_public_key(bytes: &[u8]) -> Result<UnpackedPublicKey, ThresholdError> {
    if bytes.len() != MLDSA65_PUBLICKEY_BYTES {
        return Err(ThresholdError::MalformedSerialization {
            reason: PUBLIC_KEY_LENGTH_MISMATCH,
        });
    }

    let mut rho = [0u8; MLDSA65_PUBLIC_SEED_BYTES];
    rho.copy_from_slice(&bytes[..MLDSA65_PUBLIC_SEED_BYTES]);

    let mut t1 = [Poly::zero(); MLDSA65_K];
    let t1_bytes = &bytes[MLDSA65_PUBLIC_SEED_BYTES..];
    for (poly, packed) in t1
        .iter_mut()
        .zip(t1_bytes.chunks_exact(MLDSA65_POLYT1_PACKED_BYTES))
    {
        *poly = unpack_t1_poly(packed);
    }

    Ok(UnpackedPublicKey {
        rho,
        t1: VectorK::from_polys(t1),
    })
}

/// Unpack an ML-DSA-65 signature into challenge, response, and hint material.
pub fn unpack_signature(bytes: &[u8]) -> Result<UnpackedSignature, ThresholdError> {
    if bytes.len() != MLDSA65_SIGNATURE_BYTES {
        return Err(ThresholdError::MalformedSerialization {
            reason: SIGNATURE_LENGTH_MISMATCH,
        });
    }

    let mut challenge = [0u8; MLDSA65_CHALLENGE_BYTES];
    challenge.copy_from_slice(&bytes[..MLDSA65_CHALLENGE_BYTES]);

    let z_start = MLDSA65_CHALLENGE_BYTES;
    let z_end = z_start + (MLDSA65_L * MLDSA65_POLYZ_PACKED_BYTES);
    let mut z = [Poly::zero(); MLDSA65_L];
    for (poly, packed) in z
        .iter_mut()
        .zip(bytes[z_start..z_end].chunks_exact(MLDSA65_POLYZ_PACKED_BYTES))
    {
        *poly = unpack_z_poly(packed);
    }

    let hint = unpack_hint(&bytes[z_end..])?;

    Ok(UnpackedSignature {
        challenge,
        z: VectorL::from_polys(z),
        hint,
    })
}

/// Return a canonical representative in `[0, Q)` for a signed integer.
pub fn reduce_mod_q(value: i64) -> i32 {
    let modulus = Q as i64;
    let mut reduced = value % modulus;
    if reduced < 0 {
        reduced += modulus;
    }
    reduced as i32
}

/// Add two canonical field elements modulo `Q`.
pub fn add_mod_q(lhs: i32, rhs: i32) -> i32 {
    reduce_mod_q(lhs as i64 + rhs as i64)
}

/// Subtract two canonical field elements modulo `Q`.
pub fn sub_mod_q(lhs: i32, rhs: i32) -> i32 {
    reduce_mod_q(lhs as i64 - rhs as i64)
}

/// Multiply two canonical field elements modulo `Q`.
pub fn mul_mod_q(lhs: i32, rhs: i32) -> i32 {
    reduce_mod_q(lhs as i64 * rhs as i64)
}

/// Sample an ML-DSA-65 challenge polynomial from `c_tilde`.
pub fn sample_in_ball(seed: &[u8; MLDSA65_CHALLENGE_BYTES]) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();

    let mut sign_bytes = [0u8; 8];
    reader.read(&mut sign_bytes);
    let signs = u64::from_le_bytes(sign_bytes);

    let mut coeffs = [0i32; N];
    for i in (N - MLDSA65_TAU as usize)..N {
        let mut j = squeeze_byte(&mut reader);
        while j > i {
            j = squeeze_byte(&mut reader);
        }

        coeffs[i] = coeffs[j];
        let sign_bit = (signs >> (i + MLDSA65_TAU as usize - N)) & 1;
        coeffs[j] = if sign_bit == 0 { 1 } else { -1 };
    }

    Poly::from_coeffs(coeffs)
}

/// Decompose `r` into `(r1, r0)` such that `r = r1 * 2^d + r0 mod q`.
pub fn power2round(r: i32) -> (i32, i32) {
    let r_plus = reduce_mod_q(r as i64);
    let modulus = 1i32 << MLDSA65_D;
    let r0 = centered_remainder(r_plus, modulus);
    ((r_plus - r0) / modulus, r0)
}

/// Decompose `r` into `(r1, r0)` such that `r = r1 * 2 * gamma2 + r0 mod q`.
pub fn decompose(r: i32) -> (i32, i32) {
    let r_plus = reduce_mod_q(r as i64);
    let alpha = 2 * MLDSA65_GAMMA2;
    let mut r0 = centered_remainder(r_plus, alpha);

    if r_plus - r0 == Q - 1 {
        r0 -= 1;
        (0, r0)
    } else {
        ((r_plus - r0) / alpha, r0)
    }
}

/// Return the high bits of `r` under ML-DSA decomposition.
pub fn high_bits(r: i32) -> i32 {
    decompose(r).0
}

/// Return the low bits of `r` under ML-DSA decomposition.
pub fn low_bits(r: i32) -> i32 {
    decompose(r).1
}

/// Return `true` when adding `z` changes the decomposed high bits of `r`.
pub fn make_hint(z: i32, r: i32) -> bool {
    high_bits(r) != high_bits(add_mod_q(r, z))
}

/// Adjust the high bits of `r` according to a verifier hint bit.
pub fn use_hint(hint: bool, r: i32) -> i32 {
    let modulus = (Q - 1) / (2 * MLDSA65_GAMMA2);
    let (r1, r0) = decompose(r);

    if !hint {
        return r1;
    }

    if r0 > 0 {
        (r1 + 1) % modulus
    } else {
        (r1 + modulus - 1) % modulus
    }
}

/// Check that all polynomial coefficients are strictly below the given bound.
pub fn check_poly_bound(poly: &Poly, bound: i32) -> bool {
    poly.check_noise_bounds(bound)
}

/// Verify a standard ML-DSA-65 signature.
///
/// This function is a deliberate hard stop until the local implementation is
/// completed against FIPS 204 known-answer tests.
pub fn verify_standard_mldsa65(
    public_key: &ThresholdPublicKey,
    _message: &[u8],
    signature: &ThresholdSignature,
) -> Result<bool, ThresholdError> {
    let _public_key = unpack_public_key(&public_key.0)?;
    let signature = unpack_signature(&signature.0)?;

    if !signature
        .z()
        .polys()
        .iter()
        .all(|poly| check_poly_bound(poly, MLDSA65_Z_NORM_BOUND))
    {
        return Err(ThresholdError::StandardVerificationFailed);
    }

    Err(ThresholdError::BackendUnavailable {
        reason: HAZMAT_VERIFIER_UNAVAILABLE,
    })
}

fn unpack_t1_poly(bytes: &[u8]) -> Poly {
    let mut coeffs = [0i32; N];
    for (index, coeff) in coeffs.iter_mut().enumerate() {
        *coeff = read_bits_le(bytes, index * 10, 10) as i32;
    }
    Poly::from_coeffs(coeffs)
}

fn pack_t1_poly(poly: &Poly) -> Result<[u8; MLDSA65_POLYT1_PACKED_BYTES], ThresholdError> {
    let mut bytes = [0u8; MLDSA65_POLYT1_PACKED_BYTES];
    for (index, coeff) in poly.coeffs.iter().enumerate() {
        if !(0..(1 << 10)).contains(coeff) {
            return Err(ThresholdError::MalformedSerialization {
                reason: T1_COEFFICIENT_UNPACKABLE,
            });
        }
        write_bits_le(&mut bytes, index * 10, 10, *coeff as u32);
    }
    Ok(bytes)
}

fn unpack_z_poly(bytes: &[u8]) -> Poly {
    let mut coeffs = [0i32; N];
    for (index, coeff) in coeffs.iter_mut().enumerate() {
        let encoded = read_bits_le(bytes, index * 20, 20) as i32;
        *coeff = MLDSA65_GAMMA1 - encoded;
    }
    Poly::from_coeffs(coeffs)
}

fn pack_z_poly(poly: &Poly) -> Result<[u8; MLDSA65_POLYZ_PACKED_BYTES], ThresholdError> {
    let mut bytes = [0u8; MLDSA65_POLYZ_PACKED_BYTES];
    for (index, coeff) in poly.coeffs.iter().enumerate() {
        if *coeff > MLDSA65_GAMMA1 || *coeff <= -MLDSA65_GAMMA1 {
            return Err(ThresholdError::MalformedSerialization {
                reason: Z_COEFFICIENT_UNPACKABLE,
            });
        }

        write_bits_le(&mut bytes, index * 20, 20, (MLDSA65_GAMMA1 - *coeff) as u32);
    }
    Ok(bytes)
}

fn unpack_hint(bytes: &[u8]) -> Result<HintVector, ThresholdError> {
    debug_assert_eq!(bytes.len(), MLDSA65_HINT_PACKED_BYTES);

    let mut indices = [0u8; MLDSA65_OMEGA];
    indices.copy_from_slice(&bytes[..MLDSA65_OMEGA]);

    let mut offsets = [0u8; MLDSA65_K];
    offsets.copy_from_slice(&bytes[MLDSA65_OMEGA..]);

    let mut previous_offset = 0usize;
    for offset in offsets {
        let offset = offset as usize;
        if offset > MLDSA65_OMEGA {
            return Err(ThresholdError::MalformedSerialization {
                reason: HINT_OFFSET_RANGE,
            });
        }
        if offset < previous_offset {
            return Err(ThresholdError::MalformedSerialization {
                reason: HINT_OFFSET_MONOTONIC,
            });
        }

        let segment = &indices[previous_offset..offset];
        if segment.windows(2).any(|window| window[1] <= window[0]) {
            return Err(ThresholdError::MalformedSerialization {
                reason: HINT_INDEX_ORDER,
            });
        }

        previous_offset = offset;
    }

    if indices[previous_offset..].iter().any(|index| *index != 0) {
        return Err(ThresholdError::MalformedSerialization {
            reason: HINT_UNUSED_NONZERO,
        });
    }

    Ok(HintVector {
        indices,
        offsets,
        weight: previous_offset,
    })
}

fn read_bits_le(bytes: &[u8], bit_offset: usize, width: usize) -> u32 {
    let mut value = 0u32;
    for bit in 0..width {
        let absolute_bit = bit_offset + bit;
        let byte = bytes[absolute_bit / 8];
        let bit_value = (byte >> (absolute_bit % 8)) & 1;
        value |= (bit_value as u32) << bit;
    }
    value
}

fn write_bits_le(bytes: &mut [u8], bit_offset: usize, width: usize, value: u32) {
    for bit in 0..width {
        let absolute_bit = bit_offset + bit;
        let bit_value = ((value >> bit) & 1) as u8;
        bytes[absolute_bit / 8] |= bit_value << (absolute_bit % 8);
    }
}

fn squeeze_byte(reader: &mut impl XofReader) -> usize {
    let mut byte = [0u8; 1];
    reader.read(&mut byte);
    byte[0] as usize
}

fn centered_remainder(value: i32, modulus: i32) -> i32 {
    let mut remainder = value % modulus;
    if remainder > modulus / 2 {
        remainder -= modulus;
    }
    remainder
}
