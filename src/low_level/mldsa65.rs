//! Hazmat ML-DSA-65 internals gated behind `hazmat-real-mldsa`.
//!
//! This module captures the local FIPS 204 ML-DSA-65 parameter surface and
//! arithmetic boundary needed by threshold experiments. It is intentionally not
//! a complete signing or verification implementation yet; callers must treat
//! every item here as low-level cryptographic construction material.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128, Shake256,
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
/// ML-DSA digest byte length for `mu`.
pub const MLDSA65_MU_BYTES: usize = 64;
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
/// Primitive 512th root of unity used for canonical reference NTT tests.
pub const MLDSA65_ROOT_OF_UNITY_512: i32 = 1753;
/// Packed byte length for one ML-DSA `t1` polynomial.
pub const MLDSA65_POLYT1_PACKED_BYTES: usize = 320;
/// Packed byte length for one ML-DSA-65 `z` polynomial.
pub const MLDSA65_POLYZ_PACKED_BYTES: usize = 640;
/// Packed byte length for an ML-DSA-65 hint vector.
pub const MLDSA65_HINT_PACKED_BYTES: usize = MLDSA65_OMEGA + MLDSA65_K;
/// Packed byte length for one ML-DSA `w1` polynomial.
pub const MLDSA65_POLYW1_PACKED_BYTES: usize = 128;
/// Packed byte length for an ML-DSA-65 `w1` vector.
pub const MLDSA65_W1_ENCODED_BYTES: usize = MLDSA65_K * MLDSA65_POLYW1_PACKED_BYTES;
/// Strict infinity norm bound for ML-DSA-65 `z`.
pub const MLDSA65_Z_NORM_BOUND: i32 = MLDSA65_GAMMA1 - MLDSA65_BETA;

const PUBLIC_KEY_LENGTH_MISMATCH: &str = "ML-DSA-65 public key length mismatch";
const SIGNATURE_LENGTH_MISMATCH: &str = "ML-DSA-65 signature length mismatch";
const HINT_OFFSET_RANGE: &str = "ML-DSA-65 hint offset exceeds omega";
const HINT_OFFSET_MONOTONIC: &str = "ML-DSA-65 hint offsets are not monotonic";
const HINT_INDEX_ORDER: &str = "ML-DSA-65 hint indices are not strictly increasing";
const HINT_POSITION_RANGE: &str = "ML-DSA-65 hint position is out of range";
const HINT_POSITION_ORDER: &str = "ML-DSA-65 hint positions are not strictly increasing";
const HINT_UNUSED_NONZERO: &str = "ML-DSA-65 hint encoding has nonzero unused slot";
const T1_COEFFICIENT_UNPACKABLE: &str = "ML-DSA-65 t1 coefficient cannot be packed";
const Z_COEFFICIENT_UNPACKABLE: &str = "ML-DSA-65 z coefficient cannot be packed";
const CONTEXT_LENGTH_RANGE: &str = "ML-DSA-65 context length exceeds FIPS 204 bound";
const MU_LENGTH_MISMATCH: &str = "ML-DSA-65 mu length mismatch";

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

    /// Build a canonical hint vector from `(row, coefficient)` positions.
    pub fn from_positions(positions: &[(usize, usize)]) -> Result<Self, ThresholdError> {
        if positions.len() > MLDSA65_OMEGA {
            return Err(ThresholdError::MalformedSerialization {
                reason: HINT_OFFSET_RANGE,
            });
        }

        let mut indices = [0u8; MLDSA65_OMEGA];
        let mut offsets = [0u8; MLDSA65_K];
        let mut cursor = 0usize;
        let mut position_iter = positions.iter().copied().peekable();

        for (row, offset) in offsets.iter_mut().enumerate() {
            let mut last_coeff = None;
            while matches!(position_iter.peek(), Some((next_row, _)) if *next_row == row) {
                let (_, coeff) = position_iter.next().expect("peeked position exists");
                if coeff >= N {
                    return Err(ThresholdError::MalformedSerialization {
                        reason: HINT_POSITION_RANGE,
                    });
                }
                if last_coeff.is_some_and(|previous| coeff <= previous) {
                    return Err(ThresholdError::MalformedSerialization {
                        reason: HINT_POSITION_ORDER,
                    });
                }
                indices[cursor] = coeff as u8;
                cursor += 1;
                last_coeff = Some(coeff);
            }
            *offset = cursor as u8;
        }

        if position_iter.peek().is_some() {
            return Err(ThresholdError::MalformedSerialization {
                reason: HINT_POSITION_RANGE,
            });
        }

        Ok(Self {
            indices,
            offsets,
            weight: cursor,
        })
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

/// ML-DSA-65 public matrix expanded from `rho`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatrixA {
    rows: [VectorL; MLDSA65_K],
}

impl MatrixA {
    /// Construct a matrix from row vectors.
    pub const fn from_rows(rows: [VectorL; MLDSA65_K]) -> Self {
        Self { rows }
    }

    /// Borrow matrix rows.
    pub fn rows(&self) -> &[VectorL; MLDSA65_K] {
        &self.rows
    }
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

/// Add two polynomials coefficientwise modulo `Q`.
pub fn poly_add(lhs: &Poly, rhs: &Poly) -> Poly {
    let mut coeffs = [0i32; N];
    for (out, (left, right)) in coeffs
        .iter_mut()
        .zip(lhs.coeffs.iter().zip(rhs.coeffs.iter()))
    {
        *out = add_mod_q(*left, *right);
    }
    Poly::from_coeffs(coeffs)
}

/// Subtract two polynomials coefficientwise modulo `Q`.
pub fn poly_sub(lhs: &Poly, rhs: &Poly) -> Poly {
    let mut coeffs = [0i32; N];
    for (out, (left, right)) in coeffs
        .iter_mut()
        .zip(lhs.coeffs.iter().zip(rhs.coeffs.iter()))
    {
        *out = sub_mod_q(*left, *right);
    }
    Poly::from_coeffs(coeffs)
}

/// Multiply two polynomials in `Z_q[X] / (X^256 + 1)`.
pub fn poly_negacyclic_mul(lhs: &Poly, rhs: &Poly) -> Poly {
    let mut accum = [0i64; N];
    for (i, left) in lhs.coeffs.iter().enumerate() {
        for (j, right) in rhs.coeffs.iter().enumerate() {
            let product = *left as i64 * *right as i64;
            let degree = i + j;
            if degree < N {
                accum[degree] += product;
            } else {
                accum[degree - N] -= product;
            }
        }
    }

    let mut coeffs = [0i32; N];
    for (out, value) in coeffs.iter_mut().zip(accum) {
        *out = reduce_mod_q(value);
    }
    Poly::from_coeffs(coeffs)
}

/// Multiply every coefficient by `2^d` modulo `Q`.
pub fn poly_shift_left_d(poly: &Poly) -> Poly {
    let mut coeffs = [0i32; N];
    for (out, coeff) in coeffs.iter_mut().zip(poly.coeffs.iter()) {
        *out = reduce_mod_q((*coeff as i64) << MLDSA65_D);
    }
    Poly::from_coeffs(coeffs)
}

/// Multiply each `t1` component by `2^d` modulo `Q`.
pub fn t1_times_2d(t1: &VectorK) -> VectorK {
    let mut polys = [Poly::zero(); MLDSA65_K];
    for (out, poly) in polys.iter_mut().zip(t1.polys().iter()) {
        *out = poly_shift_left_d(poly);
    }
    VectorK::from_polys(polys)
}

/// Reference coefficient-domain matrix-vector multiplication.
pub fn matrix_vector_mul(matrix: &MatrixA, vector: &VectorL) -> VectorK {
    let mut rows = [Poly::zero(); MLDSA65_K];
    for (out, matrix_row) in rows.iter_mut().zip(matrix.rows().iter()) {
        let mut sum = Poly::zero();
        for (entry, vector_poly) in matrix_row.polys().iter().zip(vector.polys().iter()) {
            sum = poly_add(&sum, &poly_negacyclic_mul(entry, vector_poly));
        }
        *out = sum;
    }
    VectorK::from_polys(rows)
}

/// Canonical reference NTT over the negacyclic ML-DSA ring.
///
/// This is a slow `O(n^2)` transform with canonical coefficients. It is not
/// the final Montgomery/table-optimized FIPS implementation.
pub fn ntt(poly: &Poly) -> Poly {
    let mut coeffs = [0i32; N];
    for (point, out) in coeffs.iter_mut().enumerate() {
        let root = mod_pow(MLDSA65_ROOT_OF_UNITY_512, (2 * point + 1) as u32);
        let mut root_power = 1i32;
        let mut accum = 0i64;
        for coeff in poly.coeffs {
            accum += mul_mod_q(coeff, root_power) as i64;
            root_power = mul_mod_q(root_power, root);
        }
        *out = reduce_mod_q(accum);
    }
    Poly::from_coeffs(coeffs)
}

/// Inverse of the canonical reference NTT.
pub fn inverse_ntt(poly: &Poly) -> Poly {
    let n_inverse = mod_inverse(N as i32);
    let mut coeffs = [0i32; N];
    for (degree, out) in coeffs.iter_mut().enumerate() {
        let mut accum = 0i64;
        for (point, value) in poly.coeffs.iter().enumerate() {
            let root = mod_pow(MLDSA65_ROOT_OF_UNITY_512, ((2 * point + 1) * degree) as u32);
            let inverse_root = mod_inverse(root);
            accum += mul_mod_q(*value, inverse_root) as i64;
        }
        *out = mul_mod_q(reduce_mod_q(accum), n_inverse);
    }
    Poly::from_coeffs(coeffs)
}

/// Multiply two polynomials through the canonical reference NTT.
pub fn poly_mul_ntt(lhs: &Poly, rhs: &Poly) -> Poly {
    let lhs_ntt = ntt(lhs);
    let rhs_ntt = ntt(rhs);
    let mut product = [0i32; N];
    for (out, (left, right)) in product
        .iter_mut()
        .zip(lhs_ntt.coeffs.iter().zip(rhs_ntt.coeffs.iter()))
    {
        *out = mul_mod_q(*left, *right);
    }
    inverse_ntt(&Poly::from_coeffs(product))
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

/// Rejection-sample an NTT-domain polynomial from a SHAKE128 seed stream.
pub fn rej_ntt_poly(seed: &[u8]) -> Poly {
    let mut hasher = Shake128::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();

    let mut coeffs = [0i32; N];
    let mut filled = 0usize;
    while filled < N {
        let candidate = squeeze_three_byte_candidate(&mut reader);
        if candidate < Q as u32 {
            coeffs[filled] = candidate as i32;
            filled += 1;
        }
    }

    Poly::from_coeffs(coeffs)
}

/// Expand the ML-DSA-65 public matrix `A` from public seed `rho`.
pub fn expand_a(rho: &[u8; MLDSA65_PUBLIC_SEED_BYTES]) -> MatrixA {
    let mut rows = [VectorL::zero(); MLDSA65_K];
    for (row_index, row) in rows.iter_mut().enumerate() {
        let mut polys = [Poly::zero(); MLDSA65_L];
        for (column_index, poly) in polys.iter_mut().enumerate() {
            let mut seed = [0u8; MLDSA65_PUBLIC_SEED_BYTES + 2];
            seed[..MLDSA65_PUBLIC_SEED_BYTES].copy_from_slice(rho);
            seed[MLDSA65_PUBLIC_SEED_BYTES] = column_index as u8;
            seed[MLDSA65_PUBLIC_SEED_BYTES + 1] = row_index as u8;
            *poly = rej_ntt_poly(&seed);
        }
        *row = VectorL::from_polys(polys);
    }
    MatrixA::from_rows(rows)
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

/// Apply an ML-DSA hint vector to decomposed high-bit inputs.
pub fn use_hint_vector(hint: &HintVector, values: &VectorK) -> VectorK {
    let mut adjusted = [Poly::zero(); MLDSA65_K];
    let mut start = 0usize;

    for (row_index, row) in adjusted.iter_mut().enumerate() {
        *row = values.polys()[row_index];
        let end = hint.offsets()[row_index] as usize;
        for coeff_index in hint.indices()[start..end].iter().copied() {
            let coeff_index = coeff_index as usize;
            row.coeffs[coeff_index] = use_hint(true, values.polys()[row_index].coeffs[coeff_index]);
        }
        for coeff_index in 0..N {
            if !hint.indices()[start..end].contains(&(coeff_index as u8)) {
                row.coeffs[coeff_index] =
                    use_hint(false, values.polys()[row_index].coeffs[coeff_index]);
            }
        }
        start = end;
    }

    VectorK::from_polys(adjusted)
}

/// Compute the hinted `w1` vector used by ML-DSA verification.
pub fn compute_verification_w1(
    public_key: &ThresholdPublicKey,
    _message: &[u8],
    signature: &ThresholdSignature,
) -> Result<VectorK, ThresholdError> {
    let public_key = unpack_public_key(&public_key.0)?;
    let signature = unpack_signature(&signature.0)?;

    if !signature
        .z()
        .polys()
        .iter()
        .all(|poly| check_poly_bound(poly, MLDSA65_Z_NORM_BOUND))
    {
        return Err(ThresholdError::StandardVerificationFailed);
    }

    let w_approx = compute_verification_w_approx(&public_key, &signature);

    Ok(use_hint_vector(signature.hint(), &w_approx))
}

fn compute_verification_w_approx(
    public_key: &UnpackedPublicKey,
    signature: &UnpackedSignature,
) -> VectorK {
    let matrix = expand_a(public_key.rho());
    let z_hat = fips_ntt_vector_l(signature.z());
    let az_hat = fips_matrix_vector_mul(&matrix, &z_hat);
    let challenge = sample_in_ball(signature.challenge());
    let c_hat = fips_ntt_poly(&challenge);
    let t1_d2_hat_mont = fips_t1_d2_hat_mont(public_key.t1());

    let mut w_approx_hat = [Poly::zero(); MLDSA65_K];
    for (row, (az_poly, t1_poly)) in w_approx_hat
        .iter_mut()
        .zip(az_hat.polys().iter().zip(t1_d2_hat_mont.polys().iter()))
    {
        for (coeff_index, (out, (az_coeff, t1_coeff))) in row
            .coeffs
            .iter_mut()
            .zip(az_poly.coeffs.iter().zip(t1_poly.coeffs.iter()))
            .enumerate()
        {
            *out =
                *az_coeff - montgomery_reduce(c_hat.coeffs[coeff_index] as i64 * *t1_coeff as i64);
        }
    }

    fips_inverse_ntt_vector_k(&VectorK::from_polys(w_approx_hat))
}

fn fips_ntt_vector_l(vector: &VectorL) -> VectorL {
    let mut polys = [Poly::zero(); MLDSA65_L];
    for (out, poly) in polys.iter_mut().zip(vector.polys().iter()) {
        *out = fips_ntt_poly(poly);
    }
    VectorL::from_polys(polys)
}

fn fips_inverse_ntt_vector_k(vector: &VectorK) -> VectorK {
    let mut polys = [Poly::zero(); MLDSA65_K];
    for (out, poly) in polys.iter_mut().zip(vector.polys().iter()) {
        *out = fips_inverse_ntt_poly(poly);
    }
    VectorK::from_polys(polys)
}

fn fips_t1_d2_hat_mont(t1: &VectorK) -> VectorK {
    let t1_d2 = t1_times_2d(t1);
    let mut polys = [Poly::zero(); MLDSA65_K];
    for (out, poly) in polys.iter_mut().zip(t1_d2.polys().iter()) {
        *out = fips_to_mont_poly(&fips_ntt_poly(poly));
    }
    VectorK::from_polys(polys)
}

fn fips_matrix_vector_mul(matrix: &MatrixA, vector_hat: &VectorL) -> VectorK {
    let vector_hat_mont = fips_to_mont_vector_l(vector_hat);
    let mut rows = [Poly::zero(); MLDSA65_K];

    for (out, matrix_row) in rows.iter_mut().zip(matrix.rows().iter()) {
        for (entry, vector_poly) in matrix_row
            .polys()
            .iter()
            .zip(vector_hat_mont.polys().iter())
        {
            for (accum, (left, right)) in out
                .coeffs
                .iter_mut()
                .zip(entry.coeffs.iter().zip(vector_poly.coeffs.iter()))
            {
                *accum += montgomery_reduce(*left as i64 * *right as i64);
            }
        }
    }

    VectorK::from_polys(rows)
}

fn fips_to_mont_vector_l(vector: &VectorL) -> VectorL {
    let mut polys = [Poly::zero(); MLDSA65_L];
    for (out, poly) in polys.iter_mut().zip(vector.polys().iter()) {
        *out = fips_to_mont_poly(poly);
    }
    VectorL::from_polys(polys)
}

fn fips_to_mont_poly(poly: &Poly) -> Poly {
    let mut coeffs = [0i32; N];
    for (out, coeff) in coeffs.iter_mut().zip(poly.coeffs.iter()) {
        *out = partial_reduce64((*coeff as i64) << 32);
    }
    Poly::from_coeffs(coeffs)
}

fn fips_ntt_poly(poly: &Poly) -> Poly {
    let zetas = zeta_table_mont();
    let mut coeffs = poly.coeffs;
    let mut m = 0usize;
    let mut len = 128usize;

    while len >= 1 {
        let mut start = 0usize;
        while start < N {
            m += 1;
            let zeta = zetas[m] as i64;
            for j in start..(start + len) {
                let t = montgomery_reduce(zeta * coeffs[j + len] as i64);
                coeffs[j + len] = coeffs[j] - t;
                coeffs[j] += t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }

    Poly::from_coeffs(coeffs)
}

fn fips_inverse_ntt_poly(poly: &Poly) -> Poly {
    const F_MONT: i64 = 8_347_681_i128.wrapping_mul(1 << 32).rem_euclid(Q as i128) as i64;

    let zetas = zeta_table_mont();
    let mut coeffs = poly.coeffs;
    let mut m = 256usize;
    let mut len = 1usize;

    while len < N {
        let mut start = 0usize;
        while start < N {
            m -= 1;
            let zeta = -zetas[m] as i64;
            for j in start..(start + len) {
                let t = coeffs[j];
                coeffs[j] = t + coeffs[j + len];
                coeffs[j + len] = t - coeffs[j + len];
                coeffs[j + len] = montgomery_reduce(zeta * coeffs[j + len] as i64);
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    for coeff in &mut coeffs {
        *coeff = full_reduce32(montgomery_reduce(F_MONT * *coeff as i64));
    }

    Poly::from_coeffs(coeffs)
}

fn zeta_table_mont() -> [i32; N] {
    let mut table = [0i32; N];
    let mut x = 1i64;
    for i in 0..N {
        table[reverse_bits_u8(i as u8) as usize] = ((x << 32) % Q as i64) as i32;
        x = (x * MLDSA65_ROOT_OF_UNITY_512 as i64) % Q as i64;
    }
    table
}

fn reverse_bits_u8(value: u8) -> u8 {
    value.reverse_bits()
}

fn partial_reduce64(value: i64) -> i32 {
    const M: i64 = (1 << 48) / Q as i64;
    let x = value >> 23;
    let value = value - x * Q as i64;
    let x = value >> 23;
    let value = value - x * Q as i64;
    let quotient = (value * M) >> 48;
    (value - quotient * Q as i64) as i32
}

fn partial_reduce32(value: i32) -> i32 {
    let quotient = (value + (1 << 22)) >> 23;
    value - quotient * Q
}

fn full_reduce32(value: i32) -> i32 {
    let reduced = partial_reduce32(value);
    reduced + ((reduced >> 31) & Q)
}

fn montgomery_reduce(value: i64) -> i32 {
    const QINV: i32 = 58_728_449;
    let t = (value as i32).wrapping_mul(QINV);
    ((value - (t as i64).wrapping_mul(Q as i64)) >> 32) as i32
}

/// Check that all polynomial coefficients are strictly below the given bound.
pub fn check_poly_bound(poly: &Poly, bound: i32) -> bool {
    poly.check_noise_bounds(bound)
}

/// Verify a standard ML-DSA-65 signature.
pub fn verify_standard_mldsa65(
    public_key: &ThresholdPublicKey,
    message: &[u8],
    signature: &ThresholdSignature,
) -> Result<bool, ThresholdError> {
    verify_mldsa65_external_pure(public_key, message, &[], signature)
}

/// Verify an external pure ML-DSA-65 signature with an explicit context string.
pub fn verify_mldsa65_external_pure(
    public_key: &ThresholdPublicKey,
    message: &[u8],
    context: &[u8],
    signature: &ThresholdSignature,
) -> Result<bool, ThresholdError> {
    if context.len() > u8::MAX as usize {
        return Err(ThresholdError::MalformedSerialization {
            reason: CONTEXT_LENGTH_RANGE,
        });
    }

    let unpacked_signature = unpack_signature(&signature.0)?;
    let w1 = compute_verification_w1(public_key, message, signature)?;
    let expected_challenge = compute_verification_challenge(public_key, message, context, &w1);

    Ok(unpacked_signature.challenge() == &expected_challenge)
}

/// Verify an internal ML-DSA-65 signature whose `mu` value is derived from the message.
pub fn verify_mldsa65_internal_message(
    public_key: &ThresholdPublicKey,
    message: &[u8],
    signature: &ThresholdSignature,
) -> Result<bool, ThresholdError> {
    let unpacked_signature = unpack_signature(&signature.0)?;
    let w1 = compute_verification_w1(public_key, message, signature)?;
    let tr = shake256_64(&public_key.0);
    let mu = compute_internal_message_mu(&tr, message);
    let expected_challenge = compute_challenge_from_mu(&mu, &w1);

    Ok(unpacked_signature.challenge() == &expected_challenge)
}

/// Verify an internal ML-DSA-65 signature using a caller-supplied `mu` digest.
pub fn verify_mldsa65_internal_mu(
    public_key: &ThresholdPublicKey,
    mu: &[u8],
    signature: &ThresholdSignature,
) -> Result<bool, ThresholdError> {
    let mu: &[u8; MLDSA65_MU_BYTES] =
        mu.try_into()
            .map_err(|_| ThresholdError::MalformedSerialization {
                reason: MU_LENGTH_MISMATCH,
            })?;
    let unpacked_signature = unpack_signature(&signature.0)?;
    let w1 = compute_verification_w1(public_key, &[], signature)?;
    let expected_challenge = compute_challenge_from_mu(mu, &w1);

    Ok(unpacked_signature.challenge() == &expected_challenge)
}

fn compute_verification_challenge(
    public_key: &ThresholdPublicKey,
    message: &[u8],
    context: &[u8],
    w1: &VectorK,
) -> [u8; MLDSA65_CHALLENGE_BYTES] {
    let tr = shake256_64(&public_key.0);
    let mu = compute_external_pure_mu(&tr, message, context);

    compute_challenge_from_mu(&mu, w1)
}

fn compute_external_pure_mu(
    tr: &[u8; MLDSA65_MU_BYTES],
    message: &[u8],
    context: &[u8],
) -> [u8; MLDSA65_MU_BYTES] {
    let mut mu_hasher = Shake256::default();
    mu_hasher.update(tr);
    mu_hasher.update(&[0x00, context.len() as u8]);
    mu_hasher.update(context);
    mu_hasher.update(message);
    let mut mu_reader = mu_hasher.finalize_xof();
    let mut mu = [0u8; MLDSA65_MU_BYTES];
    mu_reader.read(&mut mu);
    mu
}

fn compute_internal_message_mu(
    tr: &[u8; MLDSA65_MU_BYTES],
    message: &[u8],
) -> [u8; MLDSA65_MU_BYTES] {
    let mut mu_hasher = Shake256::default();
    mu_hasher.update(tr);
    mu_hasher.update(message);
    let mut mu_reader = mu_hasher.finalize_xof();
    let mut mu = [0u8; MLDSA65_MU_BYTES];
    mu_reader.read(&mut mu);
    mu
}

fn compute_challenge_from_mu(
    mu: &[u8; MLDSA65_MU_BYTES],
    w1: &VectorK,
) -> [u8; MLDSA65_CHALLENGE_BYTES] {
    let mut challenge_hasher = Shake256::default();
    challenge_hasher.update(mu);
    challenge_hasher.update(&encode_w1(w1));
    let mut challenge_reader = challenge_hasher.finalize_xof();
    let mut challenge = [0u8; MLDSA65_CHALLENGE_BYTES];
    challenge_reader.read(&mut challenge);
    challenge
}

fn shake256_64(input: &[u8]) -> [u8; 64] {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; 64];
    reader.read(&mut output);
    output
}

fn encode_w1(w1: &VectorK) -> [u8; MLDSA65_W1_ENCODED_BYTES] {
    let mut bytes = [0u8; MLDSA65_W1_ENCODED_BYTES];
    for (poly_index, poly) in w1.polys().iter().enumerate() {
        let offset = poly_index * MLDSA65_POLYW1_PACKED_BYTES;
        bytes[offset..offset + MLDSA65_POLYW1_PACKED_BYTES].copy_from_slice(&pack_w1_poly(poly));
    }
    bytes
}

fn pack_w1_poly(poly: &Poly) -> [u8; MLDSA65_POLYW1_PACKED_BYTES] {
    let mut bytes = [0u8; MLDSA65_POLYW1_PACKED_BYTES];
    for (pair_index, pair) in poly.coeffs.chunks_exact(2).enumerate() {
        bytes[pair_index] =
            reduce_mod_q(pair[0] as i64) as u8 | ((reduce_mod_q(pair[1] as i64) as u8) << 4);
    }
    bytes
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

fn squeeze_three_byte_candidate(reader: &mut impl XofReader) -> u32 {
    let mut bytes = [0u8; 3];
    reader.read(&mut bytes);
    ((bytes[0] as u32) | ((bytes[1] as u32) << 8) | ((bytes[2] as u32) << 16)) & 0x7f_ffff
}

fn mod_pow(base: i32, exponent: u32) -> i32 {
    let mut result = 1i32;
    let mut base = reduce_mod_q(base as i64);
    let mut exponent = exponent;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = mul_mod_q(result, base);
        }
        base = mul_mod_q(base, base);
        exponent >>= 1;
    }
    result
}

fn mod_inverse(value: i32) -> i32 {
    mod_pow(value, (Q - 2) as u32)
}

fn centered_remainder(value: i32, modulus: i32) -> i32 {
    let mut remainder = value % modulus;
    if remainder > modulus / 2 {
        remainder -= modulus;
    }
    remainder
}
