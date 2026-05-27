//! Hazmat ML-DSA-65 internals gated behind `hazmat-real-mldsa`.
//!
//! This module captures the local FIPS 204 ML-DSA-65 parameter surface and
//! arithmetic boundary needed by threshold experiments. It is intentionally not
//! a complete signing or verification implementation yet; callers must treat
//! every item here as low-level cryptographic construction material.

use std::{collections::BTreeSet, fmt, str::FromStr};

use sha2::{Digest as FixedDigest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest as Sha3Digest, Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256,
};

use crate::{
    crypto::{
        interpolation::reconstruct_secret_poly,
        vss::{
            commit_share_contribution, split_secret_poly, verify_share_contribution_commitments,
            ShareContribution, VssShareCommitment,
        },
    },
    errors::ThresholdError,
    low_level::poly::{Poly, N, Q},
    types::{
        ThresholdPublicKey, ThresholdSignature, ValidatorId, MLDSA65_PUBLICKEY_BYTES,
        MLDSA65_SIGNATURE_BYTES,
    },
};

/// ML-DSA-65 public seed byte length for `rho`.
pub const MLDSA65_PUBLIC_SEED_BYTES: usize = 32;
/// ML-DSA-65 key-generation seed byte length for `xi`.
pub const MLDSA65_KEYGEN_SEED_BYTES: usize = 32;
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
/// Packed byte length for one ML-DSA eta-4 secret polynomial.
pub const MLDSA65_POLYETA_PACKED_BYTES: usize = 128;
/// Packed byte length for one ML-DSA `t0` polynomial.
pub const MLDSA65_POLYT0_PACKED_BYTES: usize = 416;
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
/// Canonical raw byte length for a wire-encoded threshold masking contribution.
pub const MLDSA65_MASKING_CONTRIBUTION_BYTES: usize =
    2 + 2 + 2 + MLDSA65_PUBLIC_SEED_BYTES + ((MLDSA65_L + MLDSA65_K) * N * 4);
/// Canonical raw byte length for a wire-encoded threshold secret contribution.
pub const MLDSA65_SECRET_CONTRIBUTION_BYTES: usize =
    2 + 2 + 2 + MLDSA65_CHALLENGE_BYTES + ((MLDSA65_L + MLDSA65_K + MLDSA65_K) * N * 4);

const PUBLIC_KEY_LENGTH_MISMATCH: &str = "ML-DSA-65 public key length mismatch";
const SIGNATURE_LENGTH_MISMATCH: &str = "ML-DSA-65 signature length mismatch";
const SECRET_KEY_LENGTH_MISMATCH: &str = "ML-DSA-65 expanded secret key length mismatch";
const HINT_OFFSET_RANGE: &str = "ML-DSA-65 hint offset exceeds omega";
const HINT_OFFSET_MONOTONIC: &str = "ML-DSA-65 hint offsets are not monotonic";
const HINT_INDEX_ORDER: &str = "ML-DSA-65 hint indices are not strictly increasing";
const HINT_POSITION_RANGE: &str = "ML-DSA-65 hint position is out of range";
const HINT_POSITION_ORDER: &str = "ML-DSA-65 hint positions are not strictly increasing";
const HINT_UNUSED_NONZERO: &str = "ML-DSA-65 hint encoding has nonzero unused slot";
const T1_COEFFICIENT_UNPACKABLE: &str = "ML-DSA-65 t1 coefficient cannot be packed";
const Z_COEFFICIENT_UNPACKABLE: &str = "ML-DSA-65 z coefficient cannot be packed";
const SECRET_COEFFICIENT_UNPACKABLE: &str = "ML-DSA-65 secret coefficient cannot be packed";
const SECRET_COEFFICIENT_RANGE: &str = "ML-DSA-65 secret coefficient is out of range";
const CONTEXT_LENGTH_RANGE: &str = "ML-DSA-65 context length exceeds FIPS 204 bound";
const MU_LENGTH_MISMATCH: &str = "ML-DSA-65 mu length mismatch";
const SIGNING_REJECTION_EXHAUSTED: &str = "ML-DSA-65 signing rejection loop exhausted";
const SECRET_SHARE_METADATA_MISMATCH: &str = "ML-DSA-65 secret share metadata mismatch";
const SECRET_CONTRIBUTION_METADATA_MISMATCH: &str =
    "ML-DSA-65 secret contribution metadata mismatch";
const CONTRIBUTION_LENGTH_MISMATCH: &str = "ML-DSA-65 contribution payload length mismatch";
const CONTRIBUTION_COEFFICIENT_RANGE: &str = "ML-DSA-65 contribution coefficient is out of range";
const DKG_COMMITMENT_DIGEST_LABEL: &[u8] = b"dytallix.hazmat.mldsa65.dkg.public-commitment.v1";
const VSS_COMPONENT_CONTEXT_LABEL: &[u8] = b"dytallix.hazmat.mldsa65.vss.component-context.v1";
const VSS_SHARE_AGGREGATE_LABEL: &[u8] = b"dytallix.hazmat.mldsa65.vss.share-aggregate.v1";
const VSS_COMPONENT_KEY_SEED: &[u8] = b"key_seed";
const VSS_COMPONENT_S1: &[u8] = b"s1";
const VSS_COMPONENT_S2: &[u8] = b"s2";
const VSS_COMPONENT_T0: &[u8] = b"t0";

/// FIPS 204 HashML-DSA prehash algorithms accepted by ACVP `sigVer` vectors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mldsa65PreHashAlgorithm {
    /// SHA2-224 prehash.
    Sha2_224,
    /// SHA2-256 prehash.
    Sha2_256,
    /// SHA2-384 prehash.
    Sha2_384,
    /// SHA2-512 prehash.
    Sha2_512,
    /// SHA2-512/224 prehash.
    Sha2_512_224,
    /// SHA2-512/256 prehash.
    Sha2_512_256,
    /// SHA3-224 prehash.
    Sha3_224,
    /// SHA3-256 prehash.
    Sha3_256,
    /// SHA3-384 prehash.
    Sha3_384,
    /// SHA3-512 prehash.
    Sha3_512,
    /// SHAKE-128 prehash with 32 output bytes.
    Shake128,
    /// SHAKE-256 prehash with 64 output bytes.
    Shake256,
}

impl FromStr for Mldsa65PreHashAlgorithm {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "SHA2-224" => Ok(Self::Sha2_224),
            "SHA2-256" => Ok(Self::Sha2_256),
            "SHA2-384" => Ok(Self::Sha2_384),
            "SHA2-512" => Ok(Self::Sha2_512),
            "SHA2-512/224" => Ok(Self::Sha2_512_224),
            "SHA2-512/256" => Ok(Self::Sha2_512_256),
            "SHA3-224" => Ok(Self::Sha3_224),
            "SHA3-256" => Ok(Self::Sha3_256),
            "SHA3-384" => Ok(Self::Sha3_384),
            "SHA3-512" => Ok(Self::Sha3_512),
            "SHAKE-128" => Ok(Self::Shake128),
            "SHAKE-256" => Ok(Self::Shake256),
            _ => Err(()),
        }
    }
}

impl Mldsa65PreHashAlgorithm {
    fn oid_der(self) -> &'static [u8] {
        match self {
            Self::Sha2_224 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
            ],
            Self::Sha2_256 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            ],
            Self::Sha2_384 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
            ],
            Self::Sha2_512 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
            ],
            Self::Sha2_512_224 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05,
            ],
            Self::Sha2_512_256 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06,
            ],
            Self::Sha3_224 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07,
            ],
            Self::Sha3_256 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
            ],
            Self::Sha3_384 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
            ],
            Self::Sha3_512 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A,
            ],
            Self::Shake128 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B,
            ],
            Self::Shake256 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C,
            ],
        }
    }

    fn digest_message(self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha2_224 => Sha224::digest(message).to_vec(),
            Self::Sha2_256 => Sha256::digest(message).to_vec(),
            Self::Sha2_384 => Sha384::digest(message).to_vec(),
            Self::Sha2_512 => Sha512::digest(message).to_vec(),
            Self::Sha2_512_224 => Sha512_224::digest(message).to_vec(),
            Self::Sha2_512_256 => Sha512_256::digest(message).to_vec(),
            Self::Sha3_224 => Sha3_224::digest(message).to_vec(),
            Self::Sha3_256 => Sha3_256::digest(message).to_vec(),
            Self::Sha3_384 => Sha3_384::digest(message).to_vec(),
            Self::Sha3_512 => Sha3_512::digest(message).to_vec(),
            Self::Shake128 => {
                let mut digest = vec![0; 32];
                let mut hasher = Shake128::default();
                hasher.update(message);
                hasher.finalize_xof().read(&mut digest);
                digest
            }
            Self::Shake256 => {
                let mut digest = vec![0; 64];
                let mut hasher = Shake256::default();
                hasher.update(message);
                hasher.finalize_xof().read(&mut digest);
                digest
            }
        }
    }
}

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

/// Fixed-size byte wrapper for an expanded ML-DSA-65 secret key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mldsa65ExpandedSecretKeyBytes([u8; MLDSA65_SECRETKEY_BYTES]);

impl Mldsa65ExpandedSecretKeyBytes {
    /// Construct an expanded secret key byte wrapper from exactly-sized bytes.
    pub const fn new(bytes: [u8; MLDSA65_SECRETKEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// Borrow the encoded expanded secret key bytes.
    pub fn as_bytes(&self) -> &[u8; MLDSA65_SECRETKEY_BYTES] {
        &self.0
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

struct Mldsa65SigningMaterial {
    rho: [u8; MLDSA65_PUBLIC_SEED_BYTES],
    key_seed: [u8; MLDSA65_KEYGEN_SEED_BYTES],
    tr: [u8; MLDSA65_MU_BYTES],
    matrix: MatrixA,
    s1: VectorL,
    s2: VectorK,
    t0: VectorK,
    s1_hat: VectorL,
    s2_hat: VectorK,
    t0_hat: VectorK,
}

/// One Shamir-style share of the unpacked ML-DSA-65 expanded secret components.
///
/// This is a local threshold-bridge scaffold. It proves that the real expanded
/// key components can cross the VSS/interpolation boundary, but it is not a
/// production DKG transcript or MPC signing share format.
#[derive(Clone, Eq, PartialEq)]
pub struct Mldsa65ExpandedSecretKeyShare {
    receiver_index: u16,
    threshold: u16,
    total_nodes: u16,
    rho: [u8; MLDSA65_PUBLIC_SEED_BYTES],
    key_seed_share: [i32; MLDSA65_KEYGEN_SEED_BYTES],
    tr: [u8; MLDSA65_MU_BYTES],
    s1: VectorL,
    s2: VectorK,
    t0: VectorK,
    vss_commitment_digest: [u8; 32],
}

impl fmt::Debug for Mldsa65ExpandedSecretKeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mldsa65ExpandedSecretKeyShare")
            .field("receiver_index", &self.receiver_index)
            .field("threshold", &self.threshold)
            .field("total_nodes", &self.total_nodes)
            .field("rho", &self.rho)
            .field("vss_commitment_digest", &self.vss_commitment_digest)
            .field("tr", &"<redacted>")
            .field("s1", &"<redacted>")
            .field("s2", &"<redacted>")
            .field("t0", &"<redacted>")
            .finish()
    }
}

impl Mldsa65ExpandedSecretKeyShare {
    /// Return the one-based receiver index for this share.
    pub const fn receiver_index(&self) -> u16 {
        self.receiver_index
    }

    /// Return the reconstruction threshold.
    pub const fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Return the total validator count used for the split.
    pub const fn total_nodes(&self) -> u16 {
        self.total_nodes
    }

    /// Borrow the shared `s1` component.
    pub fn s1(&self) -> &VectorL {
        &self.s1
    }

    /// Borrow the shared `s2` component.
    pub fn s2(&self) -> &VectorK {
        &self.s2
    }

    /// Borrow the shared `t0` component.
    pub fn t0(&self) -> &VectorK {
        &self.t0
    }

    /// Compute a public DKG commitment digest from non-secret share metadata.
    ///
    /// This binds proof-carrying contribution statements to the validator-set
    /// key material (`rho`, `tr`, threshold, and total validator count) without
    /// exposing the secret polynomial shares.
    pub fn dkg_public_commitment_digest(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        Sha3Digest::update(&mut hasher, DKG_COMMITMENT_DIGEST_LABEL);
        Sha3Digest::update(&mut hasher, b"share");
        Sha3Digest::update(&mut hasher, self.threshold.to_be_bytes());
        Sha3Digest::update(&mut hasher, self.total_nodes.to_be_bytes());
        Sha3Digest::update(&mut hasher, self.rho);
        Sha3Digest::update(&mut hasher, self.tr);
        hasher.finalize().into()
    }

    /// Return the verified VSS transcript digest for this private share.
    ///
    /// The digest is derived from the checked VSS commitments for the key seed,
    /// `s1`, `s2`, and `t0` component shares. It is not a public DKG commitment
    /// by itself; it is a local guardrail proving this share crossed the
    /// deterministic VSS verification boundary before signing use.
    pub fn vss_commitment_digest(&self) -> [u8; 32] {
        self.vss_commitment_digest
    }
}

/// Centralized ML-DSA-65 linear secret contribution for one challenge.
///
/// This exposes the `c*s1`, `c*s2`, and `c*t0` terms used inside signing so
/// threshold scaffolding can validate partial-share interpolation without
/// reconstructing a full key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mldsa65SecretContribution {
    challenge: [u8; MLDSA65_CHALLENGE_BYTES],
    cs1: VectorL,
    cs2: VectorK,
    ct0: VectorK,
}

impl Mldsa65SecretContribution {
    /// Borrow the challenge seed used to derive this contribution.
    pub fn challenge(&self) -> &[u8; MLDSA65_CHALLENGE_BYTES] {
        &self.challenge
    }

    /// Borrow `c * s1`.
    pub fn cs1(&self) -> &VectorL {
        &self.cs1
    }

    /// Borrow `c * s2`.
    pub fn cs2(&self) -> &VectorK {
        &self.cs2
    }

    /// Borrow `c * t0`.
    pub fn ct0(&self) -> &VectorK {
        &self.ct0
    }
}

/// Share-local ML-DSA-65 linear secret contribution for one challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mldsa65PartialSecretContribution {
    receiver_index: u16,
    threshold: u16,
    total_nodes: u16,
    challenge: [u8; MLDSA65_CHALLENGE_BYTES],
    cs1: VectorL,
    cs2: VectorK,
    ct0: VectorK,
}

impl Mldsa65PartialSecretContribution {
    /// Return the one-based receiver index for this partial contribution.
    pub const fn receiver_index(&self) -> u16 {
        self.receiver_index
    }

    /// Return the reconstruction threshold.
    pub const fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Return the total validator count used for the split.
    pub const fn total_nodes(&self) -> u16 {
        self.total_nodes
    }

    /// Borrow the challenge seed used to derive this partial contribution.
    pub fn challenge(&self) -> &[u8; MLDSA65_CHALLENGE_BYTES] {
        &self.challenge
    }

    /// Borrow share-local `c * s1_i`.
    pub fn cs1(&self) -> &VectorL {
        &self.cs1
    }

    /// Borrow share-local `c * s2_i`.
    pub fn cs2(&self) -> &VectorK {
        &self.cs2
    }

    /// Borrow share-local `c * t0_i`.
    pub fn ct0(&self) -> &VectorK {
        &self.ct0
    }
}

/// Share-local masking contribution `y_i` and corresponding `w_i = A*y_i`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mldsa65MaskingContribution {
    receiver_index: u16,
    threshold: u16,
    total_nodes: u16,
    rho: [u8; MLDSA65_PUBLIC_SEED_BYTES],
    y: VectorL,
    w: VectorK,
}

impl Mldsa65MaskingContribution {
    /// Return the one-based receiver index for this masking contribution.
    pub const fn receiver_index(&self) -> u16 {
        self.receiver_index
    }

    /// Return the reconstruction threshold.
    pub const fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Return the total validator count used for the split.
    pub const fn total_nodes(&self) -> u16 {
        self.total_nodes
    }

    /// Borrow the local masking vector `y_i`.
    pub fn y(&self) -> &VectorL {
        &self.y
    }

    /// Borrow the local commitment vector `w_i = A*y_i`.
    pub fn w(&self) -> &VectorK {
        &self.w
    }
}

/// Aggregated masking state used to derive the threshold challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mldsa65AggregatedMasking {
    threshold: u16,
    total_nodes: u16,
    participant_count: u16,
    rho: [u8; MLDSA65_PUBLIC_SEED_BYTES],
    y: VectorL,
    w: VectorK,
    w1: VectorK,
}

impl Mldsa65AggregatedMasking {
    /// Return the reconstruction threshold.
    pub const fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Return the total validator count used for the split.
    pub const fn total_nodes(&self) -> u16 {
        self.total_nodes
    }

    /// Return the number of participant contributions included.
    pub const fn participant_count(&self) -> u16 {
        self.participant_count
    }

    /// Borrow the aggregated masking vector `sum(y_i)`.
    pub fn y(&self) -> &VectorL {
        &self.y
    }

    /// Borrow the aggregated commitment vector `sum(w_i)`.
    pub fn w(&self) -> &VectorK {
        &self.w
    }

    /// Borrow the high bits of `w` used for challenge derivation.
    pub fn w1(&self) -> &VectorK {
        &self.w1
    }
}

/// Final threshold response vector assembled from masking and secret terms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mldsa65ThresholdResponse {
    challenge: [u8; MLDSA65_CHALLENGE_BYTES],
    z: VectorL,
}

impl Mldsa65ThresholdResponse {
    /// Borrow the challenge seed bound to this response.
    pub fn challenge(&self) -> &[u8; MLDSA65_CHALLENGE_BYTES] {
        &self.challenge
    }

    /// Borrow the aggregated response vector `z`.
    pub fn z(&self) -> &VectorL {
        &self.z
    }
}

/// Phase marker for the hazmat threshold signing session wrapper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mldsa65ThresholdSigningPhase {
    /// Waiting for quorum masking commitments.
    AwaitingMaskingContributions,
    /// Challenge is fixed; waiting for quorum secret contributions.
    AwaitingSecretContributions,
    /// A standard signature was finalized.
    Finalized,
    /// The signing attempt failed rejection sampling and must be retried.
    Rejected,
}

/// Hazmat round-level threshold signing attempt state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mldsa65ThresholdSigningAttempt {
    threshold: u16,
    total_nodes: u16,
    mu: [u8; MLDSA65_MU_BYTES],
    phase: Mldsa65ThresholdSigningPhase,
    masking_contributions: Vec<Mldsa65MaskingContribution>,
    aggregate: Option<Mldsa65AggregatedMasking>,
    challenge: Option<[u8; MLDSA65_CHALLENGE_BYTES]>,
    secret_contributions: Vec<Mldsa65PartialSecretContribution>,
}

impl Mldsa65ThresholdSigningAttempt {
    /// Return the configured signing threshold.
    pub const fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Return the configured validator count.
    pub const fn total_nodes(&self) -> u16 {
        self.total_nodes
    }

    /// Return the current session phase.
    pub const fn phase(&self) -> Mldsa65ThresholdSigningPhase {
        self.phase
    }

    /// Borrow the fixed round-2 challenge once masking quorum has been reached.
    pub fn challenge(&self) -> Option<&[u8; MLDSA65_CHALLENGE_BYTES]> {
        self.challenge.as_ref()
    }

    /// Borrow the session `mu` digest.
    pub fn mu(&self) -> &[u8; MLDSA65_MU_BYTES] {
        &self.mu
    }
}

/// Encode a threshold masking contribution into canonical raw wire bytes.
///
/// This experimental format uses big-endian `i32` coefficients in the
/// coefficient domain. It is intentionally simple and stable for adapter
/// simulation; production deployments should replace it with compressed,
/// proof-carrying contribution encodings.
pub fn encode_mldsa65_masking_contribution(contribution: &Mldsa65MaskingContribution) -> Vec<u8> {
    let mut out = Vec::with_capacity(MLDSA65_MASKING_CONTRIBUTION_BYTES);
    out.extend_from_slice(&contribution.receiver_index.to_be_bytes());
    out.extend_from_slice(&contribution.threshold.to_be_bytes());
    out.extend_from_slice(&contribution.total_nodes.to_be_bytes());
    out.extend_from_slice(&contribution.rho);
    encode_poly_vec(&contribution.y, &mut out);
    encode_poly_vec(&contribution.w, &mut out);
    out
}

/// Build a domain-separated commitment digest for a hazmat masking opening.
pub fn masking_commitment_digest(
    session_id: &[u8; 32],
    block_height: u64,
    attempt: u16,
    validator_index: u16,
    payload: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Sha3Digest::update(&mut hasher, b"dytallix.hazmat.mldsa65.masking.commit.v1");
    Sha3Digest::update(&mut hasher, session_id);
    Sha3Digest::update(&mut hasher, block_height.to_be_bytes());
    Sha3Digest::update(&mut hasher, attempt.to_be_bytes());
    Sha3Digest::update(&mut hasher, validator_index.to_be_bytes());
    Sha3Digest::update(&mut hasher, (payload.len() as u32).to_be_bytes());
    Sha3Digest::update(&mut hasher, payload);

    hasher.finalize().into()
}

/// Compute the canonical precommitment digest for a round-2 secret opening.
pub fn secret_commitment_digest(
    session_id: &[u8; 32],
    block_height: u64,
    attempt: u16,
    validator_index: u16,
    challenge: &[u8; MLDSA65_CHALLENGE_BYTES],
    payload: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Sha3Digest::update(&mut hasher, b"dytallix.hazmat.mldsa65.secret.commit.v1");
    Sha3Digest::update(&mut hasher, session_id);
    Sha3Digest::update(&mut hasher, block_height.to_be_bytes());
    Sha3Digest::update(&mut hasher, attempt.to_be_bytes());
    Sha3Digest::update(&mut hasher, validator_index.to_be_bytes());
    Sha3Digest::update(&mut hasher, challenge);
    Sha3Digest::update(&mut hasher, (payload.len() as u32).to_be_bytes());
    Sha3Digest::update(&mut hasher, payload);

    hasher.finalize().into()
}

/// Compute a deterministic session-level DKG commitment digest.
///
/// This is the compatibility digest used by direct actor-session tests when no
/// expanded key-share metadata is available. Production integrations should
/// prefer [`Mldsa65ExpandedSecretKeyShare::dkg_public_commitment_digest`].
pub fn mldsa65_session_dkg_commitment_digest(
    session_id: &[u8; 32],
    block_height: u64,
    threshold: u16,
    total_nodes: u16,
    mu: &[u8; MLDSA65_MU_BYTES],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Sha3Digest::update(&mut hasher, DKG_COMMITMENT_DIGEST_LABEL);
    Sha3Digest::update(&mut hasher, b"session");
    Sha3Digest::update(&mut hasher, session_id);
    Sha3Digest::update(&mut hasher, block_height.to_be_bytes());
    Sha3Digest::update(&mut hasher, threshold.to_be_bytes());
    Sha3Digest::update(&mut hasher, total_nodes.to_be_bytes());
    Sha3Digest::update(&mut hasher, mu);
    hasher.finalize().into()
}

/// Decode canonical raw wire bytes into a threshold masking contribution.
pub fn decode_mldsa65_masking_contribution(
    bytes: &[u8],
) -> Result<Mldsa65MaskingContribution, ThresholdError> {
    if bytes.len() != MLDSA65_MASKING_CONTRIBUTION_BYTES {
        return Err(ThresholdError::MalformedSerialization {
            reason: CONTRIBUTION_LENGTH_MISMATCH,
        });
    }

    let mut cursor = 0;
    let receiver_index = read_u16(bytes, &mut cursor)?;
    let threshold = read_u16(bytes, &mut cursor)?;
    let total_nodes = read_u16(bytes, &mut cursor)?;
    let mut rho = [0u8; MLDSA65_PUBLIC_SEED_BYTES];
    rho.copy_from_slice(read_bytes::<MLDSA65_PUBLIC_SEED_BYTES>(bytes, &mut cursor)?);
    let y = decode_poly_vec(bytes, &mut cursor)?;
    let w = decode_poly_vec(bytes, &mut cursor)?;

    Ok(Mldsa65MaskingContribution {
        receiver_index,
        threshold,
        total_nodes,
        rho,
        y,
        w,
    })
}

/// Encode a threshold secret contribution into canonical raw wire bytes.
///
/// This carries the linear `c*s1_i`, `c*s2_i`, and `c*t0_i` terms needed by
/// the current hazmat aggregation scaffold.
pub fn encode_mldsa65_secret_contribution(
    contribution: &Mldsa65PartialSecretContribution,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(MLDSA65_SECRET_CONTRIBUTION_BYTES);
    out.extend_from_slice(&contribution.receiver_index.to_be_bytes());
    out.extend_from_slice(&contribution.threshold.to_be_bytes());
    out.extend_from_slice(&contribution.total_nodes.to_be_bytes());
    out.extend_from_slice(&contribution.challenge);
    encode_poly_vec(&contribution.cs1, &mut out);
    encode_poly_vec(&contribution.cs2, &mut out);
    encode_poly_vec(&contribution.ct0, &mut out);
    out
}

/// Decode canonical raw wire bytes into a threshold secret contribution.
pub fn decode_mldsa65_secret_contribution(
    bytes: &[u8],
) -> Result<Mldsa65PartialSecretContribution, ThresholdError> {
    if bytes.len() != MLDSA65_SECRET_CONTRIBUTION_BYTES {
        return Err(ThresholdError::MalformedSerialization {
            reason: CONTRIBUTION_LENGTH_MISMATCH,
        });
    }

    let mut cursor = 0;
    let receiver_index = read_u16(bytes, &mut cursor)?;
    let threshold = read_u16(bytes, &mut cursor)?;
    let total_nodes = read_u16(bytes, &mut cursor)?;
    let mut challenge = [0u8; MLDSA65_CHALLENGE_BYTES];
    challenge.copy_from_slice(read_bytes::<MLDSA65_CHALLENGE_BYTES>(bytes, &mut cursor)?);
    let cs1 = decode_poly_vec(bytes, &mut cursor)?;
    let cs2 = decode_poly_vec(bytes, &mut cursor)?;
    let ct0 = decode_poly_vec(bytes, &mut cursor)?;

    Ok(Mldsa65PartialSecretContribution {
        receiver_index,
        threshold,
        total_nodes,
        challenge,
        cs1,
        cs2,
        ct0,
    })
}

fn encode_poly_vec<const LEN: usize>(value: &PolyVec<LEN>, out: &mut Vec<u8>) {
    for poly in value.polys() {
        for coeff in poly.coeffs {
            out.extend_from_slice(&coeff.to_be_bytes());
        }
    }
}

fn decode_poly_vec<const LEN: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<PolyVec<LEN>, ThresholdError> {
    let mut polys = [Poly::zero(); LEN];
    for poly in &mut polys {
        for coeff in &mut poly.coeffs {
            *coeff = read_i32(bytes, cursor)?;
        }
    }
    Ok(PolyVec::from_polys(polys))
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, ThresholdError> {
    let raw = read_bytes::<2>(bytes, cursor)?;
    Ok(u16::from_be_bytes(*raw))
}

fn read_i32(bytes: &[u8], cursor: &mut usize) -> Result<i32, ThresholdError> {
    let raw = read_bytes::<4>(bytes, cursor)?;
    let value = i32::from_be_bytes(*raw);
    if !(0..Q).contains(&value) {
        return Err(ThresholdError::MalformedSerialization {
            reason: CONTRIBUTION_COEFFICIENT_RANGE,
        });
    }
    Ok(value)
}

fn read_bytes<'a, const LEN: usize>(
    bytes: &'a [u8],
    cursor: &mut usize,
) -> Result<&'a [u8; LEN], ThresholdError> {
    let end = cursor
        .checked_add(LEN)
        .ok_or(ThresholdError::MalformedSerialization {
            reason: CONTRIBUTION_LENGTH_MISMATCH,
        })?;
    let raw = bytes
        .get(*cursor..end)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(ThresholdError::MalformedSerialization {
            reason: CONTRIBUTION_LENGTH_MISMATCH,
        })?;
    *cursor = end;
    Ok(raw)
}

fn validate_contribution_receiver(
    receiver_index: u16,
    total_nodes: u16,
) -> Result<(), ThresholdError> {
    if receiver_index == 0 || receiver_index > total_nodes {
        return Err(ThresholdError::UnknownValidator {
            validator: ValidatorId(receiver_index),
        });
    }
    Ok(())
}

fn validate_masking_contribution_w(
    contribution: &Mldsa65MaskingContribution,
) -> Result<(), ThresholdError> {
    let matrix = expand_a(&contribution.rho);
    let expected_w = fips_inverse_ntt_vector_k(&fips_matrix_vector_mul(
        &matrix,
        &fips_ntt_vector_l(&contribution.y),
    ));
    if expected_w != contribution.w {
        return Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(contribution.receiver_index),
        });
    }
    Ok(())
}

/// Derive a standard ML-DSA-65 public key from a 32-byte key-generation seed.
///
/// This implements the public-key half of FIPS 204 `ML-DSA.KeyGen_internal`
/// for the hazmat backend. It deliberately returns only the verification key
/// bytes needed by threshold/DKG experiments; secret-key serialization and
/// signing remain separate hardening milestones.
pub fn derive_mldsa65_public_key_from_seed(
    seed: &[u8; MLDSA65_KEYGEN_SEED_BYTES],
) -> Result<Mldsa65PublicKeyBytes, ThresholdError> {
    let (rho, rho_prime, _key_seed) = derive_keygen_seeds(seed);
    let matrix = expand_a(&rho);
    let s1 = expand_s_eta4_vector_l(&rho_prime, 0);
    let s2 = expand_s_eta4_vector_k(&rho_prime, MLDSA65_L);
    let s1_hat = fips_ntt_vector_l(&s1);
    let as1_hat = fips_matrix_vector_mul(&matrix, &s1_hat);
    let t = vector_k_add_mod(&fips_inverse_ntt_vector_k(&as1_hat), &s2);
    let (t1, _t0) = power2round_vector_k(&t);

    pack_public_key(rho, &t1)
}

/// Derive a standard expanded ML-DSA-65 secret key from a 32-byte key-generation seed.
pub fn derive_mldsa65_expanded_secret_key_from_seed(
    seed: &[u8; MLDSA65_KEYGEN_SEED_BYTES],
) -> Result<Mldsa65ExpandedSecretKeyBytes, ThresholdError> {
    let material = derive_signing_material(seed)?;
    pack_expanded_secret_key(&material)
}

/// Derive a standard ML-DSA-65 public key from expanded secret-key bytes.
pub fn derive_mldsa65_public_key_from_expanded_secret_key(
    secret_key: &[u8],
) -> Result<Mldsa65PublicKeyBytes, ThresholdError> {
    let material = decode_expanded_secret_key(secret_key)?;
    derive_public_key_from_material(&material)
}

/// Split real expanded secret-key components into deterministic VSS shares.
///
/// The split covers `K`, `s1`, `s2`, and `t0` while copying public `rho` and
/// transcript hash `tr` metadata into each share. The deterministic masks come
/// from the crate's VSS scaffold and are suitable for repeatable tests, not
/// production secrecy.
pub fn split_mldsa65_expanded_secret_key(
    secret_key: &[u8],
    threshold: u16,
    total_nodes: u16,
) -> Result<Vec<Mldsa65ExpandedSecretKeyShare>, ThresholdError> {
    split_mldsa65_expanded_secret_key_with_vss_session([0; 32], secret_key, threshold, total_nodes)
}

/// Split expanded secret-key components after verifying deterministic VSS commitments.
///
/// The returned shares carry a local VSS transcript digest proving each
/// component share was committed and verified against `session_id`, threshold,
/// validator count, receiver index, and component lane before signing use.
pub fn split_mldsa65_expanded_secret_key_with_vss_session(
    session_id: [u8; 32],
    secret_key: &[u8],
    threshold: u16,
    total_nodes: u16,
) -> Result<Vec<Mldsa65ExpandedSecretKeyShare>, ThresholdError> {
    if threshold == 0 || threshold > total_nodes {
        return Err(ThresholdError::InvalidThresholdParameters {
            threshold,
            total_nodes,
        });
    }

    let material = decode_expanded_secret_key(secret_key)?;
    let mut shares = (1..=total_nodes)
        .map(|receiver_index| Mldsa65ExpandedSecretKeyShare {
            receiver_index,
            threshold,
            total_nodes,
            rho: material.rho,
            key_seed_share: [0; MLDSA65_KEYGEN_SEED_BYTES],
            tr: material.tr,
            s1: VectorL::zero(),
            s2: VectorK::zero(),
            t0: VectorK::zero(),
            vss_commitment_digest: [0; 32],
        })
        .collect::<Vec<_>>();

    split_key_seed_into_shares(
        session_id,
        &material.key_seed,
        threshold,
        total_nodes,
        &mut shares,
    )?;
    split_vector_l_into_shares(
        session_id,
        material.s1.polys(),
        threshold,
        total_nodes,
        &mut shares,
    )?;
    split_s2_vector_k_into_shares(
        session_id,
        material.s2.polys(),
        threshold,
        total_nodes,
        &mut shares,
    )?;
    split_t0_vector_k_into_shares(
        session_id,
        material.t0.polys(),
        threshold,
        total_nodes,
        &mut shares,
    )?;

    Ok(shares)
}

/// Reconstruct standard expanded ML-DSA-65 secret-key bytes from component shares.
pub fn reconstruct_mldsa65_expanded_secret_key_from_shares(
    shares: &[Mldsa65ExpandedSecretKeyShare],
) -> Result<Mldsa65ExpandedSecretKeyBytes, ThresholdError> {
    let first = shares
        .first()
        .ok_or(ThresholdError::InsufficientPartialShares {
            required: 1,
            received: 0,
        })?;
    let threshold = first.threshold;
    let total_nodes = first.total_nodes;

    if shares.len() < usize::from(threshold) {
        return Err(ThresholdError::InsufficientPartialShares {
            required: threshold,
            received: shares.len(),
        });
    }

    let mut seen = BTreeSet::new();
    for share in shares {
        if share.threshold != threshold
            || share.total_nodes != total_nodes
            || share.rho != first.rho
            || share.tr != first.tr
        {
            return Err(ThresholdError::MalformedSerialization {
                reason: SECRET_SHARE_METADATA_MISMATCH,
            });
        }
        if !seen.insert(share.receiver_index) {
            return Err(ThresholdError::DuplicateValidator {
                validator: ValidatorId(share.receiver_index),
            });
        }
    }

    let key_seed = reconstruct_key_seed_from_shares(shares)?;
    let s1 = reconstruct_vector_l_from_shares(shares);
    let s2 = reconstruct_vector_k_from_shares(shares, |share| share.s2.polys());
    let t0 = reconstruct_vector_k_from_shares(shares, |share| share.t0.polys());
    let matrix = expand_a(&first.rho);
    let s1_hat = fips_ntt_vector_l(&s1);
    let s2_hat = fips_ntt_vector_k(&s2);
    let t0_hat = fips_ntt_vector_k(&t0);

    pack_expanded_secret_key(&Mldsa65SigningMaterial {
        rho: first.rho,
        key_seed,
        tr: first.tr,
        matrix,
        s1,
        s2,
        t0,
        s1_hat,
        s2_hat,
        t0_hat,
    })
}

/// Derive centralized `c*s1`, `c*s2`, and `c*t0` terms from expanded key bytes.
pub fn derive_mldsa65_secret_contribution_from_expanded_secret_key(
    secret_key: &[u8],
    challenge: &[u8; MLDSA65_CHALLENGE_BYTES],
) -> Result<Mldsa65SecretContribution, ThresholdError> {
    let material = decode_expanded_secret_key(secret_key)?;
    Ok(derive_secret_contribution_from_hats(
        *challenge,
        &material.s1_hat,
        &material.s2_hat,
        &material.t0_hat,
    ))
}

/// Derive share-local `c*s1_i`, `c*s2_i`, and `c*t0_i` terms for one challenge.
pub fn derive_mldsa65_secret_contribution_from_share(
    share: &Mldsa65ExpandedSecretKeyShare,
    challenge: &[u8; MLDSA65_CHALLENGE_BYTES],
) -> Result<Mldsa65PartialSecretContribution, ThresholdError> {
    let s1_hat = fips_ntt_vector_l(&share.s1);
    let s2_hat = fips_ntt_vector_k(&share.s2);
    let t0_hat = fips_ntt_vector_k(&share.t0);
    let contribution = derive_secret_contribution_from_hats(*challenge, &s1_hat, &s2_hat, &t0_hat);

    Ok(Mldsa65PartialSecretContribution {
        receiver_index: share.receiver_index,
        threshold: share.threshold,
        total_nodes: share.total_nodes,
        challenge: *challenge,
        cs1: contribution.cs1,
        cs2: contribution.cs2,
        ct0: contribution.ct0,
    })
}

/// Reconstruct centralized linear secret terms from share-local contributions.
pub fn reconstruct_mldsa65_secret_contribution_from_shares(
    shares: &[Mldsa65PartialSecretContribution],
) -> Result<Mldsa65SecretContribution, ThresholdError> {
    let first = shares
        .first()
        .ok_or(ThresholdError::InsufficientPartialShares {
            required: 1,
            received: 0,
        })?;
    let threshold = first.threshold;
    let total_nodes = first.total_nodes;

    if shares.len() < usize::from(threshold) {
        return Err(ThresholdError::InsufficientPartialShares {
            required: threshold,
            received: shares.len(),
        });
    }

    let mut seen = BTreeSet::new();
    for share in shares {
        if share.threshold != threshold
            || share.total_nodes != total_nodes
            || share.challenge != first.challenge
        {
            return Err(ThresholdError::MalformedSerialization {
                reason: SECRET_CONTRIBUTION_METADATA_MISMATCH,
            });
        }
        if !seen.insert(share.receiver_index) {
            return Err(ThresholdError::DuplicateValidator {
                validator: ValidatorId(share.receiver_index),
            });
        }
    }

    Ok(Mldsa65SecretContribution {
        challenge: first.challenge,
        cs1: reconstruct_contribution_vector_l(shares, |share| share.cs1.polys()),
        cs2: reconstruct_contribution_vector_k(shares, |share| share.cs2.polys()),
        ct0: reconstruct_contribution_vector_k(shares, |share| share.ct0.polys()),
    })
}

/// Derive a local masking contribution from a share and session seed.
pub fn derive_mldsa65_masking_contribution_from_share(
    share: &Mldsa65ExpandedSecretKeyShare,
    masking_seed: &[u8; MLDSA65_MU_BYTES],
    round: u16,
) -> Result<Mldsa65MaskingContribution, ThresholdError> {
    let base = round
        .checked_mul(MLDSA65_L as u16)
        .and_then(|base| base.checked_add((MLDSA65_L - 1) as u16))
        .ok_or(ThresholdError::MalformedSerialization {
            reason: SECRET_SHARE_METADATA_MISMATCH,
        })?;
    let base = base - (MLDSA65_L - 1) as u16;
    let local_masking_seed =
        derive_validator_masking_seed(masking_seed, share.receiver_index, round);
    let y = shrink_threshold_masking_vector_l(
        &expand_mask_vector_l(&local_masking_seed, base),
        share.total_nodes.saturating_add(2),
    );
    let matrix = expand_a(&share.rho);
    let w = fips_inverse_ntt_vector_k(&fips_matrix_vector_mul(&matrix, &fips_ntt_vector_l(&y)));

    Ok(Mldsa65MaskingContribution {
        receiver_index: share.receiver_index,
        threshold: share.threshold,
        total_nodes: share.total_nodes,
        rho: share.rho,
        y,
        w,
    })
}

/// Aggregate local masking contributions into `sum(y_i)` and `sum(w_i)`.
pub fn aggregate_mldsa65_masking_contributions(
    contributions: &[Mldsa65MaskingContribution],
) -> Result<Mldsa65AggregatedMasking, ThresholdError> {
    let first = contributions
        .first()
        .ok_or(ThresholdError::InsufficientCommitments {
            required: 1,
            received: 0,
        })?;
    let threshold = first.threshold;
    let total_nodes = first.total_nodes;

    if contributions.len() < usize::from(threshold) {
        return Err(ThresholdError::InsufficientCommitments {
            required: threshold,
            received: contributions.len(),
        });
    }

    let mut seen = BTreeSet::new();
    let mut y = VectorL::zero();
    let mut w = VectorK::zero();

    for contribution in contributions {
        if contribution.threshold != threshold
            || contribution.total_nodes != total_nodes
            || contribution.rho != first.rho
        {
            return Err(ThresholdError::MalformedSerialization {
                reason: SECRET_SHARE_METADATA_MISMATCH,
            });
        }
        validate_contribution_receiver(contribution.receiver_index, contribution.total_nodes)?;
        validate_masking_contribution_w(contribution)?;
        if !seen.insert(contribution.receiver_index) {
            return Err(ThresholdError::DuplicateValidator {
                validator: ValidatorId(contribution.receiver_index),
            });
        }
        y = vector_l_add_mod(&y, &contribution.y);
        w = vector_k_add_mod(&w, &contribution.w);
    }

    let w1 = high_bits_vector_k(&w);
    Ok(Mldsa65AggregatedMasking {
        threshold,
        total_nodes,
        participant_count: contributions.len() as u16,
        rho: first.rho,
        y,
        w,
        w1,
    })
}

/// Derive the ML-DSA challenge from `mu` and aggregated masking high bits.
pub fn derive_mldsa65_challenge_from_aggregated_masking(
    mu: &[u8; MLDSA65_MU_BYTES],
    masking: &Mldsa65AggregatedMasking,
) -> [u8; MLDSA65_CHALLENGE_BYTES] {
    compute_challenge_from_mu(mu, &masking.w1)
}

/// Assemble `z = sum(y_i) + c*s1` and enforce the ML-DSA-65 `z` bound.
pub fn finalize_mldsa65_threshold_response(
    masking: &Mldsa65AggregatedMasking,
    mu: &[u8; MLDSA65_MU_BYTES],
    secret: &Mldsa65SecretContribution,
) -> Result<Mldsa65ThresholdResponse, ThresholdError> {
    if secret.challenge != compute_challenge_from_mu(mu, &masking.w1) {
        return Err(ThresholdError::TranscriptMismatch);
    }

    let z = mod_plus_minus_q_vector_l(&vector_l_add_mod(&masking.y, &secret.cs1));
    if vector_l_infinity_norm_mod_q(&z) >= MLDSA65_Z_NORM_BOUND {
        return Err(ThresholdError::RejectionSamplingFailed {
            validator: ValidatorId(0),
        });
    }

    Ok(Mldsa65ThresholdResponse {
        challenge: secret.challenge,
        z,
    })
}

/// Finalize a standard-size ML-DSA-65 signature attempt from threshold terms.
pub fn finalize_mldsa65_threshold_signature_attempt(
    masking: &Mldsa65AggregatedMasking,
    mu: &[u8; MLDSA65_MU_BYTES],
    secret: &Mldsa65SecretContribution,
) -> Result<Mldsa65SignatureBytes, ThresholdError> {
    let response = finalize_mldsa65_threshold_response(masking, mu, secret)?;
    let r0 = low_bits_vector_k(&vector_k_sub_mod(&masking.w, &secret.cs2));

    if vector_k_infinity_norm_signed(&r0) >= MLDSA65_GAMMA2 - MLDSA65_BETA {
        return Err(ThresholdError::RejectionSamplingFailed {
            validator: ValidatorId(0),
        });
    }

    let minus_ct0 = vector_k_neg_mod(&secret.ct0);
    let w_cs2_ct0 = vector_k_add_mod(&vector_k_sub_mod(&masking.w, &secret.cs2), &secret.ct0);
    let hint = hint_vector_from_make_hint(&minus_ct0, &w_cs2_ct0)?;

    if vector_k_infinity_norm_mod_q(&secret.ct0) >= MLDSA65_GAMMA2 || hint.weight() > MLDSA65_OMEGA
    {
        return Err(ThresholdError::RejectionSamplingFailed {
            validator: ValidatorId(0),
        });
    }

    pack_signature(*response.challenge(), response.z(), &hint)
}

/// Start a hazmat threshold signing attempt for one fixed `mu` digest.
pub fn begin_mldsa65_threshold_attempt(
    threshold: u16,
    total_nodes: u16,
    mu: [u8; MLDSA65_MU_BYTES],
) -> Result<Mldsa65ThresholdSigningAttempt, ThresholdError> {
    if threshold == 0 || threshold > total_nodes {
        return Err(ThresholdError::InvalidThresholdParameters {
            threshold,
            total_nodes,
        });
    }

    Ok(Mldsa65ThresholdSigningAttempt {
        threshold,
        total_nodes,
        mu,
        phase: Mldsa65ThresholdSigningPhase::AwaitingMaskingContributions,
        masking_contributions: Vec::with_capacity(threshold as usize),
        aggregate: None,
        challenge: None,
        secret_contributions: Vec::with_capacity(threshold as usize),
    })
}

/// Submit one masking contribution during round 1.
pub fn submit_mldsa65_masking_contribution(
    session: &mut Mldsa65ThresholdSigningAttempt,
    contribution: Mldsa65MaskingContribution,
) -> Result<(), ThresholdError> {
    if session.phase != Mldsa65ThresholdSigningPhase::AwaitingMaskingContributions {
        return Err(ThresholdError::TranscriptMismatch);
    }
    if contribution.threshold != session.threshold
        || contribution.total_nodes != session.total_nodes
    {
        return Err(ThresholdError::MalformedSerialization {
            reason: SECRET_SHARE_METADATA_MISMATCH,
        });
    }
    validate_contribution_receiver(contribution.receiver_index, contribution.total_nodes)?;
    validate_masking_contribution_w(&contribution)?;
    if session
        .masking_contributions
        .iter()
        .any(|existing| existing.receiver_index == contribution.receiver_index)
    {
        return Err(ThresholdError::DuplicateValidator {
            validator: ValidatorId(contribution.receiver_index),
        });
    }

    session.masking_contributions.push(contribution);
    Ok(())
}

/// Aggregate round-1 masking contributions and fix the session challenge.
pub fn derive_mldsa65_session_challenge_once_quorum_met(
    session: &mut Mldsa65ThresholdSigningAttempt,
) -> Result<[u8; MLDSA65_CHALLENGE_BYTES], ThresholdError> {
    if session.phase != Mldsa65ThresholdSigningPhase::AwaitingMaskingContributions {
        return Err(ThresholdError::TranscriptMismatch);
    }
    if session.masking_contributions.len() < usize::from(session.threshold) {
        return Err(ThresholdError::InsufficientCommitments {
            required: session.threshold,
            received: session.masking_contributions.len(),
        });
    }
    let aggregate = aggregate_mldsa65_masking_contributions(&session.masking_contributions)?;
    let challenge = derive_mldsa65_challenge_from_aggregated_masking(&session.mu, &aggregate);

    session.aggregate = Some(aggregate);
    session.challenge = Some(challenge);
    session.phase = Mldsa65ThresholdSigningPhase::AwaitingSecretContributions;

    Ok(challenge)
}

/// Submit one share-local secret contribution during round 2.
pub fn submit_mldsa65_secret_contribution(
    session: &mut Mldsa65ThresholdSigningAttempt,
    contribution: Mldsa65PartialSecretContribution,
) -> Result<(), ThresholdError> {
    if session.phase != Mldsa65ThresholdSigningPhase::AwaitingSecretContributions {
        return Err(ThresholdError::TranscriptMismatch);
    }
    if contribution.threshold != session.threshold
        || contribution.total_nodes != session.total_nodes
    {
        return Err(ThresholdError::MalformedSerialization {
            reason: SECRET_CONTRIBUTION_METADATA_MISMATCH,
        });
    }
    validate_contribution_receiver(contribution.receiver_index, contribution.total_nodes)?;
    if Some(contribution.challenge) != session.challenge {
        return Err(ThresholdError::TranscriptMismatch);
    }
    if session
        .secret_contributions
        .iter()
        .any(|existing| existing.receiver_index == contribution.receiver_index)
    {
        return Err(ThresholdError::DuplicateValidator {
            validator: ValidatorId(contribution.receiver_index),
        });
    }

    session.secret_contributions.push(contribution);
    Ok(())
}

/// Finalize a standard signature once round-2 quorum is available.
pub fn finalize_mldsa65_session_signature_once_quorum_met(
    session: &mut Mldsa65ThresholdSigningAttempt,
) -> Result<Mldsa65SignatureBytes, ThresholdError> {
    if session.phase != Mldsa65ThresholdSigningPhase::AwaitingSecretContributions {
        return Err(ThresholdError::TranscriptMismatch);
    }
    let aggregate = session
        .aggregate
        .as_ref()
        .ok_or(ThresholdError::TranscriptMismatch)?;
    let secret =
        reconstruct_mldsa65_secret_contribution_from_shares(&session.secret_contributions)?;

    match finalize_mldsa65_threshold_signature_attempt(aggregate, &session.mu, &secret) {
        Ok(signature) => {
            session.phase = Mldsa65ThresholdSigningPhase::Finalized;
            Ok(signature)
        }
        Err(ThresholdError::RejectionSamplingFailed { validator }) => {
            session.phase = Mldsa65ThresholdSigningPhase::Rejected;
            Err(ThresholdError::RejectionSamplingFailed { validator })
        }
        Err(err) => Err(err),
    }
}

/// Deterministically sign an internal ML-DSA-65 message from a key-generation seed.
///
/// This is the hazmat equivalent of FIPS 204 `ML-DSA.Sign_internal` with the
/// deterministic `rnd = 0^32` option used for differential and KAT testing.
pub fn sign_mldsa65_internal_deterministic_from_seed(
    seed: &[u8; MLDSA65_KEYGEN_SEED_BYTES],
    message: &[u8],
) -> Result<Mldsa65SignatureBytes, ThresholdError> {
    sign_mldsa65_internal_from_seed(seed, message, &[0u8; MLDSA65_KEYGEN_SEED_BYTES])
}

/// Sign an internal ML-DSA-65 message from a key-generation seed and caller-supplied randomness.
pub fn sign_mldsa65_internal_from_seed(
    seed: &[u8; MLDSA65_KEYGEN_SEED_BYTES],
    message: &[u8],
    rnd: &[u8; MLDSA65_KEYGEN_SEED_BYTES],
) -> Result<Mldsa65SignatureBytes, ThresholdError> {
    let material = derive_signing_material(seed)?;
    let mu = compute_internal_message_mu(&material.tr, message);
    sign_mldsa65_mu(&material, &mu, rnd)
}

/// Deterministically sign an internal ML-DSA-65 message from expanded secret-key bytes.
pub fn sign_mldsa65_internal_deterministic_from_expanded_secret_key(
    secret_key: &[u8],
    message: &[u8],
) -> Result<Mldsa65SignatureBytes, ThresholdError> {
    sign_mldsa65_internal_from_expanded_secret_key(
        secret_key,
        message,
        &[0u8; MLDSA65_KEYGEN_SEED_BYTES],
    )
}

/// Sign an internal ML-DSA-65 message from expanded secret-key bytes and caller randomness.
pub fn sign_mldsa65_internal_from_expanded_secret_key(
    secret_key: &[u8],
    message: &[u8],
    rnd: &[u8; MLDSA65_KEYGEN_SEED_BYTES],
) -> Result<Mldsa65SignatureBytes, ThresholdError> {
    let material = decode_expanded_secret_key(secret_key)?;
    let mu = compute_internal_message_mu(&material.tr, message);
    sign_mldsa65_mu(&material, &mu, rnd)
}

/// Deterministically sign a caller-supplied internal ML-DSA-65 `mu` digest.
///
/// This exposes the same low-level internal-`mu` path used by threshold
/// experiments for baseline benchmarking. It is hazmat-only and uses
/// deterministic `rnd = 0^32`.
pub fn sign_mldsa65_internal_mu_deterministic_from_expanded_secret_key(
    secret_key: &[u8],
    mu: &[u8; MLDSA65_MU_BYTES],
) -> Result<Mldsa65SignatureBytes, ThresholdError> {
    let material = decode_expanded_secret_key(secret_key)?;
    sign_mldsa65_mu(&material, mu, &[0u8; MLDSA65_KEYGEN_SEED_BYTES])
}

/// Deterministically sign an external pure ML-DSA-65 message and context from a seed.
pub fn sign_mldsa65_external_pure_deterministic_from_seed(
    seed: &[u8; MLDSA65_KEYGEN_SEED_BYTES],
    message: &[u8],
    context: &[u8],
) -> Result<Mldsa65SignatureBytes, ThresholdError> {
    sign_mldsa65_external_pure_from_seed(seed, message, context, &[0u8; MLDSA65_KEYGEN_SEED_BYTES])
}

/// Deterministically sign an external pure ML-DSA-65 message from expanded secret-key bytes.
pub fn sign_mldsa65_external_pure_deterministic_from_expanded_secret_key(
    secret_key: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<Mldsa65SignatureBytes, ThresholdError> {
    sign_mldsa65_external_pure_from_expanded_secret_key(
        secret_key,
        message,
        context,
        &[0u8; MLDSA65_KEYGEN_SEED_BYTES],
    )
}

/// Sign an external pure ML-DSA-65 message and context from a seed and caller-supplied randomness.
pub fn sign_mldsa65_external_pure_from_seed(
    seed: &[u8; MLDSA65_KEYGEN_SEED_BYTES],
    message: &[u8],
    context: &[u8],
    rnd: &[u8; MLDSA65_KEYGEN_SEED_BYTES],
) -> Result<Mldsa65SignatureBytes, ThresholdError> {
    if context.len() > u8::MAX as usize {
        return Err(ThresholdError::MalformedSerialization {
            reason: CONTEXT_LENGTH_RANGE,
        });
    }

    let material = derive_signing_material(seed)?;
    let mu = compute_external_pure_mu(&material.tr, message, context);
    sign_mldsa65_mu(&material, &mu, rnd)
}

/// Sign an external pure ML-DSA-65 message from expanded secret-key bytes and caller randomness.
pub fn sign_mldsa65_external_pure_from_expanded_secret_key(
    secret_key: &[u8],
    message: &[u8],
    context: &[u8],
    rnd: &[u8; MLDSA65_KEYGEN_SEED_BYTES],
) -> Result<Mldsa65SignatureBytes, ThresholdError> {
    if context.len() > u8::MAX as usize {
        return Err(ThresholdError::MalformedSerialization {
            reason: CONTEXT_LENGTH_RANGE,
        });
    }

    let material = decode_expanded_secret_key(secret_key)?;
    let mu = compute_external_pure_mu(&material.tr, message, context);
    sign_mldsa65_mu(&material, &mu, rnd)
}

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

/// Table-driven FIPS 204 NTT used by the ML-DSA verifier equation.
///
/// This exposes the current hazmat verifier transform for regression fixtures
/// before replacing internals with a more optimized implementation.
pub fn fips_ntt(poly: &Poly) -> Poly {
    fips_ntt_poly(poly)
}

/// Table-driven FIPS 204 inverse NTT used by the ML-DSA verifier equation.
pub fn fips_inverse_ntt(poly: &Poly) -> Poly {
    fips_inverse_ntt_poly(poly)
}

/// Montgomery-domain FIPS 204 zeta table in bit-reversed order.
pub fn fips_zeta_table_mont() -> [i32; N] {
    zeta_table_mont()
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

fn derive_keygen_seeds(
    seed: &[u8; MLDSA65_KEYGEN_SEED_BYTES],
) -> (
    [u8; MLDSA65_PUBLIC_SEED_BYTES],
    [u8; 64],
    [u8; MLDSA65_KEYGEN_SEED_BYTES],
) {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    hasher.update(&[MLDSA65_K as u8]);
    hasher.update(&[MLDSA65_L as u8]);
    let mut reader = hasher.finalize_xof();

    let mut rho = [0u8; MLDSA65_PUBLIC_SEED_BYTES];
    let mut rho_prime = [0u8; 64];
    let mut key_seed = [0u8; MLDSA65_KEYGEN_SEED_BYTES];
    reader.read(&mut rho);
    reader.read(&mut rho_prime);
    reader.read(&mut key_seed);

    (rho, rho_prime, key_seed)
}

fn derive_signing_material(
    seed: &[u8; MLDSA65_KEYGEN_SEED_BYTES],
) -> Result<Mldsa65SigningMaterial, ThresholdError> {
    let (rho, rho_prime, key_seed) = derive_keygen_seeds(seed);
    let matrix = expand_a(&rho);
    let s1 = expand_s_eta4_vector_l(&rho_prime, 0);
    let s2 = expand_s_eta4_vector_k(&rho_prime, MLDSA65_L);
    let s1_hat = fips_ntt_vector_l(&s1);
    let s2_hat = fips_ntt_vector_k(&s2);
    let as1_hat = fips_matrix_vector_mul(&matrix, &s1_hat);
    let t = vector_k_add_mod(&fips_inverse_ntt_vector_k(&as1_hat), &s2);
    let (t1, t0) = power2round_vector_k(&t);
    let public_key = pack_public_key(rho, &t1)?;
    let tr = shake256_64(public_key.as_bytes());
    let t0_hat = fips_ntt_vector_k(&t0);

    Ok(Mldsa65SigningMaterial {
        rho,
        key_seed,
        tr,
        matrix,
        s1,
        s2,
        t0,
        s1_hat,
        s2_hat,
        t0_hat,
    })
}

fn decode_expanded_secret_key(secret_key: &[u8]) -> Result<Mldsa65SigningMaterial, ThresholdError> {
    if secret_key.len() != MLDSA65_SECRETKEY_BYTES {
        return Err(ThresholdError::MalformedSerialization {
            reason: SECRET_KEY_LENGTH_MISMATCH,
        });
    }

    let mut offset = 0usize;
    let mut rho = [0u8; MLDSA65_PUBLIC_SEED_BYTES];
    rho.copy_from_slice(&secret_key[offset..offset + MLDSA65_PUBLIC_SEED_BYTES]);
    offset += MLDSA65_PUBLIC_SEED_BYTES;

    let mut key_seed = [0u8; MLDSA65_KEYGEN_SEED_BYTES];
    key_seed.copy_from_slice(&secret_key[offset..offset + MLDSA65_KEYGEN_SEED_BYTES]);
    offset += MLDSA65_KEYGEN_SEED_BYTES;

    let mut tr = [0u8; MLDSA65_MU_BYTES];
    tr.copy_from_slice(&secret_key[offset..offset + MLDSA65_MU_BYTES]);
    offset += MLDSA65_MU_BYTES;

    let mut s1 = [Poly::zero(); MLDSA65_L];
    for poly in &mut s1 {
        *poly = unpack_eta4_poly(&secret_key[offset..offset + MLDSA65_POLYETA_PACKED_BYTES])?;
        offset += MLDSA65_POLYETA_PACKED_BYTES;
    }

    let mut s2 = [Poly::zero(); MLDSA65_K];
    for poly in &mut s2 {
        *poly = unpack_eta4_poly(&secret_key[offset..offset + MLDSA65_POLYETA_PACKED_BYTES])?;
        offset += MLDSA65_POLYETA_PACKED_BYTES;
    }

    let mut t0 = [Poly::zero(); MLDSA65_K];
    for poly in &mut t0 {
        *poly = unpack_t0_poly(&secret_key[offset..offset + MLDSA65_POLYT0_PACKED_BYTES])?;
        offset += MLDSA65_POLYT0_PACKED_BYTES;
    }
    debug_assert_eq!(offset, MLDSA65_SECRETKEY_BYTES);

    let matrix = expand_a(&rho);
    let s1 = VectorL::from_polys(s1);
    let s2 = VectorK::from_polys(s2);
    let t0 = VectorK::from_polys(t0);
    let s1_hat = fips_ntt_vector_l(&s1);
    let s2_hat = fips_ntt_vector_k(&s2);
    let t0_hat = fips_ntt_vector_k(&t0);

    Ok(Mldsa65SigningMaterial {
        rho,
        key_seed,
        tr,
        matrix,
        s1,
        s2,
        t0,
        s1_hat,
        s2_hat,
        t0_hat,
    })
}

fn derive_public_key_from_material(
    material: &Mldsa65SigningMaterial,
) -> Result<Mldsa65PublicKeyBytes, ThresholdError> {
    let as1_hat = fips_matrix_vector_mul(&material.matrix, &material.s1_hat);
    let t = vector_k_add_mod(&fips_inverse_ntt_vector_k(&as1_hat), &material.s2);
    let (t1, _t0) = power2round_vector_k(&t);

    pack_public_key(material.rho, &t1)
}

fn split_key_seed_into_shares(
    session_id: [u8; 32],
    key_seed: &[u8; MLDSA65_KEYGEN_SEED_BYTES],
    threshold: u16,
    total_nodes: u16,
    output: &mut [Mldsa65ExpandedSecretKeyShare],
) -> Result<(), ThresholdError> {
    let mut key_poly = Poly::zero();
    for (out, byte) in key_poly
        .coeffs
        .iter_mut()
        .zip(key_seed.iter().map(|byte| i32::from(*byte)))
    {
        *out = byte;
    }

    let poly_shares = split_verified_component_poly(
        session_id,
        VSS_COMPONENT_KEY_SEED,
        0,
        &key_poly,
        threshold,
        total_nodes,
    )?;
    for (share, (contribution, commitment)) in output.iter_mut().zip(poly_shares) {
        debug_assert_eq!(share.receiver_index, contribution.receiver_index);
        for (out, coeff) in share
            .key_seed_share
            .iter_mut()
            .zip(contribution.polynomial_share.coeffs.iter())
        {
            *out = *coeff;
        }
        absorb_share_vss_commitment(share, VSS_COMPONENT_KEY_SEED, 0, &commitment);
    }
    Ok(())
}

fn reconstruct_key_seed_from_shares(
    shares: &[Mldsa65ExpandedSecretKeyShare],
) -> Result<[u8; MLDSA65_KEYGEN_SEED_BYTES], ThresholdError> {
    let active = shares
        .iter()
        .map(|share| {
            let mut coeffs = [0i32; N];
            for (out, coeff) in coeffs.iter_mut().zip(share.key_seed_share.iter()) {
                *out = *coeff;
            }
            (share.receiver_index, Poly::from_coeffs(coeffs))
        })
        .collect::<Vec<_>>();
    let reconstructed = reconstruct_secret_poly(&active);
    let mut key_seed = [0u8; MLDSA65_KEYGEN_SEED_BYTES];
    for (out, coeff) in key_seed.iter_mut().zip(reconstructed.coeffs.iter()) {
        if !(0..=u8::MAX as i32).contains(coeff) {
            return Err(ThresholdError::MalformedSerialization {
                reason: SECRET_SHARE_METADATA_MISMATCH,
            });
        }
        *out = *coeff as u8;
    }
    Ok(key_seed)
}

fn split_vector_l_into_shares(
    session_id: [u8; 32],
    secrets: &[Poly; MLDSA65_L],
    threshold: u16,
    total_nodes: u16,
    output: &mut [Mldsa65ExpandedSecretKeyShare],
) -> Result<(), ThresholdError> {
    for (lane, secret_poly) in secrets.iter().enumerate() {
        let poly_shares = split_verified_component_poly(
            session_id,
            VSS_COMPONENT_S1,
            lane as u16,
            secret_poly,
            threshold,
            total_nodes,
        )?;
        for (share, (contribution, commitment)) in output.iter_mut().zip(poly_shares) {
            debug_assert_eq!(share.receiver_index, contribution.receiver_index);
            share.s1.polys_mut()[lane] = contribution.polynomial_share;
            absorb_share_vss_commitment(share, VSS_COMPONENT_S1, lane as u16, &commitment);
        }
    }
    Ok(())
}

fn split_s2_vector_k_into_shares(
    session_id: [u8; 32],
    secrets: &[Poly; MLDSA65_K],
    threshold: u16,
    total_nodes: u16,
    output: &mut [Mldsa65ExpandedSecretKeyShare],
) -> Result<(), ThresholdError> {
    for (lane, secret_poly) in secrets.iter().enumerate() {
        let poly_shares = split_verified_component_poly(
            session_id,
            VSS_COMPONENT_S2,
            lane as u16,
            secret_poly,
            threshold,
            total_nodes,
        )?;
        for (share, (contribution, commitment)) in output.iter_mut().zip(poly_shares) {
            debug_assert_eq!(share.receiver_index, contribution.receiver_index);
            share.s2.polys_mut()[lane] = contribution.polynomial_share;
            absorb_share_vss_commitment(share, VSS_COMPONENT_S2, lane as u16, &commitment);
        }
    }
    Ok(())
}

fn split_t0_vector_k_into_shares(
    session_id: [u8; 32],
    secrets: &[Poly; MLDSA65_K],
    threshold: u16,
    total_nodes: u16,
    output: &mut [Mldsa65ExpandedSecretKeyShare],
) -> Result<(), ThresholdError> {
    for (lane, secret_poly) in secrets.iter().enumerate() {
        let poly_shares = split_verified_component_poly(
            session_id,
            VSS_COMPONENT_T0,
            lane as u16,
            secret_poly,
            threshold,
            total_nodes,
        )?;
        for (share, (contribution, commitment)) in output.iter_mut().zip(poly_shares) {
            debug_assert_eq!(share.receiver_index, contribution.receiver_index);
            share.t0.polys_mut()[lane] = contribution.polynomial_share;
            absorb_share_vss_commitment(share, VSS_COMPONENT_T0, lane as u16, &commitment);
        }
    }
    Ok(())
}

fn split_verified_component_poly(
    session_id: [u8; 32],
    component_label: &[u8],
    lane: u16,
    secret_poly: &Poly,
    threshold: u16,
    total_nodes: u16,
) -> Result<Vec<(ShareContribution, VssShareCommitment)>, ThresholdError> {
    let component_session_id = vss_component_session_id(session_id, component_label, lane);
    let shares = split_secret_poly(secret_poly, threshold, total_nodes);
    let entries = shares
        .iter()
        .map(|share| {
            let commitment =
                commit_share_contribution(component_session_id, threshold, total_nodes, share)?;
            Ok((share.clone(), commitment))
        })
        .collect::<Result<Vec<_>, ThresholdError>>()?;
    verify_share_contribution_commitments(component_session_id, threshold, total_nodes, &entries)?;
    Ok(entries)
}

fn vss_component_session_id(session_id: [u8; 32], component_label: &[u8], lane: u16) -> [u8; 32] {
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, VSS_COMPONENT_CONTEXT_LABEL);
    Update::update(&mut hasher, &session_id);
    Update::update(&mut hasher, &(component_label.len() as u64).to_be_bytes());
    Update::update(&mut hasher, component_label);
    Update::update(&mut hasher, &lane.to_be_bytes());
    let mut out = [0u8; 32];
    hasher.finalize_xof().read(&mut out);
    out
}

fn absorb_share_vss_commitment(
    share: &mut Mldsa65ExpandedSecretKeyShare,
    component_label: &[u8],
    lane: u16,
    commitment: &VssShareCommitment,
) {
    let mut hasher = Sha3_256::new();
    Sha3Digest::update(&mut hasher, VSS_SHARE_AGGREGATE_LABEL);
    Sha3Digest::update(&mut hasher, share.vss_commitment_digest);
    Sha3Digest::update(&mut hasher, (component_label.len() as u64).to_be_bytes());
    Sha3Digest::update(&mut hasher, component_label);
    Sha3Digest::update(&mut hasher, lane.to_be_bytes());
    Sha3Digest::update(&mut hasher, commitment.session_id);
    Sha3Digest::update(&mut hasher, commitment.threshold.to_be_bytes());
    Sha3Digest::update(&mut hasher, commitment.total_nodes.to_be_bytes());
    Sha3Digest::update(&mut hasher, commitment.receiver_index.to_be_bytes());
    Sha3Digest::update(&mut hasher, commitment.commitment_digest);
    Sha3Digest::update(&mut hasher, commitment.proof.proof_digest);
    share.vss_commitment_digest = hasher.finalize().into();
}

fn reconstruct_vector_l_from_shares(shares: &[Mldsa65ExpandedSecretKeyShare]) -> VectorL {
    let mut polys = [Poly::zero(); MLDSA65_L];
    for (lane, output) in polys.iter_mut().enumerate() {
        let active = shares
            .iter()
            .map(|share| (share.receiver_index, share.s1.polys()[lane]))
            .collect::<Vec<_>>();
        *output = reconstruct_secret_poly(&active);
    }
    VectorL::from_polys(polys)
}

fn reconstruct_vector_k_from_shares(
    shares: &[Mldsa65ExpandedSecretKeyShare],
    selector: fn(&Mldsa65ExpandedSecretKeyShare) -> &[Poly; MLDSA65_K],
) -> VectorK {
    let mut polys = [Poly::zero(); MLDSA65_K];
    for (lane, output) in polys.iter_mut().enumerate() {
        let active = shares
            .iter()
            .map(|share| (share.receiver_index, selector(share)[lane]))
            .collect::<Vec<_>>();
        *output = reconstruct_secret_poly(&active);
    }
    VectorK::from_polys(polys)
}

fn derive_secret_contribution_from_hats(
    challenge: [u8; MLDSA65_CHALLENGE_BYTES],
    s1_hat: &VectorL,
    s2_hat: &VectorK,
    t0_hat: &VectorK,
) -> Mldsa65SecretContribution {
    let challenge_poly = sample_in_ball(&challenge);
    let challenge_hat = fips_ntt_poly(&challenge_poly);
    let cs1 = fips_inverse_ntt_vector_l(&fips_ntt_poly_mul_vector_l(&challenge_hat, s1_hat));
    let cs2 = fips_inverse_ntt_vector_k(&fips_ntt_poly_mul_vector_k(&challenge_hat, s2_hat));
    let ct0 = fips_inverse_ntt_vector_k(&fips_ntt_poly_mul_vector_k(&challenge_hat, t0_hat));

    Mldsa65SecretContribution {
        challenge,
        cs1,
        cs2,
        ct0,
    }
}

fn reconstruct_contribution_vector_l(
    shares: &[Mldsa65PartialSecretContribution],
    selector: fn(&Mldsa65PartialSecretContribution) -> &[Poly; MLDSA65_L],
) -> VectorL {
    let mut polys = [Poly::zero(); MLDSA65_L];
    for (lane, output) in polys.iter_mut().enumerate() {
        let active = shares
            .iter()
            .map(|share| (share.receiver_index, selector(share)[lane]))
            .collect::<Vec<_>>();
        *output = reconstruct_secret_poly(&active);
    }
    VectorL::from_polys(polys)
}

fn reconstruct_contribution_vector_k(
    shares: &[Mldsa65PartialSecretContribution],
    selector: fn(&Mldsa65PartialSecretContribution) -> &[Poly; MLDSA65_K],
) -> VectorK {
    let mut polys = [Poly::zero(); MLDSA65_K];
    for (lane, output) in polys.iter_mut().enumerate() {
        let active = shares
            .iter()
            .map(|share| (share.receiver_index, selector(share)[lane]))
            .collect::<Vec<_>>();
        *output = reconstruct_secret_poly(&active);
    }
    VectorK::from_polys(polys)
}

fn pack_expanded_secret_key(
    material: &Mldsa65SigningMaterial,
) -> Result<Mldsa65ExpandedSecretKeyBytes, ThresholdError> {
    let mut bytes = [0u8; MLDSA65_SECRETKEY_BYTES];
    let mut offset = 0usize;

    bytes[offset..offset + MLDSA65_PUBLIC_SEED_BYTES].copy_from_slice(&material.rho);
    offset += MLDSA65_PUBLIC_SEED_BYTES;
    bytes[offset..offset + MLDSA65_KEYGEN_SEED_BYTES].copy_from_slice(&material.key_seed);
    offset += MLDSA65_KEYGEN_SEED_BYTES;
    bytes[offset..offset + MLDSA65_MU_BYTES].copy_from_slice(&material.tr);
    offset += MLDSA65_MU_BYTES;

    for poly in material.s1.polys() {
        let packed = pack_eta4_poly(poly)?;
        bytes[offset..offset + MLDSA65_POLYETA_PACKED_BYTES].copy_from_slice(&packed);
        offset += MLDSA65_POLYETA_PACKED_BYTES;
    }
    for poly in material.s2.polys() {
        let packed = pack_eta4_poly(poly)?;
        bytes[offset..offset + MLDSA65_POLYETA_PACKED_BYTES].copy_from_slice(&packed);
        offset += MLDSA65_POLYETA_PACKED_BYTES;
    }
    for poly in material.t0.polys() {
        let packed = pack_t0_poly(poly)?;
        bytes[offset..offset + MLDSA65_POLYT0_PACKED_BYTES].copy_from_slice(&packed);
        offset += MLDSA65_POLYT0_PACKED_BYTES;
    }

    debug_assert_eq!(offset, MLDSA65_SECRETKEY_BYTES);
    Ok(Mldsa65ExpandedSecretKeyBytes::new(bytes))
}

fn sign_mldsa65_mu(
    material: &Mldsa65SigningMaterial,
    mu: &[u8; MLDSA65_MU_BYTES],
    rnd: &[u8; MLDSA65_KEYGEN_SEED_BYTES],
) -> Result<Mldsa65SignatureBytes, ThresholdError> {
    let mut hasher = Shake256::default();
    hasher.update(&material.key_seed);
    hasher.update(rnd);
    hasher.update(mu);
    let mut reader = hasher.finalize_xof();
    let mut rho_double_prime = [0u8; MLDSA65_MU_BYTES];
    reader.read(&mut rho_double_prime);

    for kappa in (0..u16::MAX).step_by(MLDSA65_L) {
        let y = expand_mask_vector_l(&rho_double_prime, kappa);
        let w = fips_inverse_ntt_vector_k(&fips_matrix_vector_mul(
            &material.matrix,
            &fips_ntt_vector_l(&y),
        ));
        let w1 = high_bits_vector_k(&w);
        let challenge = compute_challenge_from_mu(mu, &w1);
        let challenge_poly = sample_in_ball(&challenge);
        let challenge_hat = fips_ntt_poly(&challenge_poly);

        let cs1 = fips_inverse_ntt_vector_l(&fips_ntt_poly_mul_vector_l(
            &challenge_hat,
            &material.s1_hat,
        ));
        let cs2 = fips_inverse_ntt_vector_k(&fips_ntt_poly_mul_vector_k(
            &challenge_hat,
            &material.s2_hat,
        ));
        let z = vector_l_add_mod(&y, &cs1);
        let r0 = low_bits_vector_k(&vector_k_sub_mod(&w, &cs2));

        if vector_l_infinity_norm_mod_q(&z) >= MLDSA65_GAMMA1 - MLDSA65_BETA
            || vector_k_infinity_norm_signed(&r0) >= MLDSA65_GAMMA2 - MLDSA65_BETA
        {
            continue;
        }

        let ct0 = fips_inverse_ntt_vector_k(&fips_ntt_poly_mul_vector_k(
            &challenge_hat,
            &material.t0_hat,
        ));
        let minus_ct0 = vector_k_neg_mod(&ct0);
        let w_cs2_ct0 = vector_k_add_mod(&vector_k_sub_mod(&w, &cs2), &ct0);
        let hint = hint_vector_from_make_hint(&minus_ct0, &w_cs2_ct0)?;

        if vector_k_infinity_norm_mod_q(&ct0) >= MLDSA65_GAMMA2 || hint.weight() > MLDSA65_OMEGA {
            continue;
        }

        let z = mod_plus_minus_q_vector_l(&z);
        return pack_signature(challenge, &z, &hint);
    }

    Err(ThresholdError::BackendUnavailable {
        reason: SIGNING_REJECTION_EXHAUSTED,
    })
}

fn expand_s_eta4_vector_l(rho_prime: &[u8; 64], base: usize) -> VectorL {
    let mut polys = [Poly::zero(); MLDSA65_L];
    for (index, poly) in polys.iter_mut().enumerate() {
        *poly = rej_bounded_eta4_poly(rho_prime, (base + index) as u16);
    }
    VectorL::from_polys(polys)
}

fn expand_s_eta4_vector_k(rho_prime: &[u8; 64], base: usize) -> VectorK {
    let mut polys = [Poly::zero(); MLDSA65_K];
    for (index, poly) in polys.iter_mut().enumerate() {
        *poly = rej_bounded_eta4_poly(rho_prime, (base + index) as u16);
    }
    VectorK::from_polys(polys)
}

fn rej_bounded_eta4_poly(rho_prime: &[u8; 64], nonce: u16) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(rho_prime);
    hasher.update(&nonce.to_le_bytes());
    let mut reader = hasher.finalize_xof();

    let mut coeffs = [0i32; N];
    let mut filled = 0usize;
    let mut block = [0u8; 272];
    reader.read(&mut block);

    for byte in block {
        filled = push_eta4_half_byte(byte & 0x0f, &mut coeffs, filled);
        if filled == N {
            break;
        }

        filled = push_eta4_half_byte(byte >> 4, &mut coeffs, filled);
        if filled == N {
            break;
        }
    }

    while filled < N {
        let mut byte = [0u8; 1];
        reader.read(&mut byte);
        filled = push_eta4_half_byte(byte[0] & 0x0f, &mut coeffs, filled);
        if filled < N {
            filled = push_eta4_half_byte(byte[0] >> 4, &mut coeffs, filled);
        }
    }

    Poly::from_coeffs(coeffs)
}

fn push_eta4_half_byte(nibble: u8, coeffs: &mut [i32; N], filled: usize) -> usize {
    match coeff_from_eta4_halfbyte(nibble) {
        Some(coeff) if filled < N => {
            coeffs[filled] = coeff;
            filled + 1
        }
        _ => filled,
    }
}

fn coeff_from_eta4_halfbyte(nibble: u8) -> Option<i32> {
    if nibble < 9 {
        if nibble <= 4 {
            Some(4 - nibble as i32)
        } else {
            Some(-((nibble as i32) - 4))
        }
    } else {
        None
    }
}

fn vector_k_add_mod(lhs: &VectorK, rhs: &VectorK) -> VectorK {
    let mut polys = [Poly::zero(); MLDSA65_K];
    for (out, (left, right)) in polys
        .iter_mut()
        .zip(lhs.polys().iter().zip(rhs.polys().iter()))
    {
        let mut coeffs = [0i32; N];
        for (out_coeff, (left_coeff, right_coeff)) in coeffs
            .iter_mut()
            .zip(left.coeffs.iter().zip(right.coeffs.iter()))
        {
            *out_coeff = add_mod_q(*left_coeff, *right_coeff);
        }
        *out = Poly::from_coeffs(coeffs);
    }
    VectorK::from_polys(polys)
}

fn power2round_vector_k(vector: &VectorK) -> (VectorK, VectorK) {
    let mut high = [Poly::zero(); MLDSA65_K];
    let mut low = [Poly::zero(); MLDSA65_K];

    for ((high_poly, low_poly), input_poly) in high
        .iter_mut()
        .zip(low.iter_mut())
        .zip(vector.polys().iter())
    {
        let mut high_coeffs = [0i32; N];
        let mut low_coeffs = [0i32; N];
        for (index, coeff) in input_poly.coeffs.iter().enumerate() {
            let (t1, t0) = power2round(*coeff);
            high_coeffs[index] = t1;
            low_coeffs[index] = t0;
        }
        *high_poly = Poly::from_coeffs(high_coeffs);
        *low_poly = Poly::from_coeffs(low_coeffs);
    }

    (VectorK::from_polys(high), VectorK::from_polys(low))
}

fn expand_mask_vector_l(rho_double_prime: &[u8; MLDSA65_MU_BYTES], base: u16) -> VectorL {
    let mut polys = [Poly::zero(); MLDSA65_L];
    for (index, poly) in polys.iter_mut().enumerate() {
        let mut hasher = Shake256::default();
        hasher.update(rho_double_prime);
        hasher.update(&(base + index as u16).to_le_bytes());
        let mut reader = hasher.finalize_xof();
        let mut bytes = [0u8; MLDSA65_POLYZ_PACKED_BYTES];
        reader.read(&mut bytes);
        *poly = unpack_z_poly(&bytes);
    }
    VectorL::from_polys(polys)
}

fn derive_validator_masking_seed(
    masking_seed: &[u8; MLDSA65_MU_BYTES],
    receiver_index: u16,
    round: u16,
) -> [u8; MLDSA65_MU_BYTES] {
    let mut hasher = Shake256::default();
    hasher.update(masking_seed);
    hasher.update(&receiver_index.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; MLDSA65_MU_BYTES];
    reader.read(&mut output);
    output
}

fn shrink_threshold_masking_vector_l(vector: &VectorL, divisor: u16) -> VectorL {
    let divisor = i32::from(divisor.max(1));
    let mut polys = [Poly::zero(); MLDSA65_L];
    for (out, poly) in polys.iter_mut().zip(vector.polys().iter()) {
        let mut coeffs = [0i32; N];
        for (out_coeff, coeff) in coeffs.iter_mut().zip(poly.coeffs.iter()) {
            *out_coeff = reduce_mod_q(i64::from(mod_plus_minus_q(*coeff) / divisor));
        }
        *out = Poly::from_coeffs(coeffs);
    }
    VectorL::from_polys(polys)
}

fn vector_l_add_mod(lhs: &VectorL, rhs: &VectorL) -> VectorL {
    let mut polys = [Poly::zero(); MLDSA65_L];
    for (out, (left, right)) in polys
        .iter_mut()
        .zip(lhs.polys().iter().zip(rhs.polys().iter()))
    {
        let mut coeffs = [0i32; N];
        for (out_coeff, (left_coeff, right_coeff)) in coeffs
            .iter_mut()
            .zip(left.coeffs.iter().zip(right.coeffs.iter()))
        {
            *out_coeff = add_mod_q(*left_coeff, *right_coeff);
        }
        *out = Poly::from_coeffs(coeffs);
    }
    VectorL::from_polys(polys)
}

fn vector_k_sub_mod(lhs: &VectorK, rhs: &VectorK) -> VectorK {
    let mut polys = [Poly::zero(); MLDSA65_K];
    for (out, (left, right)) in polys
        .iter_mut()
        .zip(lhs.polys().iter().zip(rhs.polys().iter()))
    {
        let mut coeffs = [0i32; N];
        for (out_coeff, (left_coeff, right_coeff)) in coeffs
            .iter_mut()
            .zip(left.coeffs.iter().zip(right.coeffs.iter()))
        {
            *out_coeff = sub_mod_q(*left_coeff, *right_coeff);
        }
        *out = Poly::from_coeffs(coeffs);
    }
    VectorK::from_polys(polys)
}

fn vector_k_neg_mod(vector: &VectorK) -> VectorK {
    let mut polys = [Poly::zero(); MLDSA65_K];
    for (out, poly) in polys.iter_mut().zip(vector.polys().iter()) {
        let mut coeffs = [0i32; N];
        for (out_coeff, coeff) in coeffs.iter_mut().zip(poly.coeffs.iter()) {
            *out_coeff = sub_mod_q(0, *coeff);
        }
        *out = Poly::from_coeffs(coeffs);
    }
    VectorK::from_polys(polys)
}

fn high_bits_vector_k(vector: &VectorK) -> VectorK {
    map_vector_k_coeffs(vector, high_bits)
}

fn low_bits_vector_k(vector: &VectorK) -> VectorK {
    map_vector_k_coeffs(vector, low_bits)
}

fn map_vector_k_coeffs(vector: &VectorK, f: fn(i32) -> i32) -> VectorK {
    let mut polys = [Poly::zero(); MLDSA65_K];
    for (out, poly) in polys.iter_mut().zip(vector.polys().iter()) {
        let mut coeffs = [0i32; N];
        for (out_coeff, coeff) in coeffs.iter_mut().zip(poly.coeffs.iter()) {
            *out_coeff = f(*coeff);
        }
        *out = Poly::from_coeffs(coeffs);
    }
    VectorK::from_polys(polys)
}

fn hint_vector_from_make_hint(z: &VectorK, r: &VectorK) -> Result<HintVector, ThresholdError> {
    let mut positions = Vec::new();
    for (row_index, (z_poly, r_poly)) in z.polys().iter().zip(r.polys().iter()).enumerate() {
        for (coeff_index, (z_coeff, r_coeff)) in
            z_poly.coeffs.iter().zip(r_poly.coeffs.iter()).enumerate()
        {
            if make_hint(*z_coeff, *r_coeff) {
                positions.push((row_index, coeff_index));
            }
        }
    }
    HintVector::from_positions(&positions)
}

fn mod_plus_minus_q_vector_l(vector: &VectorL) -> VectorL {
    let mut polys = [Poly::zero(); MLDSA65_L];
    for (out, poly) in polys.iter_mut().zip(vector.polys().iter()) {
        let mut coeffs = [0i32; N];
        for (out_coeff, coeff) in coeffs.iter_mut().zip(poly.coeffs.iter()) {
            *out_coeff = mod_plus_minus_q(*coeff);
        }
        *out = Poly::from_coeffs(coeffs);
    }
    VectorL::from_polys(polys)
}

fn mod_plus_minus_q(value: i32) -> i32 {
    let value = reduce_mod_q(value as i64);
    if value > Q / 2 {
        value - Q
    } else {
        value
    }
}

fn vector_l_infinity_norm_mod_q(vector: &VectorL) -> i32 {
    vector
        .polys()
        .iter()
        .map(poly_infinity_norm_mod_q)
        .max()
        .unwrap_or(0)
}

fn vector_k_infinity_norm_mod_q(vector: &VectorK) -> i32 {
    vector
        .polys()
        .iter()
        .map(poly_infinity_norm_mod_q)
        .max()
        .unwrap_or(0)
}

fn vector_k_infinity_norm_signed(vector: &VectorK) -> i32 {
    vector
        .polys()
        .iter()
        .flat_map(|poly| poly.coeffs.iter())
        .map(|coeff| coeff.abs())
        .max()
        .unwrap_or(0)
}

fn poly_infinity_norm_mod_q(poly: &Poly) -> i32 {
    poly.coeffs
        .iter()
        .map(|coeff| mod_plus_minus_q(*coeff).abs())
        .max()
        .unwrap_or(0)
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

fn fips_ntt_vector_k(vector: &VectorK) -> VectorK {
    let mut polys = [Poly::zero(); MLDSA65_K];
    for (out, poly) in polys.iter_mut().zip(vector.polys().iter()) {
        *out = fips_ntt_poly(poly);
    }
    VectorK::from_polys(polys)
}

fn fips_inverse_ntt_vector_l(vector: &VectorL) -> VectorL {
    let mut polys = [Poly::zero(); MLDSA65_L];
    for (out, poly) in polys.iter_mut().zip(vector.polys().iter()) {
        *out = fips_inverse_ntt_poly(poly);
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

fn fips_ntt_poly_mul_vector_l(poly_hat: &Poly, vector_hat: &VectorL) -> VectorL {
    let vector_hat_mont = fips_to_mont_vector_l(vector_hat);
    let mut polys = [Poly::zero(); MLDSA65_L];
    for (out, vector_poly) in polys.iter_mut().zip(vector_hat_mont.polys().iter()) {
        *out = fips_ntt_poly_mul_poly_mont(poly_hat, vector_poly);
    }
    VectorL::from_polys(polys)
}

fn fips_ntt_poly_mul_vector_k(poly_hat: &Poly, vector_hat: &VectorK) -> VectorK {
    let vector_hat_mont = fips_to_mont_vector_k(vector_hat);
    let mut polys = [Poly::zero(); MLDSA65_K];
    for (out, vector_poly) in polys.iter_mut().zip(vector_hat_mont.polys().iter()) {
        *out = fips_ntt_poly_mul_poly_mont(poly_hat, vector_poly);
    }
    VectorK::from_polys(polys)
}

fn fips_ntt_poly_mul_poly_mont(poly_hat: &Poly, rhs_mont: &Poly) -> Poly {
    let mut coeffs = [0i32; N];
    for (out, (left, right)) in coeffs
        .iter_mut()
        .zip(poly_hat.coeffs.iter().zip(rhs_mont.coeffs.iter()))
    {
        *out = montgomery_reduce(*left as i64 * *right as i64);
    }
    Poly::from_coeffs(coeffs)
}

fn fips_to_mont_vector_l(vector: &VectorL) -> VectorL {
    let mut polys = [Poly::zero(); MLDSA65_L];
    for (out, poly) in polys.iter_mut().zip(vector.polys().iter()) {
        *out = fips_to_mont_poly(poly);
    }
    VectorL::from_polys(polys)
}

fn fips_to_mont_vector_k(vector: &VectorK) -> VectorK {
    let mut polys = [Poly::zero(); MLDSA65_K];
    for (out, poly) in polys.iter_mut().zip(vector.polys().iter()) {
        *out = fips_to_mont_poly(poly);
    }
    VectorK::from_polys(polys)
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

/// Verify an external prehash HashML-DSA-65 signature with an explicit context string.
pub fn verify_mldsa65_external_prehash(
    public_key: &ThresholdPublicKey,
    message: &[u8],
    context: &[u8],
    hash_alg: Mldsa65PreHashAlgorithm,
    signature: &ThresholdSignature,
) -> Result<bool, ThresholdError> {
    if context.len() > u8::MAX as usize {
        return Err(ThresholdError::MalformedSerialization {
            reason: CONTEXT_LENGTH_RANGE,
        });
    }

    let unpacked_signature = unpack_signature(&signature.0)?;
    let w1 = compute_verification_w1(public_key, message, signature)?;
    let tr = shake256_64(&public_key.0);
    let phm = hash_alg.digest_message(message);
    let mu = compute_external_prehash_mu(&tr, context, hash_alg.oid_der(), &phm);
    let expected_challenge = compute_challenge_from_mu(&mu, &w1);

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

fn compute_external_prehash_mu(
    tr: &[u8; MLDSA65_MU_BYTES],
    context: &[u8],
    oid: &[u8],
    phm: &[u8],
) -> [u8; MLDSA65_MU_BYTES] {
    let mut mu_hasher = Shake256::default();
    mu_hasher.update(tr);
    mu_hasher.update(&[0x01, context.len() as u8]);
    mu_hasher.update(context);
    mu_hasher.update(oid);
    mu_hasher.update(phm);
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

fn pack_eta4_poly(poly: &Poly) -> Result<[u8; MLDSA65_POLYETA_PACKED_BYTES], ThresholdError> {
    let mut bytes = [0u8; MLDSA65_POLYETA_PACKED_BYTES];
    for (index, coeff) in poly.coeffs.iter().enumerate() {
        let coeff = signed_small_coeff(*coeff);
        if !(-MLDSA65_ETA..=MLDSA65_ETA).contains(&coeff) {
            return Err(ThresholdError::MalformedSerialization {
                reason: Z_COEFFICIENT_UNPACKABLE,
            });
        }
        write_bits_le(&mut bytes, index * 4, 4, (MLDSA65_ETA - coeff) as u32);
    }
    Ok(bytes)
}

fn unpack_eta4_poly(bytes: &[u8]) -> Result<Poly, ThresholdError> {
    debug_assert_eq!(bytes.len(), MLDSA65_POLYETA_PACKED_BYTES);

    let mut coeffs = [0i32; N];
    for (index, coeff) in coeffs.iter_mut().enumerate() {
        let encoded = read_bits_le(bytes, index * 4, 4) as i32;
        if encoded > 2 * MLDSA65_ETA {
            return Err(ThresholdError::MalformedSerialization {
                reason: SECRET_COEFFICIENT_RANGE,
            });
        }
        *coeff = reduce_mod_q((MLDSA65_ETA - encoded) as i64);
    }
    Ok(Poly::from_coeffs(coeffs))
}

fn pack_t0_poly(poly: &Poly) -> Result<[u8; MLDSA65_POLYT0_PACKED_BYTES], ThresholdError> {
    const T0_MIN: i32 = -(1 << (MLDSA65_D - 1)) + 1;
    const T0_MAX: i32 = 1 << (MLDSA65_D - 1);

    let mut bytes = [0u8; MLDSA65_POLYT0_PACKED_BYTES];
    for (index, coeff) in poly.coeffs.iter().enumerate() {
        let coeff = signed_small_coeff(*coeff);
        if !(T0_MIN..=T0_MAX).contains(&coeff) {
            return Err(ThresholdError::MalformedSerialization {
                reason: SECRET_COEFFICIENT_UNPACKABLE,
            });
        }
        write_bits_le(&mut bytes, index * 13, 13, (T0_MAX - coeff) as u32);
    }
    Ok(bytes)
}

fn unpack_t0_poly(bytes: &[u8]) -> Result<Poly, ThresholdError> {
    const T0_MAX: i32 = 1 << (MLDSA65_D - 1);

    debug_assert_eq!(bytes.len(), MLDSA65_POLYT0_PACKED_BYTES);

    let mut coeffs = [0i32; N];
    for (index, coeff) in coeffs.iter_mut().enumerate() {
        let encoded = read_bits_le(bytes, index * 13, 13) as i32;
        if encoded > (1 << MLDSA65_D) - 1 {
            return Err(ThresholdError::MalformedSerialization {
                reason: SECRET_COEFFICIENT_RANGE,
            });
        }
        *coeff = reduce_mod_q((T0_MAX - encoded) as i64);
    }
    Ok(Poly::from_coeffs(coeffs))
}

fn signed_small_coeff(coeff: i32) -> i32 {
    if coeff > Q / 2 {
        coeff - Q
    } else {
        coeff
    }
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
