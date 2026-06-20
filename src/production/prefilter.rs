//! Blinded aggregate pre-filtering simulation and telemetry.
//!
//! This module models the coordinator-side ordering constraint for a future
//! threshold ML-DSA-65 backend: aggregate blinded commitments are checked before
//! raw partial responses can be synthesized or exposed. The arithmetic here is
//! deterministic audit scaffolding, not a production ML-DSA implementation.

use sha3::{Digest, Sha3_256};

use crate::{low_level::poly::Poly, ThresholdError, ValidatorId, N};

use super::epsilon::EpsilonUnit;
use super::types::AttemptId;

pub use super::epsilon::EpsilonLedger;

/// ML-DSA-65 module row dimension.
pub const MLDSA65_K: usize = 6;
/// ML-DSA-65 secret/mask vector dimension.
pub const MLDSA65_L: usize = 5;
/// ML-DSA-65 `gamma_1` bound for the profiled parameter set.
pub const GAMMA1: i32 = 1 << 19;
/// ML-DSA-65 `beta` bound for the profiled parameter set.
pub const BETA: i32 = 196;

/// Public digest and bound summary for one blinded commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlindedCommitmentSummary {
    validator: ValidatorId,
    commitment_digest: [u8; 32],
    infinity_norm: u32,
}

impl BlindedCommitmentSummary {
    /// Construct a public blinded commitment summary.
    pub const fn new(
        validator: ValidatorId,
        commitment_digest: [u8; 32],
        infinity_norm: u32,
    ) -> Self {
        Self {
            validator,
            commitment_digest,
            infinity_norm,
        }
    }

    /// Return the validator that supplied this summary.
    pub const fn validator(self) -> ValidatorId {
        self.validator
    }

    /// Return the commitment digest.
    pub const fn commitment_digest(self) -> [u8; 32] {
        self.commitment_digest
    }

    /// Return the declared infinity norm summary.
    pub const fn infinity_norm(self) -> u32 {
        self.infinity_norm
    }
}

/// Capability token proving blinded pre-filter success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreFilterPassed {
    clearance_boundary: u32,
    aggregate_infinity_norm: u32,
}

impl PreFilterPassed {
    /// Return the clearance boundary.
    pub const fn clearance_boundary(self) -> u32 {
        self.clearance_boundary
    }

    /// Return the accepted aggregate infinity norm summary.
    pub const fn aggregate_infinity_norm(self) -> u32 {
        self.aggregate_infinity_norm
    }

    /// Convert the pass token into share-release authorization for one attempt.
    pub const fn into_share_release_authorization(
        self,
        attempt_id: AttemptId,
    ) -> ShareReleaseAuthorization {
        ShareReleaseAuthorization {
            attempt_id,
            prefilter: self,
        }
    }
}

/// Capability required before response-share release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShareReleaseAuthorization {
    attempt_id: AttemptId,
    prefilter: PreFilterPassed,
}

impl ShareReleaseAuthorization {
    /// Return the authorized attempt.
    pub const fn attempt_id(self) -> AttemptId {
        self.attempt_id
    }

    /// Return the pre-filter pass token.
    pub const fn prefilter(self) -> PreFilterPassed {
        self.prefilter
    }
}

/// Public abort record for a failed pre-filter gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreFilterAborted {
    clearance_boundary: u32,
    aggregate_infinity_norm: u32,
}

impl PreFilterAborted {
    /// Return the clearance boundary.
    pub const fn clearance_boundary(self) -> u32 {
        self.clearance_boundary
    }

    /// Return the rejected aggregate infinity norm summary.
    pub const fn aggregate_infinity_norm(self) -> u32 {
        self.aggregate_infinity_norm
    }
}

/// Pre-filter result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreFilterOutcome {
    /// Share release may proceed.
    Passed(PreFilterPassed),
    /// Attempt must abort before share release.
    Aborted(PreFilterAborted),
}

/// Stateless blinded pre-filter evaluator.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlindedPreFilter;

impl BlindedPreFilter {
    /// Evaluate public blinded commitment summaries.
    pub fn evaluate(
        clearance_boundary: u32,
        rejection_increment: EpsilonUnit,
        summaries: Vec<BlindedCommitmentSummary>,
        ledger: &mut EpsilonLedger,
    ) -> Result<PreFilterOutcome, ThresholdError> {
        if summaries.is_empty() {
            return Err(ThresholdError::InvalidPreFilter {
                reason: "no blinded commitment summaries supplied",
            });
        }

        let aggregate_infinity_norm = summaries.iter().fold(0u32, |acc, summary| {
            acc.saturating_add(summary.infinity_norm())
        });

        if aggregate_infinity_norm > clearance_boundary {
            ledger.increment_rejection(rejection_increment);
            Ok(PreFilterOutcome::Aborted(PreFilterAborted {
                clearance_boundary,
                aggregate_infinity_norm,
            }))
        } else {
            Ok(PreFilterOutcome::Passed(PreFilterPassed {
                clearance_boundary,
                aggregate_infinity_norm,
            }))
        }
    }
}

/// Centered polynomial vector used by the pre-filter simulation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolyVector<const DIM: usize> {
    /// Vector elements in centered coefficient representation.
    pub elements: [Poly; DIM],
}

impl<const DIM: usize> PolyVector<DIM> {
    /// Return the zero vector.
    pub const fn zero() -> Self {
        Self {
            elements: [Poly::zero(); DIM],
        }
    }

    /// Construct from raw polynomial elements.
    pub const fn from_elements(elements: [Poly; DIM]) -> Self {
        Self { elements }
    }

    /// Add centered coefficients without modular reduction.
    pub fn add(&self, rhs: &Self) -> Self {
        let mut out = *self;
        out.add_assign(rhs);
        out
    }

    /// Add centered coefficients into this vector without modular reduction.
    pub fn add_assign(&mut self, rhs: &Self) {
        for (lhs, rhs) in self.elements.iter_mut().zip(rhs.elements.iter()) {
            for (lhs_coeff, rhs_coeff) in lhs.coeffs.iter_mut().zip(rhs.coeffs.iter()) {
                *lhs_coeff += *rhs_coeff;
            }
        }
    }

    /// Return the maximum absolute centered coefficient.
    pub fn infinity_norm(&self) -> i32 {
        self.elements
            .iter()
            .flat_map(|poly| poly.coeffs.iter())
            .map(|coeff| i64::from(*coeff).abs())
            .max()
            .unwrap_or(0)
            .min(i64::from(i32::MAX)) as i32
    }
}

impl<const DIM: usize> Default for PolyVector<DIM> {
    fn default() -> Self {
        Self::zero()
    }
}

/// Mask vector shape for ML-DSA-65.
pub type MaskVector = PolyVector<MLDSA65_L>;

/// Commitment vector shape for ML-DSA-65.
pub type CommitmentVector = PolyVector<MLDSA65_K>;

/// Noise-flooded commitment that can be checked before share exposure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlindedCommitment {
    /// Committed projection of the local flooded mask contribution.
    pub w_i_committed: CommitmentVector,
    /// Deterministic transcript binding for the simulated bounds proof.
    pub proof_hash: [u8; 32],
}

impl BlindedCommitment {
    /// Construct a blinded commitment from a projection and proof hash.
    pub const fn new(w_i_committed: CommitmentVector, proof_hash: [u8; 32]) -> Self {
        Self {
            w_i_committed,
            proof_hash,
        }
    }
}

/// Local validator share used by the pre-filter audit scaffold.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ValidatorShare {
    /// Validator index inside the active signer set.
    index: u32,
    /// Simulated secret vector used only after the pre-filter gate.
    secret_s1_share: MaskVector,
}

impl core::fmt::Debug for ValidatorShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ValidatorShare")
            .field("index", &self.index)
            .field("secret_s1_share_redacted", &true)
            .finish()
    }
}

impl ValidatorShare {
    /// Construct a validator share for the audit scaffold.
    pub const fn new(index: u32, secret_s1_share: MaskVector) -> Self {
        Self {
            index,
            secret_s1_share,
        }
    }

    /// Return validator index.
    pub const fn index(self) -> u32 {
        self.index
    }

    /// Generate a deterministic noise-flooded mask and blinded commitment.
    pub fn generate_flooded_mask(&self, rng_seed: &[u8; 32]) -> (MaskVector, BlindedCommitment) {
        let mut y_i = self.sample_uniform_mask(rng_seed);
        let noise = self.sample_gaussian_noise(rng_seed, BETA / 4);
        y_i.add_assign(&noise);

        let w_i = self.compute_lattice_projections(&y_i);
        let proof_hash = self.compute_nizk_bounds_proof(&y_i, &w_i);

        (y_i, BlindedCommitment::new(w_i, proof_hash))
    }

    fn sample_uniform_mask(&self, rng_seed: &[u8; 32]) -> MaskVector {
        let mut out = MaskVector::zero();
        for element_idx in 0..MLDSA65_L {
            for coeff_idx in 0..N {
                out.elements[element_idx].coeffs[coeff_idx] = sample_open_left_centered(
                    b"mldsa65-prefilter-mask",
                    rng_seed,
                    self.index,
                    element_idx,
                    coeff_idx,
                    GAMMA1,
                );
            }
        }
        out
    }

    fn sample_gaussian_noise(&self, rng_seed: &[u8; 32], scale: i32) -> MaskVector {
        let mut out = MaskVector::zero();
        for element_idx in 0..MLDSA65_L {
            for coeff_idx in 0..N {
                out.elements[element_idx].coeffs[coeff_idx] = sample_closed_centered(
                    b"mldsa65-prefilter-flood",
                    rng_seed,
                    self.index,
                    element_idx,
                    coeff_idx,
                    scale,
                );
            }
        }
        out
    }

    fn compute_lattice_projections(&self, y_i: &MaskVector) -> CommitmentVector {
        let mut out = CommitmentVector::zero();
        for row_idx in 0..MLDSA65_K {
            for coeff_idx in 0..N {
                let mut acc = 0i64;
                for col_idx in 0..MLDSA65_L {
                    let source_idx = (coeff_idx + row_idx + col_idx) % N;
                    let weight =
                        (((self.index as usize + row_idx + 1) * (col_idx + 2)) % 7) as i64 - 3;
                    acc += i64::from(y_i.elements[col_idx].coeffs[source_idx]) * weight;
                }
                out.elements[row_idx].coeffs[coeff_idx] = (acc / 128) as i32;
            }
        }
        out
    }

    fn compute_nizk_bounds_proof(&self, y_i: &MaskVector, w_i: &CommitmentVector) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"mldsa65-prefilter-bounds-proof-v1");
        hasher.update(self.index.to_be_bytes());
        update_hasher_with_vector(&mut hasher, y_i);
        update_hasher_with_vector(&mut hasher, w_i);
        hasher.finalize().into()
    }
}

fn sample_open_left_centered(
    domain: &[u8],
    seed: &[u8; 32],
    validator_index: u32,
    element_idx: usize,
    coeff_idx: usize,
    bound: i32,
) -> i32 {
    let modulus = (2 * i64::from(bound)) as u64;
    let sample = sample_u64(domain, seed, validator_index, element_idx, coeff_idx) % modulus;
    (i64::try_from(sample).expect("sample is bounded") + 1 - i64::from(bound)) as i32
}

fn sample_closed_centered(
    domain: &[u8],
    seed: &[u8; 32],
    validator_index: u32,
    element_idx: usize,
    coeff_idx: usize,
    bound: i32,
) -> i32 {
    let modulus = (2 * i64::from(bound) + 1) as u64;
    let sample = sample_u64(domain, seed, validator_index, element_idx, coeff_idx) % modulus;
    (i64::try_from(sample).expect("sample is bounded") - i64::from(bound)) as i32
}

fn sample_u64(
    domain: &[u8],
    seed: &[u8; 32],
    validator_index: u32,
    element_idx: usize,
    coeff_idx: usize,
) -> u64 {
    let mut hasher = Sha3_256::new();
    hasher.update(domain);
    hasher.update(seed);
    hasher.update(validator_index.to_be_bytes());
    hasher.update((element_idx as u64).to_be_bytes());
    hasher.update((coeff_idx as u64).to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    u64::from_be_bytes(
        digest[0..8]
            .try_into()
            .expect("sha3 digest prefix has fixed length"),
    )
}

fn update_hasher_with_vector<const DIM: usize>(hasher: &mut Sha3_256, vector: &PolyVector<DIM>) {
    hasher.update((DIM as u64).to_be_bytes());
    for element in vector.elements {
        for coeff in element.coeffs {
            hasher.update(coeff.to_le_bytes());
        }
    }
}
