//! FIPS 204 ML-DSA-65 public-key derivation from module secret shares.
//!
//! This module implements the linear part of ML-DSA-65 key generation without
//! reconstructing `s1` or `s2` at the aggregator.  A receiver locally evaluates
//!
//! `t_i = A * s1_i + s2_i`
//!
//! from its module share and emits only a public `t_i`, bound to both `rho` and
//! a caller-supplied ceremony digest.  The public contributions are then either
//! added (additive sharing) or interpolated at zero (Shamir sharing).  The
//! aggregate `t` is passed through the exact FIPS 204 `Power2Round` and
//! `pkEncode` operations to produce the standard 1,952 byte ML-DSA-65 public
//! key.
//!
//! # Claim boundary
//!
//! This is public-key *derivation*, not complete distributed `KeyGen_internal`:
//!
//! - joint, byte-exact `ExpandS` sampling and the other umbrella-KeyGen
//!   primitives enumerated by [`missing_keygen_primitives`] are explicitly
//!   unavailable;
//! - this layer does not distribute or verify the input secret shares and does
//!   not prove that they are short, well formed, or bound to VSS commitments;
//! - receiver transport/custody and active-security proofs are out of scope;
//! - the full aggregate `t` and its low part `t0` are disclosed to the caller.
//!   FIPS 204 permits treating full `t` as an expanded public key, but this
//!   component does not distribute or retain the epoch-bound `t0` signing state
//!   required by the surrounding threshold-signing protocol.
//!
//! Fixed-seed fixtures may be used to prove byte-for-byte FIPS conformance, but
//! starting from a known seed is not evidence for joint distributed sampling.

use std::collections::BTreeSet;

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use zeroize::Zeroize;

use crate::{
    crypto::{
        interpolation::compute_lagrange_coefficient,
        mldsa_primitives::power2round,
        poly::{Poly, N, Q},
    },
    errors::ThresholdError,
    low_level::ntt::{inv_ntt, ntt},
    types::{ThresholdPublicKey, ValidatorId, MLDSA65_PUBLICKEY_BYTES},
};

/// ML-DSA-65 module height `k`.
pub const MLDSA65_K: usize = 6;
/// ML-DSA-65 module width `l`.
pub const MLDSA65_L: usize = 5;
/// Encoded bytes per `t1` polynomial (`256 * 10 / 8`).
const T1_ENCODED_BYTES: usize = 320;

/// A missing primitive required before this component can be described as a
/// complete distributed FIPS 204 key generator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FipsKeygenMissingPrimitive {
    /// Jointly sample the exact `s1` and `s2` distribution produced by FIPS 204
    /// `ExpandS`, without any party learning the complete vectors.
    JointExactExpandSSampling,
    /// Generate the public matrix seed `rho` jointly without a last mover or
    /// caller being able to bias it.
    JointUnbiasableRhoGeneration,
    /// Construct and authenticate the surrounding epoch/validator/commitment
    /// transcript whose digest is supplied to this component.
    CeremonyContextConstructionAndAuthentication,
    /// Generate the private FIPS signing seed `K` without reconstructing it at
    /// a coordinator.
    DistributedSecretKGeneration,
    /// Bind, distribute, and retain the `t0` output required by the subsequent
    /// signing protocol for the same epoch and public key.
    EpochBoundT0SigningState,
    /// Deliver and retain each secret share only at its intended receiver over
    /// an authenticated confidential channel.
    ReceiverPrivateShareCustody,
    /// Prove that distributed secret shares have the required short FIPS
    /// distribution and are bound to the accepted VSS commitments.
    SecretShareVssAndShortnessProof,
    /// Prove that each published linear image is computed from the same secret
    /// values bound by the accepted commitments.
    PublicSecretRelationProof,
    /// Authenticate dealer/receiver frames and provide a complete complaint,
    /// exclusion, and recovery protocol for active faults and aborts.
    AuthenticatedComplaintAndRecovery,
}

const MISSING_KEYGEN_PRIMITIVES: [FipsKeygenMissingPrimitive; 9] = [
    FipsKeygenMissingPrimitive::JointExactExpandSSampling,
    FipsKeygenMissingPrimitive::JointUnbiasableRhoGeneration,
    FipsKeygenMissingPrimitive::CeremonyContextConstructionAndAuthentication,
    FipsKeygenMissingPrimitive::DistributedSecretKGeneration,
    FipsKeygenMissingPrimitive::EpochBoundT0SigningState,
    FipsKeygenMissingPrimitive::ReceiverPrivateShareCustody,
    FipsKeygenMissingPrimitive::SecretShareVssAndShortnessProof,
    FipsKeygenMissingPrimitive::PublicSecretRelationProof,
    FipsKeygenMissingPrimitive::AuthenticatedComplaintAndRecovery,
];

/// Return the umbrella distributed-KeyGen primitives deliberately missing from
/// this public derivation component.
///
/// The exact public linear evaluation, one-time `Power2Round`, and standard
/// public-key encoding implemented here are not included in this list.
pub const fn missing_keygen_primitives() -> &'static [FipsKeygenMissingPrimitive] {
    &MISSING_KEYGEN_PRIMITIVES
}

/// How receiver-held secret shares represent the joint module secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareAggregation {
    /// Every configured additive share is required and public `t` shares are
    /// summed coefficient-wise.
    Additive {
        /// Exact number of additive shares expected for this derivation.
        expected_shares: u16,
    },
    /// At least `threshold` Shamir shares are interpolated at `x = 0`.
    ShamirAtZero {
        /// Degree-plus-one threshold of the sharing polynomial.
        threshold: u16,
    },
}

/// Public domain binding for one distributed public-key derivation ceremony.
///
/// `rho` alone identifies the FIPS public matrix but is not a unique protocol
/// session.  The ceremony digest must bind the surrounding epoch, validator
/// set, threshold, accepted commitments, and protocol version.  This component
/// treats it as an opaque caller-supplied digest and enforces equality; it does
/// not construct or authenticate that transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FipsPublicKeyContext65 {
    rho: [u8; 32],
    ceremony_digest: [u8; 32],
}

impl FipsPublicKeyContext65 {
    /// Construct a public ceremony binding.
    pub const fn new(rho: [u8; 32], ceremony_digest: [u8; 32]) -> Self {
        Self {
            rho,
            ceremony_digest,
        }
    }

    /// Public FIPS matrix seed.
    pub const fn rho(&self) -> &[u8; 32] {
        &self.rho
    }

    /// Opaque digest of the surrounding distributed-KeyGen ceremony.
    pub const fn ceremony_digest(&self) -> &[u8; 32] {
        &self.ceremony_digest
    }
}

/// One receiver's module secret share `(s1_i, s2_i)`.
///
/// The fields are deliberately private and the type does not implement
/// `Clone` or `Debug`: it is meant to stay with the receiver and be supplied to
/// [`evaluate_public_t_share`] locally.  Construction takes caller-owned
/// polynomial values by copy, so this type cannot prove that no prior copies
/// exist; exclusive receiver custody is a separate protocol obligation.
pub struct FipsModuleSecretShare65 {
    receiver_index: u16,
    s1: [Poly; MLDSA65_L],
    s2: [Poly; MLDSA65_K],
}

impl FipsModuleSecretShare65 {
    /// Construct a share at a nonzero Shamir/additive receiver index.
    pub fn new(
        receiver_index: u16,
        s1: [Poly; MLDSA65_L],
        s2: [Poly; MLDSA65_K],
    ) -> Result<Self, ThresholdError> {
        if receiver_index == 0 {
            return Err(ThresholdError::BackendUnavailable {
                reason: "FIPS public-key derivation requires a nonzero receiver index",
            });
        }
        Ok(Self {
            receiver_index,
            s1,
            s2,
        })
    }

    /// One-based receiver/Shamir evaluation index.
    pub const fn receiver_index(&self) -> u16 {
        self.receiver_index
    }
}

impl Drop for FipsModuleSecretShare65 {
    fn drop(&mut self) {
        for poly in self.s1.iter_mut().chain(self.s2.iter_mut()) {
            poly.coeffs.zeroize();
        }
    }
}

/// Public linear image `t_i = A*s1_i+s2_i` emitted by one receiver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FipsPublicTShare65 {
    context: FipsPublicKeyContext65,
    receiver_index: u16,
    t: [Poly; MLDSA65_K],
}

impl FipsPublicTShare65 {
    /// Ceremony context to which this public contribution is bound.
    pub const fn context(&self) -> &FipsPublicKeyContext65 {
        &self.context
    }

    /// One-based receiver/Shamir evaluation index.
    pub const fn receiver_index(&self) -> u16 {
        self.receiver_index
    }

    /// Public module-vector contribution.
    pub const fn t(&self) -> &[Poly; MLDSA65_K] {
        &self.t
    }
}

/// Exact FIPS public-key derivation and its deliberately disclosed public
/// intermediates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FipsPublicKeyDerivation65 {
    context: FipsPublicKeyContext65,
    public_key: ThresholdPublicKey,
    public_t: [Poly; MLDSA65_K],
    t1: [Poly; MLDSA65_K],
    t0: [Poly; MLDSA65_K],
}

impl FipsPublicKeyDerivation65 {
    /// Public ceremony context shared by every accepted contribution.
    pub const fn context(&self) -> &FipsPublicKeyContext65 {
        &self.context
    }

    /// Standard 1,952-byte ML-DSA-65 public key `rho || pkEncode(t1)`.
    pub const fn public_key(&self) -> &ThresholdPublicKey {
        &self.public_key
    }

    /// Full aggregate `t = A*s1+s2`, disclosed by this public derivation.
    pub const fn public_t(&self) -> &[Poly; MLDSA65_K] {
        &self.public_t
    }

    /// High part emitted in the standard public key.
    pub const fn t1(&self) -> &[Poly; MLDSA65_K] {
        &self.t1
    }

    /// Low part disclosed by aggregating full `t`; not encoded in the public
    /// key and not kept private by this component.
    pub const fn t0(&self) -> &[Poly; MLDSA65_K] {
        &self.t0
    }
}

/// Locally evaluate one receiver's FIPS-exact public linear image.
///
/// The exact `ExpandA` matrix is derived from public `rho`; only the resulting
/// public `t_i`, receiver index, and ceremony binding need to leave the
/// receiver.
pub fn evaluate_public_t_share(
    context: &FipsPublicKeyContext65,
    share: &FipsModuleSecretShare65,
) -> FipsPublicTShare65 {
    FipsPublicTShare65 {
        context: *context,
        receiver_index: share.receiver_index,
        t: compute_t(context.rho(), &share.s1, &share.s2),
    }
}

/// Aggregate public `t` shares, apply exact `Power2Round`, and encode the
/// standard ML-DSA-65 public key.
///
/// Secret `s1`/`s2` shares are not accepted by this function.  It validates
/// complete ceremony-context binding and receiver-index uniqueness before
/// combining only public linear images.
pub fn aggregate_public_key_from_t_shares(
    context: &FipsPublicKeyContext65,
    shares: &[FipsPublicTShare65],
    aggregation: ShareAggregation,
) -> Result<FipsPublicKeyDerivation65, ThresholdError> {
    validate_public_shares(context, shares, aggregation)?;

    let receiver_indices: Vec<u16> = shares.iter().map(|share| share.receiver_index).collect();
    let mut public_t = [Poly::zero(); MLDSA65_K];
    for share in shares {
        let weight = match aggregation {
            ShareAggregation::Additive { .. } => 1,
            ShareAggregation::ShamirAtZero { .. } => {
                compute_lagrange_coefficient(&receiver_indices, share.receiver_index)
            }
        };
        for (aggregate, contribution) in public_t.iter_mut().zip(share.t.iter()) {
            aggregate.add_assign(&contribution.scalar_mul(i64::from(weight)));
        }
    }

    let (t1, t0) = power2round_vector(&public_t);
    let public_key = encode_public_key(context.rho(), &t1);
    Ok(FipsPublicKeyDerivation65 {
        context: *context,
        public_key,
        public_t,
        t1,
        t0,
    })
}

fn validate_public_shares(
    context: &FipsPublicKeyContext65,
    shares: &[FipsPublicTShare65],
    aggregation: ShareAggregation,
) -> Result<(), ThresholdError> {
    let required = match aggregation {
        ShareAggregation::Additive { expected_shares } => {
            if expected_shares == 0 {
                return Err(ThresholdError::InvalidThresholdParameters {
                    threshold: 0,
                    total_nodes: 0,
                });
            }
            if shares.len() != usize::from(expected_shares) {
                return Err(ThresholdError::InsufficientPartialShares {
                    required: expected_shares,
                    received: shares.len(),
                });
            }
            expected_shares
        }
        ShareAggregation::ShamirAtZero { threshold } => {
            if threshold == 0 {
                return Err(ThresholdError::InvalidThresholdParameters {
                    threshold,
                    total_nodes: shares.len().try_into().unwrap_or(u16::MAX),
                });
            }
            if shares.len() < usize::from(threshold) {
                return Err(ThresholdError::InsufficientPartialShares {
                    required: threshold,
                    received: shares.len(),
                });
            }
            threshold
        }
    };

    let mut seen = BTreeSet::new();
    for share in shares {
        if share.context != *context {
            return Err(ThresholdError::TranscriptMismatch);
        }
        if !seen.insert(share.receiver_index) {
            return Err(ThresholdError::DuplicateValidator {
                validator: ValidatorId(share.receiver_index),
            });
        }
    }
    debug_assert!(required > 0);
    Ok(())
}

fn compute_t(rho: &[u8; 32], s1: &[Poly; MLDSA65_L], s2: &[Poly; MLDSA65_K]) -> [Poly; MLDSA65_K] {
    let a_hat = expand_a_hat(rho);
    let s1_hat: [[i32; N]; MLDSA65_L] = std::array::from_fn(|column| {
        let mut transformed = s1[column].canonical().coeffs;
        ntt(&mut transformed);
        transformed
    });

    std::array::from_fn(|row| {
        let mut aggregate_hat = [0i32; N];
        for column in 0..MLDSA65_L {
            for coefficient in 0..N {
                let product = (i64::from(a_hat[row][column][coefficient])
                    * i64::from(s1_hat[column][coefficient]))
                .rem_euclid(i64::from(Q)) as i32;
                aggregate_hat[coefficient] = add_mod(aggregate_hat[coefficient], product);
            }
        }
        inv_ntt(&mut aggregate_hat);
        let mut output = Poly::from_coeffs(aggregate_hat);
        output.add_assign(&s2[row].canonical());
        output
    })
}

fn expand_a_hat(rho: &[u8; 32]) -> [[[i32; N]; MLDSA65_L]; MLDSA65_K] {
    std::array::from_fn(|row| {
        std::array::from_fn(|column| expand_a_hat_entry(rho, column as u8, row as u8))
    })
}

fn expand_a_hat_entry(rho: &[u8; 32], column: u8, row: u8) -> [i32; N] {
    let mut hasher = Shake128::default();
    hasher.update(rho);
    hasher.update(&[column, row]);
    let mut reader = hasher.finalize_xof();
    let mut output = [0i32; N];
    let mut accepted = 0usize;
    let mut encoded = [0u8; 3];
    while accepted < N {
        reader.read(&mut encoded);
        let candidate = u32::from(encoded[0])
            | (u32::from(encoded[1]) << 8)
            | (u32::from(encoded[2] & 0x7f) << 16);
        if candidate < Q as u32 {
            output[accepted] = candidate as i32;
            accepted += 1;
        }
    }
    output
}

fn power2round_vector(public_t: &[Poly; MLDSA65_K]) -> ([Poly; MLDSA65_K], [Poly; MLDSA65_K]) {
    let mut t1 = [Poly::zero(); MLDSA65_K];
    let mut t0 = [Poly::zero(); MLDSA65_K];
    for row in 0..MLDSA65_K {
        for coefficient in 0..N {
            let (high, low) = power2round(public_t[row].coeffs[coefficient]);
            t1[row].coeffs[coefficient] = high;
            t0[row].coeffs[coefficient] = low;
        }
    }
    (t1, t0)
}

fn encode_public_key(rho: &[u8; 32], t1: &[Poly; MLDSA65_K]) -> ThresholdPublicKey {
    let mut encoded = [0u8; MLDSA65_PUBLICKEY_BYTES];
    encoded[..rho.len()].copy_from_slice(rho);

    for (row, poly) in t1.iter().enumerate() {
        let row_offset = rho.len() + row * T1_ENCODED_BYTES;
        for (coefficient, &value) in poly.coeffs.iter().enumerate() {
            debug_assert!((0..(1 << 10)).contains(&value));
            let value = value as u32;
            let bit_offset = coefficient * 10;
            for bit in 0..10 {
                if (value >> bit) & 1 == 1 {
                    encoded[row_offset + (bit_offset + bit) / 8] |= 1 << ((bit_offset + bit) % 8);
                }
            }
        }
    }

    ThresholdPublicKey(encoded)
}

fn add_mod(lhs: i32, rhs: i32) -> i32 {
    let sum = lhs + rhs;
    if sum >= Q {
        sum - Q
    } else {
        sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_expand_s_primitive_is_explicit() {
        assert!(missing_keygen_primitives()
            .contains(&FipsKeygenMissingPrimitive::JointExactExpandSSampling));
        assert!(missing_keygen_primitives()
            .contains(&FipsKeygenMissingPrimitive::ReceiverPrivateShareCustody));
        assert!(missing_keygen_primitives()
            .contains(&FipsKeygenMissingPrimitive::PublicSecretRelationProof));
    }

    #[test]
    fn rejects_zero_receiver_index() {
        assert!(FipsModuleSecretShare65::new(
            0,
            [Poly::zero(); MLDSA65_L],
            [Poly::zero(); MLDSA65_K],
        )
        .is_err());
    }

    #[cfg(feature = "raw-real-mldsa")]
    #[test]
    fn additive_share_derivation_matches_known_seed_fips_keygen() {
        // Conformance fixture only: this deliberately starts from complete
        // secret material expanded from a known seed, then splits it.  It proves
        // the share-linear derivation and encoding match KeyGen_internal; it is
        // not evidence for joint exact ExpandS sampling or receiver custody.
        let fixture = crate::backend::keygen_from_seed(&[0x11; 32]).expect("known-seed keygen");
        let mut first_s1 = [Poly::zero(); MLDSA65_L];
        let mut first_s2 = [Poly::zero(); MLDSA65_K];
        let mut second_s1 = [Poly::zero(); MLDSA65_L];
        let mut second_s2 = [Poly::zero(); MLDSA65_K];

        split_additive(&fixture.s1, &mut first_s1, &mut second_s1, 17);
        split_additive(&fixture.s2, &mut first_s2, &mut second_s2, 29);

        let first = FipsModuleSecretShare65::new(1, first_s1, first_s2).unwrap();
        let second = FipsModuleSecretShare65::new(2, second_s1, second_s2).unwrap();
        let context = FipsPublicKeyContext65::new(fixture.rho, [0xC1; 32]);
        let public_shares = [
            evaluate_public_t_share(&context, &first),
            evaluate_public_t_share(&context, &second),
        ];
        let derived = aggregate_public_key_from_t_shares(
            &context,
            &public_shares,
            ShareAggregation::Additive { expected_shares: 2 },
        )
        .expect("aggregate public t shares");

        assert_eq!(derived.public_key(), &fixture.public_key);
    }

    #[cfg(feature = "raw-real-mldsa")]
    fn split_additive<const WIDTH: usize>(
        secret: &[Poly; WIDTH],
        first: &mut [Poly; WIDTH],
        second: &mut [Poly; WIDTH],
        domain: i32,
    ) {
        for component in 0..WIDTH {
            for coefficient in 0..N {
                let mask = ((component as i64 + 1) * 65_537
                    + (coefficient as i64 + 1) * i64::from(domain))
                .rem_euclid(i64::from(Q)) as i32;
                first[component].coeffs[coefficient] = mask;
                second[component].coeffs[coefficient] =
                    (secret[component].coeffs[coefficient] - mask).rem_euclid(Q);
            }
        }
    }
}
