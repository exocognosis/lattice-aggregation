//! Binding hash-based VSS for 32-byte secrets over the ML-DSA modulus.
//!
//! This implements a **malicious-dealer-detectable** verifiable secret sharing
//! shape for research / P1 coordinator profiles:
//!
//! - Degree `t-1` Shamir polynomials over `q` (one per secret byte).
//! - Public coefficient commitments (SHA3-256) binding the dealer polynomial.
//! - Per-receiver share openings that can be checked against those commitments
//!   by re-evaluating the committed coefficients (Feldman-style verification
//!   in the hash-commitment model).
//!
//! # Claim boundary
//!
//! - Provides **binding** dealer commitments and share verification.
//! - Detects inconsistent shares relative to the published commitment transcript.
//! - Does **not** provide UC security, adaptive security, zero-knowledge
//!   discrete-log proofs, or a side-channel-audited constant-time field.
//! - Randomness is caller-supplied (TEE/HSM or test RNG); this module does not
//!   claim a secure entropy source.

use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use crate::{errors::ThresholdError, types::ValidatorId};

/// ML-DSA prime modulus `q`.
pub const Q: u64 = 8_380_417;
const SEED_BYTES: usize = 32;

/// Public coefficient commitment for one polynomial degree.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CoeffCommitment(pub [u8; 32]);

/// One verified receiver share of a 32-byte secret.
#[derive(Clone)]
pub struct VssShare {
    /// Receiver validator identity.
    pub receiver: ValidatorId,
    /// Nonzero evaluation point.
    pub x: u16,
    /// Field elements, one per secret byte.
    pub elements: [u64; SEED_BYTES],
}

impl Drop for VssShare {
    fn drop(&mut self) {
        for e in &mut self.elements {
            e.zeroize();
        }
    }
}

impl core::fmt::Debug for VssShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VssShare")
            .field("receiver", &self.receiver)
            .field("x", &self.x)
            .field("redacted", &true)
            .finish()
    }
}

/// Public VSS transcript for one dealer contribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VssTranscript {
    /// Threshold `t` (polynomial degree is `t - 1`).
    pub threshold: u16,
    /// Domain separator bound into commitments.
    pub domain: Vec<u8>,
    /// Per-byte, per-degree coefficient commitments: `coeffs[byte][degree]`.
    pub coefficient_commitments: Vec<Vec<CoeffCommitment>>,
    /// Per-receiver binding commitments to share openings (x, elements).
    pub share_commitments: Vec<(ValidatorId, CoeffCommitment)>,
    /// Transcript root digest.
    pub transcript_digest: [u8; 32],
}

/// Dealer output: public transcript plus private receiver shares.
#[derive(Clone, Debug)]
pub struct VssDeal {
    /// Public verifiable transcript.
    pub transcript: VssTranscript,
    /// Ordered receiver shares.
    pub shares: Vec<VssShare>,
    /// Digest of the secret (never the secret itself).
    pub secret_digest: [u8; 32],
}

/// Deal a 32-byte secret with binding coefficient commitments.
///
/// `randomness` must be high-entropy dealer randomness (32+ bytes recommended).
#[allow(clippy::needless_range_loop)]
pub fn deal_secret(
    secret: &[u8; SEED_BYTES],
    threshold: u16,
    receivers: &[ValidatorId],
    domain: &[u8],
    randomness: &[u8],
) -> Result<VssDeal, ThresholdError> {
    let n = receivers.len() as u16;
    if threshold == 0 || threshold > n || receivers.is_empty() {
        return Err(ThresholdError::InvalidThresholdParameters {
            threshold,
            total_nodes: n,
        });
    }
    if randomness.is_empty() {
        return Err(ThresholdError::BackendUnavailable {
            reason: "VSS dealer randomness must be non-empty",
        });
    }

    let mut seen = std::collections::BTreeSet::new();
    for receiver in receivers {
        if !seen.insert(*receiver) {
            return Err(ThresholdError::DuplicateValidator {
                validator: *receiver,
            });
        }
    }

    let degree = threshold as usize;
    let mut coefficient_commitments = Vec::with_capacity(SEED_BYTES);
    let mut polys: Vec<Vec<u64>> = Vec::with_capacity(SEED_BYTES);

    for byte_index in 0..SEED_BYTES {
        let mut coeffs = Vec::with_capacity(degree);
        coeffs.push(u64::from(secret[byte_index]) % Q);
        for d in 1..degree {
            coeffs.push(derive_coeff(randomness, domain, byte_index, d as u16));
        }
        let mut commits = Vec::with_capacity(degree);
        for (d, coeff) in coeffs.iter().enumerate() {
            commits.push(commit_coeff(domain, byte_index, d as u16, *coeff));
        }
        coefficient_commitments.push(commits);
        polys.push(coeffs);
    }

    let mut shares = Vec::with_capacity(receivers.len());
    let mut share_commitments = Vec::with_capacity(receivers.len());
    for receiver in receivers {
        let x = x_coordinate_for(*receiver);
        let mut elements = [0u64; SEED_BYTES];
        for byte_index in 0..SEED_BYTES {
            elements[byte_index] = eval_poly(&polys[byte_index], x);
        }
        let share = VssShare {
            receiver: *receiver,
            x,
            elements,
        };
        share_commitments.push((*receiver, commit_share(domain, &share)));
        shares.push(share);
    }

    // Zeroize dealer coefficients.
    for poly in &mut polys {
        for c in poly.iter_mut() {
            c.zeroize();
        }
    }

    let transcript_digest = transcript_root(
        domain,
        threshold,
        &coefficient_commitments,
        &share_commitments,
        receivers,
    );
    let transcript = VssTranscript {
        threshold,
        domain: domain.to_vec(),
        coefficient_commitments,
        share_commitments,
        transcript_digest,
    };

    Ok(VssDeal {
        transcript,
        shares,
        secret_digest: sha3_bytes(secret),
    })
}

/// Verify that a share opens its published share commitment and is in-range.
pub fn verify_share(transcript: &VssTranscript, share: &VssShare) -> Result<(), ThresholdError> {
    if transcript.coefficient_commitments.len() != SEED_BYTES {
        return Err(ThresholdError::BackendUnavailable {
            reason: "VSS transcript has wrong coefficient commitment width",
        });
    }
    if share.x == 0 {
        return Err(ThresholdError::BackendUnavailable {
            reason: "VSS share x-coordinate must be nonzero",
        });
    }

    let expected = commit_share(&transcript.domain, share);
    let Some((_, published)) = transcript
        .share_commitments
        .iter()
        .find(|(validator, _)| *validator == share.receiver)
    else {
        return Err(ThresholdError::UnknownValidator {
            validator: share.receiver,
        });
    };
    if *published != expected {
        return Err(ThresholdError::PartialShareVerificationFailed {
            validator: share.receiver,
        });
    }

    for byte_index in 0..SEED_BYTES {
        let commits = &transcript.coefficient_commitments[byte_index];
        if commits.len() != transcript.threshold as usize {
            return Err(ThresholdError::BackendUnavailable {
                reason: "VSS transcript degree mismatch",
            });
        }
        if share.elements[byte_index] >= Q {
            return Err(ThresholdError::PartialShareVerificationFailed {
                validator: share.receiver,
            });
        }
    }
    Ok(())
}

/// Verify a share using explicit coefficient openings (dealer response / audit path).
#[allow(clippy::needless_range_loop)]
pub fn verify_share_with_openings(
    transcript: &VssTranscript,
    share: &VssShare,
    openings: &[[u64; SEED_BYTES]],
) -> Result<(), ThresholdError> {
    // openings[degree][byte]
    if openings.len() != transcript.threshold as usize {
        return Err(ThresholdError::BackendUnavailable {
            reason: "VSS opening degree mismatch",
        });
    }
    for (degree, opening) in openings.iter().enumerate() {
        for byte_index in 0..SEED_BYTES {
            let expected = commit_coeff(
                &transcript.domain,
                byte_index,
                degree as u16,
                opening[byte_index],
            );
            if expected != transcript.coefficient_commitments[byte_index][degree] {
                return Err(ThresholdError::CommitmentVerificationFailed {
                    validator: share.receiver,
                });
            }
        }
    }

    for byte_index in 0..SEED_BYTES {
        let mut coeffs = Vec::with_capacity(openings.len());
        for opening in openings {
            coeffs.push(opening[byte_index]);
        }
        let expected = eval_poly(&coeffs, share.x);
        if expected != share.elements[byte_index] {
            return Err(ThresholdError::PartialShareVerificationFailed {
                validator: share.receiver,
            });
        }
    }
    Ok(())
}

/// Reconstruct a 32-byte secret from at least `threshold` verified shares.
#[allow(clippy::needless_range_loop)]
pub fn reconstruct_secret(
    threshold: u16,
    shares: &[VssShare],
) -> Result<[u8; SEED_BYTES], ThresholdError> {
    if shares.len() < threshold as usize {
        return Err(ThresholdError::InsufficientPartialShares {
            required: threshold,
            received: shares.len(),
        });
    }
    let active: Vec<&VssShare> = shares.iter().take(threshold as usize).collect();
    let xs: Vec<u16> = active.iter().map(|s| s.x).collect();
    let mut secret = [0u8; SEED_BYTES];
    for byte_index in 0..SEED_BYTES {
        let mut acc = 0u64;
        for share in &active {
            let lambda = lagrange_at_zero(&xs, share.x)?;
            acc = mod_add(acc, mod_mul(lambda, share.elements[byte_index]));
        }
        if acc > 255 {
            return Err(ThresholdError::BackendUnavailable {
                reason: "VSS reconstruction emitted non-byte field element",
            });
        }
        secret[byte_index] = acc as u8;
    }
    Ok(secret)
}

/// Map validator ID to a nonzero evaluation point.
pub fn x_coordinate_for(validator: ValidatorId) -> u16 {
    validator.0.wrapping_add(1)
}

fn commit_coeff(domain: &[u8], byte_index: usize, degree: u16, coeff: u64) -> CoeffCommitment {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:feldman-vss-coeff:v1");
    hasher.update(domain);
    hasher.update((byte_index as u64).to_be_bytes());
    hasher.update(degree.to_be_bytes());
    hasher.update(coeff.to_be_bytes());
    CoeffCommitment(hasher.finalize().into())
}

fn derive_coeff(randomness: &[u8], domain: &[u8], byte_index: usize, degree: u16) -> u64 {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:feldman-vss-coeff-sample:v1");
    hasher.update(domain);
    hasher.update(randomness);
    hasher.update((byte_index as u64).to_be_bytes());
    hasher.update(degree.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let wide = u128::from_be_bytes(digest[..16].try_into().expect("16 bytes"));
    (wide % u128::from(Q)) as u64
}

fn eval_poly(coeffs: &[u64], x: u16) -> u64 {
    let mut acc = 0u64;
    let mut x_pow = 1u64;
    for (degree, coeff) in coeffs.iter().enumerate() {
        if degree > 0 {
            x_pow = mod_mul(x_pow, u64::from(x));
        }
        acc = mod_add(acc, mod_mul(*coeff, x_pow));
    }
    acc
}

fn lagrange_at_zero(active_xs: &[u16], current_x: u16) -> Result<u64, ThresholdError> {
    let mut numerator = 1u64;
    let mut denominator = 1u64;
    for &peer in active_xs {
        if peer == current_x {
            continue;
        }
        numerator = mod_mul(numerator, u64::from(peer));
        denominator = mod_mul(denominator, mod_sub(u64::from(peer), u64::from(current_x)));
    }
    Ok(mod_mul(numerator, mod_inv(denominator)?))
}

fn commit_share(domain: &[u8], share: &VssShare) -> CoeffCommitment {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:feldman-vss-share:v1");
    hasher.update(domain);
    hasher.update(share.receiver.0.to_be_bytes());
    hasher.update(share.x.to_be_bytes());
    for element in &share.elements {
        hasher.update(element.to_be_bytes());
    }
    CoeffCommitment(hasher.finalize().into())
}

fn transcript_root(
    domain: &[u8],
    threshold: u16,
    commits: &[Vec<CoeffCommitment>],
    share_commitments: &[(ValidatorId, CoeffCommitment)],
    receivers: &[ValidatorId],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:feldman-vss-transcript:v1");
    hasher.update(domain);
    hasher.update(threshold.to_be_bytes());
    hasher.update((receivers.len() as u64).to_be_bytes());
    for receiver in receivers {
        hasher.update(receiver.0.to_be_bytes());
    }
    for byte_commits in commits {
        for commit in byte_commits {
            hasher.update(commit.0);
        }
    }
    for (validator, commit) in share_commitments {
        hasher.update(validator.0.to_be_bytes());
        hasher.update(commit.0);
    }
    hasher.finalize().into()
}

fn sha3_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha3_256::digest(bytes).into()
}

fn mod_add(a: u64, b: u64) -> u64 {
    (a + b) % Q
}

fn mod_sub(a: u64, b: u64) -> u64 {
    (a + Q - (b % Q)) % Q
}

fn mod_mul(a: u64, b: u64) -> u64 {
    ((u128::from(a) * u128::from(b)) % u128::from(Q)) as u64
}

fn mod_inv(value: u64) -> Result<u64, ThresholdError> {
    if value.is_multiple_of(Q) {
        return Err(ThresholdError::BackendUnavailable {
            reason: "VSS modular inverse of zero",
        });
    }
    Ok(mod_pow(value % Q, Q - 2))
}

fn mod_pow(mut base: u64, mut exp: u64) -> u64 {
    let mut result = 1u64;
    base %= Q;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mod_mul(result, base);
        }
        base = mod_mul(base, base);
        exp >>= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deal_reconstruct_round_trip() {
        let secret = [0x5Au8; 32];
        let receivers = vec![
            ValidatorId(0),
            ValidatorId(1),
            ValidatorId(2),
            ValidatorId(3),
        ];
        let deal = deal_secret(&secret, 3, &receivers, b"test-domain", b"dealer-rand-1").unwrap();
        let reconstructed = reconstruct_secret(3, &deal.shares[..3]).unwrap();
        assert_eq!(reconstructed, secret);
        assert_eq!(deal.secret_digest, sha3_bytes(&secret));
    }

    #[test]
    fn verify_share_accepts_honest_and_rejects_tamper() {
        let secret = [1u8; 32];
        let receivers = vec![ValidatorId(1), ValidatorId(2)];
        let deal = deal_secret(&secret, 2, &receivers, b"dom", b"rand").unwrap();
        verify_share(&deal.transcript, &deal.shares[0]).unwrap();

        let mut tampered = deal.shares[0].clone();
        tampered.elements[0] = (tampered.elements[0] + 1) % Q;
        assert!(verify_share(&deal.transcript, &tampered).is_err());
    }
}
