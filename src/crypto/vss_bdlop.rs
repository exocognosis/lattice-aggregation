//! Hiding verifiable secret sharing over `R_q` using BDLOP commitments.
//!
//! Increment 2 of the real threshold key material build-out
//! (`docs/superpowers/plans/2026-07-10-real-threshold-key-material-vss.md`).
//! This is the hiding upgrade of [`crate::crypto::vss_real`]: instead of the
//! perfectly-binding-but-leaky Feldman map `C_j = g * c_j`, each sharing
//! coefficient is committed with a computationally hiding BDLOP commitment
//! (`crate::crypto::bdlop`).
//!
//! ## Scheme
//!
//! A dealer shares a secret ring element `c_0` with polynomial
//! `P(x) = sum_j c_j x^j` of degree `< threshold`, sampling `c_1..c_{tau-1}` and
//! the per-coefficient commitment randomness `rho_j` from a dealer seed. It
//! publishes `C_j = commit(c_j; rho_j)`. Each receiver `i` gets the share value
//! `P(i)` and the aggregated randomness `rho(i) = sum_j i^j rho_j`.
//!
//! Because the BDLOP commitment is additively/scalar homomorphic,
//! `commit(P(i); rho(i)) = sum_j i^j C_j`, so a receiver verifies its share
//! against the public commitments without a private channel to the dealer.
//!
//! ## What this improves over Feldman ([`crate::crypto::vss_real`])
//!
//! Feldman commitments leak `g * c_0`; here the per-coefficient commitments are
//! computationally hiding (Module-LWE). Against a PPT adversary holding all
//! public commitments and fewer than `threshold` shares, the secret stays
//! hidden. Each share also carries the aggregated randomness `rho(i)`, so the
//! hiding argument is the revealed-randomness variant of Module-LWE, which this
//! increment assumes rather than proves.
//!
//! ## Claim boundary
//!
//! - **Hiding** rests on the (parameter-pending) Module-LWE assumption of
//!   [`crate::crypto::bdlop`]. It is computational, not the perfect hiding of
//!   plain Shamir.
//! - **Binding is NOT enforced by [`verify_share`].** The aggregated randomness
//!   `rho(i) = sum_j i^j rho_j` is legitimately non-short, so `verify_share`
//!   checks only the homomorphic relation and applies no norm bound. It
//!   therefore does not bind a malicious dealer: a dealer able to solve the
//!   linear system could hand different receivers inconsistent values that each
//!   verify. Binding of the underlying commitments holds only for the short
//!   openings checked by
//!   [`crate::crypto::bdlop::CommitmentKey::verify_opening`]; malicious-dealer
//!   binding and extractability require the per-share validity proofs deferred
//!   to a later increment. The test
//!   `verify_share_does_not_enforce_randomness_shortness` documents this gap.
//!
//! This module does not implement encrypted per-receiver share transport,
//! per-share validity proofs, complaints, or a malicious-secure DKG, closes no
//! hypothesis criterion, and makes no production threshold ML-DSA security
//! claim.

use crate::{
    crypto::{
        bdlop::{Commitment, CommitmentKey, K},
        interpolation::reconstruct_secret_poly,
        module_lattice::{sample_short_vec, uniform_poly, vec_add, vec_scalar_mul},
        poly::{Poly, Q},
    },
    errors::ThresholdError,
};

const COEFFICIENT_SAMPLE_DOMAIN: u32 = 0x0100_0000;
const RANDOMNESS_SAMPLE_DOMAIN: u32 = 0x0200_0000;

/// A hiding VSS share issued to one receiver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HidingShare {
    /// One-based receiver index (polynomial evaluation point).
    pub receiver_index: u16,
    /// Share value `P(receiver_index)` in `R_q`.
    pub value: Poly,
    /// Aggregated commitment randomness `rho(receiver_index)` in `R_q^K`.
    pub randomness: Vec<Poly>,
}

/// Deal a secret into `total_nodes` hiding-verifiable shares.
///
/// The constant term of the sharing polynomial is `secret`; the non-constant
/// coefficients and all commitment randomness are derived from `dealer_seed`.
/// Returns one share per receiver index `1..=total_nodes` plus the public
/// per-coefficient BDLOP commitments (`threshold` of them, constant term first).
///
/// Returns [`ThresholdError::InvalidThresholdParameters`] when `threshold` is
/// zero or exceeds `total_nodes`.
pub fn deal_secret(
    secret: &Poly,
    threshold: u16,
    total_nodes: u16,
    dealer_seed: &[u8; 32],
    key: &CommitmentKey,
) -> Result<(Vec<HidingShare>, Vec<Commitment>), ThresholdError> {
    if threshold == 0 || total_nodes < threshold {
        return Err(ThresholdError::InvalidThresholdParameters {
            threshold,
            total_nodes,
        });
    }

    // Sharing polynomial coefficients: constant term is the secret, the rest are
    // CSPRNG-sampled so the polynomial has degree `< threshold`.
    let mut coefficients = Vec::with_capacity(usize::from(threshold));
    coefficients.push(secret.canonical());
    for degree in 1..threshold {
        coefficients.push(uniform_poly(
            dealer_seed,
            COEFFICIENT_SAMPLE_DOMAIN + u32::from(degree),
        ));
    }

    // Fresh short commitment randomness per coefficient, and the public
    // commitments to each coefficient.
    let mut coefficient_randomness = Vec::with_capacity(usize::from(threshold));
    let mut commitments = Vec::with_capacity(usize::from(threshold));
    for (degree, coefficient) in coefficients.iter().enumerate() {
        let randomness = sample_short_vec(dealer_seed, RANDOMNESS_SAMPLE_DOMAIN + degree as u32, K);
        commitments.push(key.commit(coefficient, &randomness));
        coefficient_randomness.push(randomness);
    }

    // Each receiver's share is the polynomial value and the aggregated
    // randomness evaluated at the receiver index.
    let mut shares = Vec::with_capacity(usize::from(total_nodes));
    for receiver_index in 1..=total_nodes {
        shares.push(HidingShare {
            receiver_index,
            value: evaluate_poly(&coefficients, receiver_index),
            randomness: evaluate_randomness(&coefficient_randomness, receiver_index),
        });
    }

    Ok((shares, commitments))
}

/// Verify a share against the public per-coefficient commitments.
///
/// Checks the homomorphic relation `commit(P(i); rho(i)) == sum_j i^j C_j`.
pub fn verify_share(share: &HidingShare, commitments: &[Commitment], key: &CommitmentKey) -> bool {
    if share.randomness.len() != K || commitments.is_empty() {
        return false;
    }

    let recomputed = key.commit(&share.value, &share.randomness);
    let expected = combine_commitments(commitments, share.receiver_index);
    recomputed.canonical() == expected.canonical()
}

/// Reconstruct the shared secret `P(0)` from a set of shares via Lagrange
/// interpolation at `x = 0`. Callers should verify shares first.
pub fn reconstruct(shares: &[HidingShare]) -> Poly {
    let points: Vec<(u16, Poly)> = shares
        .iter()
        .map(|share| (share.receiver_index, share.value))
        .collect();
    reconstruct_secret_poly(&points)
}

/// Homomorphically evaluate `sum_j i^j C_j` at receiver index `i`.
fn combine_commitments(commitments: &[Commitment], receiver_index: u16) -> Commitment {
    let q = i64::from(Q);
    let point = i64::from(receiver_index);
    let mut power = 1i64; // point^0
    let mut accumulator: Option<Commitment> = None;
    for commitment in commitments {
        let term = commitment.scalar_mul(power);
        accumulator = Some(match accumulator {
            Some(existing) => existing.add(&term),
            None => term,
        });
        power = (power * point) % q;
    }
    accumulator.expect("commitments is non-empty")
}

/// Evaluate `P(x) = sum_j coefficients[j] * x^j` at integer point `x` via
/// Horner's method over the ring.
fn evaluate_poly(coefficients: &[Poly], x: u16) -> Poly {
    let point = i64::from(x);
    let mut result = Poly::zero();
    for coeff in coefficients.iter().rev() {
        result = result.scalar_mul(point);
        result.add_assign(coeff);
    }
    result
}

/// Evaluate the vector polynomial `rho(x) = sum_j rho_j * x^j` at point `x`,
/// component-wise over `R_q^K`.
fn evaluate_randomness(coefficient_randomness: &[Vec<Poly>], x: u16) -> Vec<Poly> {
    let point = i64::from(x);
    let mut result = vec![Poly::zero(); K];
    for randomness in coefficient_randomness.iter().rev() {
        result = vec_add(&vec_scalar_mul(&result, point), randomness);
    }
    // `randomness` is short (signed); adding it onto a canonical accumulator can
    // leave non-canonical coefficients, so normalize before returning.
    result.iter().map(Poly::canonical).collect()
}

#[cfg(test)]
mod vss_bdlop_tests {
    use super::*;
    use crate::crypto::poly::N;

    fn secret_fixture() -> Poly {
        let mut coeffs = [0i32; N];
        for (index, coeff) in coeffs.iter_mut().enumerate() {
            *coeff = ((index as i32) * 4_242 + 99).rem_euclid(Q);
        }
        Poly::from_coeffs(coeffs)
    }

    #[test]
    fn deal_and_reconstruct_recovers_secret() {
        let key = CommitmentKey::from_seed(b"public");
        let secret = secret_fixture();
        let (shares, _commitments) = deal_secret(&secret, 3, 5, &[7u8; 32], &key).unwrap();

        let subset = [shares[0].clone(), shares[2].clone(), shares[4].clone()];
        assert_eq!(
            reconstruct(&subset).canonical().coeffs,
            secret.canonical().coeffs
        );
    }

    #[test]
    fn valid_shares_verify() {
        let key = CommitmentKey::from_seed(b"public");
        let secret = secret_fixture();
        let (shares, commitments) = deal_secret(&secret, 4, 7, &[3u8; 32], &key).unwrap();
        for share in &shares {
            assert!(verify_share(share, &commitments, &key));
        }
    }

    #[test]
    fn tampered_value_fails_verification() {
        let key = CommitmentKey::from_seed(b"public");
        let secret = secret_fixture();
        let (mut shares, commitments) = deal_secret(&secret, 3, 5, &[1u8; 32], &key).unwrap();
        shares[0].value.coeffs[0] = (shares[0].value.coeffs[0] + 1) % Q;
        assert!(!verify_share(&shares[0], &commitments, &key));
    }

    #[test]
    fn tampered_randomness_fails_verification() {
        let key = CommitmentKey::from_seed(b"public");
        let secret = secret_fixture();
        let (mut shares, commitments) = deal_secret(&secret, 3, 5, &[1u8; 32], &key).unwrap();
        shares[1].randomness[0].coeffs[0] = (shares[1].randomness[0].coeffs[0] + 1) % Q;
        assert!(!verify_share(&shares[1], &commitments, &key));
    }

    #[test]
    fn different_threshold_subsets_agree() {
        let key = CommitmentKey::from_seed(b"public");
        let secret = secret_fixture();
        let (shares, _commitments) = deal_secret(&secret, 3, 6, &[9u8; 32], &key).unwrap();
        let first = reconstruct(&[shares[0].clone(), shares[1].clone(), shares[2].clone()]);
        let second = reconstruct(&[shares[3].clone(), shares[4].clone(), shares[5].clone()]);
        assert_eq!(first.canonical().coeffs, second.canonical().coeffs);
    }

    #[test]
    fn sub_threshold_does_not_recover_secret() {
        let key = CommitmentKey::from_seed(b"public");
        let secret = secret_fixture();
        let (shares, _commitments) = deal_secret(&secret, 3, 5, &[42u8; 32], &key).unwrap();
        let recovered = reconstruct(&[shares[0].clone(), shares[1].clone()]);
        assert_ne!(recovered.canonical().coeffs, secret.canonical().coeffs);
    }

    #[test]
    fn rejects_invalid_parameters() {
        let key = CommitmentKey::from_seed(b"public");
        let secret = secret_fixture();
        assert!(deal_secret(&secret, 0, 5, &[0u8; 32], &key).is_err());
        assert!(deal_secret(&secret, 4, 3, &[0u8; 32], &key).is_err());
    }

    #[test]
    fn verify_share_does_not_enforce_randomness_shortness() {
        // Documents the Increment 2 binding gap: verify_share checks only the
        // homomorphic relation and applies no norm bound on the randomness (the
        // aggregated rho(i) is legitimately non-short). The commitment
        // primitive's verify_opening DOES enforce shortness. Encoded as a
        // passing test so the limitation is captured, not hidden.
        use crate::crypto::module_lattice::sample_short_vec;

        let key = CommitmentKey::from_seed(b"public");
        let value = secret_fixture();
        let mut randomness = sample_short_vec(b"rand", 0, K);
        randomness[0].coeffs[0] = 5; // non-short coefficient

        let commitment = key.commit(&value, &randomness);
        let share = HidingShare {
            receiver_index: 1,
            value,
            randomness: randomness.clone(),
        };

        // verify_share accepts the non-short randomness (no norm bound enforced).
        assert!(verify_share(
            &share,
            std::slice::from_ref(&commitment),
            &key
        ));
        // The commitment primitive rejects the same non-short opening.
        assert!(!key.verify_opening(&commitment, &share.value, &randomness));
    }
}
