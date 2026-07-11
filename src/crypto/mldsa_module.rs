//! ML-DSA-65 module-vector threshold key material.
//!
//! Increment 3 of the real threshold key material build-out
//! (`docs/superpowers/plans/2026-07-10-real-threshold-key-material-vss.md`).
//! Increments 1 and 2 shared a single ring element; this module lifts the key to
//! the real ML-DSA-65 module structure — secret vectors `s1 in R_q^L`,
//! `s2 in R_q^K`, a public matrix `A in R_q^{K x L}`, and the key relation
//! `t = A s1 + s2` — and shares the whole secret key with the hiding verifiable
//! secret sharing of [`crate::crypto::vss_bdlop`], so no single validator ever
//! holds a full key component below the threshold.
//!
//! ## Claim boundary
//!
//! This establishes the module structure and the linear key relation. It is
//! **not** a wire-format FIPS 204 key:
//!
//! - `A` is sampled uniformly over `R_q`; byte-exact `ExpandA` (NTT-domain
//!   sampling) is not implemented.
//! - the `eta = 4` secret sampler covers the ML-DSA-65 coefficient range but is
//!   not asserted bit-identical to `ExpandS`.
//! - the `Power2Round` split of `t` into `(t1, t0)` and public-key encoding are
//!   deferred.
//!
//! Distributed key generation across multiple dealers (so the key is *jointly*
//! generated, not dealt by one party) is Increment 4. Malicious-dealer binding
//! is the Increment 2b gap inherited from [`crate::crypto::vss_bdlop`]. This
//! module closes no hypothesis criterion and makes no production threshold
//! ML-DSA security claim.

use std::collections::BTreeSet;

use sha3::{Digest, Sha3_256};

use crate::{
    crypto::{
        bdlop::{Commitment, CommitmentKey},
        module_lattice::{matrix_vec_mul, sample_eta_vec, sample_uniform_matrix, vec_add},
        poly::Poly,
        vss_bdlop::{self, HidingShare},
    },
    errors::ThresholdError,
};

/// ML-DSA-65 module height `k` (length of `s2` and `t`).
pub const MODULE_K: usize = 6;
/// ML-DSA-65 module width `l` (length of `s1`).
pub const MODULE_L: usize = 5;
/// ML-DSA-65 secret-coefficient infinity-norm bound `eta`.
pub const ETA: i32 = 4;

const S1_SAMPLE_DOMAIN: u32 = 0x0001_0000;
const S2_SAMPLE_DOMAIN: u32 = 0x0002_0000;
const SEED_DERIVE_LABEL: &[u8] = b"lattice-aggregation/mldsa-module/derive-seed";
const COMMITMENT_DIGEST_LABEL: &[u8] = b"lattice-aggregation/mldsa-module/commitment-digest";

/// Per-component receiver shares: `shares[j][p]` is validator `p`'s share of
/// component `j`.
type ComponentShares = Vec<Vec<HidingShare>>;
/// Per-component public commitments: `commitments[j]` are the `threshold`
/// coefficient commitments for component `j`.
type ComponentCommitments = Vec<Vec<Commitment>>;

/// ML-DSA-65 secret key in module form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretKey {
    /// Short secret vector `s1 in R_q^L`.
    pub s1: Vec<Poly>,
    /// Short secret vector `s2 in R_q^K`.
    pub s2: Vec<Poly>,
}

impl SecretKey {
    /// Return a copy with every component reduced to canonical `[0, Q)` form,
    /// for representation-independent comparison.
    pub fn canonical(&self) -> SecretKey {
        SecretKey {
            s1: self.s1.iter().map(Poly::canonical).collect(),
            s2: self.s2.iter().map(Poly::canonical).collect(),
        }
    }
}

/// ML-DSA-65 public key: matrix seed `rho` and `t = A s1 + s2`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey {
    /// Public matrix seed `rho`.
    pub rho: [u8; 32],
    /// Public vector `t = A s1 + s2 in R_q^K`.
    pub t: Vec<Poly>,
}

/// Expand the public matrix `A in R_q^{K x L}` from seed `rho`.
///
/// `A` is sampled uniformly over `R_q`. Byte-exact FIPS 204 `ExpandA` is
/// deferred (see the module claim boundary).
pub fn expand_matrix_a(rho: &[u8; 32]) -> Vec<Vec<Poly>> {
    sample_uniform_matrix(rho, MODULE_K, MODULE_L)
}

/// Sample a short ML-DSA-65 secret key `(s1, s2)` with coefficients in
/// `[-ETA, ETA]` from a seed.
pub fn sample_secret_key(seed: &[u8; 32]) -> SecretKey {
    SecretKey {
        s1: sample_eta_vec(seed, S1_SAMPLE_DOMAIN, MODULE_L),
        s2: sample_eta_vec(seed, S2_SAMPLE_DOMAIN, MODULE_K),
    }
}

/// Compute `t = A s1 + s2`, returned in canonical `[0, Q)` form.
pub fn compute_t(a: &[Vec<Poly>], secret: &SecretKey) -> Vec<Poly> {
    // `s2` is signed-centered; normalize the sum so `t` is canonical.
    vec_add(&matrix_vec_mul(a, &secret.s1), &secret.s2)
        .iter()
        .map(Poly::canonical)
        .collect()
}

/// Generate an ML-DSA-65 module keypair deterministically from a seed.
pub fn keygen(seed: &[u8; 32]) -> (SecretKey, PublicKey) {
    let rho = derive_seed(seed, b"rho", 0);
    let secret = sample_secret_key(seed);
    let t = compute_t(&expand_matrix_a(&rho), &secret);
    (secret, PublicKey { rho, t })
}

/// Hiding, verifiable threshold shares of an ML-DSA-65 secret key.
///
/// Every one of the `L + K` secret component polynomials is shared with the
/// hiding VSS ([`crate::crypto::vss_bdlop`]); `s1_shares[j][p]` is validator
/// `p`'s share of `s1[j]`.
#[derive(Clone, Debug)]
pub struct SharedSecretKey {
    total_nodes: u16,
    threshold: u16,
    s1_shares: ComponentShares,
    s2_shares: ComponentShares,
    s1_commitments: ComponentCommitments,
    s2_commitments: ComponentCommitments,
}

/// Deal an ML-DSA-65 secret key into hiding, verifiable threshold shares.
///
/// Each secret component polynomial is shared with a component-separated dealer
/// seed, so the components use independent sharing randomness. Returns
/// [`ThresholdError::InvalidThresholdParameters`] when `threshold` is zero or
/// exceeds `total_nodes`.
pub fn deal_secret_key(
    secret: &SecretKey,
    threshold: u16,
    total_nodes: u16,
    dealer_seed: &[u8; 32],
    key: &CommitmentKey,
) -> Result<SharedSecretKey, ThresholdError> {
    let (s1_shares, s1_commitments) =
        deal_components(&secret.s1, b"s1", threshold, total_nodes, dealer_seed, key)?;
    let (s2_shares, s2_commitments) =
        deal_components(&secret.s2, b"s2", threshold, total_nodes, dealer_seed, key)?;
    Ok(SharedSecretKey {
        total_nodes,
        threshold,
        s1_shares,
        s2_shares,
        s1_commitments,
        s2_commitments,
    })
}

impl SharedSecretKey {
    /// Configured signing threshold.
    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Configured validator count.
    pub fn total_nodes(&self) -> u16 {
        self.total_nodes
    }

    /// Verify every validator's share of every component against the public
    /// commitments.
    pub fn verify(&self, key: &CommitmentKey) -> bool {
        verify_components(&self.s1_shares, &self.s1_commitments, key)
            && verify_components(&self.s2_shares, &self.s2_commitments, key)
    }

    /// Reconstruct the secret key from shares at the given one-based receiver
    /// indices.
    ///
    /// Fails closed rather than returning a silently-wrong key: indices are
    /// deduplicated and restricted to the dealt range `1..=total_nodes`, and at
    /// least `threshold` distinct valid indices must remain. Returns
    /// [`ThresholdError::InsufficientPartialShares`] otherwise.
    pub fn reconstruct(&self, receiver_indices: &[u16]) -> Result<SecretKey, ThresholdError> {
        let mut seen = BTreeSet::new();
        let mut distinct = Vec::new();
        for &index in receiver_indices {
            if (1..=self.total_nodes).contains(&index) && seen.insert(index) {
                distinct.push(index);
            }
        }
        if distinct.len() < usize::from(self.threshold) {
            return Err(ThresholdError::InsufficientPartialShares {
                required: self.threshold,
                received: distinct.len(),
            });
        }
        Ok(SecretKey {
            s1: reconstruct_components(&self.s1_shares, &distinct),
            s2: reconstruct_components(&self.s2_shares, &distinct),
        })
    }

    /// Domain-separated digest binding all public coefficient commitments.
    ///
    /// The DKG commit phase uses this to bind a dealer to its contribution
    /// before shares are aggregated (commit-before-reveal).
    pub fn commitment_digest(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(COMMITMENT_DIGEST_LABEL);
        hasher.update(self.threshold.to_be_bytes());
        hasher.update(self.total_nodes.to_be_bytes());
        for component in self.s1_commitments.iter().chain(self.s2_commitments.iter()) {
            for commitment in component {
                absorb_commitment(&mut hasher, commitment);
            }
        }
        hasher.finalize().into()
    }
}

/// Aggregate several verifiable shared secret keys into their component-wise sum.
///
/// Every input must share the same threshold, validator count, and module
/// dimensions. Because the hiding VSS is additively homomorphic, the summed
/// shares form a valid verifiable sharing of the summed secret key (summed
/// shares verify against summed commitments). The DKG uses this to combine
/// accepted dealer contributions into the joint key.
///
/// Returns [`ThresholdError::BackendUnavailable`] on an empty input or a
/// shape mismatch between contributions.
pub fn aggregate(contributions: &[SharedSecretKey]) -> Result<SharedSecretKey, ThresholdError> {
    let (first, rest) = contributions
        .split_first()
        .ok_or(ThresholdError::BackendUnavailable {
            reason: "aggregate requires at least one contribution",
        })?;

    let mut accumulator = first.clone();
    for contribution in rest {
        if contribution.threshold != accumulator.threshold
            || contribution.total_nodes != accumulator.total_nodes
            || contribution.s1_shares.len() != accumulator.s1_shares.len()
            || contribution.s2_shares.len() != accumulator.s2_shares.len()
        {
            return Err(ThresholdError::BackendUnavailable {
                reason: "aggregate: mismatched contribution shape",
            });
        }
        add_shares_into(&mut accumulator.s1_shares, &contribution.s1_shares);
        add_shares_into(&mut accumulator.s2_shares, &contribution.s2_shares);
        add_commitments_into(
            &mut accumulator.s1_commitments,
            &contribution.s1_commitments,
        );
        add_commitments_into(
            &mut accumulator.s2_commitments,
            &contribution.s2_commitments,
        );
    }
    Ok(accumulator)
}

fn add_shares_into(accumulator: &mut ComponentShares, other: &ComponentShares) {
    for (acc_component, other_component) in accumulator.iter_mut().zip(other.iter()) {
        for (acc_share, other_share) in acc_component.iter_mut().zip(other_component.iter()) {
            acc_share.value.add_assign(&other_share.value);
            acc_share.randomness = vec_add(&acc_share.randomness, &other_share.randomness);
        }
    }
}

fn add_commitments_into(accumulator: &mut ComponentCommitments, other: &ComponentCommitments) {
    for (acc_component, other_component) in accumulator.iter_mut().zip(other.iter()) {
        for (acc_commitment, other_commitment) in
            acc_component.iter_mut().zip(other_component.iter())
        {
            *acc_commitment = acc_commitment.add(other_commitment);
        }
    }
}

fn absorb_commitment(hasher: &mut Sha3_256, commitment: &Commitment) {
    for poly in commitment.t1.iter().chain(std::iter::once(&commitment.t2)) {
        for coeff in poly.canonical().coeffs {
            hasher.update(coeff.to_be_bytes());
        }
    }
}

fn deal_components(
    components: &[Poly],
    label: &[u8],
    threshold: u16,
    total_nodes: u16,
    dealer_seed: &[u8; 32],
    key: &CommitmentKey,
) -> Result<(ComponentShares, ComponentCommitments), ThresholdError> {
    let mut all_shares = Vec::with_capacity(components.len());
    let mut all_commitments = Vec::with_capacity(components.len());
    for (index, component) in components.iter().enumerate() {
        let seed = derive_seed(dealer_seed, label, index as u16);
        let (shares, commitments) =
            vss_bdlop::deal_secret(component, threshold, total_nodes, &seed, key)?;
        all_shares.push(shares);
        all_commitments.push(commitments);
    }
    Ok((all_shares, all_commitments))
}

fn verify_components(
    shares: &[Vec<HidingShare>],
    commitments: &[Vec<Commitment>],
    key: &CommitmentKey,
) -> bool {
    shares
        .iter()
        .zip(commitments.iter())
        .all(|(component_shares, component_commitments)| {
            component_shares
                .iter()
                .all(|share| vss_bdlop::verify_share(share, component_commitments, key))
        })
}

fn reconstruct_components(shares: &[Vec<HidingShare>], receiver_indices: &[u16]) -> Vec<Poly> {
    shares
        .iter()
        .map(|component_shares| {
            let subset: Vec<HidingShare> = receiver_indices
                .iter()
                .filter_map(|&index| {
                    component_shares
                        .iter()
                        .find(|share| share.receiver_index == index)
                        .cloned()
                })
                .collect();
            vss_bdlop::reconstruct(&subset)
        })
        .collect()
}

/// Derive a 32-byte sub-seed from a base seed, a label, and an index.
fn derive_seed(base: &[u8; 32], label: &[u8], index: u16) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(SEED_DERIVE_LABEL);
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label);
    hasher.update(index.to_be_bytes());
    hasher.update(base);
    hasher.finalize().into()
}

#[cfg(test)]
mod mldsa_module_tests {
    use super::*;

    #[test]
    fn keygen_is_deterministic_and_short() {
        let (sk_a, pk_a) = keygen(&[5u8; 32]);
        let (sk_b, pk_b) = keygen(&[5u8; 32]);
        assert_eq!(sk_a, sk_b);
        assert_eq!(pk_a, pk_b);
        assert_eq!(sk_a.s1.len(), MODULE_L);
        assert_eq!(sk_a.s2.len(), MODULE_K);
        assert_eq!(pk_a.t.len(), MODULE_K);
        for component in sk_a.s1.iter().chain(sk_a.s2.iter()) {
            assert!(
                component.check_noise_bounds(ETA + 1),
                "secret coefficients must be within [-ETA, ETA]"
            );
        }
    }

    #[test]
    fn key_relation_holds() {
        let (sk, pk) = keygen(&[9u8; 32]);
        let recomputed = compute_t(&expand_matrix_a(&pk.rho), &sk);
        for (lhs, rhs) in recomputed.iter().zip(pk.t.iter()) {
            assert_eq!(lhs.canonical().coeffs, rhs.canonical().coeffs);
        }
    }

    #[test]
    fn threshold_reconstruction_recovers_key_and_public_t() {
        let (sk, pk) = keygen(&[1u8; 32]);
        let commit_key = CommitmentKey::from_seed(b"public");
        let shared = deal_secret_key(&sk, 2, 3, &[7u8; 32], &commit_key).unwrap();

        assert!(shared.verify(&commit_key), "all shares must verify");

        // Reconstruct from a threshold-sized subset and confirm the key and the
        // public t both recompute.
        let recovered = shared.reconstruct(&[1, 3]).unwrap();
        assert_eq!(recovered.canonical(), sk.canonical());

        let recovered_t = compute_t(&expand_matrix_a(&pk.rho), &recovered);
        for (lhs, rhs) in recovered_t.iter().zip(pk.t.iter()) {
            assert_eq!(lhs.canonical().coeffs, rhs.canonical().coeffs);
        }
    }

    #[test]
    fn sub_threshold_is_rejected() {
        let (sk, _pk) = keygen(&[2u8; 32]);
        let commit_key = CommitmentKey::from_seed(b"public");
        let shared = deal_secret_key(&sk, 3, 5, &[8u8; 32], &commit_key).unwrap();

        // Only two indices for a threshold-3 sharing: fail closed, do not return
        // a silently-wrong key.
        assert!(shared.reconstruct(&[1, 2]).is_err());
    }

    #[test]
    fn reconstruct_fails_closed_on_bad_index_sets() {
        let (sk, _pk) = keygen(&[4u8; 32]);
        let commit_key = CommitmentKey::from_seed(b"public");
        let shared = deal_secret_key(&sk, 2, 3, &[6u8; 32], &commit_key).unwrap();

        // Unknown index is dropped, leaving 1 valid < threshold 2.
        assert!(shared.reconstruct(&[1, 99]).is_err());
        // Duplicate index collapses to 1 distinct < threshold 2.
        assert!(shared.reconstruct(&[2, 2]).is_err());
        // Duplicates tolerated when enough distinct valid indices remain.
        assert_eq!(
            shared.reconstruct(&[1, 1, 3]).unwrap().canonical(),
            sk.canonical()
        );
    }

    #[test]
    fn rejects_invalid_parameters() {
        let (sk, _pk) = keygen(&[3u8; 32]);
        let commit_key = CommitmentKey::from_seed(b"public");
        assert!(deal_secret_key(&sk, 0, 5, &[0u8; 32], &commit_key).is_err());
        assert!(deal_secret_key(&sk, 4, 3, &[0u8; 32], &commit_key).is_err());
    }
}
