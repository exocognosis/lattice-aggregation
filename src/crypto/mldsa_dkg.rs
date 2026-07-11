//! Multi-dealer distributed key generation for ML-DSA-65 module keys.
//!
//! Increment 4 of the real threshold key material build-out
//! (`docs/superpowers/plans/2026-07-10-real-threshold-key-material-vss.md`).
//! Increment 3 let one dealer share a key; here every dealer contributes an
//! independently-sampled random key, and the joint key is their sum. Because the
//! hiding VSS ([`crate::crypto::vss_bdlop`]) is additively homomorphic, each
//! validator's final share is the sum of the shares it received from the
//! accepted dealers, and those summed shares verify against the summed
//! commitments. No sub-threshold coalition of validators can recover the joint
//! secret key; only `>= threshold` validator shares reconstruct it. (This
//! increment does not implement encrypted share transport — see the claim
//! boundary — so a party that assembles all shares, e.g. the coordinator
//! running `finalize` or any holder of a [`DkgOutput`], can reconstruct.)
//!
//! ## Phases
//!
//! - **Commit / share** — [`DkgCoordinator::deal`] samples a dealer's random
//!   contribution, publishes its public value `t^(d) = A s1^(d) + s2^(d)` and a
//!   [`DealerContribution::commitment_digest`] (commit-before-reveal binding),
//!   and VSS-shares the contribution.
//! - **Complaint** — [`DkgCoordinator::finalize`] accepts a dealer only when
//!   every one of its shares verifies (the homomorphic relation) AND every
//!   commitment carries a valid well-formedness opening proof
//!   ([`crate::crypto::bdlop_pok`]); dealers that fail either check are excluded.
//! - **Finalize** — the joint public key is the sum of accepted `t^(d)`, and the
//!   per-validator shares and commitments are summed into the joint key.
//!
//! ## Claim boundary
//!
//! This is an honest-but-verifiable DKG, not yet malicious-secure:
//!
//! - the complaint rule *detects* non-verifying dealers, but complaint
//!   *adjudication* (a dealer answering a complaint with public, anti-framing
//!   evidence) is deferred to Increment 5;
//! - dealer commitments are now proven well-formed (opening proofs, checked in
//!   `finalize`), but a published `t^(d)` is still not cryptographically bound to
//!   those commitments, so a malicious dealer's public/secret consistency is not
//!   enforced (needs a lattice linear-relation proof over `R_q`, deferred);
//! - the opening proofs give per-commitment well-formedness only: full
//!   extractability additionally needs slack reconciliation and a share norm
//!   bound (see the [`crate::crypto::bdlop_pok`] and [`crate::crypto::vss_bdlop`]
//!   claim boundaries);
//! - rushing / last-mover key-bias resistance is Increment 5. The commit digest
//!   is computable but not yet consumed by `finalize` (no
//!   commit->reveal->compare round), so no bias-resistance is claimed;
//! - shares are held in the clear here (no encrypted per-receiver transport,
//!   deferred to Increment 2b), so a party that assembles all shares — the
//!   `finalize` caller or any holder of a `DkgOutput` — can reconstruct the key.
//!   Secrecy is against sub-threshold *validator* coalitions, not against such a
//!   share-collecting party.
//!
//! It closes no hypothesis criterion and makes no production threshold ML-DSA
//! security claim.

use sha3::{Digest, Sha3_256};

use crate::{
    crypto::{
        bdlop::CommitmentKey,
        mldsa_module::{
            self, aggregate, compute_t, expand_matrix_a, sample_secret_key, KeyProofs, PublicKey,
            SharedSecretKey, MODULE_K,
        },
        module_lattice::vec_add,
        poly::Poly,
    },
    errors::ThresholdError,
};

const SUBSEED_LABEL: &[u8] = b"lattice-aggregation/mldsa-dkg/dealer-subseed";
const DEALER_DIGEST_LABEL: &[u8] = b"lattice-aggregation/mldsa-dkg/dealer-commitment";

/// One dealer's published DKG contribution.
///
/// Holds the dealer's verifiable shares of a random secret key and the matching
/// public value `t^(d) = A s1^(d) + s2^(d)`.
#[derive(Clone, Debug)]
pub struct DealerContribution {
    dealer_id: u16,
    shared: SharedSecretKey,
    proofs: KeyProofs,
    public_contribution: Vec<Poly>,
}

impl DealerContribution {
    /// Dealer identifier.
    pub fn dealer_id(&self) -> u16 {
        self.dealer_id
    }

    /// Public contribution `t^(d) = A s1^(d) + s2^(d)`.
    pub fn public_contribution(&self) -> &[Poly] {
        &self.public_contribution
    }

    /// Digest over this contribution (its public value and all VSS
    /// commitments), intended for a future commit-before-reveal round. It is
    /// computable but not yet consumed by [`DkgCoordinator::finalize`], so it
    /// currently binds nothing operationally.
    pub fn commitment_digest(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(DEALER_DIGEST_LABEL);
        hasher.update(self.dealer_id.to_be_bytes());
        for poly in &self.public_contribution {
            for coeff in poly.canonical().coeffs {
                hasher.update(coeff.to_be_bytes());
            }
        }
        hasher.update(self.shared.commitment_digest());
        hasher.finalize().into()
    }
}

/// Output of a finalized DKG session.
#[derive(Clone, Debug)]
pub struct DkgOutput {
    /// Joint public key `{ rho, t = sum of accepted t^(d) }`.
    pub public_key: PublicKey,
    /// Verifiable sharing of the joint secret key across the validators.
    pub shared_key: SharedSecretKey,
    /// Ids of the accepted dealers, sorted ascending.
    pub accepted_dealers: Vec<u16>,
}

/// Coordinator for a coordinator-assisted ML-DSA-65 DKG session over a fixed
/// public matrix seed and validator set.
pub struct DkgCoordinator {
    rho: [u8; 32],
    matrix_a: Vec<Vec<Poly>>,
    threshold: u16,
    total_nodes: u16,
    commit_key: CommitmentKey,
}

impl DkgCoordinator {
    /// Create a DKG coordinator for a public matrix seed, threshold, validator
    /// count, and commitment key.
    pub fn new(rho: [u8; 32], threshold: u16, total_nodes: u16, commit_key: CommitmentKey) -> Self {
        Self {
            matrix_a: expand_matrix_a(&rho),
            rho,
            threshold,
            total_nodes,
            commit_key,
        }
    }

    /// Dealer `dealer_id` samples a random contribution and VSS-shares it.
    ///
    /// The secret and the sharing randomness are derived from independent
    /// sub-seeds of `contribution_seed`. Returns
    /// [`ThresholdError::InvalidThresholdParameters`] for an invalid
    /// threshold / validator count.
    pub fn deal(
        &self,
        dealer_id: u16,
        contribution_seed: &[u8; 32],
    ) -> Result<DealerContribution, ThresholdError> {
        let secret = sample_secret_key(&derive_subseed(contribution_seed, dealer_id, b"secret"));
        let public_contribution = compute_t(&self.matrix_a, &secret);
        let (shared, proofs) = mldsa_module::deal_secret_key(
            &secret,
            self.threshold,
            self.total_nodes,
            &derive_subseed(contribution_seed, dealer_id, b"share"),
            &self.commit_key,
        )?;
        Ok(DealerContribution {
            dealer_id,
            shared,
            proofs,
            public_contribution,
        })
    }

    /// Finalize the DKG over the supplied contributions.
    ///
    /// A dealer is accepted only when every one of its shares verifies (the
    /// complaint rule); non-verifying dealers are excluded. Rejects duplicate
    /// dealer ids and requires at least one accepted dealer.
    pub fn finalize(
        &self,
        contributions: &[DealerContribution],
    ) -> Result<DkgOutput, ThresholdError> {
        let mut ids: Vec<u16> = contributions.iter().map(|c| c.dealer_id).collect();
        ids.sort_unstable();
        if ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ThresholdError::BackendUnavailable {
                reason: "duplicate dealer id",
            });
        }

        // Complaint rule: accept a dealer only when every share verifies (the
        // homomorphic relation) AND every commitment carries a valid
        // well-formedness opening proof.
        let mut accepted: Vec<&DealerContribution> = contributions
            .iter()
            .filter(|contribution| {
                contribution.shared.verify(&self.commit_key)
                    && contribution
                        .shared
                        .verify_commitment_proofs(&contribution.proofs, &self.commit_key)
            })
            .collect();
        accepted.sort_by_key(|contribution| contribution.dealer_id);
        if accepted.is_empty() {
            return Err(ThresholdError::BackendUnavailable {
                reason: "no accepted dealers",
            });
        }

        // Joint public key: sum of accepted public contributions.
        let mut t = vec![Poly::zero(); MODULE_K];
        for contribution in &accepted {
            t = vec_add(&t, &contribution.public_contribution);
        }
        let t = t.iter().map(Poly::canonical).collect();

        // Joint shared key: component-wise sum of accepted shared keys.
        let shared_keys: Vec<SharedSecretKey> = accepted.iter().map(|c| c.shared.clone()).collect();
        let shared_key = aggregate(&shared_keys)?;

        Ok(DkgOutput {
            public_key: PublicKey { rho: self.rho, t },
            shared_key,
            accepted_dealers: accepted.iter().map(|c| c.dealer_id).collect(),
        })
    }
}

/// Derive an independent 32-byte sub-seed from a base seed, dealer id, and label.
fn derive_subseed(base: &[u8; 32], dealer_id: u16, label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(SUBSEED_LABEL);
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label);
    hasher.update(dealer_id.to_be_bytes());
    hasher.update(base);
    hasher.finalize().into()
}

#[cfg(test)]
mod mldsa_dkg_tests {
    use super::*;

    #[test]
    fn dkg_produces_verifiable_joint_key_and_depends_on_dealer_set() {
        let commit_key = CommitmentKey::from_seed(b"public");
        let coordinator = DkgCoordinator::new([1u8; 32], 2, 3, commit_key.clone());

        let contributions = vec![
            coordinator.deal(0, &[10u8; 32]).unwrap(),
            coordinator.deal(1, &[11u8; 32]).unwrap(),
        ];

        let output = coordinator.finalize(&contributions).unwrap();
        assert_eq!(output.accepted_dealers, vec![0, 1]);

        // The joint shares verify against the summed commitments.
        assert!(output.shared_key.verify(&commit_key));

        // Reconstructing the joint secret recomputes the joint public key.
        let secret = output.shared_key.reconstruct(&[1, 3]).unwrap();
        let recomputed = compute_t(&expand_matrix_a(&output.public_key.rho), &secret);
        for (lhs, rhs) in recomputed.iter().zip(output.public_key.t.iter()) {
            assert_eq!(lhs.canonical().coeffs, rhs.canonical().coeffs);
        }

        // The joint key depends on the whole dealer set: dropping a dealer
        // changes the public key, so no single dealer determines it.
        let single = coordinator.finalize(&contributions[0..1]).unwrap();
        assert_ne!(
            single.public_key.t[0].canonical().coeffs,
            output.public_key.t[0].canonical().coeffs
        );
    }

    #[test]
    fn finalize_excludes_non_verifying_dealer() {
        let session_key = CommitmentKey::from_seed(b"public");
        let coordinator = DkgCoordinator::new([2u8; 32], 2, 3, session_key.clone());
        let good = coordinator.deal(0, &[20u8; 32]).unwrap();

        // A dealer whose shares were committed under a different key does not
        // verify against the session key and must be excluded.
        let rogue = DkgCoordinator::new([2u8; 32], 2, 3, CommitmentKey::from_seed(b"other"));
        let bad = rogue.deal(1, &[21u8; 32]).unwrap();

        let output = coordinator.finalize(&[good, bad]).unwrap();
        assert_eq!(output.accepted_dealers, vec![0]);
        assert!(output.shared_key.verify(&session_key));
    }

    #[test]
    fn finalize_rejects_empty_and_duplicate_dealers() {
        let commit_key = CommitmentKey::from_seed(b"public");
        let coordinator = DkgCoordinator::new([3u8; 32], 2, 3, commit_key);

        assert!(coordinator.finalize(&[]).is_err());

        let contribution = coordinator.deal(0, &[30u8; 32]).unwrap();
        assert!(coordinator
            .finalize(&[contribution.clone(), contribution])
            .is_err());
    }

    #[test]
    fn deal_rejects_invalid_parameters() {
        let commit_key = CommitmentKey::from_seed(b"public");
        let coordinator = DkgCoordinator::new([4u8; 32], 4, 3, commit_key);
        assert!(coordinator.deal(0, &[40u8; 32]).is_err());
    }
}
