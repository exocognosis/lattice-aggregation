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
//! Two finalize paths coexist. The original one-shot [`DkgCoordinator::finalize`]
//! (Increment 4) is kept for back-compat; the two-round
//! [`DkgCoordinator::finalize_with_evidence`] (Increment 5) adds a committing
//! round and public fault evidence.
//!
//! - **Commit** — each dealer publishes a session-bound
//!   [`DkgCoordinator::contribution_digest`] over its contribution before any
//!   share is revealed; [`DkgCoordinator::collect_commitments`] freezes the
//!   id-sorted commit vector for the round.
//! - **Share / reveal** — [`DkgCoordinator::deal`] samples a dealer's random
//!   contribution, publishes its public value `t^(d) = A s1^(d) + s2^(d)`, and
//!   VSS-shares the contribution.
//! - **Adjudicate** — [`DkgCoordinator::finalize_with_evidence`] opens each
//!   commit against the revealed contribution, accepts a dealer only when its
//!   shares verify (the homomorphic relation) AND every commitment carries a
//!   valid well-formedness opening proof ([`crate::crypto::bdlop_pok`]), and emits
//!   a re-checkable [`DealerFault`] for every committed dealer excluded by a
//!   *failed accept predicate* (commit mismatch, invalid share, or bad commitment
//!   proof); a committed dealer that never reveals is a silent exclusion, not a
//!   fault. Any party can re-run [`DkgCoordinator::verify_fault`] against the
//!   public transcript.
//! - **Finalize** — the joint public key is the sum of accepted `t^(d)`, the
//!   per-validator shares and commitments are summed into the joint key, and a
//!   [`DkgCoordinator::transcript_digest`] binds the round outcome.
//!
//! ## Claim boundary
//!
//! This hardens the DKG toward malicious security but does **not** reach it:
//!
//! - **Fault evidence is diagnostic, not slashing-grade.** `finalize_with_evidence`
//!   emits [`DealerFault`] records that any holder of the public transcript can
//!   re-check ([`DkgCoordinator::verify_fault`]), and an honest dealer cannot be
//!   framed: the round-1 commit digest binds the dealer's *entire* contribution
//!   (shares, commitments, and proofs), and every predicate-failure re-check is
//!   gated on that digest, so no substituted contribution convicts an honest
//!   dealer. But with no signed dealer frames in this synchronous in-memory
//!   model, a fault is not cryptographically attributable to a dealer's key — it
//!   is not a non-repudiable proof usable to slash on-chain.
//! - **Commit binding stops adaptive-choice bias, not last-mover abort bias.**
//!   The commit round binds each contribution before reveal, so a rushing dealer
//!   cannot *choose* its contribution after seeing others'. It does **not** stop a
//!   last dealer from *aborting* after seeing the others' reveals to bias the
//!   accepted set; abort-resistance needs an unbiasable-output mechanism (e.g. a
//!   VUF/commit-reveal-with-recovery) that this layer does not have.
//! - **Missing reveal is exclusion only, never a fault.** A committed dealer that
//!   never reveals is silently dropped, not recorded as faulty — silence cannot be
//!   forged into evidence against a dealer.
//! - Only fault classes recomputable from public data exist
//!   ([`DealerFaultClass`]); equivocation-across-receivers and invalid-complaint
//!   classes are deliberately absent (they need signed frames or a
//!   per-receiver/deadline model).
//! - A published `t^(d)` is still not cryptographically bound to the commitments,
//!   so a malicious dealer's public/secret consistency is not enforced (needs a
//!   lattice linear-relation proof over `R_q`, deferred); and the opening proofs
//!   give per-commitment well-formedness only, so full extractability additionally
//!   needs slack reconciliation and a share norm bound (see the
//!   [`crate::crypto::bdlop_pok`] and [`crate::crypto::vss_bdlop`] claim boundaries).
//! - Shares are held in the clear here (no encrypted per-receiver transport,
//!   deferred to Increment 2b), so a party that assembles all shares — the
//!   finalize caller or any holder of a `DkgOutput` — can reconstruct the key.
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
const COMMIT_DIGEST_LABEL: &[u8] = b"lattice-aggregation/mldsa-dkg/commit-digest/v1";
const TRANSCRIPT_DIGEST_LABEL: &[u8] = b"lattice-aggregation/mldsa-dkg/transcript-digest/v1";

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

/// A publicly re-checkable dealer fault surfaced by
/// [`DkgCoordinator::finalize_with_evidence`].
///
/// **These are diagnostics, not slashing-grade proofs.** This synchronous,
/// in-memory model has no signed dealer frames, so a fault is re-checkable only
/// *relative to a fixed public transcript* (the commit vector plus each dealer's
/// revealed public contribution). That is enough to guarantee an honest dealer
/// cannot be framed — [`DkgCoordinator::verify_fault`] re-runs the same public
/// predicate and returns `false` for a well-formed contribution — but it does
/// **not** cryptographically attribute misbehaviour to a dealer's signing key.
/// Only fault classes that an evaluator can independently recompute from public
/// data exist here; equivocation-across-receivers and invalid-complaint classes
/// are deliberately absent because proving them needs signed frames or a
/// per-receiver/deadline model this layer does not have.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DealerFaultClass {
    /// The revealed contribution does not hash to its round-1 commitment
    /// (`contribution_digest != committed digest`).
    CommitMismatch,
    /// A share fails the homomorphic VSS relation against its commitments
    /// (`shared.verify` is false).
    InvalidShareRelation,
    /// A commitment fails its well-formedness opening proof
    /// (`verify_commitment_proofs` is false).
    InvalidCommitmentProof,
}

/// A dealer excluded from the DKG together with the re-checkable reason, as
/// emitted by [`DkgCoordinator::finalize_with_evidence`] and re-verifiable via
/// [`DkgCoordinator::verify_fault`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DealerFault {
    /// The excluded dealer.
    pub dealer_id: u16,
    /// The public fault class.
    pub class: DealerFaultClass,
}

/// A dealer's round-1 commitment: a session-bound digest that binds its
/// contribution before any share is revealed (see
/// [`DkgCoordinator::contribution_digest`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitRecord {
    /// The committing dealer.
    pub dealer_id: u16,
    /// The commitment digest.
    pub digest: [u8; 32],
}

/// Result of [`DkgCoordinator::finalize_with_evidence`]: the finalized joint key,
/// the public fault evidence for excluded dealers, and a transcript digest
/// binding the whole round.
#[derive(Clone, Debug)]
pub struct DkgFinalizeReport {
    /// The joint key over the accepted dealers.
    pub output: DkgOutput,
    /// Public fault evidence, sorted by `(dealer_id, class)`.
    pub faults: Vec<DealerFault>,
    /// Digest binding the session, the commit vector, the faults, and the
    /// accepted set (see [`DkgCoordinator::transcript_digest`]).
    pub transcript_digest: [u8; 32],
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

        self.build_output(&accepted)
    }

    /// Aggregate an id-sorted, already-accepted dealer set into the joint key.
    ///
    /// Shared by [`finalize`](Self::finalize) and
    /// [`finalize_with_evidence`](Self::finalize_with_evidence): the joint public
    /// key is the canonical sum of the accepted public contributions and the
    /// joint shared key is the component-wise sum of the accepted shared keys.
    fn build_output(&self, accepted: &[&DealerContribution]) -> Result<DkgOutput, ThresholdError> {
        let mut t = vec![Poly::zero(); MODULE_K];
        for contribution in accepted {
            t = vec_add(&t, &contribution.public_contribution);
        }
        let t = t.iter().map(Poly::canonical).collect();

        let shared_keys: Vec<SharedSecretKey> = accepted.iter().map(|c| c.shared.clone()).collect();
        let shared_key = aggregate(&shared_keys)?;

        Ok(DkgOutput {
            public_key: PublicKey { rho: self.rho, t },
            shared_key,
            accepted_dealers: accepted.iter().map(|c| c.dealer_id).collect(),
        })
    }

    /// Session-bound digest binding a dealer's **entire** contribution for the
    /// round-1 commit.
    ///
    /// Binds the session (`rho`, threshold, validator count) and the dealer id
    /// so a commit cannot be replayed across sessions or reattributed to another
    /// dealer, then folds in *everything the round-2 accept predicates read*: the
    /// public value `t^(d)`, the full VSS reveal (share values **and**
    /// commitments, via [`SharedSecretKey::reveal_digest`]), and the
    /// well-formedness proofs ([`KeyProofs::digest`]). Because the commit pins the
    /// whole contribution, no distinct contribution shares its digest, so
    /// [`verify_fault`](Self::verify_fault) cannot be made to convict an honest
    /// dealer via a same-digest substitution. This is the value a dealer commits
    /// to in round 1 and that
    /// [`finalize_with_evidence`](Self::finalize_with_evidence) recomputes from
    /// the revealed contribution in round 2.
    pub fn contribution_digest(&self, contribution: &DealerContribution) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(COMMIT_DIGEST_LABEL);
        hasher.update(self.rho);
        hasher.update(self.threshold.to_be_bytes());
        hasher.update(self.total_nodes.to_be_bytes());
        hasher.update(contribution.dealer_id.to_be_bytes());
        for poly in &contribution.public_contribution {
            for coeff in poly.canonical().coeffs {
                hasher.update(coeff.to_be_bytes());
            }
        }
        hasher.update(contribution.shared.reveal_digest());
        hasher.update(contribution.proofs.digest());
        hasher.finalize().into()
    }

    /// Round 1: freeze the commit vector, rejecting duplicate dealer ids and
    /// returning the records sorted by dealer id.
    ///
    /// The returned order defines the deterministic participant order that
    /// [`finalize_with_evidence`](Self::finalize_with_evidence) processes, so the
    /// accepted set and fault list do not depend on reveal-message arrival order.
    pub fn collect_commitments(
        &self,
        commits: &[CommitRecord],
    ) -> Result<Vec<CommitRecord>, ThresholdError> {
        let mut sorted = commits.to_vec();
        sorted.sort_by_key(|record| record.dealer_id);
        if sorted
            .windows(2)
            .any(|pair| pair[0].dealer_id == pair[1].dealer_id)
        {
            return Err(ThresholdError::BackendUnavailable {
                reason: "duplicate dealer id in commits",
            });
        }
        Ok(sorted)
    }

    /// Round 2: open the commits, run the accept predicates, and emit public
    /// fault evidence for each committed dealer excluded by a *failed accept
    /// predicate* (commit mismatch, invalid share relation, or invalid commitment
    /// proof). Committed dealers that never reveal are silently excluded without
    /// evidence — see below.
    ///
    /// The commit vector fixes the participant set (in id order). For each
    /// committed dealer:
    /// - a **missing** reveal is a silent exclusion, *not* a fault — silence
    ///   cannot be forged into evidence against a dealer;
    /// - a reveal whose digest does not match the commit is a
    ///   [`DealerFaultClass::CommitMismatch`];
    /// - a mismatching share is a [`DealerFaultClass::InvalidShareRelation`];
    /// - a bad commitment proof is a [`DealerFaultClass::InvalidCommitmentProof`].
    ///
    /// Acceptance is deterministic in the id order fixed by round 1, so the joint
    /// key and evidence are independent of message arrival order. Requires at
    /// least one accepted dealer. Contributions for uncommitted dealer ids are
    /// ignored (they were never part of the round).
    pub fn finalize_with_evidence(
        &self,
        commits: &[CommitRecord],
        contributions: &[DealerContribution],
    ) -> Result<DkgFinalizeReport, ThresholdError> {
        let commit_set = self.collect_commitments(commits)?;

        let mut contribution_ids: Vec<u16> = contributions.iter().map(|c| c.dealer_id).collect();
        contribution_ids.sort_unstable();
        if contribution_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ThresholdError::BackendUnavailable {
                reason: "duplicate dealer id",
            });
        }

        let mut accepted: Vec<&DealerContribution> = Vec::new();
        let mut faults: Vec<DealerFault> = Vec::new();
        for record in &commit_set {
            let Some(contribution) = contributions
                .iter()
                .find(|c| c.dealer_id == record.dealer_id)
            else {
                // Missing reveal: exclusion only, never a fault.
                continue;
            };

            if self.contribution_digest(contribution) != record.digest {
                faults.push(DealerFault {
                    dealer_id: record.dealer_id,
                    class: DealerFaultClass::CommitMismatch,
                });
            } else if !contribution.shared.verify(&self.commit_key) {
                faults.push(DealerFault {
                    dealer_id: record.dealer_id,
                    class: DealerFaultClass::InvalidShareRelation,
                });
            } else if !contribution
                .shared
                .verify_commitment_proofs(&contribution.proofs, &self.commit_key)
            {
                faults.push(DealerFault {
                    dealer_id: record.dealer_id,
                    class: DealerFaultClass::InvalidCommitmentProof,
                });
            } else {
                accepted.push(contribution);
            }
        }

        if accepted.is_empty() {
            return Err(ThresholdError::BackendUnavailable {
                reason: "no accepted dealers",
            });
        }

        let output = self.build_output(&accepted)?;
        let accepted_ids: Vec<u16> = accepted.iter().map(|c| c.dealer_id).collect();
        let transcript_digest = self.transcript_digest(&commit_set, &faults, &accepted_ids);
        Ok(DkgFinalizeReport {
            output,
            faults,
            transcript_digest,
        })
    }

    /// Publicly re-check a fault against a dealer's committed digest and revealed
    /// contribution, using only public state.
    ///
    /// Returns `true` only when the fault genuinely holds for the contribution
    /// the dealer actually committed to. Every predicate-failure arm
    /// (`InvalidShareRelation`, `InvalidCommitmentProof`) is **guarded by the
    /// commit binding** — it first requires `contribution_digest(contribution) ==
    /// committed_digest`, mirroring the digest-first ordering
    /// [`finalize_with_evidence`](Self::finalize_with_evidence) uses to emit the
    /// fault. Since [`contribution_digest`](Self::contribution_digest) binds the
    /// *entire* contribution (shares, commitments, and proofs), this defeats
    /// framing by substitution: a party cannot present a different contribution
    /// (with corrupted shares, grafted proofs, or a foreign key) under an honest
    /// dealer's digest, because its digest will not match. For an honest dealer's
    /// own contribution the accept predicates pass, so no fault re-checks `true`.
    /// This depends on no private coordinator state, so any party holding the
    /// public transcript can run it.
    pub fn verify_fault(
        &self,
        fault: &DealerFault,
        contribution: &DealerContribution,
        committed_digest: &[u8; 32],
    ) -> bool {
        if contribution.dealer_id != fault.dealer_id {
            return false;
        }
        match fault.class {
            DealerFaultClass::CommitMismatch => {
                self.contribution_digest(contribution) != *committed_digest
            }
            DealerFaultClass::InvalidShareRelation => {
                self.contribution_digest(contribution) == *committed_digest
                    && !contribution.shared.verify(&self.commit_key)
            }
            DealerFaultClass::InvalidCommitmentProof => {
                self.contribution_digest(contribution) == *committed_digest
                    && !contribution
                        .shared
                        .verify_commitment_proofs(&contribution.proofs, &self.commit_key)
            }
        }
    }

    /// Digest binding a finalized round: the session parameters, the (sorted)
    /// commit vector, the (sorted) fault evidence, and the (sorted) accepted set.
    ///
    /// Two coordinators processing the same commits and reveals derive the same
    /// digest regardless of input order, so it is a canonical, order-independent
    /// fingerprint of the round outcome.
    pub fn transcript_digest(
        &self,
        commits: &[CommitRecord],
        faults: &[DealerFault],
        accepted: &[u16],
    ) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(TRANSCRIPT_DIGEST_LABEL);
        hasher.update(self.rho);
        hasher.update(self.threshold.to_be_bytes());
        hasher.update(self.total_nodes.to_be_bytes());

        let mut commits = commits.to_vec();
        commits.sort_by_key(|record| record.dealer_id);
        hasher.update((commits.len() as u64).to_be_bytes());
        for record in &commits {
            hasher.update(record.dealer_id.to_be_bytes());
            hasher.update(record.digest);
        }

        let mut faults = faults.to_vec();
        faults.sort_by_key(|fault| (fault.dealer_id, fault.class as u8));
        hasher.update((faults.len() as u64).to_be_bytes());
        for fault in &faults {
            hasher.update(fault.dealer_id.to_be_bytes());
            hasher.update([fault.class as u8]);
        }

        let mut accepted = accepted.to_vec();
        accepted.sort_unstable();
        hasher.update((accepted.len() as u64).to_be_bytes());
        for id in &accepted {
            hasher.update(id.to_be_bytes());
        }

        hasher.finalize().into()
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

    // --- Increment 5: committing round + public fault evidence ---

    /// A coordinator with two honest dealer contributions over a shared key.
    fn evidence_setup() -> (CommitmentKey, DkgCoordinator, Vec<DealerContribution>) {
        let commit_key = CommitmentKey::from_seed(b"public");
        let coordinator = DkgCoordinator::new([7u8; 32], 2, 3, commit_key.clone());
        let contributions = vec![
            coordinator.deal(0, &[70u8; 32]).unwrap(),
            coordinator.deal(1, &[71u8; 32]).unwrap(),
        ];
        (commit_key, coordinator, contributions)
    }

    /// Round-1 commit vector for a set of contributions under a coordinator.
    fn commits_for(
        coordinator: &DkgCoordinator,
        contributions: &[DealerContribution],
    ) -> Vec<CommitRecord> {
        contributions
            .iter()
            .map(|c| CommitRecord {
                dealer_id: c.dealer_id(),
                digest: coordinator.contribution_digest(c),
            })
            .collect()
    }

    #[test]
    fn evidence_happy_path_matches_finalize() {
        let (commit_key, coordinator, contributions) = evidence_setup();
        let commits = commits_for(&coordinator, &contributions);

        let report = coordinator
            .finalize_with_evidence(&commits, &contributions)
            .unwrap();

        assert!(report.faults.is_empty(), "no faults for honest dealers");
        assert_eq!(report.output.accepted_dealers, vec![0, 1]);
        assert!(report.output.shared_key.verify(&commit_key));

        // The evidence path produces the same joint key as the one-shot path.
        let base = coordinator.finalize(&contributions).unwrap();
        for (lhs, rhs) in report
            .output
            .public_key
            .t
            .iter()
            .zip(base.public_key.t.iter())
        {
            assert_eq!(lhs.canonical().coeffs, rhs.canonical().coeffs);
        }
    }

    #[test]
    fn evidence_acceptance_is_order_independent() {
        let (_commit_key, coordinator, contributions) = evidence_setup();
        let commits = commits_for(&coordinator, &contributions);

        let forward = coordinator
            .finalize_with_evidence(&commits, &contributions)
            .unwrap();

        let mut reversed_contributions = contributions.clone();
        reversed_contributions.reverse();
        let mut reversed_commits = commits.clone();
        reversed_commits.reverse();
        let backward = coordinator
            .finalize_with_evidence(&reversed_commits, &reversed_contributions)
            .unwrap();

        assert_eq!(forward.transcript_digest, backward.transcript_digest);
        assert_eq!(
            forward.output.accepted_dealers,
            backward.output.accepted_dealers
        );
        assert_eq!(forward.faults, backward.faults);
    }

    #[test]
    fn commit_binding_rejects_post_commit_change() {
        let (_commit_key, coordinator, contributions) = evidence_setup();
        // Commit to the original contributions, then reveal a *different*
        // contribution for dealer 1 (adaptive post-commit choice).
        let commits = commits_for(&coordinator, &contributions);
        let swapped = coordinator.deal(1, &[99u8; 32]).unwrap();
        let revealed = vec![contributions[0].clone(), swapped.clone()];

        let report = coordinator
            .finalize_with_evidence(&commits, &revealed)
            .unwrap();

        assert_eq!(report.output.accepted_dealers, vec![0]);
        assert_eq!(
            report.faults,
            vec![DealerFault {
                dealer_id: 1,
                class: DealerFaultClass::CommitMismatch,
            }]
        );
        // The fault re-checks against the committed digest and the revealed value.
        assert!(coordinator.verify_fault(&report.faults[0], &swapped, &commits[1].digest));
    }

    #[test]
    fn genuine_bad_share_yields_verifiable_fault() {
        let commit_key = CommitmentKey::from_seed(b"public");
        let coordinator = DkgCoordinator::new([8u8; 32], 2, 3, commit_key);
        let good = coordinator.deal(0, &[80u8; 32]).unwrap();

        // A dealer whose shares were committed under a different key: its reveal
        // matches its own commit digest (so no CommitMismatch), but the share
        // relation fails against the session key.
        let rogue = DkgCoordinator::new([8u8; 32], 2, 3, CommitmentKey::from_seed(b"other"));
        let bad = rogue.deal(1, &[81u8; 32]).unwrap();
        let bad_digest = coordinator.contribution_digest(&bad);

        let commits = vec![
            CommitRecord {
                dealer_id: 0,
                digest: coordinator.contribution_digest(&good),
            },
            CommitRecord {
                dealer_id: 1,
                digest: bad_digest,
            },
        ];
        let report = coordinator
            .finalize_with_evidence(&commits, &[good, bad.clone()])
            .unwrap();

        assert_eq!(report.output.accepted_dealers, vec![0]);
        assert_eq!(
            report.faults,
            vec![DealerFault {
                dealer_id: 1,
                class: DealerFaultClass::InvalidShareRelation,
            }]
        );
        assert!(coordinator.verify_fault(&report.faults[0], &bad, &bad_digest));
    }

    #[test]
    fn invalid_commitment_proof_yields_fault() {
        let (_commit_key, coordinator, contributions) = evidence_setup();
        // Keep dealer 1's shares (so the relation still verifies) but graft
        // dealer 0's proofs onto them: the opening proofs no longer match the
        // commitments. Since the commit digest binds the proofs, a *consistent*
        // commit-and-reveal of this tampered contribution (dealer honestly
        // commits to its own bad proofs) surfaces as an InvalidCommitmentProof
        // fault after the commit-open check passes.
        let mut tampered = contributions[1].clone();
        tampered.proofs = contributions[0].proofs.clone();
        assert_ne!(
            coordinator.contribution_digest(&tampered),
            coordinator.contribution_digest(&contributions[1]),
            "grafting proofs must change the commit digest (proofs are bound)"
        );

        let commits = vec![
            CommitRecord {
                dealer_id: 0,
                digest: coordinator.contribution_digest(&contributions[0]),
            },
            CommitRecord {
                dealer_id: 1,
                digest: coordinator.contribution_digest(&tampered),
            },
        ];
        let revealed = vec![contributions[0].clone(), tampered.clone()];
        let report = coordinator
            .finalize_with_evidence(&commits, &revealed)
            .unwrap();

        assert_eq!(report.output.accepted_dealers, vec![0]);
        assert_eq!(
            report.faults,
            vec![DealerFault {
                dealer_id: 1,
                class: DealerFaultClass::InvalidCommitmentProof,
            }]
        );
        assert!(coordinator.verify_fault(&report.faults[0], &tampered, &commits[1].digest));
    }

    #[test]
    fn anti_framing_forged_fault_against_honest_dealer_fails() {
        let (_commit_key, coordinator, contributions) = evidence_setup();
        let honest = &contributions[0];
        let honest_digest = coordinator.contribution_digest(honest);

        // No fabricated fault class re-checks true against an honest contribution.
        for class in [
            DealerFaultClass::CommitMismatch,
            DealerFaultClass::InvalidShareRelation,
            DealerFaultClass::InvalidCommitmentProof,
        ] {
            let forged = DealerFault {
                dealer_id: honest.dealer_id(),
                class,
            };
            assert!(
                !coordinator.verify_fault(&forged, honest, &honest_digest),
                "honest dealer must not be framable as {class:?}"
            );
        }

        // A fault whose id does not match the contribution is rejected outright.
        let wrong_id = DealerFault {
            dealer_id: honest.dealer_id() + 100,
            class: DealerFaultClass::InvalidShareRelation,
        };
        assert!(!coordinator.verify_fault(&wrong_id, honest, &honest_digest));
    }

    #[test]
    fn anti_framing_substituted_foreign_contribution_fails() {
        // An accuser tries to convict honest dealer 0 by substituting a
        // *different* contribution (dealt under a foreign key, so verify() and
        // verify_commitment_proofs() both fail) while presenting honest dealer
        // 0's real committed digest. The digest guard rejects the substitution.
        let (_commit_key, coordinator, contributions) = evidence_setup();
        let honest_digest = coordinator.contribution_digest(&contributions[0]);

        let rogue = DkgCoordinator::new([7u8; 32], 2, 3, CommitmentKey::from_seed(b"other"));
        let mut foreign = rogue.deal(1, &[123u8; 32]).unwrap();
        foreign.dealer_id = 0; // relabel to the honest dealer

        for class in [
            DealerFaultClass::InvalidShareRelation,
            DealerFaultClass::InvalidCommitmentProof,
        ] {
            let forged = DealerFault {
                dealer_id: 0,
                class,
            };
            assert!(
                !coordinator.verify_fault(&forged, &foreign, &honest_digest),
                "substituted foreign contribution must not frame dealer 0 as {class:?}"
            );
        }
    }

    #[test]
    fn anti_framing_same_commitment_bad_shares_fails() {
        // The subtle vector: keep honest dealer 0's *commitments* (so a digest
        // that bound only commitments would collide) but corrupt a share value so
        // verify() fails. Because contribution_digest binds the share values, the
        // corrupted contribution has a different digest and cannot frame dealer 0.
        let (_commit_key, coordinator, contributions) = evidence_setup();
        let honest_digest = coordinator.contribution_digest(&contributions[0]);

        let mut bad_shares = contributions[0].clone();
        bad_shares.shared = contributions[0].shared.with_corrupted_first_share();
        assert!(
            !bad_shares.shared.verify(&coordinator.commit_key),
            "corrupting a share must break the homomorphic relation"
        );
        assert_ne!(
            coordinator.contribution_digest(&bad_shares),
            honest_digest,
            "share values must be bound by the commit digest"
        );

        let forged = DealerFault {
            dealer_id: 0,
            class: DealerFaultClass::InvalidShareRelation,
        };
        assert!(
            !coordinator.verify_fault(&forged, &bad_shares, &honest_digest),
            "same-commitment corrupted-share substitution must not frame dealer 0"
        );
    }

    #[test]
    fn anti_framing_grafted_proofs_change_digest_and_fail() {
        // Keep honest dealer 1's shares and commitments but graft dealer 0's
        // proofs. Because the commit digest binds the proofs, the grafted
        // contribution has a different digest and cannot frame dealer 1.
        let (_commit_key, coordinator, contributions) = evidence_setup();
        let honest_digest = coordinator.contribution_digest(&contributions[1]);

        let mut grafted = contributions[1].clone();
        grafted.proofs = contributions[0].proofs.clone();
        assert!(
            !grafted
                .shared
                .verify_commitment_proofs(&grafted.proofs, &coordinator.commit_key),
            "grafted proofs must fail against dealer 1's commitments"
        );
        assert_ne!(
            coordinator.contribution_digest(&grafted),
            honest_digest,
            "proofs must be bound by the commit digest"
        );

        let forged = DealerFault {
            dealer_id: 1,
            class: DealerFaultClass::InvalidCommitmentProof,
        };
        assert!(
            !coordinator.verify_fault(&forged, &grafted, &honest_digest),
            "grafted-proof substitution must not frame dealer 1"
        );
    }

    #[test]
    fn verify_fault_uses_only_public_state() {
        let commit_key = CommitmentKey::from_seed(b"public");
        let coordinator = DkgCoordinator::new([9u8; 32], 2, 3, commit_key.clone());
        let rogue = DkgCoordinator::new([9u8; 32], 2, 3, CommitmentKey::from_seed(b"other"));
        let bad = rogue.deal(1, &[91u8; 32]).unwrap();
        let bad_digest = coordinator.contribution_digest(&bad);
        let fault = DealerFault {
            dealer_id: 1,
            class: DealerFaultClass::InvalidShareRelation,
        };

        // A fresh coordinator sharing only the public parameters re-checks the
        // fault — no private finalize state is required.
        let evaluator = DkgCoordinator::new([9u8; 32], 2, 3, commit_key);
        assert!(evaluator.verify_fault(&fault, &bad, &bad_digest));
    }

    #[test]
    fn missing_reveal_is_exclusion_not_fault() {
        let (_commit_key, coordinator, contributions) = evidence_setup();
        // Both dealers commit, but dealer 1 never reveals.
        let commits = commits_for(&coordinator, &contributions);
        let report = coordinator
            .finalize_with_evidence(&commits, &contributions[0..1])
            .unwrap();

        assert_eq!(report.output.accepted_dealers, vec![0]);
        assert!(
            report.faults.is_empty(),
            "a silent no-show is excluded, never recorded as a fault"
        );
    }

    #[test]
    fn transcript_digest_binds_outcome() {
        let (_commit_key, coordinator, contributions) = evidence_setup();
        let commits = commits_for(&coordinator, &contributions);

        let full = coordinator
            .finalize_with_evidence(&commits, &contributions)
            .unwrap();
        let partial = coordinator
            .finalize_with_evidence(&commits, &contributions[0..1])
            .unwrap();

        assert_ne!(full.transcript_digest, partial.transcript_digest);
    }

    #[test]
    fn finalize_with_evidence_rejects_duplicate_and_empty() {
        let (_commit_key, coordinator, contributions) = evidence_setup();
        let commits = commits_for(&coordinator, &contributions);

        // Duplicate commit ids are rejected at round 1.
        let dup_commits = vec![commits[0], commits[0]];
        assert!(coordinator
            .finalize_with_evidence(&dup_commits, &contributions)
            .is_err());

        // Duplicate revealed contribution ids are rejected.
        let dup_reveals = vec![contributions[0].clone(), contributions[0].clone()];
        assert!(coordinator
            .finalize_with_evidence(&commits, &dup_reveals)
            .is_err());

        // A committed dealer with no valid reveal leaves nothing to accept.
        assert!(coordinator
            .finalize_with_evidence(&[commits[0]], &[])
            .is_err());
    }

    #[test]
    fn dealer_fault_class_is_closed() {
        // Over-claim guard: only publicly re-checkable classes exist. Adding a
        // class (e.g. an unprovable `Equivocation`) forces this match to be
        // updated deliberately rather than shipped silently.
        fn discriminant(class: DealerFaultClass) -> u8 {
            match class {
                DealerFaultClass::CommitMismatch => 0,
                DealerFaultClass::InvalidShareRelation => 1,
                DealerFaultClass::InvalidCommitmentProof => 2,
            }
        }
        assert_eq!(discriminant(DealerFaultClass::CommitMismatch), 0);
        assert_eq!(discriminant(DealerFaultClass::InvalidShareRelation), 1);
        assert_eq!(discriminant(DealerFaultClass::InvalidCommitmentProof), 2);
    }
}
