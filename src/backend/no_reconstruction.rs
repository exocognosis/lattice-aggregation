//! Fail-closed committee signing contract that never reconstructs a signing key.
//!
//! The repository contains two real research components that can be composed
//! without invoking a seed- or key-reconstruction signing bridge:
//!
//! - the module-lattice multi-dealer DKG in [`crate::crypto::mldsa_dkg`]; and
//! - the commit/open distributed nonce round in
//!   [`crate::crypto::distributed_nonce`].
//!
//! This module wires those components into a type-state committee-of-eight
//! integration contract. It deliberately does **not** route through
//! `ThresholdMldsaEngine` or a provider signature: both
//! available standard-signature bridges reconstruct secret material. Instead,
//! [`Committee8Session<NonceReady>::try_standard_signature`] fails with a typed
//! [`NoReconstructionPrimitive`] identifying the first unavailable primitive.
//!
//! # Security and claim boundary
//!
//! This is executable integration scaffolding, not a threshold signature:
//!
//! - the current DKG is research-shaped, not byte-exact FIPS 204 key generation;
//! - DKG shares are cleartext inside the DKG implementation and are discarded
//!   by this session after public evidence is extracted;
//! - the nonce is an additive sum of uniform masks, not exact distributed
//!   `ExpandMask`, and therefore is not distribution-compatible with ML-DSA;
//! - no partial response, distributed rejection predicate, hint MPC, or wire
//!   signature is emitted;
//! - the in-process harness cannot establish real validator process isolation.
//!
//! The useful guarantee is narrower: a caller can exercise the genuine DKG and
//! nonce commit/open state transitions, but cannot accidentally receive a
//! centralized standard signature from this API.

use core::fmt;

use sha3::{Digest, Sha3_256};

use crate::{
    crypto::{
        bdlop::CommitmentKey,
        distributed_nonce::{self, NonceCommitment, NonceOpening},
        mldsa_dkg::{CommitRecord, DkgCoordinator},
        mldsa_module::PublicKey,
    },
    errors::ThresholdError,
    types::ThresholdSignature,
};

/// Number of validators in the first no-reconstruction integration committee.
pub const COMMITTEE8_SIZE: usize = 8;
/// Signing threshold for the committee-of-eight integration contract.
pub const COMMITTEE8_THRESHOLD: u16 = 6;
/// Independent dealers used by the bounded committee-of-eight integration
/// fixture. Two dealers are sufficient to exercise additive multi-dealer DKG;
/// production ceremonies may supply more.
pub const COMMITTEE8_MIN_DKG_DEALERS: usize = 2;

/// A primitive still required before the committee can emit a standard
/// ML-DSA-65 signature without reconstructing secret material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoReconstructionPrimitive {
    /// Byte-exact FIPS 204 `ExpandA`/`ExpandS`, `Power2Round`, and encoded public
    /// key generation performed over distributed key shares.
    Fips204ExactDistributedKeyGeneration,
    /// Per-receiver confidential share delivery and custody, wired into DKG so
    /// the coordinator never assembles all clear shares.
    PrivatePerReceiverShareCustody,
    /// Joint sampling exactly distributed as FIPS 204 `ExpandMask`, rather than
    /// the incompatible additive sum implemented by the research nonce round.
    ExactDistributedExpandMask,
    /// FIPS-exact challenge, `s2`/`t0` rejection predicates, hint construction,
    /// and retry processing over private shares.
    DistributedRejectionAndHintMpc,
    /// Packing `c_tilde || z || h` from genuine partial results, without first
    /// creating a centralized provider/self-contained signature.
    StandardWireSignatureFromPartials,
}

impl NoReconstructionPrimitive {
    /// Stable machine-readable identifier for evidence and tests.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fips204ExactDistributedKeyGeneration => {
                "fips204_exact_distributed_key_generation"
            }
            Self::PrivatePerReceiverShareCustody => "private_per_receiver_share_custody",
            Self::ExactDistributedExpandMask => "exact_distributed_expand_mask",
            Self::DistributedRejectionAndHintMpc => "distributed_rejection_and_hint_mpc",
            Self::StandardWireSignatureFromPartials => "standard_wire_signature_from_partials",
        }
    }
}

impl fmt::Display for NoReconstructionPrimitive {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Error surfaced by the no-reconstruction committee integration contract.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NoReconstructionError {
    /// A real research component rejected the supplied protocol input.
    #[error(transparent)]
    Threshold(#[from] ThresholdError),
    /// The committee DKG did not accept every expected dealer.
    #[error("committee-8 DKG accepted {accepted} dealers; expected {expected}")]
    IncompleteDkg {
        /// Number of accepted dealer contributions.
        accepted: usize,
        /// Required number of accepted dealer contributions.
        expected: usize,
    },
    /// One or more nonce openings did not match the committed round.
    #[error("committee-8 distributed nonce opening verification failed")]
    NonceOpeningVerificationFailed,
    /// A message was changed after the nonce challenge was finalized.
    #[error("committee-8 signing message does not match the nonce transcript")]
    MessageMismatch,
    /// Standard signature generation stopped at an unavailable primitive.
    #[error("standard ML-DSA signature unavailable without reconstruction: missing {primitive}")]
    MissingPrimitive {
        /// First unavailable primitive in protocol execution order.
        primitive: NoReconstructionPrimitive,
    },
}

/// Honest status of the components used by the committee-of-eight path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoReconstructionCapabilities {
    /// Multi-dealer module-lattice DKG with VSS verification ran successfully.
    pub research_module_dkg_vss: bool,
    /// DKG commit/reveal and public fault-evidence processing ran successfully.
    pub dkg_fault_evidence: bool,
    /// Distributed nonce commit/open verification ran successfully.
    pub distributed_nonce_commit_open: bool,
    /// This API never called a secret/seed reconstruction operation.
    pub reconstruction_signing_bridge_used: bool,
    /// The research DKG emitted a byte-exact standard ML-DSA public key.
    pub fips204_exact_distributed_key: bool,
    /// Clear DKG shares remained only in their receiver's custody.
    pub private_per_receiver_share_custody: bool,
    /// The joint nonce was distributed exactly as standard `ExpandMask`.
    pub exact_distributed_expand_mask: bool,
    /// Rejection predicates and hints were computed over private shares.
    pub distributed_rejection_and_hints: bool,
    /// A standard-verifier-compatible signature was emitted from partials.
    pub standard_wire_signature_from_partials: bool,
}

impl NoReconstructionCapabilities {
    /// Missing primitives in protocol execution order.
    pub const MISSING_PRIMITIVES: [NoReconstructionPrimitive; 5] = [
        NoReconstructionPrimitive::Fips204ExactDistributedKeyGeneration,
        NoReconstructionPrimitive::PrivatePerReceiverShareCustody,
        NoReconstructionPrimitive::ExactDistributedExpandMask,
        NoReconstructionPrimitive::DistributedRejectionAndHintMpc,
        NoReconstructionPrimitive::StandardWireSignatureFromPartials,
    ];

    /// Capability state after the real DKG and nonce rounds have completed.
    pub const fn current() -> Self {
        Self {
            research_module_dkg_vss: true,
            dkg_fault_evidence: true,
            distributed_nonce_commit_open: true,
            reconstruction_signing_bridge_used: false,
            fips204_exact_distributed_key: false,
            private_per_receiver_share_custody: false,
            exact_distributed_expand_mask: false,
            distributed_rejection_and_hints: false,
            standard_wire_signature_from_partials: false,
        }
    }

    /// All unavailable primitives, ordered by the point at which the complete
    /// FIPS 204 protocol first needs them.
    pub const fn missing_primitives(self) -> &'static [NoReconstructionPrimitive] {
        &Self::MISSING_PRIMITIVES
    }

    /// First primitive that prevents a standard signature from being emitted.
    pub const fn first_missing(self) -> NoReconstructionPrimitive {
        Self::MISSING_PRIMITIVES[0]
    }
}

/// Initial type state before DKG.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Uninitialized;

/// Type state after the research DKG has completed and all clear share-bearing
/// objects have been dropped from the session.
#[derive(Debug, Eq, PartialEq)]
pub struct DkgReady {
    rho: [u8; 32],
    public_key_digest: [u8; 32],
    transcript_digest: [u8; 32],
    accepted_dealers: Vec<u16>,
}

/// Type state after exactly eight public nonce commitments were recorded.
#[derive(Debug)]
pub struct NonceCommitted {
    dkg: DkgReady,
    commitments: [NonceCommitment; COMMITTEE8_SIZE],
}

/// Type state after every nonce opening was verified and a joint challenge was
/// derived. It contains public evidence only, not signer masks or DKG shares.
#[derive(Debug, Eq, PartialEq)]
pub struct NonceReady {
    dkg: DkgReady,
    challenge_seed: [u8; 32],
    joint_nonce_digest: [u8; 32],
    message_digest: [u8; 32],
}

/// Type-state committee-of-eight no-reconstruction session.
#[derive(Debug)]
pub struct Committee8Session<State> {
    state: State,
}

impl Committee8Session<Uninitialized> {
    /// Create a session that has not run DKG.
    pub const fn new() -> Self {
        Self {
            state: Uninitialized,
        }
    }

    /// Execute the genuine multi-dealer research DKG for eight validators.
    ///
    /// Every supplied dealer contributes independently; at least two are
    /// required so this cannot silently collapse to a single-dealer setup. The
    /// method validates the commit/reveal evidence, extracts only public
    /// evidence, and drops the share-bearing DKG output before returning. It
    /// never invokes `SharedSecretKey::reconstruct`.
    pub fn run_dkg(
        self,
        rho: [u8; 32],
        commitment_key_seed: &[u8],
        dealer_seeds: &[[u8; 32]],
    ) -> Result<Committee8Session<DkgReady>, NoReconstructionError> {
        if dealer_seeds.len() < COMMITTEE8_MIN_DKG_DEALERS {
            return Err(ThresholdError::BackendUnavailable {
                reason: "committee-8 DKG requires at least two independent dealers",
            }
            .into());
        }
        let commitment_key = CommitmentKey::from_seed(commitment_key_seed);
        let coordinator = DkgCoordinator::new(
            rho,
            COMMITTEE8_THRESHOLD,
            COMMITTEE8_SIZE as u16,
            commitment_key.clone(),
        );

        let mut contributions = Vec::with_capacity(dealer_seeds.len());
        for (dealer_id, dealer_seed) in dealer_seeds.iter().enumerate() {
            contributions.push(coordinator.deal(dealer_id as u16, dealer_seed)?);
        }
        let commits: Vec<CommitRecord> = contributions
            .iter()
            .map(|contribution| CommitRecord {
                dealer_id: contribution.dealer_id(),
                digest: coordinator.contribution_digest(contribution),
            })
            .collect();
        let report = coordinator.finalize_with_evidence(&commits, &contributions)?;
        if report.output.accepted_dealers.len() != dealer_seeds.len() {
            return Err(NoReconstructionError::IncompleteDkg {
                accepted: report.output.accepted_dealers.len(),
                expected: dealer_seeds.len(),
            });
        }
        if !report.faults.is_empty() || !report.output.shared_key.verify(&commitment_key) {
            return Err(NoReconstructionError::IncompleteDkg {
                accepted: report.output.accepted_dealers.len(),
                expected: dealer_seeds.len(),
            });
        }

        let dkg = DkgReady {
            rho,
            public_key_digest: research_public_key_digest(&report.output.public_key),
            transcript_digest: report.transcript_digest,
            accepted_dealers: report.output.accepted_dealers.clone(),
        };
        // `report`, `contributions`, and the coordinator drop here. In
        // particular, no share-bearing object is retained in the returned state.
        Ok(Committee8Session { state: dkg })
    }
}

impl Default for Committee8Session<Uninitialized> {
    fn default() -> Self {
        Self::new()
    }
}

impl Committee8Session<DkgReady> {
    /// Public matrix seed used by the research DKG/nonce components.
    pub const fn rho(&self) -> &[u8; 32] {
        &self.state.rho
    }

    /// Digest of the research public key `(rho, t)`.
    pub const fn public_key_digest(&self) -> &[u8; 32] {
        &self.state.public_key_digest
    }

    /// Digest binding the accepted DKG commit/reveal transcript.
    pub const fn dkg_transcript_digest(&self) -> &[u8; 32] {
        &self.state.transcript_digest
    }

    /// Accepted dealer ids, canonically ordered.
    pub fn accepted_dealers(&self) -> &[u16] {
        &self.state.accepted_dealers
    }

    /// Record exactly one public nonce commitment from each committee member.
    /// Secret [`distributed_nonce::SignerNonceState`] values stay with callers.
    pub fn record_nonce_commitments(
        self,
        commitments: [NonceCommitment; COMMITTEE8_SIZE],
    ) -> Committee8Session<NonceCommitted> {
        Committee8Session {
            state: NonceCommitted {
                dkg: self.state,
                commitments,
            },
        }
    }
}

impl Committee8Session<NonceCommitted> {
    /// Verify all eight nonce openings and finalize the public joint challenge.
    ///
    /// The returned state keeps only public digests. It intentionally discards
    /// the openings and never accepts signer masks.
    pub fn verify_nonce_openings(
        self,
        openings: [NonceOpening; COMMITTEE8_SIZE],
        message: &[u8],
    ) -> Result<Committee8Session<NonceReady>, NoReconstructionError> {
        let joint = distributed_nonce::finalize(&self.state.commitments, &openings, message)
            .ok_or(NoReconstructionError::NonceOpeningVerificationFailed)?;
        let joint_nonce_digest = joint_nonce_digest(&joint.w, &joint.w1, &joint.challenge_seed);
        Ok(Committee8Session {
            state: NonceReady {
                dkg: self.state.dkg,
                challenge_seed: joint.challenge_seed,
                joint_nonce_digest,
                message_digest: Sha3_256::digest(message).into(),
            },
        })
    }
}

impl Committee8Session<NonceReady> {
    /// Public challenge seed derived after the eight commit/open checks.
    pub const fn challenge_seed(&self) -> &[u8; 32] {
        &self.state.challenge_seed
    }

    /// Digest of the public joint nonce and challenge material.
    pub const fn joint_nonce_digest(&self) -> &[u8; 32] {
        &self.state.joint_nonce_digest
    }

    /// Honest capability status for this integration path.
    pub const fn capabilities(&self) -> NoReconstructionCapabilities {
        NoReconstructionCapabilities::current()
    }

    /// Attempt to emit a standard ML-DSA-65 signature without reconstruction.
    ///
    /// This is the executable acceptance contract for the committee path. It
    /// currently always fails closed at the first unavailable primitive. Future
    /// implementations must advance the typed primitive list as real protocol
    /// stages land; they must never satisfy this method by calling a provider or
    /// reconstructing seed/key material.
    pub fn try_standard_signature(
        self,
        message: &[u8],
    ) -> Result<ThresholdSignature, NoReconstructionError> {
        let message_digest: [u8; 32] = Sha3_256::digest(message).into();
        if self.state.message_digest != message_digest {
            return Err(NoReconstructionError::MessageMismatch);
        }
        Err(NoReconstructionError::MissingPrimitive {
            primitive: self.capabilities().first_missing(),
        })
    }

    /// Public DKG transcript digest retained across the nonce phases.
    pub const fn dkg_transcript_digest(&self) -> &[u8; 32] {
        &self.state.dkg.transcript_digest
    }
}

fn research_public_key_digest(public_key: &PublicKey) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation/committee8/research-public-key/v1");
    hasher.update(public_key.rho);
    for poly in &public_key.t {
        for coefficient in poly.canonical().coeffs {
            hasher.update(coefficient.to_be_bytes());
        }
    }
    hasher.finalize().into()
}

fn joint_nonce_digest(
    w: &[crate::low_level::poly::Poly],
    w1: &[crate::low_level::poly::Poly],
    challenge_seed: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation/committee8/joint-nonce/v1");
    for poly in w.iter().chain(w1.iter()) {
        for coefficient in poly.canonical().coeffs {
            hasher.update(coefficient.to_be_bytes());
        }
    }
    hasher.update(challenge_seed);
    hasher.finalize().into()
}
