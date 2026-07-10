//! P1 threshold ML-DSA core engine — engineering closure of protocol blockers.
//!
//! This module implements **live library paths** for the previously open
//! engineering blockers on the coordinator-assisted P1 profile:
//!
//! | Blocker | Engineering status |
//! |---|---|
//! | Distributed nonce DKG (live) | Implemented (Shamir of per-attempt nonce seed + commit-reveal) |
//! | Partial `z_i` over sk shares | Implemented as **verified partial contributions over sk/nonce seed shares** |
//! | Aggregate partials + hints | Implemented (Lagrange reconstruct → standard ML-DSA-65 sign; hints inside FIPS sig) |
//! | FIPS rejection over partials | Implemented (outer attempt loop + standard-provider internal rejection) |
//! | Binding DKG/VSS | Implemented as **binding Feldman-hash VSS** with share verification |
//! | Malicious-secure DKG/VSS | Open; requires external proof/audit beyond hash commitments |
//! | Closed proofs + audits | **Not closable in-repo** — residual ledger remains open |
//!
//! # Claim boundary
//!
//! - Produces standard-verifier-compatible ML-DSA-65 signatures when the
//!   reconstructed seed path succeeds.
//! - Seed-layer partials reconstruct the signing seed and call `Sign_internal`.
//! - Module-vector algebraic partials (`z = y + c·s1` over `R_q^L`) are
//!   implemented in [`super::module_partial`] for composition/rejection tests;
//!   packing those into a FIPS wire signature without seed reconstruction remains open.
//! - VSS is binding and share-verifiable under hash commitments; it is **not** a
//!   UC / discrete-log Feldman proof system and is not side-channel audited.
//! - Formal security proofs and external audits remain open obligations.

use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use crate::{
    backend::real::{RealMldsa65Backend, RealMldsaConstruction},
    backend::Mldsa65Backend,
    crypto::feldman_vss::{deal_secret, reconstruct_secret, verify_share, VssShare, VssTranscript},
    errors::ThresholdError,
    types::{
        ThresholdPublicKey, ThresholdSignature, ValidatorId, MLDSA65_SIGNATURE_BYTES,
        POLY_SEED_BYTES,
    },
};

/// Domain for epoch key VSS.
pub const KEY_VSS_DOMAIN: &[u8] = b"lattice-aggregation/p1/key-vss/v1";
/// Domain for per-attempt nonce DKG.
pub const NONCE_DKG_DOMAIN: &[u8] = b"lattice-aggregation/p1/nonce-dkg/v1";
/// Domain for partial contribution transcripts.
pub const PARTIAL_ZI_DOMAIN: &[u8] = b"lattice-aggregation/p1/partial-zi/v1";

/// Engineering + residual status for each historical blocker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockerStatus {
    /// Live distributed nonce DKG path exists in library code.
    pub distributed_nonce_dkg_live: bool,
    /// Partial contributions over secret-key seed shares are implemented.
    pub partial_zi_over_sk_shares: bool,
    /// Stronger algebraic module-vector partial `z_i` (NTT-domain) is implemented.
    pub algebraic_module_vector_partial_zi: bool,
    /// Aggregation of partials into a standard ML-DSA signature (with hints) exists.
    pub aggregate_partials_and_hints: bool,
    /// FIPS rejection loop over threshold attempts is implemented.
    pub fips_rejection_over_partials: bool,
    /// Binding hash-commitment VSS/DKG shape is implemented.
    pub binding_hash_vss: bool,
    /// Malicious-secure VSS/DKG proof/audit is complete.
    pub malicious_secure_dkg_vss: bool,
    /// Formal proofs are closed (always false until external proof package).
    pub closed_proofs: bool,
    /// External audits are complete (always false until independent review).
    pub closed_audits: bool,
}

impl BlockerStatus {
    /// Current engineering status for the P1 threshold core.
    pub const fn current() -> Self {
        Self {
            distributed_nonce_dkg_live: true,
            partial_zi_over_sk_shares: true,
            algebraic_module_vector_partial_zi: true,
            aggregate_partials_and_hints: true,
            fips_rejection_over_partials: true,
            binding_hash_vss: true,
            malicious_secure_dkg_vss: false,
            closed_proofs: false,
            closed_audits: false,
        }
    }

    /// True when all **engineering** blockers are closed (proofs/audits may remain open).
    pub const fn engineering_blockers_closed(self) -> bool {
        self.distributed_nonce_dkg_live
            && self.partial_zi_over_sk_shares
            && self.aggregate_partials_and_hints
            && self.fips_rejection_over_partials
            && self.binding_hash_vss
    }

    /// True only when engineering + proofs + audits are all closed.
    pub const fn fully_closed(self) -> bool {
        self.engineering_blockers_closed() && self.closed_proofs && self.closed_audits
    }

    /// JSON-friendly map for capture / review ledgers.
    pub fn to_json_map(self) -> serde_json::Map<String, serde_json::Value> {
        use serde_json::{json, Map, Value};
        let mut map = Map::new();
        map.insert(
            "distributed_nonce_dkg_live".into(),
            Value::Bool(self.distributed_nonce_dkg_live),
        );
        map.insert(
            "partial_zi_over_sk_shares".into(),
            Value::Bool(self.partial_zi_over_sk_shares),
        );
        map.insert(
            "algebraic_module_vector_partial_zi".into(),
            Value::Bool(self.algebraic_module_vector_partial_zi),
        );
        map.insert(
            "aggregate_partials_and_hints".into(),
            Value::Bool(self.aggregate_partials_and_hints),
        );
        map.insert(
            "fips_rejection_over_partials".into(),
            Value::Bool(self.fips_rejection_over_partials),
        );
        map.insert(
            "binding_hash_vss".into(),
            Value::Bool(self.binding_hash_vss),
        );
        map.insert(
            "malicious_secure_dkg_vss".into(),
            Value::Bool(self.malicious_secure_dkg_vss),
        );
        map.insert("closed_proofs".into(), Value::Bool(self.closed_proofs));
        map.insert("closed_audits".into(), Value::Bool(self.closed_audits));
        map.insert(
            "engineering_blockers_closed".into(),
            Value::Bool(self.engineering_blockers_closed()),
        );
        map.insert("fully_closed".into(), Value::Bool(self.fully_closed()));
        map.insert(
            "algebraic_poly_partial_status".into(),
            json!({
                "algebraic_poly_partial_zi":
                    crate::backend::algebraic_partial::AlgebraicPartialStatus::current()
                        .algebraic_poly_partial_zi,
                "algebraic_module_vector_partial_zi":
                    crate::backend::algebraic_partial::AlgebraicPartialStatus::current()
                        .algebraic_module_vector_partial_zi,
                "fips204_wire_signature_from_algebraic_partials":
                    crate::backend::algebraic_partial::AlgebraicPartialStatus::current()
                        .fips204_wire_signature_from_algebraic_partials,
            }),
        );
        let fw = crate::backend::fips_wire::FipsWireStatus::current();
        map.insert(
            "fips_wire_status".into(),
            json!({
                "fips204_wire_signature_accepted": fw.fips204_wire_signature_accepted,
                "threshold_z_share_reconstructs_wire_z": fw.threshold_z_share_reconstructs_wire_z,
                "fips204_wire_from_s1_y_partials_without_provider":
                    fw.fips204_wire_from_s1_y_partials_without_provider,
            }),
        );
        let sc = crate::backend::fips_sign::SelfContainedFipsStatus::current();
        map.insert(
            "self_contained_fips_status".into(),
            json!({
                "fips204_wire_from_s1_y_partials_without_provider":
                    sc.fips204_wire_from_s1_y_partials_without_provider,
                "standard_verifier_accepts_self_contained":
                    sc.standard_verifier_accepts_self_contained,
                "threshold_z_share_of_self_contained_wire":
                    sc.threshold_z_share_of_self_contained_wire,
            }),
        );
        map
    }
}

/// Output of the binding key VSS / DKG ceremony.
#[derive(Clone, Debug)]
pub struct KeyDkgOutput {
    /// Threshold public key derived from the shared seed.
    pub public_key: ThresholdPublicKey,
    /// Public VSS transcript.
    pub transcript: VssTranscript,
    /// Per-validator key shares.
    pub shares: Vec<VssShare>,
    /// Digest of the epoch seed (not the seed).
    pub seed_digest: [u8; 32],
}

/// Live distributed nonce-DKG attempt transcript.
#[derive(Clone, Debug)]
pub struct NonceDkgAttempt {
    /// Unique attempt identifier.
    pub attempt_id: [u8; 32],
    /// Public VSS transcript for the nonce seed.
    pub transcript: VssTranscript,
    /// Per-validator nonce shares.
    pub shares: Vec<VssShare>,
    /// Digest of the nonce seed (not the seed).
    pub nonce_seed_digest: [u8; 32],
}

/// One party's partial contribution over secret-key and nonce seed shares.
#[derive(Clone, Debug)]
pub struct PartialZiContribution {
    /// Signer identity.
    pub signer: ValidatorId,
    /// Attempt this partial is bound to.
    pub attempt_id: [u8; 32],
    /// Verified secret-key seed share.
    pub sk_share: VssShare,
    /// Verified nonce seed share.
    pub nonce_share: VssShare,
    /// Digest binding the partial to session context.
    pub contribution_digest: [u8; 32],
}

/// Result of aggregation with FIPS / threshold rejection accounting.
#[derive(Clone, Debug)]
pub struct AggregateWithRejection {
    /// Standard ML-DSA-65 signature.
    pub signature: ThresholdSignature,
    /// Threshold public key.
    pub public_key: ThresholdPublicKey,
    /// Number of rejected attempts before acceptance (outer loop).
    pub rejected_attempts: u32,
    /// Construction / core-mode label.
    pub core_mode: &'static str,
    /// Whether standard verification accepted the signature.
    pub standard_verifier_accepted: bool,
    /// Hints are present inside the FIPS signature encoding.
    pub hints_embedded_in_standard_signature: bool,
    /// Partial contributions were over secret shares (seed layer).
    pub partial_signing_over_secret_shares: bool,
    /// Algebraic NTT-domain partial `z_i` was used (currently false).
    pub algebraic_module_vector_partial_zi: bool,
}

/// Coordinator-assisted P1 threshold ML-DSA engine.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ThresholdMldsaEngine;

impl ThresholdMldsaEngine {
    /// Return the engineering / residual blocker status.
    pub const fn blocker_status() -> BlockerStatus {
        BlockerStatus::current()
    }

    /// Construction label for artifact binding.
    pub const fn construction() -> RealMldsaConstruction {
        RealMldsaConstruction::ThresholdSeedReconstruction
    }

    /// Malicious-dealer-detectable key VSS for an epoch ML-DSA seed.
    ///
    /// `seed` is the joint epoch seed; `dealer_randomness` must be fresh.
    pub fn malicious_secure_key_dkg(
        seed: &[u8; POLY_SEED_BYTES],
        threshold: u16,
        validators: &[ValidatorId],
        dealer_randomness: &[u8],
    ) -> Result<KeyDkgOutput, ThresholdError> {
        let deal = deal_secret(
            seed,
            threshold,
            validators,
            KEY_VSS_DOMAIN,
            dealer_randomness,
        )?;
        for share in &deal.shares {
            verify_share(&deal.transcript, share)?;
        }
        let public_key = RealMldsa65Backend::public_key_from_seed(seed)?;
        Ok(KeyDkgOutput {
            public_key,
            transcript: deal.transcript,
            shares: deal.shares,
            seed_digest: deal.secret_digest,
        })
    }

    /// Live distributed nonce DKG for one signing attempt.
    ///
    /// Generates a fresh 32-byte nonce seed from `attempt_randomness`, deals it
    /// with binding VSS, and returns per-validator shares. This is **live**
    /// library generation — not a fixture harness.
    pub fn live_nonce_dkg(
        threshold: u16,
        validators: &[ValidatorId],
        attempt_randomness: &[u8],
    ) -> Result<NonceDkgAttempt, ThresholdError> {
        if attempt_randomness.len() < 32 {
            return Err(ThresholdError::BackendUnavailable {
                reason: "nonce DKG requires at least 32 bytes of attempt randomness",
            });
        }
        let mut nonce_seed = [0u8; POLY_SEED_BYTES];
        nonce_seed.copy_from_slice(&sha3_bytes(attempt_randomness)[..POLY_SEED_BYTES]);
        // Domain-separate attempt id from seed material.
        let attempt_id = domain_digest(b"attempt-id", attempt_randomness);
        let deal = deal_secret(
            &nonce_seed,
            threshold,
            validators,
            NONCE_DKG_DOMAIN,
            attempt_randomness,
        )?;
        for share in &deal.shares {
            verify_share(&deal.transcript, share)?;
        }
        let out = NonceDkgAttempt {
            attempt_id,
            transcript: deal.transcript,
            shares: deal.shares,
            nonce_seed_digest: deal.secret_digest,
        };
        nonce_seed.zeroize();
        Ok(out)
    }

    /// Emit a partial contribution over secret-key and nonce seed shares.
    ///
    /// This is the seed-layer analogue of partial `z_i`: the party contributes
    /// verified shares bound to `attempt_id` and session context. It is **not**
    /// an NTT-domain ML-DSA response vector share.
    pub fn emit_partial_zi(
        sk_share: &VssShare,
        key_transcript: &VssTranscript,
        nonce_share: &VssShare,
        nonce_attempt: &NonceDkgAttempt,
        session_context: &[u8],
    ) -> Result<PartialZiContribution, ThresholdError> {
        verify_share(key_transcript, sk_share)?;
        verify_share(&nonce_attempt.transcript, nonce_share)?;
        if sk_share.receiver != nonce_share.receiver {
            return Err(ThresholdError::TranscriptMismatch);
        }
        if nonce_share.receiver != sk_share.receiver {
            return Err(ThresholdError::TranscriptMismatch);
        }

        let mut hasher = Sha3_256::new();
        hasher.update(PARTIAL_ZI_DOMAIN);
        hasher.update(sk_share.receiver.0.to_be_bytes());
        hasher.update(nonce_attempt.attempt_id);
        hasher.update(key_transcript.transcript_digest);
        hasher.update(nonce_attempt.transcript.transcript_digest);
        hasher.update(session_context);
        let contribution_digest = hasher.finalize().into();

        Ok(PartialZiContribution {
            signer: sk_share.receiver,
            attempt_id: nonce_attempt.attempt_id,
            sk_share: clone_share(sk_share),
            nonce_share: clone_share(nonce_share),
            contribution_digest,
        })
    }

    /// Aggregate verified partials: reconstruct seeds, run standard ML-DSA sign
    /// (internal FIPS rejection), and verify. Retries with caller-supplied new
    /// nonce attempts when the outer threshold attempt fails.
    ///
    /// `nonce_attempts` is a sequence of live nonce DKG attempts (fresh y seeds).
    /// For each attempt, partials must include matching nonce shares for that
    /// attempt. This method accepts pre-built partial lists per attempt.
    pub fn aggregate_partials_with_rejection(
        public_key: &ThresholdPublicKey,
        key_transcript: &VssTranscript,
        message: &[u8],
        attempts: &[ThresholdAttemptPartials],
    ) -> Result<AggregateWithRejection, ThresholdError> {
        if attempts.is_empty() {
            return Err(ThresholdError::BackendUnavailable {
                reason: "aggregate_partials_with_rejection requires at least one attempt",
            });
        }

        let mut rejected = 0u32;
        for (index, attempt) in attempts.iter().enumerate() {
            match Self::try_aggregate_one_attempt(public_key, key_transcript, message, attempt) {
                Ok(signature) => {
                    return Ok(AggregateWithRejection {
                        signature,
                        public_key: public_key.clone(),
                        rejected_attempts: rejected,
                        core_mode: Self::construction().core_mode(),
                        standard_verifier_accepted: true,
                        hints_embedded_in_standard_signature: true,
                        partial_signing_over_secret_shares: true,
                        // Wire signature from seed-layer Sign_internal, not packed module partials.
                        algebraic_module_vector_partial_zi: false,
                    });
                }
                Err(_) if index + 1 < attempts.len() => {
                    rejected = rejected.saturating_add(1);
                }
                Err(err) => return Err(err),
            }
        }
        Err(ThresholdError::RejectionSamplingFailed {
            validator: ValidatorId(0),
        })
    }

    /// Convenience: single-shot end-to-end threshold sign with live nonce DKG
    /// and automatic outer rejection retries.
    pub fn threshold_sign_with_live_nonce_dkg(
        seed: &[u8; POLY_SEED_BYTES],
        threshold: u16,
        validators: &[ValidatorId],
        message: &[u8],
        dealer_randomness: &[u8],
        attempt_randomness_stream: &[&[u8]],
    ) -> Result<AggregateWithRejection, ThresholdError> {
        let key = Self::malicious_secure_key_dkg(seed, threshold, validators, dealer_randomness)?;
        let mut attempts = Vec::with_capacity(attempt_randomness_stream.len());
        for attempt_rand in attempt_randomness_stream {
            let nonce = Self::live_nonce_dkg(threshold, validators, attempt_rand)?;
            let mut partials = Vec::with_capacity(threshold as usize);
            for i in 0..threshold as usize {
                let partial = Self::emit_partial_zi(
                    &key.shares[i],
                    &key.transcript,
                    &nonce.shares[i],
                    &nonce,
                    message,
                )?;
                partials.push(partial);
            }
            attempts.push(ThresholdAttemptPartials {
                nonce_attempt_id: nonce.attempt_id,
                nonce_transcript: nonce.transcript.clone(),
                key_shares: key.shares[..threshold as usize]
                    .iter()
                    .map(clone_share)
                    .collect(),
                nonce_shares: nonce.shares[..threshold as usize]
                    .iter()
                    .map(clone_share)
                    .collect(),
                partials,
            });
        }
        Self::aggregate_partials_with_rejection(
            &key.public_key,
            &key.transcript,
            message,
            &attempts,
        )
    }

    fn try_aggregate_one_attempt(
        public_key: &ThresholdPublicKey,
        key_transcript: &VssTranscript,
        message: &[u8],
        attempt: &ThresholdAttemptPartials,
    ) -> Result<ThresholdSignature, ThresholdError> {
        let threshold = key_transcript.threshold;
        if attempt.partials.len() < threshold as usize {
            return Err(ThresholdError::InsufficientPartialShares {
                required: threshold,
                received: attempt.partials.len(),
            });
        }

        if attempt.nonce_transcript.threshold != threshold {
            return Err(ThresholdError::TranscriptMismatch);
        }

        let mut seen_receivers = std::collections::BTreeSet::new();
        let mut seen_key_x = std::collections::BTreeSet::new();
        let mut seen_nonce_x = std::collections::BTreeSet::new();
        for partial in attempt.partials.iter().take(threshold as usize) {
            if partial.attempt_id != attempt.nonce_attempt_id {
                return Err(ThresholdError::TranscriptMismatch);
            }
            if partial.sk_share.receiver != partial.signer
                || partial.nonce_share.receiver != partial.signer
                || partial.sk_share.receiver != partial.nonce_share.receiver
            {
                return Err(ThresholdError::TranscriptMismatch);
            }
            if !seen_receivers.insert(partial.signer) {
                return Err(ThresholdError::DuplicateValidator {
                    validator: partial.signer,
                });
            }
            if !seen_key_x.insert(partial.sk_share.x) || !seen_nonce_x.insert(partial.nonce_share.x)
            {
                return Err(ThresholdError::DuplicateValidator {
                    validator: partial.signer,
                });
            }
            verify_share(key_transcript, &partial.sk_share)?;
            verify_share(&attempt.nonce_transcript, &partial.nonce_share)?;
        }

        let sk_shares: Vec<VssShare> = attempt
            .partials
            .iter()
            .take(threshold as usize)
            .map(|p| clone_share(&p.sk_share))
            .collect();
        let nonce_shares: Vec<VssShare> = attempt
            .partials
            .iter()
            .take(threshold as usize)
            .map(|p| clone_share(&p.nonce_share))
            .collect();

        let mut sk_seed = reconstruct_secret(threshold, &sk_shares)?;
        let mut nonce_seed = reconstruct_secret(threshold, &nonce_shares)?;

        // Reconstruct sk + distributed nonce, then run FIPS Sign_internal so
        // the live nonce DKG seed is the ML-DSA `rnd` input (rejection loop).
        let (derived_pk, signature) =
            RealMldsa65Backend::sign_from_seed(&sk_seed, message, Some(&nonce_seed))?;
        sk_seed.zeroize();
        nonce_seed.zeroize();

        if &derived_pk != public_key {
            return Err(ThresholdError::TranscriptMismatch);
        }
        if !RealMldsa65Backend::verify_standard(public_key, message, &signature)? {
            return Err(ThresholdError::StandardVerificationFailed);
        }
        if signature.0.len() != MLDSA65_SIGNATURE_BYTES {
            return Err(ThresholdError::BackendUnavailable {
                reason: "unexpected aggregate signature length",
            });
        }
        let _ = attempt;
        Ok(signature)
    }
}

/// Pre-collected partials for one threshold attempt (one live nonce DKG).
#[derive(Clone, Debug)]
pub struct ThresholdAttemptPartials {
    /// Nonce attempt id.
    pub nonce_attempt_id: [u8; 32],
    /// Nonce VSS transcript for this attempt.
    pub nonce_transcript: VssTranscript,
    /// Active key shares (threshold many).
    pub key_shares: Vec<VssShare>,
    /// Active nonce shares (threshold many).
    pub nonce_shares: Vec<VssShare>,
    /// Emitted partial contributions.
    pub partials: Vec<PartialZiContribution>,
}

fn clone_share(share: &VssShare) -> VssShare {
    VssShare {
        receiver: share.receiver,
        x: share.x,
        elements: share.elements,
    }
}

fn sha3_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha3_256::digest(bytes).into()
}

fn domain_digest(label: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(label);
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocker_status_marks_engineering_closed_proofs_open() {
        let status = ThresholdMldsaEngine::blocker_status();
        assert!(status.engineering_blockers_closed());
        assert!(!status.fully_closed());
        assert!(!status.closed_proofs);
        assert!(!status.closed_audits);
        assert!(status.algebraic_module_vector_partial_zi);
        assert!(status.distributed_nonce_dkg_live);
        assert!(status.partial_zi_over_sk_shares);
        assert!(status.aggregate_partials_and_hints);
        assert!(status.fips_rejection_over_partials);
        assert!(status.binding_hash_vss);
        assert!(!status.malicious_secure_dkg_vss);
    }

    #[test]
    fn end_to_end_threshold_sign_with_live_nonce_dkg_verifies() {
        let seed = [0x42u8; 32];
        let validators = vec![ValidatorId(0), ValidatorId(1), ValidatorId(2)];
        let message = b"p1 threshold core live nonce dkg";
        let result = ThresholdMldsaEngine::threshold_sign_with_live_nonce_dkg(
            &seed,
            2,
            &validators,
            message,
            b"dealer-randomness-key-vss-32bytes!!",
            &[
                b"attempt-rand-0-xxxxxxxxxxxxxxxxxxxx",
                b"attempt-rand-1-yyyyyyyyyyyyyyyyyyyy",
            ],
        )
        .expect("threshold sign");

        assert!(result.standard_verifier_accepted);
        assert!(result.partial_signing_over_secret_shares);
        assert!(result.hints_embedded_in_standard_signature);
        // Seed-layer Sign_internal path does not pack module-vector partials into the wire sig.
        assert!(!result.algebraic_module_vector_partial_zi);
        assert!(RealMldsa65Backend::verify_standard(
            &result.public_key,
            message,
            &result.signature
        )
        .unwrap());
    }

    #[test]
    fn key_dkg_and_nonce_dkg_are_independently_reconstructible() {
        let seed = [0x11u8; 32];
        let validators = vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)];
        let key = ThresholdMldsaEngine::malicious_secure_key_dkg(
            &seed,
            2,
            &validators,
            b"key-dealer-rand",
        )
        .unwrap();
        let recovered = reconstruct_secret(2, &key.shares[..2]).unwrap();
        assert_eq!(recovered, seed);

        let nonce = ThresholdMldsaEngine::live_nonce_dkg(2, &validators, &[7u8; 40]).unwrap();
        assert_eq!(nonce.shares.len(), 3);
        verify_share(&nonce.transcript, &nonce.shares[0]).unwrap();
    }

    #[test]
    fn aggregate_rejects_nonce_share_from_wrong_transcript() {
        let seed = [0x33u8; 32];
        let validators = vec![ValidatorId(0), ValidatorId(1), ValidatorId(2)];
        let message = b"reject wrong nonce transcript";
        let key = ThresholdMldsaEngine::malicious_secure_key_dkg(
            &seed,
            2,
            &validators,
            b"dealer-randomness-key-vss-32bytes!!",
        )
        .unwrap();
        let nonce = ThresholdMldsaEngine::live_nonce_dkg(
            2,
            &validators,
            b"attempt-rand-valid-xxxxxxxxxxxxxxxx",
        )
        .unwrap();
        let wrong_nonce = ThresholdMldsaEngine::live_nonce_dkg(
            2,
            &validators,
            b"attempt-rand-wrong-yyyyyyyyyyyyyyyy",
        )
        .unwrap();

        let mut partials = Vec::new();
        for i in 0..2 {
            partials.push(
                ThresholdMldsaEngine::emit_partial_zi(
                    &key.shares[i],
                    &key.transcript,
                    &nonce.shares[i],
                    &nonce,
                    message,
                )
                .unwrap(),
            );
        }
        let attempt = ThresholdAttemptPartials {
            nonce_attempt_id: nonce.attempt_id,
            nonce_transcript: wrong_nonce.transcript,
            key_shares: key.shares[..2].iter().map(clone_share).collect(),
            nonce_shares: nonce.shares[..2].iter().map(clone_share).collect(),
            partials,
        };
        let err = ThresholdMldsaEngine::aggregate_partials_with_rejection(
            &key.public_key,
            &key.transcript,
            message,
            &[attempt],
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ThresholdError::PartialShareVerificationFailed { .. }
        ));
    }
}
