//! Deterministic hazmat fuzz/property helpers.
//!
//! These helpers are intentionally dependency-free so they can run in CI
//! without a cargo-fuzz installation. They complement, but do not replace,
//! coverage-guided fuzzing.

use std::time::Duration;

use crate::{
    adapter::{actor::HazmatMldsa65ActorSession, wire::PqcThresholdWireMsg},
    mldsa65::{
        derive_mldsa65_secret_contribution_from_share, Mldsa65ExpandedSecretKeyShare,
        MLDSA65_MU_BYTES,
    },
    ThresholdError,
};

/// One deterministic wire-frame mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireMutation {
    /// Human-readable mutation label used in assertion messages.
    pub label: &'static str,
    /// Mutated bytes.
    pub bytes: Vec<u8>,
}

/// Summary of actor sequencing corpus behavior.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ActorPermutationSummary {
    /// Number of out-of-order sequences rejected by the actor session.
    pub rejected_out_of_order_sequences: usize,
    /// Number of sequences that finalized when they should not have.
    pub unexpected_finalizations: usize,
}

/// Produce deterministic mutations for one canonical wire frame.
pub fn deterministic_wire_mutations(encoded: &[u8]) -> Vec<WireMutation> {
    let mut mutations = Vec::new();
    if encoded.is_empty() {
        return mutations;
    }

    mutations.push(WireMutation {
        label: "truncate-last-byte",
        bytes: encoded[..encoded.len() - 1].to_vec(),
    });

    let mut extended = encoded.to_vec();
    extended.push(0xA5);
    mutations.push(WireMutation {
        label: "append-trailing-byte",
        bytes: extended,
    });

    let mut bad_version = encoded.to_vec();
    bad_version[0] = bad_version[0].wrapping_add(1);
    mutations.push(WireMutation {
        label: "bad-version",
        bytes: bad_version,
    });

    if encoded.len() > 1 {
        let mut bad_type = encoded.to_vec();
        bad_type[1] = 0xFF;
        mutations.push(WireMutation {
            label: "bad-message-type",
            bytes: bad_type,
        });
    }

    if encoded.len() > 10 {
        let mut middle_flip = encoded.to_vec();
        let mid = middle_flip.len() / 2;
        middle_flip[mid] ^= 0x80;
        mutations.push(WireMutation {
            label: "middle-bit-flip",
            bytes: middle_flip,
        });
    }

    if encoded.len() >= 8 {
        let mut prefix_only = encoded.to_vec();
        prefix_only.truncate(8);
        mutations.push(WireMutation {
            label: "prefix-only",
            bytes: prefix_only,
        });
    }

    mutations
}

/// Return true if a byte frame is rejected or decodes to a stable canonical frame.
pub fn verify_decode_is_stable_or_rejected(bytes: &[u8]) -> bool {
    match PqcThresholdWireMsg::decode(bytes) {
        Ok(decoded) => PqcThresholdWireMsg::decode(&decoded.encode()) == Ok(decoded),
        Err(_) => true,
    }
}

/// Exercise invalid actor-session event orderings and count expected rejections.
pub fn run_actor_event_permutation_corpus(
    shares: &[Mldsa65ExpandedSecretKeyShare],
    mu: [u8; MLDSA65_MU_BYTES],
) -> Result<ActorPermutationSummary, ThresholdError> {
    let first = shares
        .first()
        .ok_or(ThresholdError::InsufficientPartialShares {
            required: 1,
            received: 0,
        })?;
    let threshold = first.threshold();
    let total_nodes = first.total_nodes();
    let challenge = [0xA9; crate::mldsa65::MLDSA65_CHALLENGE_BYTES];
    let secret = derive_mldsa65_secret_contribution_from_share(first, &challenge)?;
    let mut summary = ActorPermutationSummary::default();

    let mut secret_before_masking = HazmatMldsa65ActorSession::new(
        [0xE1; 32],
        1,
        threshold,
        total_nodes,
        mu,
        Duration::from_secs(1),
    )?;
    match secret_before_masking.submit_secret_contribution(secret) {
        Err(ThresholdError::TranscriptMismatch) => summary.rejected_out_of_order_sequences += 1,
        Ok(()) => {
            if secret_before_masking.finalize_signature().is_ok() {
                summary.unexpected_finalizations += 1;
            }
        }
        Err(_) => summary.rejected_out_of_order_sequences += 1,
    }

    let mut finalize_before_quorum = HazmatMldsa65ActorSession::new(
        [0xE2; 32],
        2,
        threshold,
        total_nodes,
        mu,
        Duration::from_secs(1),
    )?;
    match finalize_before_quorum.finalize_signature() {
        Err(ThresholdError::TranscriptMismatch)
        | Err(ThresholdError::InsufficientPartialShares { .. })
        | Err(ThresholdError::InsufficientCommitments { .. }) => {
            summary.rejected_out_of_order_sequences += 1;
        }
        Ok((_height, _signature)) => summary.unexpected_finalizations += 1,
        Err(_) => summary.rejected_out_of_order_sequences += 1,
    }

    Ok(summary)
}
