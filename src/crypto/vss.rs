//! Verifiable-secret-sharing arithmetic scaffold for polynomial shares.
//!
//! This module models Shamir-style polynomial evaluation over ML-DSA
//! coefficient polynomials. The masking coefficients are deterministic test
//! fixtures, not cryptographic randomness.

use std::collections::BTreeSet;

use crate::{
    collections::validate_threshold,
    crypto::poly::{Poly, Q},
    SessionId, ThresholdError, ValidatorId,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest as Sha3Digest, Sha3_256, Shake256,
};

const VSS_SHARE_COMMITMENT_DOMAIN: &[u8] = b"dytallix.vss.share.commitment.scaffold.v1";
const VSS_SHARE_PROOF_DOMAIN: &[u8] = b"dytallix.vss.share.proof.scaffold.v1";
const PRODUCTION_VSS_RELATION_STATEMENT_DOMAIN: &[u8] =
    b"dytallix.threshold.vss.production-relation-statement.v1";

/// Byte length of deterministic VSS commitment and proof transcript digests.
pub const VSS_SHARE_COMMITMENT_BYTES: usize = 32;
/// Canonical byte length of a [`ProductionVssRelationStatement`].
pub const PRODUCTION_VSS_RELATION_STATEMENT_BYTES: usize =
    2 + 32 + 32 + 32 + 32 + 2 + 2 + 2 + 2 + (4 * 32);

#[cfg(feature = "experimental-vss")]
const EXPERIMENTAL_VSS_BACKEND_UNAVAILABLE: &str =
    "experimental VSS backend is a fail-closed production candidate scaffold";

/// Canonical byte length of an experimental production-shaped VSS statement.
#[cfg(feature = "experimental-vss")]
pub const EXPERIMENTAL_VSS_STATEMENT_BYTES: usize = 1 + 32 + 2 + 2 + 2 + 2 + 32 + 32;
/// Canonical byte length of an experimental production-shaped VSS opening.
#[cfg(feature = "experimental-vss")]
pub const EXPERIMENTAL_VSS_OPENING_BYTES: usize = 1 + 32 + 2 + 2 + 32 + 32 + 4;
/// Canonical byte length of an experimental production-shaped VSS proof.
#[cfg(feature = "experimental-vss")]
pub const EXPERIMENTAL_VSS_PROOF_BYTES: usize = 1 + 32 + 32;
/// Canonical byte length of an experimental VSS complaint evidence frame.
#[cfg(feature = "experimental-vss")]
pub const EXPERIMENTAL_VSS_COMPLAINT_EVIDENCE_BYTES: usize = 1
    + EXPERIMENTAL_VSS_STATEMENT_BYTES
    + EXPERIMENTAL_VSS_OPENING_BYTES
    + EXPERIMENTAL_VSS_PROOF_BYTES;

#[cfg(feature = "experimental-vss")]
const EXPERIMENTAL_VSS_OBJECT_VERSION: u8 = 1;

/// Point-evaluation share sent to one validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareContribution {
    /// Receiver validator index, using one-based epoch ordering.
    pub receiver_index: u16,
    /// Polynomial share `P(receiver_index)`.
    pub polynomial_share: Poly,
}

/// Deterministic VSS commitment scaffold for one Shamir-style share.
///
/// This public object binds a [`ShareContribution`] to session, threshold,
/// validator-set size, and receiver index using SHAKE transcript digests over
/// the share coefficients. It is a deterministic testing and integration
/// scaffold, not a production hiding or binding polynomial commitment scheme.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VssShareCommitment {
    /// Protocol session bound into the commitment transcript.
    pub session_id: SessionId,
    /// Threshold bound into the commitment transcript.
    pub threshold: u16,
    /// Validator count bound into the commitment transcript.
    pub total_nodes: u16,
    /// Receiver validator index, using one-based epoch ordering.
    pub receiver_index: u16,
    /// SHAKE digest over public context and polynomial share coefficients.
    pub commitment_digest: [u8; VSS_SHARE_COMMITMENT_BYTES],
    /// Deterministic proof digest binding the commitment digest to context.
    pub proof: VssShareProof,
}

/// Deterministic VSS proof scaffold for one committed share.
///
/// This proof is a transcript digest, not a zero-knowledge proof. It exists so
/// DKG/signing plumbing can require proof-carrying VSS shares before accepting
/// deterministic scaffold contributions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VssShareProof {
    /// SHAKE transcript digest over public context and the commitment digest.
    pub proof_digest: [u8; VSS_SHARE_COMMITMENT_BYTES],
}

/// Public production-target statement for a receiver-specific VSS relation.
///
/// This object is a canonical binding target for the future production VSS/DKG
/// proof relation. It does not implement a hiding/binding commitment scheme and
/// must not be treated as a production proof by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionVssRelationStatement {
    /// Version of this public relation statement schema.
    pub protocol_version: u16,
    /// DKG/public-key epoch identifier.
    pub epoch_id: [u8; 32],
    /// DKG protocol session ID.
    pub session_id: SessionId,
    /// Digest of the canonical validator set.
    pub validator_set_digest: [u8; 32],
    /// Digest identifying the selected VSS backend and relation.
    pub backend_id: [u8; 32],
    /// Dealer validator index, using one-based epoch ordering.
    pub dealer_index: u16,
    /// Receiver validator index, using one-based epoch ordering.
    pub receiver_index: u16,
    /// DKG threshold.
    pub threshold: u16,
    /// Validator-set size.
    pub total_nodes: u16,
    /// Digest of the dealer commitment object.
    pub dealer_commitment_digest: [u8; 32],
    /// Digest of the receiver-specific encrypted share payload.
    pub encrypted_share_digest: [u8; 32],
    /// Digest of receiver-specific opening material.
    pub opening_digest: [u8; 32],
    /// Digest of the dealer public-key contribution.
    pub public_key_contribution_digest: [u8; 32],
}

impl ProductionVssRelationStatement {
    /// Encode this production-target statement as canonical big-endian bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ThresholdError> {
        validate_production_vss_relation_statement(self)?;

        let mut out = Vec::with_capacity(PRODUCTION_VSS_RELATION_STATEMENT_BYTES);
        out.extend_from_slice(&self.protocol_version.to_be_bytes());
        out.extend_from_slice(&self.epoch_id);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.validator_set_digest);
        out.extend_from_slice(&self.backend_id);
        out.extend_from_slice(&self.dealer_index.to_be_bytes());
        out.extend_from_slice(&self.receiver_index.to_be_bytes());
        out.extend_from_slice(&self.threshold.to_be_bytes());
        out.extend_from_slice(&self.total_nodes.to_be_bytes());
        out.extend_from_slice(&self.dealer_commitment_digest);
        out.extend_from_slice(&self.encrypted_share_digest);
        out.extend_from_slice(&self.opening_digest);
        out.extend_from_slice(&self.public_key_contribution_digest);
        Ok(out)
    }

    /// Decode a canonical production-target statement.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ThresholdError> {
        if bytes.len() != PRODUCTION_VSS_RELATION_STATEMENT_BYTES {
            return malformed("invalid production VSS relation statement length");
        }

        let mut cursor = 0;
        let protocol_version = read_u16(bytes, &mut cursor);
        let epoch_id = read_array_32(bytes, &mut cursor);
        let session_id = read_array_32(bytes, &mut cursor);
        let validator_set_digest = read_array_32(bytes, &mut cursor);
        let backend_id = read_array_32(bytes, &mut cursor);
        let dealer_index = read_u16(bytes, &mut cursor);
        let receiver_index = read_u16(bytes, &mut cursor);
        let threshold = read_u16(bytes, &mut cursor);
        let total_nodes = read_u16(bytes, &mut cursor);
        let dealer_commitment_digest = read_array_32(bytes, &mut cursor);
        let encrypted_share_digest = read_array_32(bytes, &mut cursor);
        let opening_digest = read_array_32(bytes, &mut cursor);
        let public_key_contribution_digest = read_array_32(bytes, &mut cursor);

        let statement = Self {
            protocol_version,
            epoch_id,
            session_id,
            validator_set_digest,
            backend_id,
            dealer_index,
            receiver_index,
            threshold,
            total_nodes,
            dealer_commitment_digest,
            encrypted_share_digest,
            opening_digest,
            public_key_contribution_digest,
        };
        validate_production_vss_relation_statement(&statement)?;
        Ok(statement)
    }

    /// Compute a domain-separated digest of the canonical statement bytes.
    pub fn statement_digest(&self) -> Result<[u8; 32], ThresholdError> {
        let mut hasher = Sha3_256::new();
        Sha3Digest::update(&mut hasher, PRODUCTION_VSS_RELATION_STATEMENT_DOMAIN);
        Sha3Digest::update(&mut hasher, self.to_canonical_bytes()?);
        Ok(hasher.finalize().into())
    }
}

/// Production-shaped public statement for a receiver-specific VSS opening.
///
/// This object is a canonical serialization target for the future production
/// VSS relation. It does not by itself prove that the relation is implemented.
#[cfg(feature = "experimental-vss")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentalVssStatement {
    /// Digest of the canonical DKG/VSS public context.
    pub context_digest: [u8; 32],
    /// Dealer validator index, using one-based epoch ordering.
    pub dealer_index: u16,
    /// Receiver validator index, using one-based epoch ordering.
    pub receiver_index: u16,
    /// DKG threshold bound into this statement.
    pub threshold: u16,
    /// Validator-set size bound into this statement.
    pub total_nodes: u16,
    /// Digest of the dealer commitment object.
    pub dealer_commitment_digest: [u8; 32],
    /// Digest of the receiver-specific share representation.
    pub share_digest: [u8; 32],
}

#[cfg(feature = "experimental-vss")]
impl ExperimentalVssStatement {
    /// Encode this statement as fixed-width canonical big-endian bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ThresholdError> {
        validate_experimental_vss_statement(self)?;

        let mut out = Vec::with_capacity(EXPERIMENTAL_VSS_STATEMENT_BYTES);
        out.push(EXPERIMENTAL_VSS_OBJECT_VERSION);
        out.extend_from_slice(&self.context_digest);
        out.extend_from_slice(&self.dealer_index.to_be_bytes());
        out.extend_from_slice(&self.receiver_index.to_be_bytes());
        out.extend_from_slice(&self.threshold.to_be_bytes());
        out.extend_from_slice(&self.total_nodes.to_be_bytes());
        out.extend_from_slice(&self.dealer_commitment_digest);
        out.extend_from_slice(&self.share_digest);
        Ok(out)
    }

    /// Decode a fixed-width canonical statement.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ThresholdError> {
        if bytes.len() != EXPERIMENTAL_VSS_STATEMENT_BYTES {
            return malformed("invalid experimental VSS statement length");
        }
        if bytes[0] != EXPERIMENTAL_VSS_OBJECT_VERSION {
            return malformed("unsupported experimental VSS statement version");
        }

        let mut cursor = 1;
        let context_digest = read_array_32(bytes, &mut cursor);
        let dealer_index = read_u16(bytes, &mut cursor);
        let receiver_index = read_u16(bytes, &mut cursor);
        let threshold = read_u16(bytes, &mut cursor);
        let total_nodes = read_u16(bytes, &mut cursor);
        let dealer_commitment_digest = read_array_32(bytes, &mut cursor);
        let share_digest = read_array_32(bytes, &mut cursor);

        let statement = Self {
            context_digest,
            dealer_index,
            receiver_index,
            threshold,
            total_nodes,
            dealer_commitment_digest,
            share_digest,
        };
        validate_experimental_vss_statement(&statement)?;
        Ok(statement)
    }
}

/// Production-shaped private opening metadata for one VSS share delivery.
///
/// This object binds receiver-specific opening metadata to a context and
/// ciphertext/share digest. It intentionally carries digests and lengths only.
#[cfg(feature = "experimental-vss")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentalVssOpening {
    /// Digest of the canonical DKG/VSS public context.
    pub context_digest: [u8; 32],
    /// Dealer validator index, using one-based epoch ordering.
    pub dealer_index: u16,
    /// Receiver validator index, using one-based epoch ordering.
    pub receiver_index: u16,
    /// Digest of the encrypted or transport-bound share payload.
    pub encrypted_share_digest: [u8; 32],
    /// Digest of receiver-specific opening material.
    pub opening_digest: [u8; 32],
    /// Canonical byte length of the encrypted share payload.
    pub encrypted_share_len: u32,
}

#[cfg(feature = "experimental-vss")]
impl ExperimentalVssOpening {
    /// Encode this opening as fixed-width canonical big-endian bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ThresholdError> {
        validate_experimental_vss_opening(self)?;

        let mut out = Vec::with_capacity(EXPERIMENTAL_VSS_OPENING_BYTES);
        out.push(EXPERIMENTAL_VSS_OBJECT_VERSION);
        out.extend_from_slice(&self.context_digest);
        out.extend_from_slice(&self.dealer_index.to_be_bytes());
        out.extend_from_slice(&self.receiver_index.to_be_bytes());
        out.extend_from_slice(&self.encrypted_share_digest);
        out.extend_from_slice(&self.opening_digest);
        out.extend_from_slice(&self.encrypted_share_len.to_be_bytes());
        Ok(out)
    }

    /// Decode a fixed-width canonical opening.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ThresholdError> {
        if bytes.len() != EXPERIMENTAL_VSS_OPENING_BYTES {
            return malformed("invalid experimental VSS opening length");
        }
        if bytes[0] != EXPERIMENTAL_VSS_OBJECT_VERSION {
            return malformed("unsupported experimental VSS opening version");
        }

        let mut cursor = 1;
        let context_digest = read_array_32(bytes, &mut cursor);
        let dealer_index = read_u16(bytes, &mut cursor);
        let receiver_index = read_u16(bytes, &mut cursor);
        let encrypted_share_digest = read_array_32(bytes, &mut cursor);
        let opening_digest = read_array_32(bytes, &mut cursor);
        let encrypted_share_len = read_u32(bytes, &mut cursor);

        let opening = Self {
            context_digest,
            dealer_index,
            receiver_index,
            encrypted_share_digest,
            opening_digest,
            encrypted_share_len,
        };
        validate_experimental_vss_opening(&opening)?;
        Ok(opening)
    }
}

/// Production-shaped proof container for a future VSS relation.
///
/// The `proof_digest` is only an opaque canonical placeholder. The
/// `ExperimentalVssCommitmentBackend` still fails closed and does not treat this
/// object as a valid cryptographic proof.
#[cfg(feature = "experimental-vss")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentalVssProof {
    /// Digest of the canonical [`ExperimentalVssStatement`] bytes.
    pub statement_digest: [u8; 32],
    /// Digest or commitment to backend-defined proof bytes.
    pub proof_digest: [u8; 32],
}

#[cfg(feature = "experimental-vss")]
impl ExperimentalVssProof {
    /// Encode this proof container as fixed-width canonical bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ThresholdError> {
        validate_experimental_vss_proof(self)?;

        let mut out = Vec::with_capacity(EXPERIMENTAL_VSS_PROOF_BYTES);
        out.push(EXPERIMENTAL_VSS_OBJECT_VERSION);
        out.extend_from_slice(&self.statement_digest);
        out.extend_from_slice(&self.proof_digest);
        Ok(out)
    }

    /// Decode a fixed-width canonical proof container.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ThresholdError> {
        if bytes.len() != EXPERIMENTAL_VSS_PROOF_BYTES {
            return malformed("invalid experimental VSS proof length");
        }
        if bytes[0] != EXPERIMENTAL_VSS_OBJECT_VERSION {
            return malformed("unsupported experimental VSS proof version");
        }

        let mut cursor = 1;
        let statement_digest = read_array_32(bytes, &mut cursor);
        let proof_digest = read_array_32(bytes, &mut cursor);

        let proof = Self {
            statement_digest,
            proof_digest,
        };
        validate_experimental_vss_proof(&proof)?;
        Ok(proof)
    }
}

/// Production-shaped public complaint evidence for a disputed VSS opening.
///
/// This frame binds a statement, receiver-specific opening metadata, and proof
/// container into one canonical evidence object. Verification is structural
/// only; it does not verify the eventual cryptographic VSS relation.
#[cfg(feature = "experimental-vss")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentalVssComplaintEvidence {
    /// Public statement identifying the dealer, receiver, context, and share.
    pub statement: ExperimentalVssStatement,
    /// Receiver-specific opening metadata being disputed.
    pub opening: ExperimentalVssOpening,
    /// Production-shaped proof container bound to the statement bytes.
    pub proof: ExperimentalVssProof,
}

#[cfg(feature = "experimental-vss")]
impl ExperimentalVssComplaintEvidence {
    /// Encode this evidence frame as fixed-width canonical bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ThresholdError> {
        verify_experimental_vss_complaint_evidence(self)?;

        let statement = self.statement.to_canonical_bytes()?;
        let opening = self.opening.to_canonical_bytes()?;
        let proof = self.proof.to_canonical_bytes()?;

        let mut out = Vec::with_capacity(EXPERIMENTAL_VSS_COMPLAINT_EVIDENCE_BYTES);
        out.push(EXPERIMENTAL_VSS_OBJECT_VERSION);
        out.extend_from_slice(&statement);
        out.extend_from_slice(&opening);
        out.extend_from_slice(&proof);
        Ok(out)
    }

    /// Decode a fixed-width canonical evidence frame.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ThresholdError> {
        if bytes.len() != EXPERIMENTAL_VSS_COMPLAINT_EVIDENCE_BYTES {
            return malformed("invalid experimental VSS complaint evidence length");
        }
        if bytes[0] != EXPERIMENTAL_VSS_OBJECT_VERSION {
            return malformed("unsupported experimental VSS complaint evidence version");
        }

        let mut cursor = 1;
        let statement = ExperimentalVssStatement::from_canonical_bytes(
            &bytes[cursor..cursor + EXPERIMENTAL_VSS_STATEMENT_BYTES],
        )?;
        cursor += EXPERIMENTAL_VSS_STATEMENT_BYTES;
        let opening = ExperimentalVssOpening::from_canonical_bytes(
            &bytes[cursor..cursor + EXPERIMENTAL_VSS_OPENING_BYTES],
        )?;
        cursor += EXPERIMENTAL_VSS_OPENING_BYTES;
        let proof = ExperimentalVssProof::from_canonical_bytes(
            &bytes[cursor..cursor + EXPERIMENTAL_VSS_PROOF_BYTES],
        )?;

        let evidence = Self {
            statement,
            opening,
            proof,
        };
        verify_experimental_vss_complaint_evidence(&evidence)?;
        Ok(evidence)
    }
}

/// Structurally verify an experimental VSS complaint evidence frame.
///
/// This checks canonical object consistency and statement digest binding only.
/// It does not prove a malicious dealer fault and does not validate the future
/// production VSS relation.
#[cfg(feature = "experimental-vss")]
pub fn verify_experimental_vss_complaint_evidence(
    evidence: &ExperimentalVssComplaintEvidence,
) -> Result<(), ThresholdError> {
    validate_experimental_vss_statement(&evidence.statement)?;
    validate_experimental_vss_opening(&evidence.opening)?;
    validate_experimental_vss_proof(&evidence.proof)?;

    if evidence.statement.context_digest != evidence.opening.context_digest {
        return malformed("experimental VSS complaint context mismatch");
    }
    if evidence.statement.dealer_index != evidence.opening.dealer_index {
        return Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(evidence.statement.dealer_index),
        });
    }
    if evidence.statement.receiver_index != evidence.opening.receiver_index {
        return Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(evidence.statement.receiver_index),
        });
    }

    let expected_statement_digest = experimental_vss_statement_digest(&evidence.statement)?;
    if evidence.proof.statement_digest != expected_statement_digest {
        return Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(evidence.statement.dealer_index),
        });
    }

    Ok(())
}

/// Compute the canonical SHA3-256 digest for an experimental VSS statement.
///
/// This helper exists only for structural binding inside experimental
/// complaint-evidence containers. It is not a VSS proof verifier.
#[cfg(feature = "experimental-vss")]
pub fn experimental_vss_statement_digest(
    statement: &ExperimentalVssStatement,
) -> Result<[u8; 32], ThresholdError> {
    let statement_bytes = statement.to_canonical_bytes()?;
    Ok(Sha3_256::digest(statement_bytes).into())
}

/// Declared security posture of a VSS commitment backend.
///
/// The declaration is intentionally explicit so consensus or manuscript
/// harnesses can reject deterministic integration scaffolds when a
/// production-security claim would otherwise be implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VssCommitmentSecurityProfile {
    /// Deterministic transcript-hash commitment used for integration tests.
    ///
    /// This profile is not hiding, is not zero-knowledge, and is not suitable
    /// for a production VSS/DKG security theorem.
    DeterministicTranscriptScaffold,
    /// Production-oriented API shape without an implemented proof relation.
    ///
    /// Candidate scaffolds are useful for wire/API integration tests, but they
    /// must fail production-security gates until the commitment relation,
    /// opening proof, and verification algorithm are implemented and reviewed.
    ProductionCandidateScaffold,
    /// Backend claims a production VSS commitment relation.
    ///
    /// Implementers must only use this after selecting and implementing a
    /// concrete hiding/binding commitment or proof system with an external
    /// security argument.
    ProductionBindingHiding,
}

impl VssCommitmentSecurityProfile {
    /// Returns whether this profile is acceptable for production-security
    /// claims.
    pub const fn supports_production_security_claim(self) -> bool {
        matches!(self, Self::ProductionBindingHiding)
    }
}

/// Backend boundary for producing and verifying VSS share commitments.
pub trait VssCommitmentBackend {
    /// Declares the backend's VSS security profile.
    fn security_profile(&self) -> VssCommitmentSecurityProfile;

    /// Commit one share contribution under the public DKG context.
    fn commit_share_contribution(
        &self,
        session_id: SessionId,
        threshold: u16,
        total_nodes: u16,
        share: &ShareContribution,
    ) -> Result<VssShareCommitment, ThresholdError>;

    /// Verify one share contribution commitment under the public DKG context.
    fn verify_share_contribution_commitment(
        &self,
        session_id: SessionId,
        threshold: u16,
        total_nodes: u16,
        share: &ShareContribution,
        commitment: &VssShareCommitment,
    ) -> Result<(), ThresholdError>;

    /// Batch-verify a complete validator set of share commitments.
    ///
    /// The batch must contain exactly `total_nodes` entries and each receiver
    /// index must appear once before individual commitments are checked.
    fn verify_share_contribution_commitments(
        &self,
        session_id: SessionId,
        threshold: u16,
        total_nodes: u16,
        shares_and_commitments: &[(ShareContribution, VssShareCommitment)],
    ) -> Result<(), ThresholdError> {
        validate_threshold(threshold, total_nodes)?;
        if shares_and_commitments.len() != usize::from(total_nodes) {
            return Err(ThresholdError::InsufficientCommitments {
                required: total_nodes,
                received: shares_and_commitments.len(),
            });
        }

        let mut seen = BTreeSet::new();
        for (share, commitment) in shares_and_commitments {
            validate_share_receiver(share.receiver_index, total_nodes)?;
            validate_share_receiver(commitment.receiver_index, total_nodes)?;
            if commitment.session_id != session_id
                || commitment.threshold != threshold
                || commitment.total_nodes != total_nodes
                || commitment.receiver_index != share.receiver_index
            {
                return Err(ThresholdError::PartialShareVerificationFailed {
                    validator: ValidatorId(share.receiver_index),
                });
            }

            if !seen.insert(share.receiver_index) {
                return Err(ThresholdError::DuplicateValidator {
                    validator: ValidatorId(share.receiver_index),
                });
            }
            self.verify_share_contribution_commitment(
                session_id,
                threshold,
                total_nodes,
                share,
                commitment,
            )?;
        }

        Ok(())
    }
}

/// Default deterministic transcript-hash VSS commitment scaffold.
///
/// This backend preserves the current SHAKE transcript behavior for integration
/// tests and protocol plumbing. It is not a production hiding commitment, not a
/// zero-knowledge proof system, and not a replacement for a real VSS
/// commitment scheme.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TranscriptHashVssCommitmentBackend;

impl VssCommitmentBackend for TranscriptHashVssCommitmentBackend {
    fn security_profile(&self) -> VssCommitmentSecurityProfile {
        VssCommitmentSecurityProfile::DeterministicTranscriptScaffold
    }

    fn commit_share_contribution(
        &self,
        session_id: SessionId,
        threshold: u16,
        total_nodes: u16,
        share: &ShareContribution,
    ) -> Result<VssShareCommitment, ThresholdError> {
        validate_threshold(threshold, total_nodes)?;
        validate_share_receiver(share.receiver_index, total_nodes)?;

        let commitment_digest = share_commitment_digest(
            session_id,
            threshold,
            total_nodes,
            share.receiver_index,
            share,
        );
        let proof = VssShareProof {
            proof_digest: share_proof_digest(
                session_id,
                threshold,
                total_nodes,
                share.receiver_index,
                &commitment_digest,
            ),
        };

        Ok(VssShareCommitment {
            session_id,
            threshold,
            total_nodes,
            receiver_index: share.receiver_index,
            commitment_digest,
            proof,
        })
    }

    fn verify_share_contribution_commitment(
        &self,
        session_id: SessionId,
        threshold: u16,
        total_nodes: u16,
        share: &ShareContribution,
        commitment: &VssShareCommitment,
    ) -> Result<(), ThresholdError> {
        validate_threshold(threshold, total_nodes)?;
        validate_share_receiver(share.receiver_index, total_nodes)?;
        validate_share_receiver(commitment.receiver_index, total_nodes)?;

        if commitment.session_id != session_id
            || commitment.threshold != threshold
            || commitment.total_nodes != total_nodes
            || commitment.receiver_index != share.receiver_index
        {
            return Err(ThresholdError::PartialShareVerificationFailed {
                validator: ValidatorId(share.receiver_index),
            });
        }

        let expected_commitment = share_commitment_digest(
            session_id,
            threshold,
            total_nodes,
            share.receiver_index,
            share,
        );
        let expected_proof = share_proof_digest(
            session_id,
            threshold,
            total_nodes,
            share.receiver_index,
            &expected_commitment,
        );

        if commitment.commitment_digest == expected_commitment
            && commitment.proof.proof_digest == expected_proof
        {
            Ok(())
        } else {
            Err(ThresholdError::PartialShareVerificationFailed {
                validator: ValidatorId(share.receiver_index),
            })
        }
    }
}

/// Feature-gated production-oriented VSS backend placeholder.
///
/// This type exists to stabilize the integration point for a future
/// hiding/binding VSS commitment backend. It deliberately fails closed: it does
/// not produce commitments, does not verify openings, and does not pass
/// [`require_production_vss_backend`].
#[cfg(feature = "experimental-vss")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExperimentalVssCommitmentBackend;

#[cfg(feature = "experimental-vss")]
impl VssCommitmentBackend for ExperimentalVssCommitmentBackend {
    fn security_profile(&self) -> VssCommitmentSecurityProfile {
        VssCommitmentSecurityProfile::ProductionCandidateScaffold
    }

    fn commit_share_contribution(
        &self,
        _session_id: SessionId,
        _threshold: u16,
        _total_nodes: u16,
        _share: &ShareContribution,
    ) -> Result<VssShareCommitment, ThresholdError> {
        Err(ThresholdError::BackendUnavailable {
            reason: EXPERIMENTAL_VSS_BACKEND_UNAVAILABLE,
        })
    }

    fn verify_share_contribution_commitment(
        &self,
        _session_id: SessionId,
        _threshold: u16,
        _total_nodes: u16,
        _share: &ShareContribution,
        _commitment: &VssShareCommitment,
    ) -> Result<(), ThresholdError> {
        Err(ThresholdError::BackendUnavailable {
            reason: EXPERIMENTAL_VSS_BACKEND_UNAVAILABLE,
        })
    }
}

/// Require a VSS backend that can support production-security claims.
///
/// This does not audit the backend. It only prevents accidental use of the
/// deterministic transcript scaffold in contexts that need a real VSS
/// commitment relation.
pub fn require_production_vss_backend<B: VssCommitmentBackend>(
    backend: &B,
) -> Result<(), ThresholdError> {
    if backend
        .security_profile()
        .supports_production_security_claim()
    {
        Ok(())
    } else {
        Err(ThresholdError::BackendUnavailable {
            reason:
                "VSS backend is deterministic scaffold; production VSS commitment backend required",
        })
    }
}

/// Evaluate a polynomial with `Poly` coefficients at integer point `x`.
///
/// Uses Horner's method over each coefficient lane:
/// `P(x) = c_0 + c_1*x + c_2*x^2 ... mod Q`.
pub fn evaluate_polynomial_at(coefficients: &[Poly], x: u16) -> Poly {
    let mut result = Poly::zero();
    let x_i64 = i64::from(x);
    let q_i64 = i64::from(Q);

    for poly_coeff in coefficients.iter().rev() {
        let mut scaled = Poly::zero();
        for (out, coeff) in scaled.coeffs.iter_mut().zip(result.coeffs.iter()) {
            let mut product = (i64::from(*coeff) * x_i64) % q_i64;
            if product < 0 {
                product += q_i64;
            }
            *out = product as i32;
        }
        result = scaled;
        result.add_assign(poly_coeff);
    }

    result
}

/// Split a secret polynomial into deterministic Shamir-style shares.
///
/// The upper polynomial coefficients are deterministic masks so tests can
/// validate algebraic plumbing. Production DKG must replace this with
/// cryptographically sampled coefficient polynomials and commitments.
pub fn split_secret_poly(
    secret: &Poly,
    threshold: u16,
    total_nodes: u16,
) -> Vec<ShareContribution> {
    let mut poly_coefficients = vec![*secret];

    for degree in 1..threshold {
        let mut mask = Poly::zero();
        for (index, coeff) in mask.coeffs.iter_mut().enumerate() {
            *coeff = (((index as i32) + i32::from(degree)) * 42) % Q;
        }
        poly_coefficients.push(mask);
    }

    let mut shares = Vec::with_capacity(usize::from(total_nodes));
    for receiver_index in 1..=total_nodes {
        shares.push(ShareContribution {
            receiver_index,
            polynomial_share: evaluate_polynomial_at(&poly_coefficients, receiver_index),
        });
    }

    shares
}

/// Split a secret polynomial after validating threshold parameters.
///
/// This checked variant rejects zero thresholds, zero validator counts, and
/// thresholds larger than the validator count before deriving deterministic
/// Shamir-style shares.
pub fn try_split_secret_poly(
    secret: &Poly,
    threshold: u16,
    total_nodes: u16,
) -> Result<Vec<ShareContribution>, ThresholdError> {
    validate_threshold(threshold, total_nodes)?;

    Ok(split_secret_poly(secret, threshold, total_nodes))
}

/// Build a deterministic VSS commitment/proof for one share contribution.
///
/// The digest transcript includes only the receiver's polynomial share, not the
/// full secret polynomial or masking coefficients used to derive all shares.
pub fn commit_share_contribution(
    session_id: SessionId,
    threshold: u16,
    total_nodes: u16,
    share: &ShareContribution,
) -> Result<VssShareCommitment, ThresholdError> {
    TranscriptHashVssCommitmentBackend.commit_share_contribution(
        session_id,
        threshold,
        total_nodes,
        share,
    )
}

/// Verify one deterministic VSS share commitment/proof against public context.
pub fn verify_share_contribution_commitment(
    session_id: SessionId,
    threshold: u16,
    total_nodes: u16,
    share: &ShareContribution,
    commitment: &VssShareCommitment,
) -> Result<(), ThresholdError> {
    TranscriptHashVssCommitmentBackend.verify_share_contribution_commitment(
        session_id,
        threshold,
        total_nodes,
        share,
        commitment,
    )
}

/// Batch-verify deterministic VSS share commitments before DKG/signing use.
pub fn verify_share_contribution_commitments(
    session_id: SessionId,
    threshold: u16,
    total_nodes: u16,
    shares_and_commitments: &[(ShareContribution, VssShareCommitment)],
) -> Result<(), ThresholdError> {
    TranscriptHashVssCommitmentBackend.verify_share_contribution_commitments(
        session_id,
        threshold,
        total_nodes,
        shares_and_commitments,
    )
}

fn validate_share_receiver(receiver_index: u16, total_nodes: u16) -> Result<(), ThresholdError> {
    if receiver_index == 0 || receiver_index > total_nodes {
        return Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(receiver_index),
        });
    }

    Ok(())
}

fn validate_production_vss_relation_statement(
    statement: &ProductionVssRelationStatement,
) -> Result<(), ThresholdError> {
    if statement.protocol_version == 0 {
        return malformed("invalid production VSS relation statement version");
    }
    validate_threshold(statement.threshold, statement.total_nodes)?;
    validate_production_validator_index(statement.dealer_index, statement.total_nodes)?;
    validate_production_validator_index(statement.receiver_index, statement.total_nodes)?;
    Ok(())
}

fn validate_production_validator_index(
    validator_index: u16,
    total_nodes: u16,
) -> Result<(), ThresholdError> {
    if validator_index == 0 || validator_index > total_nodes {
        return Err(ThresholdError::UnknownValidator {
            validator: ValidatorId(validator_index),
        });
    }

    Ok(())
}

#[cfg(feature = "experimental-vss")]
fn validate_experimental_vss_statement(
    statement: &ExperimentalVssStatement,
) -> Result<(), ThresholdError> {
    validate_threshold(statement.threshold, statement.total_nodes)?;
    validate_share_receiver(statement.dealer_index, statement.total_nodes)?;
    validate_share_receiver(statement.receiver_index, statement.total_nodes)?;
    reject_zero_digest(
        &statement.context_digest,
        "empty experimental VSS context digest",
    )?;
    reject_zero_digest(
        &statement.dealer_commitment_digest,
        "empty experimental VSS dealer commitment digest",
    )?;
    reject_zero_digest(
        &statement.share_digest,
        "empty experimental VSS share digest",
    )
}

#[cfg(feature = "experimental-vss")]
fn validate_experimental_vss_opening(
    opening: &ExperimentalVssOpening,
) -> Result<(), ThresholdError> {
    validate_share_receiver(opening.dealer_index, u16::MAX)?;
    validate_share_receiver(opening.receiver_index, u16::MAX)?;
    reject_zero_digest(
        &opening.context_digest,
        "empty experimental VSS context digest",
    )?;
    reject_zero_digest(
        &opening.encrypted_share_digest,
        "empty experimental VSS encrypted share digest",
    )?;
    reject_zero_digest(
        &opening.opening_digest,
        "empty experimental VSS opening digest",
    )?;
    if opening.encrypted_share_len == 0 {
        return malformed("empty experimental VSS encrypted share payload");
    }
    Ok(())
}

#[cfg(feature = "experimental-vss")]
fn validate_experimental_vss_proof(proof: &ExperimentalVssProof) -> Result<(), ThresholdError> {
    reject_zero_digest(
        &proof.statement_digest,
        "empty experimental VSS statement digest",
    )?;
    reject_zero_digest(&proof.proof_digest, "empty experimental VSS proof digest")
}

#[cfg(feature = "experimental-vss")]
fn reject_zero_digest(digest: &[u8; 32], reason: &'static str) -> Result<(), ThresholdError> {
    if digest.iter().all(|byte| *byte == 0) {
        malformed(reason)
    } else {
        Ok(())
    }
}

fn read_array_32(bytes: &[u8], cursor: &mut usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[*cursor..*cursor + 32]);
    *cursor += 32;
    out
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> u16 {
    let out = u16::from_be_bytes([bytes[*cursor], bytes[*cursor + 1]]);
    *cursor += 2;
    out
}

#[cfg(feature = "experimental-vss")]
fn read_u32(bytes: &[u8], cursor: &mut usize) -> u32 {
    let out = u32::from_be_bytes([
        bytes[*cursor],
        bytes[*cursor + 1],
        bytes[*cursor + 2],
        bytes[*cursor + 3],
    ]);
    *cursor += 4;
    out
}

fn malformed<T>(reason: &'static str) -> Result<T, ThresholdError> {
    Err(ThresholdError::MalformedSerialization { reason })
}

fn share_commitment_digest(
    session_id: SessionId,
    threshold: u16,
    total_nodes: u16,
    receiver_index: u16,
    share: &ShareContribution,
) -> [u8; VSS_SHARE_COMMITMENT_BYTES] {
    let mut hasher = Shake256::default();
    update_share_context(
        &mut hasher,
        VSS_SHARE_COMMITMENT_DOMAIN,
        session_id,
        threshold,
        total_nodes,
        receiver_index,
    );
    for coeff in share.polynomial_share.coeffs {
        hasher.update(&coeff.to_be_bytes());
    }
    finalize_digest(hasher)
}

fn share_proof_digest(
    session_id: SessionId,
    threshold: u16,
    total_nodes: u16,
    receiver_index: u16,
    commitment_digest: &[u8; VSS_SHARE_COMMITMENT_BYTES],
) -> [u8; VSS_SHARE_COMMITMENT_BYTES] {
    let mut hasher = Shake256::default();
    update_share_context(
        &mut hasher,
        VSS_SHARE_PROOF_DOMAIN,
        session_id,
        threshold,
        total_nodes,
        receiver_index,
    );
    hasher.update(commitment_digest);
    finalize_digest(hasher)
}

fn update_share_context(
    hasher: &mut Shake256,
    domain: &[u8],
    session_id: SessionId,
    threshold: u16,
    total_nodes: u16,
    receiver_index: u16,
) {
    hasher.update(domain);
    hasher.update(&session_id);
    hasher.update(&threshold.to_be_bytes());
    hasher.update(&total_nodes.to_be_bytes());
    hasher.update(&receiver_index.to_be_bytes());
}

fn finalize_digest(hasher: Shake256) -> [u8; VSS_SHARE_COMMITMENT_BYTES] {
    let mut digest = [0u8; VSS_SHARE_COMMITMENT_BYTES];
    hasher.finalize_xof().read(&mut digest);
    digest
}

#[cfg(test)]
mod vss_academic_tests {
    use super::*;
    use crate::crypto::poly::N;

    #[test]
    fn test_secret_polynomial_sharing_evaluation() {
        let mut secret = Poly::zero();
        for (index, coeff) in secret.coeffs.iter_mut().enumerate() {
            *coeff = index as i32;
        }

        let threshold = 2;
        let total_nodes = 3;

        let shares = split_secret_poly(&secret, threshold, total_nodes);

        assert_eq!(shares.len(), 3);
        assert_eq!(shares[0].receiver_index, 1);
        assert_ne!(shares[0].polynomial_share.coeffs, secret.coeffs);
    }

    #[test]
    fn polynomial_evaluation_horner_matches_linear_case() {
        let constant = Poly::from_coeffs([3; N]);
        let slope = Poly::from_coeffs([7; N]);

        let evaluated = evaluate_polynomial_at(&[constant, slope], 5);

        assert_eq!(evaluated, Poly::from_coeffs([38; N]));
    }
}
