//! Scaffold boundary for proof-bearing threshold contribution payloads.
//!
//! This module intentionally implements a deterministic transcript-hash proof,
//! not a zero-knowledge or MPC proof. It exists to define the API surface where
//! a production partial-contribution proof relation will replace raw hazmat
//! payload exposure.

use std::fmt;

use sha3::{Digest as Sha3Digest, Sha3_256};

use crate::{SessionId, ThresholdError, ValidatorId};

/// ML-DSA-65 challenge byte length bound used by contribution statements.
pub const CONTRIBUTION_CHALLENGE_BYTES: usize = 48;
/// Canonical byte length of a [`ContributionStatement`].
pub const CONTRIBUTION_STATEMENT_BYTES: usize =
    32 + 8 + 2 + 2 + CONTRIBUTION_CHALLENGE_BYTES + 32 + 32 + 32;
/// Canonical byte length of a [`ContributionProof`].
pub const CONTRIBUTION_PROOF_BYTES: usize = 4 + 32 + 32;
/// ML-DSA-65 `mu` byte length bound used by production relation statements.
pub const PRODUCTION_CONTRIBUTION_MU_BYTES: usize = 64;
/// Canonical byte length of a [`ProductionContributionStatement`].
pub const PRODUCTION_CONTRIBUTION_STATEMENT_BYTES: usize = 2
    + 32
    + 32
    + 8
    + 2
    + 2
    + 2
    + 2
    + (7 * 32)
    + PRODUCTION_CONTRIBUTION_MU_BYTES
    + CONTRIBUTION_CHALLENGE_BYTES;

const CONTRIBUTION_PROOF_DOMAIN: &[u8] = b"dytallix.threshold.contribution.proof.scaffold.v1";
const PRODUCTION_CONTRIBUTION_STATEMENT_DOMAIN: &[u8] =
    b"dytallix.threshold.contribution.production-statement.v1";

/// Public statement bound into a threshold contribution proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContributionStatement {
    /// Protocol session ID.
    pub session_id: SessionId,
    /// Block height being signed.
    pub block_height: u64,
    /// Rejection-sampling attempt number.
    pub attempt: u16,
    /// One-based validator index.
    pub validator_index: u16,
    /// Challenge bound to the contribution.
    pub challenge: [u8; CONTRIBUTION_CHALLENGE_BYTES],
    /// Digest of the corresponding masking precommitment.
    pub masking_commitment_digest: [u8; 32],
    /// Digest of the corresponding secret precommitment.
    pub secret_commitment_digest: [u8; 32],
    /// Digest binding the contribution to the epoch DKG public commitment material.
    pub dkg_commitment_digest: [u8; 32],
}

impl ContributionStatement {
    /// Encode this statement as canonical fixed-width big-endian bytes.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CONTRIBUTION_STATEMENT_BYTES);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.block_height.to_be_bytes());
        out.extend_from_slice(&self.attempt.to_be_bytes());
        out.extend_from_slice(&self.validator_index.to_be_bytes());
        out.extend_from_slice(&self.challenge);
        out.extend_from_slice(&self.masking_commitment_digest);
        out.extend_from_slice(&self.secret_commitment_digest);
        out.extend_from_slice(&self.dkg_commitment_digest);
        out
    }

    /// Decode a canonical fixed-width statement.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ThresholdError> {
        if bytes.len() != CONTRIBUTION_STATEMENT_BYTES {
            return Err(ThresholdError::MalformedSerialization {
                reason: "invalid contribution statement length",
            });
        }

        let mut cursor = 0;
        let mut session_id = [0u8; 32];
        session_id.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;

        let mut block_height = [0u8; 8];
        block_height.copy_from_slice(&bytes[cursor..cursor + 8]);
        cursor += 8;

        let attempt = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
        cursor += 2;
        let validator_index = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
        cursor += 2;

        let mut challenge = [0u8; CONTRIBUTION_CHALLENGE_BYTES];
        challenge.copy_from_slice(&bytes[cursor..cursor + CONTRIBUTION_CHALLENGE_BYTES]);
        cursor += CONTRIBUTION_CHALLENGE_BYTES;

        let mut masking_commitment_digest = [0u8; 32];
        masking_commitment_digest.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;

        let mut secret_commitment_digest = [0u8; 32];
        secret_commitment_digest.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;

        let mut dkg_commitment_digest = [0u8; 32];
        dkg_commitment_digest.copy_from_slice(&bytes[cursor..cursor + 32]);

        let statement = Self {
            session_id,
            block_height: u64::from_be_bytes(block_height),
            attempt,
            validator_index,
            challenge,
            masking_commitment_digest,
            secret_commitment_digest,
            dkg_commitment_digest,
        };
        validate_statement(&statement)?;
        Ok(statement)
    }
}

/// Public production-target statement for a future contribution proof relation.
///
/// This statement is a canonical binding target only. It does not implement a
/// production proof relation, and accepting this object is not a security
/// claim. The fields enumerate the context that a reviewed proof/MPC backend
/// must bind before it may declare
/// [`ContributionProofSecurityProfile::ProductionProofRelation`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionContributionStatement {
    /// Version of this public relation statement schema.
    pub protocol_version: u16,
    /// DKG/public-key epoch identifier.
    pub epoch_id: [u8; 32],
    /// Protocol session ID.
    pub session_id: SessionId,
    /// Block height being signed.
    pub block_height: u64,
    /// Rejection-sampling attempt number.
    pub attempt: u16,
    /// One-based validator index.
    pub validator_index: u16,
    /// Signing threshold.
    pub threshold: u16,
    /// Validator-set size.
    pub total_nodes: u16,
    /// Digest of the canonical validator set.
    pub validator_set_digest: [u8; 32],
    /// Digest of the epoch public key.
    pub public_key_digest: [u8; 32],
    /// Digest identifying the ML-DSA parameter set and proof relation.
    pub parameter_set_digest: [u8; 32],
    /// ML-DSA internal message digest.
    pub mu: [u8; PRODUCTION_CONTRIBUTION_MU_BYTES],
    /// Challenge bound to the contribution.
    pub challenge: [u8; CONTRIBUTION_CHALLENGE_BYTES],
    /// Digest binding the contribution to epoch DKG material.
    pub dkg_commitment_digest: [u8; 32],
    /// Digest of the corresponding masking precommitment.
    pub masking_commitment_digest: [u8; 32],
    /// Digest of the corresponding secret precommitment.
    pub secret_commitment_digest: [u8; 32],
    /// Digest of the claimed production contribution commitment.
    pub contribution_commitment_digest: [u8; 32],
}

impl ProductionContributionStatement {
    /// Encode this production-target statement as canonical big-endian bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ThresholdError> {
        validate_production_statement(self)?;

        let mut out = Vec::with_capacity(PRODUCTION_CONTRIBUTION_STATEMENT_BYTES);
        out.extend_from_slice(&self.protocol_version.to_be_bytes());
        out.extend_from_slice(&self.epoch_id);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.block_height.to_be_bytes());
        out.extend_from_slice(&self.attempt.to_be_bytes());
        out.extend_from_slice(&self.validator_index.to_be_bytes());
        out.extend_from_slice(&self.threshold.to_be_bytes());
        out.extend_from_slice(&self.total_nodes.to_be_bytes());
        out.extend_from_slice(&self.validator_set_digest);
        out.extend_from_slice(&self.public_key_digest);
        out.extend_from_slice(&self.parameter_set_digest);
        out.extend_from_slice(&self.mu);
        out.extend_from_slice(&self.challenge);
        out.extend_from_slice(&self.dkg_commitment_digest);
        out.extend_from_slice(&self.masking_commitment_digest);
        out.extend_from_slice(&self.secret_commitment_digest);
        out.extend_from_slice(&self.contribution_commitment_digest);
        Ok(out)
    }

    /// Decode a canonical production-target statement.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ThresholdError> {
        if bytes.len() != PRODUCTION_CONTRIBUTION_STATEMENT_BYTES {
            return Err(ThresholdError::MalformedSerialization {
                reason: "invalid production contribution statement length",
            });
        }

        let mut cursor = 0;
        let protocol_version = read_u16(bytes, &mut cursor);
        let epoch_id = read_array_32(bytes, &mut cursor);
        let session_id = read_array_32(bytes, &mut cursor);
        let block_height = read_u64(bytes, &mut cursor);
        let attempt = read_u16(bytes, &mut cursor);
        let validator_index = read_u16(bytes, &mut cursor);
        let threshold = read_u16(bytes, &mut cursor);
        let total_nodes = read_u16(bytes, &mut cursor);
        let validator_set_digest = read_array_32(bytes, &mut cursor);
        let public_key_digest = read_array_32(bytes, &mut cursor);
        let parameter_set_digest = read_array_32(bytes, &mut cursor);
        let mu = read_array_64(bytes, &mut cursor);
        let challenge = read_array_48(bytes, &mut cursor);
        let dkg_commitment_digest = read_array_32(bytes, &mut cursor);
        let masking_commitment_digest = read_array_32(bytes, &mut cursor);
        let secret_commitment_digest = read_array_32(bytes, &mut cursor);
        let contribution_commitment_digest = read_array_32(bytes, &mut cursor);

        let statement = Self {
            protocol_version,
            epoch_id,
            session_id,
            block_height,
            attempt,
            validator_index,
            threshold,
            total_nodes,
            validator_set_digest,
            public_key_digest,
            parameter_set_digest,
            mu,
            challenge,
            dkg_commitment_digest,
            masking_commitment_digest,
            secret_commitment_digest,
            contribution_commitment_digest,
        };
        validate_production_statement(&statement)?;
        Ok(statement)
    }

    /// Compute a domain-separated digest of the canonical statement bytes.
    pub fn statement_digest(&self) -> Result<[u8; 32], ThresholdError> {
        let mut hasher = Sha3_256::new();
        Sha3Digest::update(&mut hasher, PRODUCTION_CONTRIBUTION_STATEMENT_DOMAIN);
        Sha3Digest::update(&mut hasher, self.to_canonical_bytes()?);
        Ok(hasher.finalize().into())
    }
}

/// Private witness material for the current scaffold contribution proof.
#[derive(Clone, Eq, PartialEq)]
pub struct ContributionWitness {
    payload: Vec<u8>,
}

impl ContributionWitness {
    /// Construct a witness from the currently exposed hazmat contribution bytes.
    pub fn from_payload(payload: Vec<u8>) -> Self {
        Self { payload }
    }

    /// Return the raw payload length without exposing payload contents.
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    fn payload_digest(&self) -> [u8; 32] {
        Sha3_256::digest(&self.payload).into()
    }
}

impl fmt::Debug for ContributionWitness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContributionWitness")
            .field("payload_len", &self.payload.len())
            .field("payload_digest", &"<redacted>")
            .finish()
    }
}

/// Deterministic scaffold proof binding a public statement to a witness digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContributionProof {
    /// Length of the raw contribution payload committed by this proof.
    pub payload_len: u32,
    /// SHA3-256 digest of the raw contribution payload.
    pub payload_digest: [u8; 32],
    /// Transcript digest over the statement and witness digest.
    pub proof_digest: [u8; 32],
}

impl ContributionProof {
    /// Encode this proof as canonical fixed-width big-endian bytes.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CONTRIBUTION_PROOF_BYTES);
        out.extend_from_slice(&self.payload_len.to_be_bytes());
        out.extend_from_slice(&self.payload_digest);
        out.extend_from_slice(&self.proof_digest);
        out
    }

    /// Decode a canonical fixed-width proof.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ThresholdError> {
        if bytes.len() != CONTRIBUTION_PROOF_BYTES {
            return Err(ThresholdError::MalformedSerialization {
                reason: "invalid contribution proof length",
            });
        }

        let mut payload_len = [0u8; 4];
        payload_len.copy_from_slice(&bytes[..4]);
        let mut payload_digest = [0u8; 32];
        payload_digest.copy_from_slice(&bytes[4..36]);
        let mut proof_digest = [0u8; 32];
        proof_digest.copy_from_slice(&bytes[36..68]);

        Ok(Self {
            payload_len: u32::from_be_bytes(payload_len),
            payload_digest,
            proof_digest,
        })
    }
}

/// Declared security posture of a contribution proof backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContributionProofSecurityProfile {
    /// Deterministic transcript-hash scaffold used for integration tests.
    ///
    /// This profile is not zero-knowledge, does not prove well-formed secret
    /// contribution knowledge, and is not suitable for production-security
    /// claims.
    TranscriptHashScaffold,
    /// Production-oriented API shape without an implemented proof relation.
    ///
    /// Candidate scaffolds are useful for integration tests, but must fail
    /// production-security gates until a concrete proof relation is selected,
    /// implemented, and reviewed.
    ProductionCandidateScaffold,
    /// Backend claims a production contribution proof relation.
    ///
    /// Implementers must only use this after implementing a concrete proof or
    /// MPC verification relation with a matching security argument.
    ProductionProofRelation,
}

impl ContributionProofSecurityProfile {
    /// Returns whether this profile is acceptable for production-security
    /// claims.
    pub const fn supports_production_security_claim(self) -> bool {
        matches!(self, Self::ProductionProofRelation)
    }
}

/// Backend boundary for producing and verifying threshold contribution proofs.
pub trait ContributionProofBackend {
    /// Declares the backend's security posture for production policy gates.
    fn security_profile(&self) -> ContributionProofSecurityProfile {
        ContributionProofSecurityProfile::TranscriptHashScaffold
    }

    /// Produce a proof binding `statement` to private `witness` material.
    fn prove(
        &self,
        statement: &ContributionStatement,
        witness: &ContributionWitness,
    ) -> Result<ContributionProof, ThresholdError>;

    /// Verify `proof` against a public `statement`.
    fn verify(
        &self,
        statement: &ContributionStatement,
        proof: &ContributionProof,
    ) -> Result<(), ThresholdError>;
}

/// Default deterministic transcript-hash contribution proof scaffold.
///
/// This backend is not a zero-knowledge or MPC proof system. It only preserves
/// the current deterministic transcript-hash behavior behind a backend boundary
/// so a production proof relation can replace it without changing callers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TranscriptHashContributionProofBackend;

impl ContributionProofBackend for TranscriptHashContributionProofBackend {
    fn prove(
        &self,
        statement: &ContributionStatement,
        witness: &ContributionWitness,
    ) -> Result<ContributionProof, ThresholdError> {
        validate_statement(statement)?;
        if witness.payload.is_empty() {
            return Err(ThresholdError::MalformedSerialization {
                reason: "empty contribution witness payload",
            });
        }
        let payload_len = u32::try_from(witness.payload.len()).map_err(|_| {
            ThresholdError::MalformedSerialization {
                reason: "contribution witness payload too large",
            }
        })?;
        let payload_digest = witness.payload_digest();
        let proof_digest = contribution_proof_digest(statement, payload_len, &payload_digest)?;

        Ok(ContributionProof {
            payload_len,
            payload_digest,
            proof_digest,
        })
    }

    fn verify(
        &self,
        statement: &ContributionStatement,
        proof: &ContributionProof,
    ) -> Result<(), ThresholdError> {
        validate_statement(statement)?;
        if proof.payload_len == 0 {
            return Err(ThresholdError::MalformedSerialization {
                reason: "empty contribution proof payload binding",
            });
        }
        let expected =
            contribution_proof_digest(statement, proof.payload_len, &proof.payload_digest)?;
        if expected == proof.proof_digest {
            Ok(())
        } else {
            Err(ThresholdError::PartialShareVerificationFailed {
                validator: ValidatorId(statement.validator_index),
            })
        }
    }
}

/// Build a deterministic scaffold contribution proof with the default backend.
pub fn prove_contribution(
    statement: &ContributionStatement,
    witness: &ContributionWitness,
) -> Result<ContributionProof, ThresholdError> {
    TranscriptHashContributionProofBackend.prove(statement, witness)
}

/// Verify a deterministic scaffold contribution proof with the default backend.
pub fn verify_contribution_proof(
    statement: &ContributionStatement,
    proof: &ContributionProof,
) -> Result<(), ThresholdError> {
    TranscriptHashContributionProofBackend.verify(statement, proof)
}

/// Require a backend that declares a production contribution proof relation.
pub fn require_production_contribution_proof_backend<B: ContributionProofBackend>(
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
                "contribution proof backend is transcript-hash scaffold; production proof relation required",
        })
    }
}

fn validate_statement(statement: &ContributionStatement) -> Result<(), ThresholdError> {
    if statement.validator_index == 0 {
        return Err(ThresholdError::UnknownValidator {
            validator: ValidatorId(statement.validator_index),
        });
    }
    Ok(())
}

fn validate_production_statement(
    statement: &ProductionContributionStatement,
) -> Result<(), ThresholdError> {
    if statement.protocol_version == 0 {
        return Err(ThresholdError::MalformedSerialization {
            reason: "invalid production contribution statement version",
        });
    }
    if statement.threshold == 0
        || statement.total_nodes == 0
        || statement.threshold > statement.total_nodes
    {
        return Err(ThresholdError::InvalidThresholdParameters {
            threshold: statement.threshold,
            total_nodes: statement.total_nodes,
        });
    }
    if statement.validator_index == 0 || statement.validator_index > statement.total_nodes {
        return Err(ThresholdError::UnknownValidator {
            validator: ValidatorId(statement.validator_index),
        });
    }
    Ok(())
}

fn contribution_proof_digest(
    statement: &ContributionStatement,
    payload_len: u32,
    payload_digest: &[u8; 32],
) -> Result<[u8; 32], ThresholdError> {
    let mut hasher = Sha3_256::new();
    Sha3Digest::update(&mut hasher, CONTRIBUTION_PROOF_DOMAIN);
    Sha3Digest::update(&mut hasher, statement.session_id);
    Sha3Digest::update(&mut hasher, statement.block_height.to_be_bytes());
    Sha3Digest::update(&mut hasher, statement.attempt.to_be_bytes());
    Sha3Digest::update(&mut hasher, statement.validator_index.to_be_bytes());
    Sha3Digest::update(&mut hasher, statement.challenge);
    Sha3Digest::update(&mut hasher, statement.masking_commitment_digest);
    Sha3Digest::update(&mut hasher, statement.secret_commitment_digest);
    Sha3Digest::update(&mut hasher, statement.dkg_commitment_digest);
    Sha3Digest::update(&mut hasher, payload_len.to_be_bytes());
    Sha3Digest::update(&mut hasher, payload_digest);
    Ok(hasher.finalize().into())
}

fn read_array_32(bytes: &[u8], cursor: &mut usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[*cursor..*cursor + 32]);
    *cursor += 32;
    out
}

fn read_array_48(bytes: &[u8], cursor: &mut usize) -> [u8; 48] {
    let mut out = [0u8; 48];
    out.copy_from_slice(&bytes[*cursor..*cursor + 48]);
    *cursor += 48;
    out
}

fn read_array_64(bytes: &[u8], cursor: &mut usize) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes[*cursor..*cursor + 64]);
    *cursor += 64;
    out
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> u16 {
    let out = u16::from_be_bytes([bytes[*cursor], bytes[*cursor + 1]]);
    *cursor += 2;
    out
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> u64 {
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes[*cursor..*cursor + 8]);
    *cursor += 8;
    u64::from_be_bytes(out)
}
