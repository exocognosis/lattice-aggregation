//! Evidence records for adapter-level threshold-signing faults.
//!
//! These records preserve attribution and optional raw wire context for local
//! policy, audit logs, or simulation assertions. They are not an on-chain
//! slashing transaction and do not encode chain-specific penalties.

use serde::{Deserialize, Serialize};

use crate::{SessionId, ValidatorId};

/// Classification for adapter-observed evidence.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EvidenceKind {
    /// A wire message could not be decoded or failed framing validation.
    MalformedWireMessage,
    /// A validator sent a duplicate message for the same session context.
    DuplicateMessage,
    /// A validator committed but did not submit a partial signature before timeout.
    CommitmentWithoutPartial,
    /// A partial signature failed cryptographic verification.
    InvalidPartialSignature,
    /// A session expired before required messages were observed.
    SessionTimeout,
}

/// Attributable evidence captured by the adapter scaffold.
///
/// This type is a local evidence container only. It is intentionally not an
/// on-chain slashing transaction, and callers must map it into any
/// chain-specific transaction format themselves if needed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SlashingEvidence {
    /// Threshold signing session where the evidence was observed.
    pub session_id: SessionId,
    /// Validator attributed to the observed fault.
    pub validator: ValidatorId,
    /// Adapter-level evidence classification.
    pub kind: EvidenceKind,
    /// Optional raw wire frame associated with the evidence.
    pub wire_frame: Option<Vec<u8>>,
    /// Human-readable detail for logs and diagnostics.
    pub details: String,
    /// Optional canonical experimental VSS complaint evidence bytes.
    ///
    /// This is a structural research scaffold only. It is not an on-chain
    /// slashing proof and does not imply production VSS relation verification.
    #[cfg(feature = "experimental-vss")]
    pub experimental_vss_complaint_evidence: Option<Vec<u8>>,
    /// Optional digest of the canonical production VSS relation statement.
    ///
    /// This binds local evidence to the public inputs a future production VSS
    /// proof must verify. It is not a proof of the relation by itself.
    #[cfg(feature = "experimental-vss")]
    pub production_vss_relation_statement_digest: Option<[u8; 32]>,
}

impl SlashingEvidence {
    /// Creates local adapter evidence without constructing an on-chain
    /// slashing transaction.
    pub fn new(
        session_id: SessionId,
        validator: ValidatorId,
        kind: EvidenceKind,
        wire_frame: Option<Vec<u8>>,
        details: impl Into<String>,
    ) -> Self {
        Self {
            session_id,
            validator,
            kind,
            wire_frame,
            details: details.into(),
            #[cfg(feature = "experimental-vss")]
            experimental_vss_complaint_evidence: None,
            #[cfg(feature = "experimental-vss")]
            production_vss_relation_statement_digest: None,
        }
    }

    /// Attach canonical experimental VSS complaint evidence bytes.
    #[cfg(feature = "experimental-vss")]
    pub fn with_experimental_vss_complaint_evidence(mut self, evidence: Vec<u8>) -> Self {
        self.experimental_vss_complaint_evidence = Some(evidence);
        self
    }

    /// Attach the digest of a canonical production VSS relation statement.
    #[cfg(feature = "experimental-vss")]
    pub fn with_production_vss_relation_statement_digest(mut self, digest: [u8; 32]) -> Self {
        self.production_vss_relation_statement_digest = Some(digest);
        self
    }

    /// Build a deterministic fraud-proof payload from local adapter evidence.
    pub fn to_fraud_proof_payload(
        &self,
        block_height: u64,
        round_1_commitment: [u8; 32],
        round_2_malicious_share: Vec<u8>,
        error_vector_proof: Vec<u8>,
    ) -> SlashingEvidencePayload {
        SlashingEvidencePayload {
            block_height,
            session_id: self.session_id,
            offending_validator_index: self.validator.0,
            round_1_commitment,
            round_2_malicious_share,
            error_vector_proof,
        }
    }
}

/// Deterministic fraud-proof payload for on-chain slashing adapters.
///
/// This schema intentionally contains only primitive byte and integer fields so
/// a real state machine can parse it without depending on local adapter enums
/// or log strings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SlashingEvidencePayload {
    /// Height of the block where the violation occurred.
    pub block_height: u64,
    /// Unique identifier of the multi-round protocol run.
    pub session_id: SessionId,
    /// Index of the offending validator node.
    pub offending_validator_index: u16,
    /// Public polynomial commitment declared by the node in Round 1.
    pub round_1_commitment: [u8; 32],
    /// Invalid polynomial partial signature share submitted in Round 2.
    pub round_2_malicious_share: Vec<u8>,
    /// Proof bytes showing the share fails validation against its commitment.
    pub error_vector_proof: Vec<u8>,
}

impl SlashingEvidencePayload {
    /// Encode this payload to canonical adapter-owned bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            78 + self.round_2_malicious_share.len() + self.error_vector_proof.len(),
        );
        out.extend_from_slice(&self.block_height.to_be_bytes());
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.offending_validator_index.to_be_bytes());
        out.extend_from_slice(&self.round_1_commitment);
        extend_len_prefixed(&mut out, &self.round_2_malicious_share);
        extend_len_prefixed(&mut out, &self.error_vector_proof);
        out
    }

    /// Decode canonical adapter-owned bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, EvidenceDecodeError> {
        if bytes.len() < 78 {
            return Err(EvidenceDecodeError::InvalidLength);
        }

        let mut cursor = 0;
        let block_height = read_u64(bytes, &mut cursor)?;
        let session_id = read_array::<32>(bytes, &mut cursor)?;
        let offending_validator_index = read_u16(bytes, &mut cursor)?;
        let round_1_commitment = read_array::<32>(bytes, &mut cursor)?;
        let round_2_malicious_share = read_len_prefixed(bytes, &mut cursor)?;
        let error_vector_proof = read_len_prefixed(bytes, &mut cursor)?;

        if cursor != bytes.len() {
            return Err(EvidenceDecodeError::InvalidLength);
        }

        Ok(Self {
            block_height,
            session_id,
            offending_validator_index,
            round_1_commitment,
            round_2_malicious_share,
            error_vector_proof,
        })
    }
}

/// Decode failure for deterministic slashing evidence payloads.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EvidenceDecodeError {
    /// Payload length does not match the canonical framing.
    #[error("invalid evidence payload length")]
    InvalidLength,
    /// A length-prefixed field exceeds the remaining payload.
    #[error("invalid evidence vector length")]
    InvalidVectorLength,
}

fn extend_len_prefixed(out: &mut Vec<u8>, payload: &[u8]) {
    assert!(
        payload.len() <= u32::MAX as usize,
        "evidence vector length exceeds u32 framing capacity"
    );
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, EvidenceDecodeError> {
    Ok(u64::from_be_bytes(read_array(bytes, cursor)?))
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, EvidenceDecodeError> {
    Ok(u16::from_be_bytes(read_array(bytes, cursor)?))
}

fn read_len_prefixed(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u8>, EvidenceDecodeError> {
    let len = u32::from_be_bytes(read_array(bytes, cursor)?) as usize;
    let end = cursor
        .checked_add(len)
        .ok_or(EvidenceDecodeError::InvalidVectorLength)?;
    if end > bytes.len() {
        return Err(EvidenceDecodeError::InvalidVectorLength);
    }
    let payload = bytes[*cursor..end].to_vec();
    *cursor = end;
    Ok(payload)
}

fn read_array<const LEN: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; LEN], EvidenceDecodeError> {
    let end = cursor
        .checked_add(LEN)
        .ok_or(EvidenceDecodeError::InvalidLength)?;
    if end > bytes.len() {
        return Err(EvidenceDecodeError::InvalidLength);
    }
    let mut out = [0u8; LEN];
    out.copy_from_slice(&bytes[*cursor..end]);
    *cursor = end;
    Ok(out)
}
