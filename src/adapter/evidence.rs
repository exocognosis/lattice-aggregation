//! Evidence records for adapter-level threshold-signing faults.
//!
//! These records preserve attribution and optional raw wire context for local
//! policy, audit logs, or simulation assertions. They are not an on-chain
//! slashing transaction and do not encode chain-specific penalties.

use crate::{SessionId, ValidatorId};

/// Classification for adapter-observed evidence.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
#[derive(Clone, Debug, Eq, PartialEq)]
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
        }
    }
}
