//! Version 2 coordinator-assisted production wire frames.

use crate::SessionId;

const WIRE_VERSION: u8 = 2;
const MSG_COORDINATOR_CHALLENGE: u8 = 3;
const MSG_COORDINATOR_ABORT: u8 = 4;

/// Decode failure for production wire frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProductionWireDecodeError {
    /// Frame length is invalid.
    #[error("invalid production wire length")]
    InvalidLength,
    /// Wire version is unsupported.
    #[error("unsupported production wire version")]
    UnsupportedVersion,
    /// Message type is unknown.
    #[error("unknown production wire message type")]
    UnknownMessageType,
}

/// Production coordinator wire messages.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProductionWireMsg {
    /// Coordinator challenge broadcast.
    CoordinatorChallenge {
        /// Session ID.
        session_id: SessionId,
        /// Epoch.
        epoch: u64,
        /// Attempt ID.
        attempt_id: [u8; 32],
        /// Active signer set digest.
        active_set_digest: [u8; 32],
        /// Challenge digest.
        challenge_digest: [u8; 32],
    },
    /// Coordinator abort notice.
    CoordinatorAbort {
        /// Session ID.
        session_id: SessionId,
        /// Epoch.
        epoch: u64,
        /// Attempt ID.
        attempt_id: [u8; 32],
        /// Public abort reason code.
        reason_code: u16,
    },
}

impl ProductionWireMsg {
    /// Encode canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::CoordinatorChallenge {
                session_id,
                epoch,
                attempt_id,
                active_set_digest,
                challenge_digest,
            } => {
                let mut out = Vec::with_capacity(138);
                out.push(WIRE_VERSION);
                out.push(MSG_COORDINATOR_CHALLENGE);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(attempt_id);
                out.extend_from_slice(active_set_digest);
                out.extend_from_slice(challenge_digest);
                out
            }
            Self::CoordinatorAbort {
                session_id,
                epoch,
                attempt_id,
                reason_code,
            } => {
                let mut out = Vec::with_capacity(76);
                out.push(WIRE_VERSION);
                out.push(MSG_COORDINATOR_ABORT);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(attempt_id);
                out.extend_from_slice(&reason_code.to_be_bytes());
                out
            }
        }
    }

    /// Decode canonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProductionWireDecodeError> {
        if bytes.len() < 2 {
            return Err(ProductionWireDecodeError::InvalidLength);
        }
        if bytes[0] != WIRE_VERSION {
            return Err(ProductionWireDecodeError::UnsupportedVersion);
        }
        match bytes[1] {
            MSG_COORDINATOR_CHALLENGE => decode_challenge(bytes),
            MSG_COORDINATOR_ABORT => decode_abort(bytes),
            _ => Err(ProductionWireDecodeError::UnknownMessageType),
        }
    }
}

fn decode_challenge(bytes: &[u8]) -> Result<ProductionWireMsg, ProductionWireDecodeError> {
    if bytes.len() != 138 {
        return Err(ProductionWireDecodeError::InvalidLength);
    }
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&bytes[2..34]);
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&bytes[34..42]);
    let mut attempt_id = [0u8; 32];
    attempt_id.copy_from_slice(&bytes[42..74]);
    let mut active_set_digest = [0u8; 32];
    active_set_digest.copy_from_slice(&bytes[74..106]);
    let mut challenge_digest = [0u8; 32];
    challenge_digest.copy_from_slice(&bytes[106..138]);
    Ok(ProductionWireMsg::CoordinatorChallenge {
        session_id,
        epoch: u64::from_be_bytes(epoch),
        attempt_id,
        active_set_digest,
        challenge_digest,
    })
}

fn decode_abort(bytes: &[u8]) -> Result<ProductionWireMsg, ProductionWireDecodeError> {
    if bytes.len() != 76 {
        return Err(ProductionWireDecodeError::InvalidLength);
    }
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&bytes[2..34]);
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&bytes[34..42]);
    let mut attempt_id = [0u8; 32];
    attempt_id.copy_from_slice(&bytes[42..74]);
    let reason_code = u16::from_be_bytes([bytes[74], bytes[75]]);
    Ok(ProductionWireMsg::CoordinatorAbort {
        session_id,
        epoch: u64::from_be_bytes(epoch),
        attempt_id,
        reason_code,
    })
}
