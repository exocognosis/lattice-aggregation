//! Versioned threshold wire messages and canonical byte encoding.

use crate::SessionId;

/// Maximum encrypted DKG share payload accepted by the adapter.
pub const MAX_DKG_SHARE_BYTES: usize = 16 * 1024;
/// Maximum partial signature share payload accepted by the adapter.
pub const MAX_PARTIAL_SHARE_BYTES: usize = 16 * 1024;

const WIRE_VERSION: u8 = 1;
const MSG_DKG_COMMIT: u8 = 1;
const MSG_DKG_SHARE_EXCHANGE: u8 = 2;
const MSG_SIGN_COMMIT: u8 = 3;
const MSG_PARTIAL_SIGNATURE: u8 = 4;

/// Decode failure for canonical adapter wire frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WireDecodeError {
    /// Frame is shorter or longer than required for its message type.
    #[error("invalid wire length")]
    InvalidLength,
    /// Version byte is unsupported.
    #[error("unsupported wire version")]
    UnsupportedVersion,
    /// Message type byte is unknown.
    #[error("unknown wire message type")]
    UnknownMessageType,
    /// Variable payload length exceeds adapter bounds.
    #[error("wire payload too large")]
    PayloadTooLarge,
}

/// Threshold protocol wire message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PqcThresholdWireMsg {
    /// Distributed key generation commitment.
    DkgCommit {
        /// Protocol session ID.
        session_id: SessionId,
        /// Sending validator index.
        validator_index: u16,
        /// Commitment digest.
        commitment_hash: [u8; 32],
    },
    /// Targeted encrypted DKG share exchange.
    DkgShareExchange {
        /// Protocol session ID.
        session_id: SessionId,
        /// Receiving validator index.
        target_validator_index: u16,
        /// Encrypted share bytes.
        encrypted_share: Vec<u8>,
    },
    /// Signing commitment for a block height.
    SignCommit {
        /// Protocol session ID.
        session_id: SessionId,
        /// Block height being signed.
        block_height: u64,
        /// Sending validator index.
        validator_index: u16,
        /// Commitment bytes.
        commitment: [u8; 32],
    },
    /// Partial signature response.
    PartialSignature {
        /// Protocol session ID.
        session_id: SessionId,
        /// Sending validator index.
        validator_index: u16,
        /// Backend-defined partial share bytes.
        partial_sig_share: Vec<u8>,
    },
}

impl PqcThresholdWireMsg {
    /// Encode this message into canonical versioned bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::DkgCommit {
                session_id,
                validator_index,
                commitment_hash,
            } => {
                let mut out = Vec::with_capacity(68);
                out.push(WIRE_VERSION);
                out.push(MSG_DKG_COMMIT);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&validator_index.to_be_bytes());
                out.extend_from_slice(commitment_hash);
                out
            }
            Self::DkgShareExchange {
                session_id,
                target_validator_index,
                encrypted_share,
            } => encode_variable(
                MSG_DKG_SHARE_EXCHANGE,
                session_id,
                *target_validator_index,
                encrypted_share,
            ),
            Self::SignCommit {
                session_id,
                block_height,
                validator_index,
                commitment,
            } => {
                let mut out = Vec::with_capacity(76);
                out.push(WIRE_VERSION);
                out.push(MSG_SIGN_COMMIT);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&block_height.to_be_bytes());
                out.extend_from_slice(&validator_index.to_be_bytes());
                out.extend_from_slice(commitment);
                out
            }
            Self::PartialSignature {
                session_id,
                validator_index,
                partial_sig_share,
            } => encode_variable(
                MSG_PARTIAL_SIGNATURE,
                session_id,
                *validator_index,
                partial_sig_share,
            ),
        }
    }

    /// Decode canonical versioned bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireDecodeError> {
        if bytes.len() < 2 {
            return Err(WireDecodeError::InvalidLength);
        }
        if bytes[0] != WIRE_VERSION {
            return Err(WireDecodeError::UnsupportedVersion);
        }

        match bytes[1] {
            MSG_DKG_COMMIT => decode_dkg_commit(bytes),
            MSG_DKG_SHARE_EXCHANGE => decode_variable(bytes, MAX_DKG_SHARE_BYTES).map(
                |(session_id, target_validator_index, encrypted_share)| Self::DkgShareExchange {
                    session_id,
                    target_validator_index,
                    encrypted_share,
                },
            ),
            MSG_SIGN_COMMIT => decode_sign_commit(bytes),
            MSG_PARTIAL_SIGNATURE => decode_variable(bytes, MAX_PARTIAL_SHARE_BYTES).map(
                |(session_id, validator_index, partial_sig_share)| Self::PartialSignature {
                    session_id,
                    validator_index,
                    partial_sig_share,
                },
            ),
            _ => Err(WireDecodeError::UnknownMessageType),
        }
    }
}

fn encode_variable(
    msg_type: u8,
    session_id: &SessionId,
    validator: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(40 + payload.len());
    out.push(WIRE_VERSION);
    out.push(msg_type);
    out.extend_from_slice(session_id);
    out.extend_from_slice(&validator.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn decode_dkg_commit(bytes: &[u8]) -> Result<PqcThresholdWireMsg, WireDecodeError> {
    if bytes.len() != 68 {
        return Err(WireDecodeError::InvalidLength);
    }

    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&bytes[2..34]);
    let validator_index = u16::from_be_bytes([bytes[34], bytes[35]]);
    let mut commitment_hash = [0u8; 32];
    commitment_hash.copy_from_slice(&bytes[36..68]);

    Ok(PqcThresholdWireMsg::DkgCommit {
        session_id,
        validator_index,
        commitment_hash,
    })
}

fn decode_sign_commit(bytes: &[u8]) -> Result<PqcThresholdWireMsg, WireDecodeError> {
    if bytes.len() != 76 {
        return Err(WireDecodeError::InvalidLength);
    }

    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&bytes[2..34]);
    let mut block_height = [0u8; 8];
    block_height.copy_from_slice(&bytes[34..42]);
    let validator_index = u16::from_be_bytes([bytes[42], bytes[43]]);
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&bytes[44..76]);

    Ok(PqcThresholdWireMsg::SignCommit {
        session_id,
        block_height: u64::from_be_bytes(block_height),
        validator_index,
        commitment,
    })
}

fn decode_variable(
    bytes: &[u8],
    max_payload: usize,
) -> Result<(SessionId, u16, Vec<u8>), WireDecodeError> {
    if bytes.len() < 40 {
        return Err(WireDecodeError::InvalidLength);
    }

    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&bytes[2..34]);
    let validator = u16::from_be_bytes([bytes[34], bytes[35]]);
    let mut payload_len = [0u8; 4];
    payload_len.copy_from_slice(&bytes[36..40]);
    let payload_len = u32::from_be_bytes(payload_len) as usize;

    if payload_len > max_payload {
        return Err(WireDecodeError::PayloadTooLarge);
    }
    if bytes.len() != 40 + payload_len {
        return Err(WireDecodeError::InvalidLength);
    }

    Ok((session_id, validator, bytes[40..].to_vec()))
}
