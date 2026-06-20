//! Version 2 coordinator-assisted production wire frames.

use crate::SessionId;

const WIRE_VERSION: u8 = 2;
const MSG_COORDINATOR_CHALLENGE: u8 = 3;
const MSG_COORDINATOR_ABORT: u8 = 4;
const MSG_PREFILTER_ABORT: u8 = 5;
const MSG_PREFILTER_PASS: u8 = 6;
const MSG_HINT_ROUTING_REQUEST: u8 = 7;
const MSG_HINT_ROUTING_RESPONSE: u8 = 8;

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
    /// Blinded pre-filter abort notice.
    PreFilterAbort {
        /// Session ID.
        session_id: SessionId,
        /// Epoch.
        epoch: u64,
        /// Attempt ID.
        attempt_id: [u8; 32],
        /// Public abort reason code.
        reason_code: u16,
        /// Declared aggregate infinity norm.
        aggregate_infinity_norm: u32,
    },
    /// Blinded pre-filter pass notice.
    PreFilterPass {
        /// Session ID.
        session_id: SessionId,
        /// Epoch.
        epoch: u64,
        /// Attempt ID.
        attempt_id: [u8; 32],
        /// Configured clearance boundary.
        clearance_boundary: u32,
        /// Accepted aggregate infinity norm.
        aggregate_infinity_norm: u32,
    },
    /// Hint-routing request with public context digests only.
    HintRoutingRequest {
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
        /// Near-boundary commitment digest.
        near_boundary_commitment_digest: [u8; 32],
    },
    /// Hint-routing response with public response digest only.
    HintRoutingResponse {
        /// Session ID.
        session_id: SessionId,
        /// Epoch.
        epoch: u64,
        /// Attempt ID.
        attempt_id: [u8; 32],
        /// Responding validator index.
        validator_index: u16,
        /// Public response digest.
        response_digest: [u8; 32],
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
            Self::PreFilterAbort {
                session_id,
                epoch,
                attempt_id,
                reason_code,
                aggregate_infinity_norm,
            } => {
                let mut out = Vec::with_capacity(80);
                out.push(WIRE_VERSION);
                out.push(MSG_PREFILTER_ABORT);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(attempt_id);
                out.extend_from_slice(&reason_code.to_be_bytes());
                out.extend_from_slice(&aggregate_infinity_norm.to_be_bytes());
                out
            }
            Self::PreFilterPass {
                session_id,
                epoch,
                attempt_id,
                clearance_boundary,
                aggregate_infinity_norm,
            } => {
                let mut out = Vec::with_capacity(82);
                out.push(WIRE_VERSION);
                out.push(MSG_PREFILTER_PASS);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(attempt_id);
                out.extend_from_slice(&clearance_boundary.to_be_bytes());
                out.extend_from_slice(&aggregate_infinity_norm.to_be_bytes());
                out
            }
            Self::HintRoutingRequest {
                session_id,
                epoch,
                attempt_id,
                active_set_digest,
                challenge_digest,
                near_boundary_commitment_digest,
            } => {
                let mut out = Vec::with_capacity(170);
                out.push(WIRE_VERSION);
                out.push(MSG_HINT_ROUTING_REQUEST);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(attempt_id);
                out.extend_from_slice(active_set_digest);
                out.extend_from_slice(challenge_digest);
                out.extend_from_slice(near_boundary_commitment_digest);
                out
            }
            Self::HintRoutingResponse {
                session_id,
                epoch,
                attempt_id,
                validator_index,
                response_digest,
            } => {
                let mut out = Vec::with_capacity(108);
                out.push(WIRE_VERSION);
                out.push(MSG_HINT_ROUTING_RESPONSE);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(attempt_id);
                out.extend_from_slice(&validator_index.to_be_bytes());
                out.extend_from_slice(response_digest);
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
            MSG_PREFILTER_ABORT => decode_prefilter_abort(bytes),
            MSG_PREFILTER_PASS => decode_prefilter_pass(bytes),
            MSG_HINT_ROUTING_REQUEST => decode_hint_routing_request(bytes),
            MSG_HINT_ROUTING_RESPONSE => decode_hint_routing_response(bytes),
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

fn decode_prefilter_abort(bytes: &[u8]) -> Result<ProductionWireMsg, ProductionWireDecodeError> {
    if bytes.len() != 80 {
        return Err(ProductionWireDecodeError::InvalidLength);
    }
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&bytes[2..34]);
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&bytes[34..42]);
    let mut attempt_id = [0u8; 32];
    attempt_id.copy_from_slice(&bytes[42..74]);
    let reason_code = u16::from_be_bytes([bytes[74], bytes[75]]);
    let aggregate_infinity_norm = u32::from_be_bytes([bytes[76], bytes[77], bytes[78], bytes[79]]);
    Ok(ProductionWireMsg::PreFilterAbort {
        session_id,
        epoch: u64::from_be_bytes(epoch),
        attempt_id,
        reason_code,
        aggregate_infinity_norm,
    })
}

fn decode_prefilter_pass(bytes: &[u8]) -> Result<ProductionWireMsg, ProductionWireDecodeError> {
    if bytes.len() != 82 {
        return Err(ProductionWireDecodeError::InvalidLength);
    }
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&bytes[2..34]);
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&bytes[34..42]);
    let mut attempt_id = [0u8; 32];
    attempt_id.copy_from_slice(&bytes[42..74]);
    let clearance_boundary = u32::from_be_bytes([bytes[74], bytes[75], bytes[76], bytes[77]]);
    let aggregate_infinity_norm = u32::from_be_bytes([bytes[78], bytes[79], bytes[80], bytes[81]]);
    Ok(ProductionWireMsg::PreFilterPass {
        session_id,
        epoch: u64::from_be_bytes(epoch),
        attempt_id,
        clearance_boundary,
        aggregate_infinity_norm,
    })
}

fn decode_hint_routing_request(
    bytes: &[u8],
) -> Result<ProductionWireMsg, ProductionWireDecodeError> {
    if bytes.len() != 170 {
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
    let mut near_boundary_commitment_digest = [0u8; 32];
    near_boundary_commitment_digest.copy_from_slice(&bytes[138..170]);
    Ok(ProductionWireMsg::HintRoutingRequest {
        session_id,
        epoch: u64::from_be_bytes(epoch),
        attempt_id,
        active_set_digest,
        challenge_digest,
        near_boundary_commitment_digest,
    })
}

fn decode_hint_routing_response(
    bytes: &[u8],
) -> Result<ProductionWireMsg, ProductionWireDecodeError> {
    if bytes.len() != 108 {
        return Err(ProductionWireDecodeError::InvalidLength);
    }
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&bytes[2..34]);
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&bytes[34..42]);
    let mut attempt_id = [0u8; 32];
    attempt_id.copy_from_slice(&bytes[42..74]);
    let validator_index = u16::from_be_bytes([bytes[74], bytes[75]]);
    let mut response_digest = [0u8; 32];
    response_digest.copy_from_slice(&bytes[76..108]);
    Ok(ProductionWireMsg::HintRoutingResponse {
        session_id,
        epoch: u64::from_be_bytes(epoch),
        attempt_id,
        validator_index,
        response_digest,
    })
}
