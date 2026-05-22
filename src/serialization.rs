//! Versioned wire serialization helpers for threshold protocol payloads.

use crate::{
    errors::ThresholdError,
    types::{Commitment, SessionId, ValidatorId, COMMITMENT_BYTES, SESSION_ID_BYTES},
};

/// Current canonical wire format version.
pub const WIRE_VERSION: u8 = 1;
/// Message type tag for commitment payloads.
pub const MSG_COMMITMENT: u8 = 1;
/// Byte length of a serialized commitment payload.
pub const COMMITMENT_PAYLOAD_LEN: usize = 1 + 1 + SESSION_ID_BYTES + 2 + 4 + COMMITMENT_BYTES;

const VERSION_OFFSET: usize = 0;
const MSG_TYPE_OFFSET: usize = VERSION_OFFSET + 1;
const SESSION_ID_OFFSET: usize = MSG_TYPE_OFFSET + 1;
const VALIDATOR_OFFSET: usize = SESSION_ID_OFFSET + SESSION_ID_BYTES;
const PAYLOAD_LEN_OFFSET: usize = VALIDATOR_OFFSET + 2;
const COMMITMENT_OFFSET: usize = PAYLOAD_LEN_OFFSET + 4;

/// Encode a commitment payload into canonical versioned wire bytes.
///
/// Layout: version, message type, session ID, validator ID as big-endian `u16`,
/// payload length as big-endian `u32`, then commitment bytes.
pub fn encode_commitment_payload(
    session_id: SessionId,
    validator: ValidatorId,
    commitment: Commitment,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(COMMITMENT_PAYLOAD_LEN);
    bytes.push(WIRE_VERSION);
    bytes.push(MSG_COMMITMENT);
    bytes.extend_from_slice(&session_id);
    bytes.extend_from_slice(&validator.0.to_be_bytes());
    bytes.extend_from_slice(&(COMMITMENT_BYTES as u32).to_be_bytes());
    bytes.extend_from_slice(&commitment.0);
    bytes
}

/// Decode a canonical versioned commitment payload.
pub fn decode_commitment_payload(
    bytes: &[u8],
) -> Result<(SessionId, ValidatorId, Commitment), ThresholdError> {
    if bytes.len() != COMMITMENT_PAYLOAD_LEN {
        return malformed("invalid length");
    }
    if bytes[VERSION_OFFSET] != WIRE_VERSION {
        return malformed("unsupported version");
    }
    if bytes[MSG_TYPE_OFFSET] != MSG_COMMITMENT {
        return malformed("unexpected message type");
    }

    let payload_len = u32::from_be_bytes([
        bytes[PAYLOAD_LEN_OFFSET],
        bytes[PAYLOAD_LEN_OFFSET + 1],
        bytes[PAYLOAD_LEN_OFFSET + 2],
        bytes[PAYLOAD_LEN_OFFSET + 3],
    ]);
    if payload_len != COMMITMENT_BYTES as u32 {
        return malformed("invalid payload length");
    }

    let mut session_id = [0; SESSION_ID_BYTES];
    session_id.copy_from_slice(&bytes[SESSION_ID_OFFSET..VALIDATOR_OFFSET]);

    let validator = ValidatorId(u16::from_be_bytes([
        bytes[VALIDATOR_OFFSET],
        bytes[VALIDATOR_OFFSET + 1],
    ]));

    let mut commitment = [0; COMMITMENT_BYTES];
    commitment.copy_from_slice(&bytes[COMMITMENT_OFFSET..COMMITMENT_PAYLOAD_LEN]);

    Ok((session_id, validator, Commitment(commitment)))
}

fn malformed<T>(reason: &'static str) -> Result<T, ThresholdError> {
    Err(ThresholdError::MalformedSerialization { reason })
}
