//! Versioned threshold wire messages and canonical byte encoding.

#[cfg(feature = "hazmat-real-mldsa")]
use crate::crypto::contribution_proof::{ContributionProof, CONTRIBUTION_PROOF_BYTES};
use crate::SessionId;

/// Maximum encrypted DKG share payload accepted by the adapter.
pub const MAX_DKG_SHARE_BYTES: usize = 16 * 1024;
/// Maximum partial signature share payload accepted by the adapter.
pub const MAX_PARTIAL_SHARE_BYTES: usize = 16 * 1024;
/// Maximum encoded hazmat ML-DSA-65 masking contribution accepted by the adapter.
#[cfg(feature = "hazmat-real-mldsa")]
pub const MAX_HAZMAT_MLDSA65_MASKING_CONTRIBUTION_BYTES: usize = 16 * 1024;
/// Maximum encoded hazmat ML-DSA-65 secret contribution accepted by the adapter.
#[cfg(feature = "hazmat-real-mldsa")]
pub const MAX_HAZMAT_MLDSA65_SECRET_CONTRIBUTION_BYTES: usize = 24 * 1024;

const WIRE_VERSION: u8 = 1;
const MSG_DKG_COMMIT: u8 = 1;
const MSG_DKG_SHARE_EXCHANGE: u8 = 2;
const MSG_SIGN_COMMIT: u8 = 3;
const MSG_PARTIAL_SIGNATURE: u8 = 4;
#[cfg(feature = "hazmat-real-mldsa")]
const MSG_HAZMAT_MLDSA65_MASKING_CONTRIBUTION: u8 = 5;
#[cfg(feature = "hazmat-real-mldsa")]
const MSG_HAZMAT_MLDSA65_CHALLENGE: u8 = 6;
#[cfg(feature = "hazmat-real-mldsa")]
const MSG_HAZMAT_MLDSA65_SECRET_CONTRIBUTION: u8 = 7;
#[cfg(feature = "hazmat-real-mldsa")]
const MSG_HAZMAT_MLDSA65_MASKING_COMMITMENT: u8 = 8;
#[cfg(feature = "hazmat-real-mldsa")]
const MSG_HAZMAT_MLDSA65_SECRET_COMMITMENT: u8 = 9;
#[cfg(feature = "hazmat-real-mldsa")]
const MSG_HAZMAT_MLDSA65_PROOF_BOUND_SECRET_CONTRIBUTION: u8 = 10;

#[cfg(feature = "hazmat-real-mldsa")]
type HazmatVariableFrame = (
    SessionId,
    u64,
    u16,
    u16,
    Option<[u8; crate::mldsa65::MLDSA65_CHALLENGE_BYTES]>,
    Vec<u8>,
);

/// Decode failure for canonical adapter wire frames.
#[non_exhaustive]
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
///
/// `SignCommit` carries `validator_index` in this adapter scaffold so actor
/// simulations can attribute commitments without a separate transport envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
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
    /// Hazmat ML-DSA-65 round-1 masking contribution.
    #[cfg(feature = "hazmat-real-mldsa")]
    HazmatMldsa65MaskingContribution {
        /// Protocol session ID.
        session_id: SessionId,
        /// Block height being signed.
        block_height: u64,
        /// Rejection-sampling attempt number.
        attempt: u16,
        /// Sending validator index.
        validator_index: u16,
        /// Encoded [`crate::mldsa65::Mldsa65MaskingContribution`] bytes.
        payload: Vec<u8>,
    },
    /// Hazmat ML-DSA-65 round-1 masking precommitment.
    #[cfg(feature = "hazmat-real-mldsa")]
    HazmatMldsa65MaskingCommitment {
        /// Protocol session ID.
        session_id: SessionId,
        /// Block height being signed.
        block_height: u64,
        /// Rejection-sampling attempt number.
        attempt: u16,
        /// Sending validator index.
        validator_index: u16,
        /// Commitment digest binding the later masking opening.
        commitment: [u8; 32],
    },
    /// Hazmat ML-DSA-65 challenge fixed after masking quorum.
    #[cfg(feature = "hazmat-real-mldsa")]
    HazmatMldsa65Challenge {
        /// Protocol session ID.
        session_id: SessionId,
        /// Block height being signed.
        block_height: u64,
        /// Rejection-sampling attempt number.
        attempt: u16,
        /// ML-DSA-65 `c_tilde` challenge bytes.
        challenge: [u8; crate::mldsa65::MLDSA65_CHALLENGE_BYTES],
    },
    /// Hazmat ML-DSA-65 round-2 secret precommitment.
    #[cfg(feature = "hazmat-real-mldsa")]
    HazmatMldsa65SecretCommitment {
        /// Protocol session ID.
        session_id: SessionId,
        /// Block height being signed.
        block_height: u64,
        /// Rejection-sampling attempt number.
        attempt: u16,
        /// Sending validator index.
        validator_index: u16,
        /// Challenge the later secret opening must be bound to.
        challenge: [u8; crate::mldsa65::MLDSA65_CHALLENGE_BYTES],
        /// Commitment digest binding the later secret opening.
        commitment: [u8; 32],
    },
    /// Hazmat ML-DSA-65 round-2 secret contribution.
    #[cfg(feature = "hazmat-real-mldsa")]
    HazmatMldsa65SecretContribution {
        /// Protocol session ID.
        session_id: SessionId,
        /// Block height being signed.
        block_height: u64,
        /// Rejection-sampling attempt number.
        attempt: u16,
        /// Sending validator index.
        validator_index: u16,
        /// Challenge this contribution is bound to.
        challenge: [u8; crate::mldsa65::MLDSA65_CHALLENGE_BYTES],
        /// Encoded [`crate::mldsa65::Mldsa65PartialSecretContribution`] bytes.
        payload: Vec<u8>,
    },
    /// Hazmat ML-DSA-65 round-2 secret contribution with proof binding.
    #[cfg(feature = "hazmat-real-mldsa")]
    HazmatMldsa65ProofBoundSecretContribution {
        /// Protocol session ID.
        session_id: SessionId,
        /// Block height being signed.
        block_height: u64,
        /// Rejection-sampling attempt number.
        attempt: u16,
        /// Sending validator index.
        validator_index: u16,
        /// Challenge this contribution is bound to.
        challenge: [u8; crate::mldsa65::MLDSA65_CHALLENGE_BYTES],
        /// Digest of the corresponding masking precommitment.
        masking_commitment_digest: [u8; 32],
        /// Digest of the corresponding secret precommitment.
        secret_commitment_digest: [u8; 32],
        /// Digest binding this opening to the epoch DKG public commitment material.
        dkg_commitment_digest: [u8; 32],
        /// Digest of the canonical production-target contribution statement.
        production_statement_digest: [u8; 32],
        /// Scaffold proof binding the statement to the payload digest.
        proof: ContributionProof,
        /// Encoded [`crate::mldsa65::Mldsa65PartialSecretContribution`] bytes.
        payload: Vec<u8>,
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
            #[cfg(feature = "hazmat-real-mldsa")]
            Self::HazmatMldsa65MaskingContribution {
                session_id,
                block_height,
                attempt,
                validator_index,
                payload,
            } => encode_hazmat_variable(
                MSG_HAZMAT_MLDSA65_MASKING_CONTRIBUTION,
                session_id,
                *block_height,
                *attempt,
                *validator_index,
                None,
                payload,
            ),
            #[cfg(feature = "hazmat-real-mldsa")]
            Self::HazmatMldsa65MaskingCommitment {
                session_id,
                block_height,
                attempt,
                validator_index,
                commitment,
            } => {
                let mut out = Vec::with_capacity(78);
                out.push(WIRE_VERSION);
                out.push(MSG_HAZMAT_MLDSA65_MASKING_COMMITMENT);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&block_height.to_be_bytes());
                out.extend_from_slice(&attempt.to_be_bytes());
                out.extend_from_slice(&validator_index.to_be_bytes());
                out.extend_from_slice(commitment);
                out
            }
            #[cfg(feature = "hazmat-real-mldsa")]
            Self::HazmatMldsa65Challenge {
                session_id,
                block_height,
                attempt,
                challenge,
            } => {
                let mut out = Vec::with_capacity(92);
                out.push(WIRE_VERSION);
                out.push(MSG_HAZMAT_MLDSA65_CHALLENGE);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&block_height.to_be_bytes());
                out.extend_from_slice(&attempt.to_be_bytes());
                out.extend_from_slice(challenge);
                out
            }
            #[cfg(feature = "hazmat-real-mldsa")]
            Self::HazmatMldsa65SecretCommitment {
                session_id,
                block_height,
                attempt,
                validator_index,
                challenge,
                commitment,
            } => {
                let mut out = Vec::with_capacity(126);
                out.push(WIRE_VERSION);
                out.push(MSG_HAZMAT_MLDSA65_SECRET_COMMITMENT);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&block_height.to_be_bytes());
                out.extend_from_slice(&attempt.to_be_bytes());
                out.extend_from_slice(&validator_index.to_be_bytes());
                out.extend_from_slice(challenge);
                out.extend_from_slice(commitment);
                out
            }
            #[cfg(feature = "hazmat-real-mldsa")]
            Self::HazmatMldsa65SecretContribution {
                session_id,
                block_height,
                attempt,
                validator_index,
                challenge,
                payload,
            } => encode_hazmat_variable(
                MSG_HAZMAT_MLDSA65_SECRET_CONTRIBUTION,
                session_id,
                *block_height,
                *attempt,
                *validator_index,
                Some(challenge),
                payload,
            ),
            #[cfg(feature = "hazmat-real-mldsa")]
            Self::HazmatMldsa65ProofBoundSecretContribution {
                session_id,
                block_height,
                attempt,
                validator_index,
                challenge,
                masking_commitment_digest,
                secret_commitment_digest,
                dkg_commitment_digest,
                production_statement_digest,
                proof,
                payload,
            } => {
                assert!(
                    payload.len() <= u32::MAX as usize,
                    "wire payload length exceeds u32 framing capacity"
                );
                let mut out = Vec::with_capacity(294 + payload.len());
                out.push(WIRE_VERSION);
                out.push(MSG_HAZMAT_MLDSA65_PROOF_BOUND_SECRET_CONTRIBUTION);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&block_height.to_be_bytes());
                out.extend_from_slice(&attempt.to_be_bytes());
                out.extend_from_slice(&validator_index.to_be_bytes());
                out.extend_from_slice(challenge);
                out.extend_from_slice(masking_commitment_digest);
                out.extend_from_slice(secret_commitment_digest);
                out.extend_from_slice(dkg_commitment_digest);
                out.extend_from_slice(production_statement_digest);
                out.extend_from_slice(&proof.to_canonical_bytes());
                out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                out.extend_from_slice(payload);
                out
            }
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
            #[cfg(feature = "hazmat-real-mldsa")]
            MSG_HAZMAT_MLDSA65_MASKING_CONTRIBUTION => {
                decode_hazmat_variable(bytes, MAX_HAZMAT_MLDSA65_MASKING_CONTRIBUTION_BYTES, false)
                    .map(
                        |(
                            session_id,
                            block_height,
                            attempt,
                            validator_index,
                            _challenge,
                            payload,
                        )| {
                            Self::HazmatMldsa65MaskingContribution {
                                session_id,
                                block_height,
                                attempt,
                                validator_index,
                                payload,
                            }
                        },
                    )
            }
            #[cfg(feature = "hazmat-real-mldsa")]
            MSG_HAZMAT_MLDSA65_CHALLENGE => decode_hazmat_challenge(bytes),
            #[cfg(feature = "hazmat-real-mldsa")]
            MSG_HAZMAT_MLDSA65_SECRET_CONTRIBUTION => {
                decode_hazmat_variable(bytes, MAX_HAZMAT_MLDSA65_SECRET_CONTRIBUTION_BYTES, true)
                    .map(
                        |(
                            session_id,
                            block_height,
                            attempt,
                            validator_index,
                            challenge,
                            payload,
                        )| {
                            Self::HazmatMldsa65SecretContribution {
                                session_id,
                                block_height,
                                attempt,
                                validator_index,
                                challenge: challenge
                                    .expect("challenge is decoded for secret frames"),
                                payload,
                            }
                        },
                    )
            }
            #[cfg(feature = "hazmat-real-mldsa")]
            MSG_HAZMAT_MLDSA65_MASKING_COMMITMENT => decode_hazmat_masking_commitment(bytes),
            #[cfg(feature = "hazmat-real-mldsa")]
            MSG_HAZMAT_MLDSA65_SECRET_COMMITMENT => decode_hazmat_secret_commitment(bytes),
            #[cfg(feature = "hazmat-real-mldsa")]
            MSG_HAZMAT_MLDSA65_PROOF_BOUND_SECRET_CONTRIBUTION => {
                decode_hazmat_proof_bound_secret_contribution(bytes)
            }
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
    assert!(
        payload.len() <= u32::MAX as usize,
        "wire payload length exceeds u32 framing capacity"
    );
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

#[cfg(feature = "hazmat-real-mldsa")]
fn encode_hazmat_variable(
    msg_type: u8,
    session_id: &SessionId,
    block_height: u64,
    attempt: u16,
    validator_index: u16,
    challenge: Option<&[u8; crate::mldsa65::MLDSA65_CHALLENGE_BYTES]>,
    payload: &[u8],
) -> Vec<u8> {
    assert!(
        payload.len() <= u32::MAX as usize,
        "wire payload length exceeds u32 framing capacity"
    );
    let challenge_len = challenge.map_or(0, |_| crate::mldsa65::MLDSA65_CHALLENGE_BYTES);
    let mut out = Vec::with_capacity(50 + challenge_len + payload.len());
    out.push(WIRE_VERSION);
    out.push(msg_type);
    out.extend_from_slice(session_id);
    out.extend_from_slice(&block_height.to_be_bytes());
    out.extend_from_slice(&attempt.to_be_bytes());
    out.extend_from_slice(&validator_index.to_be_bytes());
    if let Some(challenge) = challenge {
        out.extend_from_slice(challenge);
    }
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[cfg(feature = "hazmat-real-mldsa")]
fn decode_hazmat_challenge(bytes: &[u8]) -> Result<PqcThresholdWireMsg, WireDecodeError> {
    if bytes.len() != 92 {
        return Err(WireDecodeError::InvalidLength);
    }

    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&bytes[2..34]);
    let mut block_height = [0u8; 8];
    block_height.copy_from_slice(&bytes[34..42]);
    let attempt = u16::from_be_bytes([bytes[42], bytes[43]]);
    let mut challenge = [0u8; crate::mldsa65::MLDSA65_CHALLENGE_BYTES];
    challenge.copy_from_slice(&bytes[44..92]);

    Ok(PqcThresholdWireMsg::HazmatMldsa65Challenge {
        session_id,
        block_height: u64::from_be_bytes(block_height),
        attempt,
        challenge,
    })
}

#[cfg(feature = "hazmat-real-mldsa")]
fn decode_hazmat_masking_commitment(bytes: &[u8]) -> Result<PqcThresholdWireMsg, WireDecodeError> {
    if bytes.len() != 78 {
        return Err(WireDecodeError::InvalidLength);
    }

    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&bytes[2..34]);
    let mut block_height = [0u8; 8];
    block_height.copy_from_slice(&bytes[34..42]);
    let attempt = u16::from_be_bytes([bytes[42], bytes[43]]);
    let validator_index = u16::from_be_bytes([bytes[44], bytes[45]]);
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&bytes[46..78]);

    Ok(PqcThresholdWireMsg::HazmatMldsa65MaskingCommitment {
        session_id,
        block_height: u64::from_be_bytes(block_height),
        attempt,
        validator_index,
        commitment,
    })
}

#[cfg(feature = "hazmat-real-mldsa")]
fn decode_hazmat_secret_commitment(bytes: &[u8]) -> Result<PqcThresholdWireMsg, WireDecodeError> {
    if bytes.len() != 126 {
        return Err(WireDecodeError::InvalidLength);
    }

    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&bytes[2..34]);
    let mut block_height = [0u8; 8];
    block_height.copy_from_slice(&bytes[34..42]);
    let attempt = u16::from_be_bytes([bytes[42], bytes[43]]);
    let validator_index = u16::from_be_bytes([bytes[44], bytes[45]]);
    let mut challenge = [0u8; crate::mldsa65::MLDSA65_CHALLENGE_BYTES];
    challenge.copy_from_slice(&bytes[46..94]);
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&bytes[94..126]);

    Ok(PqcThresholdWireMsg::HazmatMldsa65SecretCommitment {
        session_id,
        block_height: u64::from_be_bytes(block_height),
        attempt,
        validator_index,
        challenge,
        commitment,
    })
}

#[cfg(feature = "hazmat-real-mldsa")]
fn decode_hazmat_variable(
    bytes: &[u8],
    max_payload: usize,
    has_challenge: bool,
) -> Result<HazmatVariableFrame, WireDecodeError> {
    let fixed_len = if has_challenge { 98 } else { 50 };
    if bytes.len() < fixed_len {
        return Err(WireDecodeError::InvalidLength);
    }

    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&bytes[2..34]);
    let mut block_height = [0u8; 8];
    block_height.copy_from_slice(&bytes[34..42]);
    let attempt = u16::from_be_bytes([bytes[42], bytes[43]]);
    let validator_index = u16::from_be_bytes([bytes[44], bytes[45]]);

    let mut cursor = 46;
    let challenge = if has_challenge {
        let mut challenge = [0u8; crate::mldsa65::MLDSA65_CHALLENGE_BYTES];
        let end = cursor + crate::mldsa65::MLDSA65_CHALLENGE_BYTES;
        challenge.copy_from_slice(&bytes[cursor..end]);
        cursor = end;
        Some(challenge)
    } else {
        None
    };

    let mut payload_len = [0u8; 4];
    payload_len.copy_from_slice(&bytes[cursor..cursor + 4]);
    cursor += 4;
    let payload_len = u32::from_be_bytes(payload_len) as usize;

    if payload_len > max_payload {
        return Err(WireDecodeError::PayloadTooLarge);
    }
    if bytes.len() != cursor + payload_len {
        return Err(WireDecodeError::InvalidLength);
    }

    Ok((
        session_id,
        u64::from_be_bytes(block_height),
        attempt,
        validator_index,
        challenge,
        bytes[cursor..].to_vec(),
    ))
}

#[cfg(feature = "hazmat-real-mldsa")]
fn decode_hazmat_proof_bound_secret_contribution(
    bytes: &[u8],
) -> Result<PqcThresholdWireMsg, WireDecodeError> {
    const FIXED_LEN: usize = 294;
    if bytes.len() < FIXED_LEN {
        return Err(WireDecodeError::InvalidLength);
    }

    let mut cursor = 2;
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

    let mut challenge = [0u8; crate::mldsa65::MLDSA65_CHALLENGE_BYTES];
    challenge.copy_from_slice(&bytes[cursor..cursor + crate::mldsa65::MLDSA65_CHALLENGE_BYTES]);
    cursor += crate::mldsa65::MLDSA65_CHALLENGE_BYTES;

    let mut masking_commitment_digest = [0u8; 32];
    masking_commitment_digest.copy_from_slice(&bytes[cursor..cursor + 32]);
    cursor += 32;

    let mut secret_commitment_digest = [0u8; 32];
    secret_commitment_digest.copy_from_slice(&bytes[cursor..cursor + 32]);
    cursor += 32;

    let mut dkg_commitment_digest = [0u8; 32];
    dkg_commitment_digest.copy_from_slice(&bytes[cursor..cursor + 32]);
    cursor += 32;

    let mut production_statement_digest = [0u8; 32];
    production_statement_digest.copy_from_slice(&bytes[cursor..cursor + 32]);
    cursor += 32;

    let proof =
        ContributionProof::from_canonical_bytes(&bytes[cursor..cursor + CONTRIBUTION_PROOF_BYTES])
            .map_err(|_| WireDecodeError::InvalidLength)?;
    cursor += CONTRIBUTION_PROOF_BYTES;

    let mut payload_len = [0u8; 4];
    payload_len.copy_from_slice(&bytes[cursor..cursor + 4]);
    cursor += 4;
    let payload_len = u32::from_be_bytes(payload_len) as usize;

    if proof.payload_len as usize != payload_len {
        return Err(WireDecodeError::InvalidLength);
    }
    if payload_len > MAX_HAZMAT_MLDSA65_SECRET_CONTRIBUTION_BYTES {
        return Err(WireDecodeError::PayloadTooLarge);
    }
    if bytes.len() != cursor + payload_len {
        return Err(WireDecodeError::InvalidLength);
    }

    Ok(
        PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
            session_id,
            block_height: u64::from_be_bytes(block_height),
            attempt,
            validator_index,
            challenge,
            masking_commitment_digest,
            secret_commitment_digest,
            dkg_commitment_digest,
            production_statement_digest,
            proof,
            payload: bytes[cursor..].to_vec(),
        },
    )
}
