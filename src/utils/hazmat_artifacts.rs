//! Reproducibility artifact exporters for hazmat ML-DSA-65 benchmark transcripts.

use std::{collections::BTreeMap, fmt::Write};

use sha3::{Digest as Sha3Digest, Sha3_256};

#[cfg(feature = "experimental-vss")]
use crate::{
    adapter::evidence::{EvidenceKind, SlashingEvidence},
    crypto::vss::ExperimentalVssComplaintEvidence,
};
use crate::{adapter::wire::PqcThresholdWireMsg, SessionId};

/// Verification failure for generated hazmat transcript artifacts.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HazmatArtifactVerificationError {
    /// Artifact contains no transcript records.
    #[error("empty transcript artifact")]
    EmptyArtifact,
    /// CSV header does not match the canonical exporter schema.
    #[error("CSV header mismatch")]
    CsvHeaderMismatch,
    /// One artifact record is malformed.
    #[error("malformed transcript record on line {line}: {reason}")]
    MalformedRecord {
        /// One-based artifact line number.
        line: usize,
        /// Static parse failure reason.
        reason: &'static str,
    },
    /// Hex field does not have the expected canonical shape.
    #[error("invalid hex field {field} on line {line}")]
    InvalidHexField {
        /// One-based artifact line number.
        line: usize,
        /// Field name.
        field: &'static str,
    },
    /// Encoded length does not match the round's wire frame constraints.
    #[error("invalid encoded length {encoded_len} for {round} on line {line}")]
    InvalidEncodedLength {
        /// One-based artifact line number.
        line: usize,
        /// Round name.
        round: String,
        /// Encoded frame length.
        encoded_len: usize,
    },
    /// Events within a trial/attempt disagree on session binding.
    #[error("session binding mismatch on line {line}")]
    SessionMismatch {
        /// One-based artifact line number.
        line: usize,
    },
    /// A precommitment/opening round appears out of order.
    #[error("invalid transcript order for {round} on line {line}")]
    InvalidRoundOrder {
        /// One-based artifact line number.
        line: usize,
        /// Round name.
        round: String,
    },
    /// Transcript event and canonical source frame disagree.
    #[error("frame binding mismatch on line {line}: {field}")]
    FrameBindingMismatch {
        /// One-based artifact line number.
        line: usize,
        /// Mismatched field name.
        field: &'static str,
    },
}

/// One replay-oriented transcript event captured from a hazmat wire frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HazmatTranscriptEvent {
    /// Human-readable experiment label.
    pub experiment: String,
    /// Zero-based benchmark trial index.
    pub trial_index: u16,
    /// Rejection-sampling attempt index.
    pub attempt_index: u16,
    /// Direction at the simulation boundary.
    pub direction: &'static str,
    /// Protocol round represented by this frame.
    pub round: &'static str,
    /// One-based validator index, or zero for non-validator-attributed frames.
    pub validator_index: u16,
    /// Block height bound into the frame.
    pub block_height: u64,
    /// Protocol session identifier.
    pub session_id: SessionId,
    /// Canonical encoded frame length.
    pub encoded_len: usize,
    /// SHA3-256 digest of the canonical encoded frame.
    pub frame_digest: [u8; 32],
    /// Digest of the canonical production contribution statement, when present.
    pub production_statement_digest: Option<[u8; 32]>,
}

/// Replay-oriented artifact for one experimental VSS complaint evidence frame.
#[cfg(feature = "experimental-vss")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentalVssComplaintArtifact {
    /// Human-readable experiment label.
    pub experiment: String,
    /// Zero-based benchmark trial index.
    pub trial_index: u16,
    /// One-based validator index attributed by the adapter.
    pub validator_index: u16,
    /// Adapter evidence classification.
    pub evidence_kind: EvidenceKind,
    /// Protocol session identifier.
    pub session_id: SessionId,
    /// Canonical evidence byte length.
    pub evidence_len: usize,
    /// SHA3-256 digest of the canonical evidence bytes.
    pub evidence_digest: [u8; 32],
    /// Digest of the canonical production VSS relation statement.
    pub production_vss_relation_statement_digest: [u8; 32],
    /// Canonical experimental VSS complaint evidence bytes.
    pub evidence_bytes: Vec<u8>,
}

/// Build a replay-oriented transcript event from one canonical hazmat wire frame.
pub fn event_from_hazmat_wire_frame(
    experiment: &str,
    trial_index: u16,
    attempt_index: u16,
    direction: &'static str,
    msg: &PqcThresholdWireMsg,
) -> HazmatTranscriptEvent {
    let encoded = msg.encode();
    let frame_digest: [u8; 32] = Sha3_256::digest(&encoded).into();
    let (round, validator_index, block_height, session_id) = classify_hazmat_frame(msg);
    let production_statement_digest = production_statement_digest_from_frame(msg);

    HazmatTranscriptEvent {
        experiment: experiment.to_string(),
        trial_index,
        attempt_index,
        direction,
        round,
        validator_index,
        block_height,
        session_id,
        encoded_len: encoded.len(),
        frame_digest,
        production_statement_digest,
    }
}

/// Build replay-oriented complaint artifacts from adapter evidence records.
#[cfg(feature = "experimental-vss")]
pub fn experimental_vss_complaint_artifacts_from_evidence(
    experiment: &str,
    trial_index: u16,
    evidence: &[SlashingEvidence],
) -> Vec<ExperimentalVssComplaintArtifact> {
    evidence
        .iter()
        .filter_map(|record| {
            let evidence_bytes = record.experimental_vss_complaint_evidence.clone()?;
            let production_vss_relation_statement_digest =
                record.production_vss_relation_statement_digest?;
            let evidence_digest = Sha3_256::digest(&evidence_bytes).into();
            Some(ExperimentalVssComplaintArtifact {
                experiment: experiment.to_string(),
                trial_index,
                validator_index: record.validator.0,
                evidence_kind: record.kind,
                session_id: record.session_id,
                evidence_len: evidence_bytes.len(),
                evidence_digest,
                production_vss_relation_statement_digest,
                evidence_bytes,
            })
        })
        .collect()
}

/// Generate newline-delimited JSON records for experimental VSS complaints.
#[cfg(feature = "experimental-vss")]
pub fn generate_experimental_vss_complaint_jsonl(
    events: &[ExperimentalVssComplaintArtifact],
) -> String {
    let mut out = String::new();
    for event in events {
        writeln!(
            &mut out,
            "{{\"experiment\":\"{}\",\"trial\":{},\"validator_index\":{},\"evidence_kind\":\"{:?}\",\"session_id\":\"{}\",\"evidence_len\":{},\"evidence_digest\":\"{}\",\"production_vss_relation_statement_digest\":\"{}\",\"evidence_hex\":\"{}\"}}",
            json_escape(&event.experiment),
            event.trial_index,
            event.validator_index,
            event.evidence_kind,
            hex_encode(&event.session_id),
            event.evidence_len,
            hex_encode(&event.evidence_digest),
            hex_encode(&event.production_vss_relation_statement_digest),
            hex_encode(&event.evidence_bytes),
        )
        .expect("writing JSONL to String cannot fail");
    }
    out
}

/// Generate CSV records for experimental VSS complaint artifacts.
#[cfg(feature = "experimental-vss")]
pub fn generate_experimental_vss_complaint_csv(
    events: &[ExperimentalVssComplaintArtifact],
) -> String {
    let mut out = String::from(
        "experiment,trial,validator_index,evidence_kind,session_id,evidence_len,evidence_digest,production_vss_relation_statement_digest,evidence_hex\n",
    );
    for event in events {
        writeln!(
            &mut out,
            "{},{},{},{:?},{},{},{},{},{}",
            csv_escape(&event.experiment),
            event.trial_index,
            event.validator_index,
            event.evidence_kind,
            hex_encode(&event.session_id),
            event.evidence_len,
            hex_encode(&event.evidence_digest),
            hex_encode(&event.production_vss_relation_statement_digest),
            hex_encode(&event.evidence_bytes),
        )
        .expect("writing CSV to String cannot fail");
    }
    out
}

/// Verify in-memory experimental VSS complaint artifacts.
#[cfg(feature = "experimental-vss")]
pub fn verify_experimental_vss_complaint_events(
    events: &[ExperimentalVssComplaintArtifact],
) -> Result<(), HazmatArtifactVerificationError> {
    if events.is_empty() {
        return Err(HazmatArtifactVerificationError::EmptyArtifact);
    }
    for (index, event) in events.iter().enumerate() {
        validate_experimental_vss_complaint_shape(index + 1, event)?;
        ExperimentalVssComplaintEvidence::from_canonical_bytes(&event.evidence_bytes).map_err(
            |_| HazmatArtifactVerificationError::MalformedRecord {
                line: index + 1,
                reason: "invalid experimental VSS complaint evidence bytes",
            },
        )?;
    }
    Ok(())
}

/// Verify generated experimental VSS complaint JSONL.
#[cfg(feature = "experimental-vss")]
pub fn verify_experimental_vss_complaint_jsonl(
    jsonl: &str,
) -> Result<(), HazmatArtifactVerificationError> {
    let records = jsonl
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| parse_experimental_vss_complaint_jsonl_record(index + 1, line))
        .collect::<Result<Vec<_>, _>>()?;
    verify_experimental_vss_complaint_events(&records)
}

/// Verify generated experimental VSS complaint CSV.
#[cfg(feature = "experimental-vss")]
pub fn verify_experimental_vss_complaint_csv(
    csv: &str,
) -> Result<(), HazmatArtifactVerificationError> {
    let mut lines = csv.lines();
    let Some(header) = lines.next() else {
        return Err(HazmatArtifactVerificationError::EmptyArtifact);
    };
    if header
        != "experiment,trial,validator_index,evidence_kind,session_id,evidence_len,evidence_digest,production_vss_relation_statement_digest,evidence_hex"
    {
        return Err(HazmatArtifactVerificationError::CsvHeaderMismatch);
    }

    let records = lines
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| parse_experimental_vss_complaint_csv_record(index + 2, line))
        .collect::<Result<Vec<_>, _>>()?;
    verify_experimental_vss_complaint_events(&records)
}

/// Generate newline-delimited JSON transcript records.
pub fn generate_hazmat_transcript_jsonl(events: &[HazmatTranscriptEvent]) -> String {
    let mut out = String::new();
    for event in events {
        writeln!(
            &mut out,
            "{{\"experiment\":\"{}\",\"trial\":{},\"attempt\":{},\"direction\":\"{}\",\"round\":\"{}\",\"validator_index\":{},\"block_height\":{},\"session_id\":\"{}\",\"encoded_len\":{},\"frame_digest\":\"{}\",\"production_statement_digest\":\"{}\"}}",
            json_escape(&event.experiment),
            event.trial_index,
            event.attempt_index,
            event.direction,
            event.round,
            event.validator_index,
            event.block_height,
            hex_encode(&event.session_id),
            event.encoded_len,
            hex_encode(&event.frame_digest),
            event
                .production_statement_digest
                .map(|digest| hex_encode(&digest))
                .unwrap_or_default(),
        )
        .expect("writing JSONL to String cannot fail");
    }
    out
}

/// Generate CSV transcript records for appendix tables and external plotting tools.
pub fn generate_hazmat_transcript_csv(events: &[HazmatTranscriptEvent]) -> String {
    let mut out = String::from(
        "experiment,trial,attempt,direction,round,validator_index,block_height,session_id,encoded_len,frame_digest,production_statement_digest\n",
    );
    for event in events {
        writeln!(
            &mut out,
            "{},{},{},{},{},{},{},{},{},{},{}",
            csv_escape(&event.experiment),
            event.trial_index,
            event.attempt_index,
            event.direction,
            event.round,
            event.validator_index,
            event.block_height,
            hex_encode(&event.session_id),
            event.encoded_len,
            hex_encode(&event.frame_digest),
            event
                .production_statement_digest
                .map(|digest| hex_encode(&digest))
                .unwrap_or_default(),
        )
        .expect("writing CSV to String cannot fail");
    }
    out
}

/// Verify in-memory transcript events emitted by the hazmat simulation harness.
pub fn verify_hazmat_transcript_events(
    events: &[HazmatTranscriptEvent],
) -> Result<(), HazmatArtifactVerificationError> {
    let records = events
        .iter()
        .enumerate()
        .map(|(index, event)| ArtifactRecord {
            line: index + 1,
            experiment: event.experiment.clone(),
            trial_index: event.trial_index,
            attempt_index: event.attempt_index,
            direction: event.direction.to_string(),
            round: event.round.to_string(),
            validator_index: event.validator_index,
            block_height: event.block_height,
            session_id_hex: hex_encode(&event.session_id),
            encoded_len: event.encoded_len,
            frame_digest_hex: hex_encode(&event.frame_digest),
            production_statement_digest_hex: event
                .production_statement_digest
                .map(|digest| hex_encode(&digest))
                .unwrap_or_default(),
        })
        .collect::<Vec<_>>();
    verify_artifact_records(&records)
}

/// Verify that in-memory transcript events bind exactly to their canonical source frames.
pub fn verify_hazmat_transcript_frame_bindings(
    events: &[HazmatTranscriptEvent],
    frames: &[PqcThresholdWireMsg],
) -> Result<(), HazmatArtifactVerificationError> {
    if events.len() != frames.len() {
        return Err(HazmatArtifactVerificationError::MalformedRecord {
            line: events.len().min(frames.len()) + 1,
            reason: "event/frame count mismatch",
        });
    }

    for (index, (event, frame)) in events.iter().zip(frames.iter()).enumerate() {
        verify_hazmat_transcript_event_frame_binding_at_line(index + 1, event, frame)?;
    }

    Ok(())
}

/// Verify that one transcript event binds exactly to its canonical source frame.
pub fn verify_hazmat_transcript_event_frame_binding(
    event: &HazmatTranscriptEvent,
    frame: &PqcThresholdWireMsg,
) -> Result<(), HazmatArtifactVerificationError> {
    verify_hazmat_transcript_event_frame_binding_at_line(1, event, frame)
}

/// Verify a newline-delimited JSON transcript artifact generated by this crate.
pub fn verify_hazmat_transcript_jsonl(jsonl: &str) -> Result<(), HazmatArtifactVerificationError> {
    let records = jsonl
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| parse_jsonl_record(index + 1, line))
        .collect::<Result<Vec<_>, _>>()?;
    verify_artifact_records(&records)
}

/// Verify a CSV transcript artifact generated by this crate.
pub fn verify_hazmat_transcript_csv(csv: &str) -> Result<(), HazmatArtifactVerificationError> {
    let mut lines = csv.lines();
    let Some(header) = lines.next() else {
        return Err(HazmatArtifactVerificationError::EmptyArtifact);
    };
    if header
        != "experiment,trial,attempt,direction,round,validator_index,block_height,session_id,encoded_len,frame_digest,production_statement_digest"
    {
        return Err(HazmatArtifactVerificationError::CsvHeaderMismatch);
    }

    let records = lines
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| parse_csv_record(index + 2, line))
        .collect::<Result<Vec<_>, _>>()?;
    verify_artifact_records(&records)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArtifactRecord {
    line: usize,
    experiment: String,
    trial_index: u16,
    attempt_index: u16,
    direction: String,
    round: String,
    validator_index: u16,
    block_height: u64,
    session_id_hex: String,
    encoded_len: usize,
    frame_digest_hex: String,
    production_statement_digest_hex: String,
}

fn verify_artifact_records(
    records: &[ArtifactRecord],
) -> Result<(), HazmatArtifactVerificationError> {
    if records.is_empty() {
        return Err(HazmatArtifactVerificationError::EmptyArtifact);
    }

    let mut attempt_bindings = BTreeMap::<(String, u16, u16), (String, u64)>::new();
    for (index, record) in records.iter().enumerate() {
        validate_record_shape(record)?;

        let key = (
            record.experiment.clone(),
            record.trial_index,
            record.attempt_index,
        );
        match attempt_bindings.get(&key) {
            Some((session_id, block_height))
                if session_id == &record.session_id_hex && *block_height == record.block_height => {
            }
            Some(_) => {
                return Err(HazmatArtifactVerificationError::SessionMismatch { line: record.line });
            }
            None => {
                attempt_bindings.insert(key, (record.session_id_hex.clone(), record.block_height));
            }
        }

        if matches!(record.round.as_str(), "masking_opening" | "secret_opening") {
            let Some(previous) = index.checked_sub(1).and_then(|prev| records.get(prev)) else {
                return Err(HazmatArtifactVerificationError::InvalidRoundOrder {
                    line: record.line,
                    round: record.round.clone(),
                });
            };
            if !is_matching_precommitment(previous, record) {
                return Err(HazmatArtifactVerificationError::InvalidRoundOrder {
                    line: record.line,
                    round: record.round.clone(),
                });
            }
        }
    }

    Ok(())
}

fn validate_record_shape(record: &ArtifactRecord) -> Result<(), HazmatArtifactVerificationError> {
    if record.experiment.is_empty() {
        return Err(HazmatArtifactVerificationError::MalformedRecord {
            line: record.line,
            reason: "empty experiment",
        });
    }
    if !is_allowed_direction(&record.direction) {
        return Err(HazmatArtifactVerificationError::MalformedRecord {
            line: record.line,
            reason: "unknown direction",
        });
    }
    if !is_hex_with_len(&record.session_id_hex, 64) {
        return Err(HazmatArtifactVerificationError::InvalidHexField {
            line: record.line,
            field: "session_id",
        });
    }
    if !is_hex_with_len(&record.frame_digest_hex, 64) {
        return Err(HazmatArtifactVerificationError::InvalidHexField {
            line: record.line,
            field: "frame_digest",
        });
    }
    if !record.production_statement_digest_hex.is_empty()
        && !is_hex_with_len(&record.production_statement_digest_hex, 64)
    {
        return Err(HazmatArtifactVerificationError::InvalidHexField {
            line: record.line,
            field: "production_statement_digest",
        });
    }
    if record.round == "secret_opening" && record.production_statement_digest_hex.is_empty() {
        return Err(HazmatArtifactVerificationError::InvalidHexField {
            line: record.line,
            field: "production_statement_digest",
        });
    }

    match record.round.as_str() {
        "masking_commitment" if record.encoded_len == 78 && record.validator_index > 0 => Ok(()),
        "secret_commitment" if record.encoded_len == 126 && record.validator_index > 0 => Ok(()),
        "masking_opening" if record.encoded_len > 50 && record.validator_index > 0 => Ok(()),
        "secret_opening" if record.encoded_len > 98 && record.validator_index > 0 => Ok(()),
        "challenge" if record.encoded_len == 92 && record.validator_index == 0 => Ok(()),
        "masking_commitment" | "secret_commitment" | "masking_opening" | "secret_opening"
        | "challenge" => Err(HazmatArtifactVerificationError::InvalidEncodedLength {
            line: record.line,
            round: record.round.clone(),
            encoded_len: record.encoded_len,
        }),
        _ => Err(HazmatArtifactVerificationError::MalformedRecord {
            line: record.line,
            reason: "unknown round",
        }),
    }
}

fn verify_hazmat_transcript_event_frame_binding_at_line(
    line: usize,
    event: &HazmatTranscriptEvent,
    frame: &PqcThresholdWireMsg,
) -> Result<(), HazmatArtifactVerificationError> {
    let (round, validator_index, block_height, session_id) = classify_hazmat_frame(frame);
    if event.round != round {
        return Err(HazmatArtifactVerificationError::FrameBindingMismatch {
            line,
            field: "round",
        });
    }
    if event.validator_index != validator_index {
        return Err(HazmatArtifactVerificationError::FrameBindingMismatch {
            line,
            field: "validator_index",
        });
    }
    if event.block_height != block_height {
        return Err(HazmatArtifactVerificationError::FrameBindingMismatch {
            line,
            field: "block_height",
        });
    }
    if event.session_id != session_id {
        return Err(HazmatArtifactVerificationError::FrameBindingMismatch {
            line,
            field: "session_id",
        });
    }
    if event.attempt_index != hazmat_attempt_from_frame(frame) {
        return Err(HazmatArtifactVerificationError::FrameBindingMismatch {
            line,
            field: "attempt",
        });
    }

    let encoded = frame.encode();
    if event.encoded_len != encoded.len() {
        return Err(HazmatArtifactVerificationError::FrameBindingMismatch {
            line,
            field: "encoded_len",
        });
    }

    let expected_frame_digest: [u8; 32] = Sha3_256::digest(&encoded).into();
    if event.frame_digest != expected_frame_digest {
        return Err(HazmatArtifactVerificationError::FrameBindingMismatch {
            line,
            field: "frame_digest",
        });
    }

    let expected_production_statement_digest = production_statement_digest_from_frame(frame);
    if event.production_statement_digest != expected_production_statement_digest {
        return Err(HazmatArtifactVerificationError::FrameBindingMismatch {
            line,
            field: "production_statement_digest",
        });
    }

    Ok(())
}

fn is_matching_precommitment(previous: &ArtifactRecord, opening: &ArtifactRecord) -> bool {
    let expected_round = match opening.round.as_str() {
        "masking_opening" => "masking_commitment",
        "secret_opening" => "secret_commitment",
        _ => return false,
    };

    previous.round == expected_round
        && previous.experiment == opening.experiment
        && previous.trial_index == opening.trial_index
        && previous.attempt_index == opening.attempt_index
        && previous.direction == opening.direction
        && previous.validator_index == opening.validator_index
        && previous.block_height == opening.block_height
        && previous.session_id_hex == opening.session_id_hex
}

fn is_allowed_direction(direction: &str) -> bool {
    matches!(
        direction,
        "local_broadcast" | "local_send_to" | "remote_inbound"
    )
}

fn parse_jsonl_record(
    line: usize,
    raw: &str,
) -> Result<ArtifactRecord, HazmatArtifactVerificationError> {
    Ok(ArtifactRecord {
        line,
        experiment: json_string_field(line, raw, "experiment")?,
        trial_index: json_number_field(line, raw, "trial")?,
        attempt_index: json_number_field(line, raw, "attempt")?,
        direction: json_string_field(line, raw, "direction")?,
        round: json_string_field(line, raw, "round")?,
        validator_index: json_number_field(line, raw, "validator_index")?,
        block_height: json_number_field(line, raw, "block_height")?,
        session_id_hex: json_string_field(line, raw, "session_id")?,
        encoded_len: json_number_field(line, raw, "encoded_len")?,
        frame_digest_hex: json_string_field(line, raw, "frame_digest")?,
        production_statement_digest_hex: json_string_field(
            line,
            raw,
            "production_statement_digest",
        )?,
    })
}

fn parse_csv_record(
    line: usize,
    raw: &str,
) -> Result<ArtifactRecord, HazmatArtifactVerificationError> {
    let fields = split_csv_line(raw);
    if fields.len() != 11 {
        return Err(HazmatArtifactVerificationError::MalformedRecord {
            line,
            reason: "wrong CSV field count",
        });
    }

    Ok(ArtifactRecord {
        line,
        experiment: fields[0].clone(),
        trial_index: parse_field(line, &fields[1], "trial")?,
        attempt_index: parse_field(line, &fields[2], "attempt")?,
        direction: fields[3].clone(),
        round: fields[4].clone(),
        validator_index: parse_field(line, &fields[5], "validator_index")?,
        block_height: parse_field(line, &fields[6], "block_height")?,
        session_id_hex: fields[7].clone(),
        encoded_len: parse_field(line, &fields[8], "encoded_len")?,
        frame_digest_hex: fields[9].clone(),
        production_statement_digest_hex: fields[10].clone(),
    })
}

#[cfg(feature = "experimental-vss")]
fn validate_experimental_vss_complaint_shape(
    line: usize,
    event: &ExperimentalVssComplaintArtifact,
) -> Result<(), HazmatArtifactVerificationError> {
    if event.experiment.is_empty() {
        return Err(HazmatArtifactVerificationError::MalformedRecord {
            line,
            reason: "empty experiment",
        });
    }
    if event.validator_index == 0 {
        return Err(HazmatArtifactVerificationError::MalformedRecord {
            line,
            reason: "empty validator index",
        });
    }
    if !matches!(event.evidence_kind, EvidenceKind::InvalidPartialSignature) {
        return Err(HazmatArtifactVerificationError::MalformedRecord {
            line,
            reason: "unsupported complaint evidence kind",
        });
    }
    if event.evidence_len != event.evidence_bytes.len() || event.evidence_len == 0 {
        return Err(HazmatArtifactVerificationError::InvalidEncodedLength {
            line,
            round: "experimental_vss_complaint".to_string(),
            encoded_len: event.evidence_len,
        });
    }
    let expected_digest: [u8; 32] = Sha3_256::digest(&event.evidence_bytes).into();
    if expected_digest != event.evidence_digest {
        return Err(HazmatArtifactVerificationError::InvalidHexField {
            line,
            field: "evidence_digest",
        });
    }
    if event
        .production_vss_relation_statement_digest
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(HazmatArtifactVerificationError::InvalidHexField {
            line,
            field: "production_vss_relation_statement_digest",
        });
    }
    Ok(())
}

#[cfg(feature = "experimental-vss")]
fn parse_experimental_vss_complaint_jsonl_record(
    line: usize,
    raw: &str,
) -> Result<ExperimentalVssComplaintArtifact, HazmatArtifactVerificationError> {
    let evidence_kind = parse_evidence_kind(line, &json_string_field(line, raw, "evidence_kind")?)?;
    let evidence_bytes = hex_decode_field(
        line,
        "evidence_hex",
        &json_string_field(line, raw, "evidence_hex")?,
    )?;
    Ok(ExperimentalVssComplaintArtifact {
        experiment: json_string_field(line, raw, "experiment")?,
        trial_index: json_number_field(line, raw, "trial")?,
        validator_index: json_number_field(line, raw, "validator_index")?,
        evidence_kind,
        session_id: hex_decode_array_field(
            line,
            "session_id",
            &json_string_field(line, raw, "session_id")?,
        )?,
        evidence_len: json_number_field(line, raw, "evidence_len")?,
        evidence_digest: hex_decode_array_field(
            line,
            "evidence_digest",
            &json_string_field(line, raw, "evidence_digest")?,
        )?,
        production_vss_relation_statement_digest: hex_decode_array_field(
            line,
            "production_vss_relation_statement_digest",
            &json_string_field(line, raw, "production_vss_relation_statement_digest")?,
        )?,
        evidence_bytes,
    })
}

#[cfg(feature = "experimental-vss")]
fn parse_experimental_vss_complaint_csv_record(
    line: usize,
    raw: &str,
) -> Result<ExperimentalVssComplaintArtifact, HazmatArtifactVerificationError> {
    let fields = split_csv_line(raw);
    if fields.len() != 9 {
        return Err(HazmatArtifactVerificationError::MalformedRecord {
            line,
            reason: "wrong CSV field count",
        });
    }

    Ok(ExperimentalVssComplaintArtifact {
        experiment: fields[0].clone(),
        trial_index: parse_field(line, &fields[1], "trial")?,
        validator_index: parse_field(line, &fields[2], "validator_index")?,
        evidence_kind: parse_evidence_kind(line, &fields[3])?,
        session_id: hex_decode_array_field(line, "session_id", &fields[4])?,
        evidence_len: parse_field(line, &fields[5], "evidence_len")?,
        evidence_digest: hex_decode_array_field(line, "evidence_digest", &fields[6])?,
        production_vss_relation_statement_digest: hex_decode_array_field(
            line,
            "production_vss_relation_statement_digest",
            &fields[7],
        )?,
        evidence_bytes: hex_decode_field(line, "evidence_hex", &fields[8])?,
    })
}

#[cfg(feature = "experimental-vss")]
fn parse_evidence_kind(
    line: usize,
    value: &str,
) -> Result<EvidenceKind, HazmatArtifactVerificationError> {
    match value {
        "InvalidPartialSignature" => Ok(EvidenceKind::InvalidPartialSignature),
        _ => Err(HazmatArtifactVerificationError::MalformedRecord {
            line,
            reason: "unknown evidence kind",
        }),
    }
}

fn split_csv_line(raw: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut chars = raw.chars().peekable();
    let mut quoted = false;

    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted && chars.peek() == Some(&'"') => {
                current.push('"');
                let _ = chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => {
                fields.push(current);
                current = String::new();
            }
            _ => current.push(ch),
        }
    }
    fields.push(current);
    fields
}

fn json_string_field(
    line: usize,
    raw: &str,
    field: &'static str,
) -> Result<String, HazmatArtifactVerificationError> {
    let marker = format!("\"{field}\":\"");
    let start = raw
        .find(&marker)
        .ok_or(HazmatArtifactVerificationError::MalformedRecord {
            line,
            reason: "missing JSON string field",
        })?
        + marker.len();
    let tail = &raw[start..];
    let mut escaped = false;
    let mut value = String::new();
    for ch in tail.chars() {
        if escaped {
            value.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => return Ok(value),
            _ => value.push(ch),
        }
    }
    Err(HazmatArtifactVerificationError::MalformedRecord {
        line,
        reason: "unterminated JSON string field",
    })
}

fn json_number_field<T>(
    line: usize,
    raw: &str,
    field: &'static str,
) -> Result<T, HazmatArtifactVerificationError>
where
    T: core::str::FromStr,
{
    let marker = format!("\"{field}\":");
    let start = raw
        .find(&marker)
        .ok_or(HazmatArtifactVerificationError::MalformedRecord {
            line,
            reason: "missing JSON number field",
        })?
        + marker.len();
    let tail = &raw[start..];
    let end = tail
        .find([',', '}'])
        .ok_or(HazmatArtifactVerificationError::MalformedRecord {
            line,
            reason: "unterminated JSON number field",
        })?;
    parse_field(line, &tail[..end], field)
}

fn parse_field<T>(
    line: usize,
    value: &str,
    _field: &'static str,
) -> Result<T, HazmatArtifactVerificationError>
where
    T: core::str::FromStr,
{
    value
        .parse()
        .map_err(|_| HazmatArtifactVerificationError::MalformedRecord {
            line,
            reason: "numeric field parse failed",
        })
}

fn is_hex_with_len(value: &str, len: usize) -> bool {
    value.len() == len && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

#[cfg(feature = "experimental-vss")]
fn hex_decode_array_field<const LEN: usize>(
    line: usize,
    field: &'static str,
    value: &str,
) -> Result<[u8; LEN], HazmatArtifactVerificationError> {
    let decoded = hex_decode_field(line, field, value)?;
    decoded
        .try_into()
        .map_err(|_| HazmatArtifactVerificationError::InvalidHexField { line, field })
}

#[cfg(feature = "experimental-vss")]
fn hex_decode_field(
    line: usize,
    field: &'static str,
    value: &str,
) -> Result<Vec<u8>, HazmatArtifactVerificationError> {
    if value.len() % 2 != 0 || !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(HazmatArtifactVerificationError::InvalidHexField { line, field });
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let hi = hex_nibble(chunk[0])
            .ok_or(HazmatArtifactVerificationError::InvalidHexField { line, field })?;
        let lo = hex_nibble(chunk[1])
            .ok_or(HazmatArtifactVerificationError::InvalidHexField { line, field })?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

#[cfg(feature = "experimental-vss")]
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn classify_hazmat_frame(msg: &PqcThresholdWireMsg) -> (&'static str, u16, u64, SessionId) {
    match msg {
        PqcThresholdWireMsg::HazmatMldsa65MaskingCommitment {
            session_id,
            block_height,
            validator_index,
            ..
        } => (
            "masking_commitment",
            *validator_index,
            *block_height,
            *session_id,
        ),
        PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
            session_id,
            block_height,
            validator_index,
            ..
        } => (
            "masking_opening",
            *validator_index,
            *block_height,
            *session_id,
        ),
        PqcThresholdWireMsg::HazmatMldsa65Challenge {
            session_id,
            block_height,
            ..
        } => ("challenge", 0, *block_height, *session_id),
        PqcThresholdWireMsg::HazmatMldsa65SecretCommitment {
            session_id,
            block_height,
            validator_index,
            ..
        } => (
            "secret_commitment",
            *validator_index,
            *block_height,
            *session_id,
        ),
        PqcThresholdWireMsg::HazmatMldsa65SecretContribution {
            session_id,
            block_height,
            validator_index,
            ..
        }
        | PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
            session_id,
            block_height,
            validator_index,
            ..
        } => (
            "secret_opening",
            *validator_index,
            *block_height,
            *session_id,
        ),
        _ => ("non_hazmat", 0, 0, [0u8; 32]),
    }
}

fn hazmat_attempt_from_frame(msg: &PqcThresholdWireMsg) -> u16 {
    match msg {
        PqcThresholdWireMsg::HazmatMldsa65MaskingCommitment { attempt, .. }
        | PqcThresholdWireMsg::HazmatMldsa65MaskingContribution { attempt, .. }
        | PqcThresholdWireMsg::HazmatMldsa65Challenge { attempt, .. }
        | PqcThresholdWireMsg::HazmatMldsa65SecretCommitment { attempt, .. }
        | PqcThresholdWireMsg::HazmatMldsa65SecretContribution { attempt, .. }
        | PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution { attempt, .. } => {
            *attempt
        }
        _ => 0,
    }
}

fn production_statement_digest_from_frame(msg: &PqcThresholdWireMsg) -> Option<[u8; 32]> {
    match msg {
        PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution {
            production_statement_digest,
            ..
        } => Some(*production_statement_digest),
        _ => None,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn csv_escape(value: &str) -> String {
    if value.contains([',', '"', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}
