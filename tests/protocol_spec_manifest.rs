use std::fs;
use std::path::Path;

const TRANSCRIPT_SPEC: &str = "docs/cryptography/formal-threshold-mldsa-transcript.md";
const PROTOCOL_CODE_CROSSWALK: &str = "docs/cryptography/protocol-code-crosswalk.md";

#[test]
fn formal_threshold_mldsa_transcript_spec_exists() {
    assert!(
        Path::new(TRANSCRIPT_SPEC).exists(),
        "missing transcript specification: {TRANSCRIPT_SPEC}"
    );
}

#[test]
fn formal_threshold_mldsa_transcript_spec_contains_required_anchors() {
    let spec = fs::read_to_string(TRANSCRIPT_SPEC)
        .unwrap_or_else(|err| panic!("failed to read {TRANSCRIPT_SPEC}: {err}"));
    let normalized = spec.to_ascii_lowercase();

    for required in [
        "static active adversary",
        "masking precommitment",
        "masking opening",
        "challenge derivation",
        "secret precommitment",
        "proof-bound secret contribution",
        "rejection sampling",
        "non-slashable retry",
        "slashing evidence",
        "standard ml-dsa-65 verification",
        "non-claims",
    ] {
        assert!(
            normalized.contains(required),
            "transcript specification missing required anchor: {required}"
        );
    }
}

#[test]
fn formal_threshold_mldsa_transcript_spec_links_supporting_protocol_docs() {
    let spec = fs::read_to_string(TRANSCRIPT_SPEC)
        .unwrap_or_else(|err| panic!("failed to read {TRANSCRIPT_SPEC}: {err}"));

    for linked_doc in [
        "protocol-lock.md",
        "security-model.md",
        "formal-proof-scaffold.md",
        "claims-matrix.md",
        "protocol-code-crosswalk.md",
    ] {
        assert!(
            spec.contains(linked_doc),
            "transcript specification missing supporting-doc link: {linked_doc}"
        );
    }
}

#[test]
fn protocol_code_crosswalk_exists_and_maps_required_review_areas() {
    let crosswalk = fs::read_to_string(PROTOCOL_CODE_CROSSWALK)
        .unwrap_or_else(|err| panic!("failed to read {PROTOCOL_CODE_CROSSWALK}: {err}"));
    let normalized = crosswalk.to_ascii_lowercase();

    for required in [
        "dkg/vss",
        "masking commitment",
        "masking opening",
        "challenge derivation",
        "secret commitment",
        "secret opening",
        "contribution proof boundary",
        "aggregation and finalization",
        "evidence export",
        "artifact verification",
        "reviewer usage",
        "limitations",
    ] {
        assert!(
            normalized.contains(required),
            "protocol-code crosswalk missing required review area: {required}"
        );
    }
}
