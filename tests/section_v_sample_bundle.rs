use sha2::{Digest, Sha256};

#[cfg(feature = "hazmat-real-mldsa")]
use dytallix_pq_threshold::utils::hazmat_artifacts::{
    verify_hazmat_transcript_csv, verify_hazmat_transcript_jsonl,
};

#[cfg(all(feature = "hazmat-real-mldsa", feature = "experimental-vss"))]
use dytallix_pq_threshold::utils::hazmat_artifacts::{
    verify_experimental_vss_complaint_csv, verify_experimental_vss_complaint_jsonl,
};

const SAMPLE_BUNDLE: &str =
    include_str!("../docs/benchmarks/artifacts/section-v-sample-output.txt");
const SAMPLE_BUNDLE_SHA256: &str =
    "c12c09b7c526b71e82d9a7b1a38b97c7232be4e39467f98d448ef338bbaac972";
const SAMPLE_BUNDLE_SHA256_SUMS: &str = include_str!("../docs/benchmarks/artifacts/SHA256SUMS");

#[test]
fn section_v_sample_bundle_contains_all_profile_sections() {
    let profiles = [
        "Small-Scale Consensus",
        "Mid-Scale Distributed Fabric",
        "Adversarial WAN Cluster",
    ];
    let sections = [
        "ML-DSA-65 Single-Signer Baseline Comparison CSV",
        "LaTeX",
        "PGFPlots CSV",
        "Transcript JSONL",
        "Transcript CSV",
    ];

    for profile in profiles {
        for section in sections.iter().skip(1) {
            let heading = format!("===== {profile}: {section} =====");
            assert!(
                SAMPLE_BUNDLE.contains(&heading),
                "sample bundle missing artifact heading: {heading}"
            );
        }
    }
    assert!(SAMPLE_BUNDLE.contains(&format!("===== {} =====", sections[0])));
    for section in [
        "Experimental VSS Complaint JSONL",
        "Experimental VSS Complaint CSV",
    ] {
        let heading = format!("===== Mid-Scale Distributed Fabric: {section} =====");
        assert!(
            SAMPLE_BUNDLE.contains(&heading),
            "sample bundle missing artifact heading: {heading}"
        );
    }

    let heading_count = SAMPLE_BUNDLE
        .lines()
        .filter(|line| line.starts_with("====="))
        .count();
    assert_eq!(heading_count, 1 + profiles.len() * (sections.len() - 1) + 2);
}

#[test]
fn section_v_sample_bundle_contains_expected_artifact_headers() {
    for required in [
        "\\begin{table}",
        "profile,validators,threshold,trial,baseline_sign_ns,baseline_verify_ns,threshold_duration_ns,threshold_bytes,signature_bytes,latency_overhead_x",
        "session_id,duration_ms,aborts,bandwidth_bytes",
        "experiment,trial,attempt,direction,round,validator_index,block_height,session_id,encoded_len,frame_digest,production_statement_digest",
        "experiment,trial,validator_index,evidence_kind,session_id,evidence_len,evidence_digest,production_vss_relation_statement_digest,evidence_hex",
    ] {
        assert!(
            SAMPLE_BUNDLE.contains(required),
            "sample bundle missing artifact header: {required}"
        );
    }
}

#[test]
fn section_v_sample_bundle_preserves_profile_and_evidence_labels() {
    for required in [
        "Small-Scale Consensus & 3",
        "Mid-Scale Distributed Fabric & 7",
        "Adversarial WAN Cluster & 15",
        "\"evidence_kind\":\"InvalidPartialSignature\"",
        ",InvalidPartialSignature,",
    ] {
        assert!(
            SAMPLE_BUNDLE.contains(required),
            "sample bundle missing expected profile or evidence label: {required}"
        );
    }
}

#[test]
fn section_v_sample_bundle_checksum_matches_sidecar() {
    let digest = Sha256::digest(SAMPLE_BUNDLE.as_bytes());
    let actual = format!("{digest:x}");
    assert_eq!(actual, SAMPLE_BUNDLE_SHA256);

    let expected_sidecar = format!("{SAMPLE_BUNDLE_SHA256}  section-v-sample-output.txt\n");
    assert_eq!(SAMPLE_BUNDLE_SHA256_SUMS, expected_sidecar);
}

#[cfg(feature = "hazmat-real-mldsa")]
#[test]
fn section_v_transcript_jsonl_rejects_missing_production_statement_digest() {
    let jsonl = sample_section("Small-Scale Consensus: Transcript JSONL");
    verify_hazmat_transcript_jsonl(&jsonl).expect("sample transcript JSONL should verify");

    let line = jsonl
        .lines()
        .find(|line| {
            line.contains("\"round\":\"secret_opening\"")
                && !line.contains("\"production_statement_digest\":\"\"")
        })
        .expect("sample transcript JSONL should include a production-bound secret opening");
    let digest_field = production_statement_digest_json_field(line);
    let tampered = jsonl.replacen(digest_field, "", 1);

    let err = verify_hazmat_transcript_jsonl(&tampered)
        .expect_err("missing production statement digest must fail verification");
    assert_eq!(
        err.to_string(),
        "malformed transcript record on line 6: missing JSON string field"
    );
}

#[cfg(feature = "hazmat-real-mldsa")]
#[test]
fn section_v_transcript_csv_rejects_malformed_production_statement_digest() {
    let csv = sample_section("Small-Scale Consensus: Transcript CSV");
    verify_hazmat_transcript_csv(&csv).expect("sample transcript CSV should verify");

    let line = csv
        .lines()
        .find(|line| line.contains(",secret_opening,") && !line.ends_with(','))
        .expect("sample transcript CSV should include a production-bound secret opening");
    let fields = line.split(',').collect::<Vec<_>>();
    let digest = fields
        .last()
        .expect("sample transcript CSV row should have digest field");
    let tampered_line = line.replace(digest, "not-a-canonical-digest");
    let tampered = csv.replacen(line, &tampered_line, 1);

    let err = verify_hazmat_transcript_csv(&tampered)
        .expect_err("malformed production statement digest must fail verification");
    assert_eq!(
        err.to_string(),
        "invalid hex field production_statement_digest on line 7"
    );
}

#[cfg(all(feature = "hazmat-real-mldsa", feature = "experimental-vss"))]
#[test]
fn section_v_complaint_jsonl_rejects_missing_production_vss_relation_statement_digest() {
    let jsonl = sample_section("Mid-Scale Distributed Fabric: Experimental VSS Complaint JSONL");
    verify_experimental_vss_complaint_jsonl(&jsonl).expect("sample complaint JSONL should verify");

    let line = jsonl
        .lines()
        .find(|line| line.contains("\"production_vss_relation_statement_digest\":\""))
        .expect("sample complaint JSONL should include a production VSS relation digest");
    let digest_field = production_vss_relation_statement_digest_json_field(line);
    let tampered = jsonl.replacen(digest_field, "", 1);

    let err = verify_experimental_vss_complaint_jsonl(&tampered)
        .expect_err("missing production VSS relation digest must fail verification");
    assert_eq!(
        err.to_string(),
        "malformed transcript record on line 1: missing JSON string field"
    );
}

#[cfg(all(feature = "hazmat-real-mldsa", feature = "experimental-vss"))]
#[test]
fn section_v_complaint_csv_rejects_malformed_production_vss_relation_statement_digest() {
    let csv = sample_section("Mid-Scale Distributed Fabric: Experimental VSS Complaint CSV");
    verify_experimental_vss_complaint_csv(&csv).expect("sample complaint CSV should verify");

    let line = csv
        .lines()
        .find(|line| line.contains(",InvalidPartialSignature,"))
        .expect("sample complaint CSV should include complaint evidence");
    let fields = line.split(',').collect::<Vec<_>>();
    let digest = fields
        .get(7)
        .expect("sample complaint CSV row should have production VSS relation digest");
    let tampered_line = line.replace(digest, "not-a-canonical-digest");
    let tampered = csv.replacen(line, &tampered_line, 1);

    let err = verify_experimental_vss_complaint_csv(&tampered)
        .expect_err("malformed production VSS relation digest must fail verification");
    assert_eq!(
        err.to_string(),
        "invalid hex field production_vss_relation_statement_digest on line 2"
    );
}

#[cfg(feature = "hazmat-real-mldsa")]
fn sample_section(section: &str) -> String {
    let heading = format!("===== {section} =====");
    let start = SAMPLE_BUNDLE
        .find(&heading)
        .unwrap_or_else(|| panic!("sample bundle missing section: {section}"));
    let body_start = start + heading.len();
    let body = SAMPLE_BUNDLE[body_start..]
        .strip_prefix('\n')
        .expect("sample section heading should be followed by a newline");
    let body_end = body.find("\n=====").unwrap_or(body.len());
    body[..body_end].to_string()
}

#[cfg(feature = "hazmat-real-mldsa")]
fn production_statement_digest_json_field(line: &str) -> &str {
    json_string_field_fragment(line, "production_statement_digest")
}

#[cfg(all(feature = "hazmat-real-mldsa", feature = "experimental-vss"))]
fn production_vss_relation_statement_digest_json_field(line: &str) -> &str {
    json_string_field_fragment(line, "production_vss_relation_statement_digest")
}

#[cfg(feature = "hazmat-real-mldsa")]
fn json_string_field_fragment<'a>(line: &'a str, field: &str) -> &'a str {
    let marker = format!(",\"{field}\":\"");
    let start = line
        .find(&marker)
        .unwrap_or_else(|| panic!("sample JSONL line missing field: {field}"));
    let tail = &line[start + marker.len()..];
    let end = tail
        .find('"')
        .unwrap_or_else(|| panic!("sample JSONL line has unterminated field: {field}"));
    &line[start..start + marker.len() + end + 1]
}
