use std::path::Path;

const MANIFEST: &str = include_str!("../docs/benchmarks/reproducibility-manifest.md");

#[test]
fn reproducibility_manifest_lists_supported_feature_commands() {
    for required in [
        "cargo test -j1 --test simulation --test simulated_flow --test production_policy",
        "cargo clippy -j1 --no-default-features",
        "cargo test -j1 --features experimental-vss",
        "cargo run -j1 --features hazmat-real-mldsa",
        "cargo run -j1 --features hazmat-real-mldsa,experimental-vss",
        "> docs/benchmarks/artifacts/section-v-sample-output.txt",
        "c12c09b7c526b71e82d9a7b1a38b97c7232be4e39467f98d448ef338bbaac972",
        "shasum -a 256 -c SHA256SUMS",
        "cargo test -j1 --features hazmat-real-mldsa",
        "cargo test -j1 --features hazmat-real-mldsa,experimental-vss",
        "cargo test -j1 --test type_state",
        "scripts/reproduce-section-v.sh",
    ] {
        assert!(
            MANIFEST.contains(required),
            "manifest missing required command fragment: {required}"
        );
    }
}

#[test]
fn reproducibility_manifest_lists_expected_artifact_sections_and_headers() {
    for required in [
        "===== <profile label>: LaTeX =====",
        "===== <profile label>: PGFPlots CSV =====",
        "===== <profile label>: Transcript JSONL =====",
        "===== <profile label>: Transcript CSV =====",
        "===== <profile label>: Experimental VSS Complaint JSONL =====",
        "===== <profile label>: Experimental VSS Complaint CSV =====",
        "session_id,duration_ms,aborts,bandwidth_bytes",
        "experiment,trial,attempt,direction,round,validator_index,block_height,session_id,encoded_len,frame_digest,production_statement_digest",
        "experiment,trial,validator_index,evidence_kind,session_id,evidence_len,evidence_digest,production_vss_relation_statement_digest,evidence_hex",
    ] {
        assert!(
            MANIFEST.contains(required),
            "manifest missing required artifact text: {required}"
        );
    }
}

#[test]
fn reproducibility_manifest_separates_engineering_evidence_from_security_proof_obligations() {
    for required in [
        "engineering evidence",
        "security proof obligations",
        "malicious-secure production DKG",
        "zero-knowledge or MPC-sound contribution proof relations",
        "side-channel resistance",
        "FIPS validation or external certification",
        "fail-closed VSS, contribution-proof, and combined production policy gates",
        "public production-labeled actor configuration construction",
        "latency values are machine-dependent",
        "bit-stable constants",
    ] {
        assert!(
            MANIFEST.contains(required),
            "manifest missing claim-boundary text: {required}"
        );
    }
}

#[test]
fn reproducibility_manifest_references_existing_supporting_docs() {
    for path in [
        "docs/cryptography/security-model.md",
        "docs/cryptography/formal-proof-scaffold.md",
        "docs/cryptography/production-vss-backend.md",
        "docs/cryptography/proof-bearing-contribution-boundary.md",
        "docs/cryptography/claims-matrix.md",
        "docs/cryptography/protocol-code-crosswalk.md",
        "docs/benchmarks/release-readiness-checklist.md",
        "docs/benchmarks/artifacts/section-v-sample-output.txt",
        "docs/benchmarks/artifacts/SHA256SUMS",
        "scripts/reproduce-section-v.sh",
    ] {
        assert!(MANIFEST.contains(path), "manifest missing path: {path}");
        assert!(
            Path::new(path).exists(),
            "referenced path does not exist: {path}"
        );
    }
}
