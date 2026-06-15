use std::{fs, path::Path};

const README: &str = "README.md";
const CHANGELOG: &str = "CHANGELOG.md";
const ARCHIVE_MANIFEST: &str = "docs/paper/archive-manifest.md";
const RELEASE_CHECKLIST: &str = "docs/paper/release-checklist.md";
const PR_SUMMARY: &str = "docs/paper/pr-summary.md";
const REVIEW_ORDER: &str = "docs/paper/review-order.md";
const CITATION: &str = "docs/paper/citation.md";
const ARTIFACT_BADGE: &str = "docs/paper/artifact-badge.md";

#[test]
fn release_package_top_level_docs_exist() {
    for path in [
        README,
        CHANGELOG,
        ARCHIVE_MANIFEST,
        RELEASE_CHECKLIST,
        PR_SUMMARY,
        REVIEW_ORDER,
        CITATION,
        ARTIFACT_BADGE,
    ] {
        assert!(
            Path::new(path).exists(),
            "missing release package doc: {path}"
        );
    }
}

#[test]
fn readme_links_reviewer_evidence_and_reproduction_paths() {
    let readme = read_doc(README);
    for required in [
        "docs/paper/reviewer-quickstart.md",
        "docs/cryptography/proof-closure-ledger.md",
        "docs/cryptography/claims-matrix.md",
        "docs/cryptography/proof-dependency-graph.md",
        "docs/cryptography/claim-hardening-matrix.md",
        "docs/cryptography/proof-obligations.md",
        "docs/audit/README.md",
        "docs/benchmarks/reproducibility-manifest.md",
        "docs/benchmarks/artifacts/section-v-sample-output.txt",
        "scripts/reproduce-section-v.sh",
        "hazmat-real-mldsa",
        "experimental-vss",
    ] {
        assert!(
            readme.contains(required),
            "README missing required text: {required}"
        );
    }
}

#[test]
fn release_docs_preserve_non_production_boundary() {
    let joined = [
        README,
        CHANGELOG,
        ARCHIVE_MANIFEST,
        PR_SUMMARY,
        REVIEW_ORDER,
        CITATION,
        ARTIFACT_BADGE,
    ]
    .iter()
    .map(|path| read_doc(path))
    .collect::<Vec<_>>()
    .join("\n")
    .to_ascii_lowercase();

    for required in [
        "research scaffold",
        "not production-ready",
        "not a security proof",
        "malicious-secure dkg",
        "contribution proof",
        "side-channel",
        "external cryptographic review",
    ] {
        assert!(
            joined.contains(required),
            "release docs missing boundary text: {required}"
        );
    }
}

#[test]
fn archive_manifest_lists_final_gate_commands_and_artifacts() {
    let manifest = read_doc(ARCHIVE_MANIFEST);
    for required in [
        "scripts/reproduce-section-v.sh",
        "cargo fmt --check",
        "cargo clippy -j1 --all-targets --all-features -- -D warnings",
        "cargo test -j1 --all-features",
        "git status --short",
        "git rev-parse HEAD",
        "docs/benchmarks/artifacts/section-v-sample-output.txt",
        "docs/benchmarks/artifacts/SHA256SUMS",
        "SECTION_V_OUTPUT",
    ] {
        assert!(
            manifest.contains(required),
            "archive manifest missing required text: {required}"
        );
    }
}

#[test]
fn pr_and_reviewer_docs_pin_review_order_and_verification() {
    let joined = [PR_SUMMARY, REVIEW_ORDER]
        .iter()
        .map(|path| read_doc(path))
        .collect::<Vec<_>>()
        .join("\n");

    for required in [
        "README.md",
        "docs/paper/reviewer-quickstart.md",
        "docs/cryptography/proof-closure-ledger.md",
        "docs/cryptography/claims-matrix.md",
        "docs/cryptography/protocol-code-crosswalk.md",
        "docs/cryptography/proof-obligations.md",
        "docs/audit/README.md",
        "scripts/reproduce-section-v.sh",
        "cargo test -j1 --all-features",
    ] {
        assert!(
            joined.contains(required),
            "PR/review docs missing required text: {required}"
        );
    }
}

#[test]
fn citation_and_badge_docs_do_not_make_license_or_security_claims() {
    let joined = [CITATION, ARTIFACT_BADGE]
        .iter()
        .map(|path| read_doc(path))
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();

    for required in [
        "placeholder",
        "artifact available",
        "artifact evaluated",
        "research scaffold",
        "not production-ready",
        "not a security proof",
        "license",
    ] {
        assert!(
            joined.contains(required),
            "citation/badge docs missing required text: {required}"
        );
    }
}

fn read_doc(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
}
