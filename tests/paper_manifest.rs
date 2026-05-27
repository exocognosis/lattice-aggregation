use std::{fs, path::Path};

const PAPER_DOCS: &[&str] = &[
    "docs/paper/artifact-overview.md",
    "docs/paper/evaluation-appendix.md",
    "docs/paper/limitations.md",
    "docs/paper/reviewer-quickstart.md",
    "docs/paper/release-checklist.md",
];

#[test]
fn paper_package_docs_exist() {
    for path in PAPER_DOCS {
        assert!(
            Path::new(path).exists(),
            "missing paper package doc: {path}"
        );
    }
}

#[test]
fn paper_package_links_required_evidence_docs() {
    let joined = PAPER_DOCS
        .iter()
        .map(|path| {
            fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
        })
        .collect::<Vec<_>>()
        .join("\n");

    for required in [
        "../cryptography/claims-matrix.md",
        "../cryptography/proof-obligations.md",
        "../audit/README.md",
        "../benchmarks/reproducibility-manifest.md",
        "../benchmarks/artifacts/section-v-sample-output.txt",
        "../benchmarks/artifacts/SHA256SUMS",
        "../../scripts/reproduce-section-v.sh",
    ] {
        assert!(
            joined.contains(required),
            "paper package missing required link: {required}"
        );
    }
}

#[test]
fn paper_package_preserves_research_scaffold_boundary() {
    let joined = PAPER_DOCS
        .iter()
        .map(|path| {
            fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
        })
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();

    for required in [
        "research scaffold",
        "hazmat",
        "not production-ready",
        "not a security proof",
        "malicious-secure dkg",
        "contribution proof soundness",
        "side-channel",
        "external cryptographic review",
    ] {
        assert!(
            joined.contains(required),
            "paper package missing boundary phrase: {required}"
        );
    }
}

#[test]
fn release_checklist_lists_final_verification_commands() {
    let checklist = fs::read_to_string("docs/paper/release-checklist.md")
        .expect("failed to read release checklist");

    for required in [
        "scripts/reproduce-section-v.sh",
        "cargo fmt --check",
        "cargo clippy -j1 --all-targets --all-features -- -D warnings",
        "cargo test -j1 --all-features",
        "git rev-parse HEAD",
    ] {
        assert!(
            checklist.contains(required),
            "release checklist missing command: {required}"
        );
    }
}
