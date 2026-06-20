use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

const PROOF_CROSSWALK: &str = "docs/cryptography/proof-implementation-crosswalk.md";
const PROTOCOL_CODE_CROSSWALK: &str = "docs/cryptography/protocol-code-crosswalk.md";
const PHASE_1_NOISE_MODEL: &str = "docs/cryptography/phase-1-noise-bound-model.md";
const CRYPTOGRAPHY_README: &str = "docs/cryptography/README.md";
const RELEASE_READINESS_CHECKLIST: &str = "docs/benchmarks/release-readiness-checklist.md";

const REQUIRED_CRYPTOGRAPHY_DOCS: &[&str] = &[
    "docs/cryptography/active-adversary-model.md",
    "docs/cryptography/claims-matrix.md",
    "docs/cryptography/correctness-lemmas.md",
    "docs/cryptography/formal-security-theorem.md",
    "docs/cryptography/formal-threshold-mldsa-transcript.md",
    "docs/cryptography/ideal-functionality.md",
    "docs/cryptography/noise-rejection-proof-plan.md",
    "docs/cryptography/phase-1-noise-bound-model.md",
    "docs/cryptography/proof-implementation-crosswalk.md",
    "docs/cryptography/protocol-code-crosswalk.md",
    "docs/cryptography/proof-obligations.md",
    "docs/cryptography/random-oracle-game.md",
    "docs/cryptography/side-channel-boundary.md",
    "docs/cryptography/vss-dkg-security-plan.md",
];

const PROOF_DOC_ANCHORS: &[(&str, &[&str])] = &[
    (
        "docs/cryptography/active-adversary-model.md",
        &[
            "# Active Adversary Model for Proof-Grade VSS/DKG",
            "## Corruption Options",
            "## Rushing Behavior",
            "## Network Model",
            "## Complaint and Evidence Semantics",
            "## Output Agreement and Finality",
        ],
    ),
    (
        "docs/cryptography/claims-matrix.md",
        &[
            "# Cryptographic Claims Matrix",
            "## Matrix",
            "## Non-Claims",
        ],
    ),
    (
        "docs/cryptography/correctness-lemmas.md",
        &[
            "# Algebraic Correctness Lemmas",
            "## Lemma 1: Field Inversion Soundness",
            "## Lemma 5: Transcript Challenge Binding",
            "## Lemma 8: Infinity-Norm Bound Preservation",
        ],
    ),
    (
        "docs/cryptography/formal-security-theorem.md",
        &[
            "# Formal Security Theorem",
            "## FST-0. Scope and Reading Notes",
            "## FST-5. Lemma Targets",
            "## FST-10. Proof Dependencies for Later Workers",
        ],
    ),
    (
        "docs/cryptography/formal-threshold-mldsa-transcript.md",
        &[
            "# Formal Threshold ML-DSA Transcript",
            "## FTMT-0. Scope",
            "## FTMT-3. Binding Invariants",
            "## FTMT-5. Stable Anchors",
        ],
    ),
    (
        "docs/cryptography/ideal-functionality.md",
        &[
            "# Ideal Functionality F_TMLDSA",
            "## IF-0. Purpose and Scope",
            "## IF-8. Simulator Obligations",
            "## IF-11. Open Proof Dependencies",
        ],
    ),
    (
        "docs/cryptography/noise-rejection-proof-plan.md",
        &[
            "# Noise-Bound and Rejection-Sampling Proof Plan",
            "## Proof Goal",
            "## Lemma A: Local Mask Commitment Before Challenge",
            "## Lemma H: Accepted-Signature Distribution",
            "## Exactly What Remains to Be Proven",
        ],
    ),
    (
        "docs/cryptography/protocol-code-crosswalk.md",
        &[
            "# Protocol Code Crosswalk",
            "## Scope",
            "## Protocol Phase Crosswalk",
            "## DKG Scaffold",
            "## Signing State Machine",
            "## Transcript Binding",
            "## Aggregation Boundary",
            "## Adapter Wire and Actor Flow",
            "## Evidence and Timeout Diagnostics",
            "## Benchmark and Export Harness",
            "## Open Production Gaps",
            "## Manifest Anchors",
        ],
    ),
    (
        "docs/cryptography/proof-obligations.md",
        &[
            "# Proof Obligations Matrix",
            "## Matrix",
            "FST-T1 threshold unforgeability",
            "FST-L8 ideal extraction",
            "Noise Lemma H accepted-signature distribution",
            "VSS binding",
            "Static active adversary model",
            "## Wording Risks",
        ],
    ),
    (
        "docs/cryptography/random-oracle-game.md",
        &[
            "# Random-Oracle Game",
            "## ROG-0. Scope",
            "### ROG-D1. Message-Binding Oracle",
            "### ROG-D5. Signing Contribution-Proof Oracle",
            "## ROG-6. Non-Claims",
        ],
    ),
    (
        "docs/cryptography/side-channel-boundary.md",
        &[
            "# Side-Channel and Constant-Time Boundary",
            "## Boundary Statement",
            "## Implementation Leakage Claims",
            "## Constant-Time Expectations",
            "## Production Gate",
        ],
    ),
    (
        "docs/cryptography/vss-dkg-security-plan.md",
        &[
            "# Proof-Grade VSS/DKG Security Plan",
            "## Required VSS Relation",
            "### Binding",
            "### Hiding",
            "### Extractability",
            "## DKG Construction Requirements",
            "## Key-Bias Resistance",
            "## Complaint and Evidence Requirements",
        ],
    ),
];

fn read_doc(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
}

fn assert_contains_all(path: &str, required: &[&str]) {
    let doc = read_doc(path);
    for needle in required {
        assert!(
            doc.contains(needle),
            "{path} is missing required text anchor: {needle}"
        );
    }
}

fn assert_not_contains_all(path: &str, forbidden: &[&str]) {
    let doc = read_doc(path);
    for needle in forbidden {
        assert!(
            !doc.contains(needle),
            "{path} still contains stale text anchor: {needle}"
        );
    }
}

fn collect_markdown_files(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|err| panic!("failed to read {dir:?}: {err}")) {
        let entry = entry.unwrap_or_else(|err| panic!("failed to read directory entry: {err}"));
        let path = entry.path();
        if path.is_dir() {
            collect_markdown_files(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "md") {
            files.push(path);
        }
    }
}

fn is_external_or_anchor(target: &str) -> bool {
    target.starts_with("http://") || target.starts_with("https://") || target.starts_with("mailto:")
}

fn local_target(markdown_file: &Path, target: &str) -> Option<(PathBuf, Option<String>)> {
    let target = target.trim();
    if target.is_empty() || is_external_or_anchor(target) {
        return None;
    }

    let (path_part, anchor) = target
        .split_once('#')
        .map_or((target, None), |(path, anchor)| {
            (path, (!anchor.is_empty()).then(|| anchor.to_string()))
        });
    let without_query = path_part.split('?').next().unwrap_or(path_part);
    let path = if without_query.is_empty() {
        markdown_file.to_path_buf()
    } else {
        markdown_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(without_query)
    };

    Some((path, anchor))
}

fn artifact_path(markdown_file: &Path, target: &str) -> PathBuf {
    let target = Path::new(target);
    if target.starts_with("docs") || target.starts_with("src") || target.starts_with("tests") {
        target.to_path_buf()
    } else {
        markdown_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(target)
    }
}

fn backticked_paths(line: &str) -> Vec<&str> {
    let mut paths = Vec::new();
    let mut remaining = line;
    while let Some(start) = remaining.find('`') {
        let after_start = &remaining[start + 1..];
        let Some(end) = after_start.find('`') else {
            break;
        };
        let candidate = &after_start[..end];
        if candidate.ends_with(".md") || candidate.ends_with(".rs") {
            paths.push(candidate);
        }
        remaining = &after_start[end + 1..];
    }
    paths
}

fn heading_slug(heading: &str) -> String {
    let mut slug = String::new();
    let mut last_was_dash = false;

    for ch in heading.to_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch);
            last_was_dash = false;
        } else if (ch.is_ascii_whitespace() || ch == '-') && !last_was_dash && !slug.is_empty() {
            slug.push('-');
            last_was_dash = true;
        }
    }

    while slug.ends_with('-') {
        slug.pop();
    }
    slug
}

fn explicit_anchor_ids(line: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut remaining = line;
    while let Some(id_start) = remaining.find("id=\"") {
        let after_start = &remaining[id_start + 4..];
        let Some(id_end) = after_start.find('"') else {
            break;
        };
        ids.push(after_start[..id_end].to_string());
        remaining = &after_start[id_end + 1..];
    }
    ids
}

fn markdown_anchors(path: &Path) -> BTreeSet<String> {
    let doc = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read markdown file {path:?}: {err}"));
    let mut anchors = BTreeSet::new();

    for line in doc.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            let heading = trimmed.trim_start_matches('#').trim();
            let heading = heading.trim_end_matches('#').trim();
            let slug = heading_slug(heading);
            if !slug.is_empty() {
                anchors.insert(slug);
            }
        }

        for id in explicit_anchor_ids(line) {
            anchors.insert(id);
        }
    }

    anchors
}

#[test]
fn proof_documentation_manifest_tracks_required_docs() {
    for path in REQUIRED_CRYPTOGRAPHY_DOCS {
        assert!(
            Path::new(path).is_file(),
            "required proof documentation file is missing: {path}"
        );
    }
}

#[test]
fn proof_docs_keep_required_anchor_contract() {
    for (path, required) in PROOF_DOC_ANCHORS {
        assert_contains_all(path, required);
    }
}

#[test]
fn release_readiness_checklist_keeps_required_anchor_contract() {
    assert_contains_all(
        RELEASE_READINESS_CHECKLIST,
        &[
            "# Release Readiness Checklist",
            "## Scope",
            "## Required Inputs",
            "## Cryptography and Proof Gates",
            "## Implementation and Backend Gates",
            "## Side-Channel and Constant-Time Gates",
            "## Benchmark and Artifact Gates",
            "## Operational and Consensus Gates",
            "## Documentation and Claim-Drift Gates",
            "## Explicit Non-Claims",
            "## Sign-Off Rule",
            "No release gate is complete until",
            "deterministic research telemetry",
            "not security evidence",
            "standard ML-DSA verifier",
            "external cryptographic review",
            "dudect",
            "ctgrind",
            "FIPS validation",
            "production consensus signing",
        ],
    );
}

#[test]
fn production_coordinator_docs_keep_claim_boundary() {
    assert_contains_all(
        "docs/cryptography/claims-matrix.md",
        &[
            "coordinator-assisted ML-DSA-65 profile",
            "hazmat conformance only",
            "standard-verifier-compatible only after KAT and audit gates",
            "EpsilonLedger",
            "blinded pre-filter",
            "Renyi divergence",
            "hint-routing conformance",
            "DKG setup-only boundary",
        ],
    );
    assert_contains_all(
        "docs/benchmarks/release-readiness-checklist.md",
        &[
            "FIPS/ACVP-style ML-DSA-65 provider KATs",
            "coordinator-assisted threshold KATs",
            "fuzz targets for production coordinator frames",
            "ignored KAT release gate",
            "simulator compile-fail guard",
            "Renyi-divergence proof evidence",
            "DKG setup-only hot-path review",
        ],
    );
    assert_contains_all(
        "docs/cryptography/proof-implementation-crosswalk.md",
        &[
            "Production coordinator candidate boundary",
            "`src/production/provider.rs`",
            "`src/production/epsilon.rs`",
            "`src/production/prefilter.rs`",
            "`src/production/hints.rs`",
            "`src/production/transcript.rs`",
            "`src/production/preprocess.rs`",
            "`src/production/coordinator.rs`",
            "`src/adapter/production_wire.rs`",
            "`tests/ui/production_simulated_backend_rejected.rs`",
            "not real ML-DSA verification",
        ],
    );
    assert_contains_all(
        "docs/cryptography/protocol-code-crosswalk.md",
        &[
            "Production coordinator candidate",
            "`src/production/provider.rs`",
            "`src/production/epsilon.rs`",
            "`src/production/prefilter.rs`",
            "`src/production/hints.rs`",
            "`src/production/transcript.rs`",
            "`src/production/preprocess.rs`",
            "`src/production/coordinator.rs`",
            "`src/adapter/production_wire.rs`",
            "Gated hazmat/conformance boundary only",
        ],
    );
    assert_contains_all(
        "docs/audit/attack-surface.md",
        &[
            "production-candidate skeleton surfaces",
            "`src/production/provider.rs`",
            "`src/production/epsilon.rs`",
            "`src/production/prefilter.rs`",
            "`src/production/hints.rs`",
            "`src/production/transcript.rs`",
            "`src/production/preprocess.rs`",
            "`src/production/coordinator.rs`",
            "`src/adapter/production_wire.rs`",
            "provider KAT gate",
            "simulated backend cannot satisfy the production coordinator contract",
        ],
    );
    assert_contains_all(
        "docs/audit/tcb.md",
        &[
            "production-candidate surfaces exist",
            "`src/production/provider.rs`",
            "`src/production/epsilon.rs`",
            "`src/production/prefilter.rs`",
            "`src/production/hints.rs`",
            "`src/production/transcript.rs`",
            "`src/production/preprocess.rs`",
            "`src/production/coordinator.rs`",
            "`src/adapter/production_wire.rs`",
            "`tests/ui/production_simulated_backend_rejected.rs`",
            "no real ML-DSA verifier",
        ],
    );
    assert_not_contains_all(
        "docs/cryptography/noise-rejection-proof-plan.md",
        &[
            "statistical distance",
            "statistical-distance",
            "quantified distance",
        ],
    );
    assert_not_contains_all(
        "docs/cryptography/proof-obligations.md",
        &[
            "statistical distance",
            "statistical-distance",
            "quantified distance",
        ],
    );
}

#[test]
fn production_acceptance_docs_keep_claim_boundary() {
    assert_contains_all(
        "docs/cryptography/proof-implementation-crosswalk.md",
        &[
            "coordinator-assisted acceptance predicates",
            "`src/production/acceptance.rs`",
            "`tests/production_acceptance.rs`",
            "`LocalAccept`",
            "`AggregateAccept`",
            "conformance-only",
        ],
    );
    assert_contains_all(
        "docs/cryptography/protocol-code-crosswalk.md",
        &[
            "coordinator-assisted acceptance predicates",
            "`src/production/acceptance.rs`",
            "`tests/production_acceptance.rs`",
            "`LocalAccept`",
            "`AggregateAccept`",
            "conformance-only",
        ],
    );
    assert_contains_all(
        "docs/cryptography/claims-matrix.md",
        &[
            "Typed acceptance predicates",
            "`LocalAccept`",
            "`AggregateAccept`",
            "hazmat/conformance-only typed acceptance predicates",
            "must not claim production partial verification",
            "real aggregate recomputation",
            "distribution proof",
        ],
    );
    assert_contains_all(
        "docs/benchmarks/release-readiness-checklist.md",
        &[
            "production LocalAccept/AggregateAccept evidence",
            "standard verifier bridge",
            "proof/audit linkage",
            "criterion promotion",
        ],
    );
}

#[test]
fn cryptography_readme_indexes_current_proof_docs() {
    assert_contains_all(
        CRYPTOGRAPHY_README,
        &[
            "active-adversary-model.md",
            "claims-matrix.md",
            "correctness-lemmas.md",
            "formal-security-theorem.md",
            "formal-threshold-mldsa-transcript.md",
            "ideal-functionality.md",
            "noise-rejection-proof-plan.md",
            "phase-1-noise-bound-model.md",
            "proof-implementation-crosswalk.md",
            "protocol-code-crosswalk.md",
            "proof-obligations.md",
            "random-oracle-game.md",
            "side-channel-boundary.md",
            "vss-dkg-security-plan.md",
        ],
    );
}

#[test]
fn missing_artifact_notes_do_not_name_present_files() {
    let mut markdown_files = Vec::new();
    collect_markdown_files(Path::new("docs/cryptography"), &mut markdown_files);

    let mut stale = Vec::new();
    for file in markdown_files {
        let doc = fs::read_to_string(&file)
            .unwrap_or_else(|err| panic!("failed to read markdown file {file:?}: {err}"));
        for paragraph in doc.split("\n\n") {
            if !(paragraph.contains("not present in this checkout")
                || paragraph.contains("were not present")
                || paragraph.contains("missing artifacts")
                || paragraph.contains("still absent"))
            {
                continue;
            }

            for target in backticked_paths(paragraph) {
                let path = artifact_path(&file, target);
                if path.exists() {
                    stale.push(format!("{} names present file {target}", file.display()));
                }
            }
        }
    }

    assert!(
        stale.is_empty(),
        "missing-artifact notes name files that now exist:\n{}",
        stale.join("\n")
    );
}

#[test]
fn proof_crosswalk_maps_obligations_to_code_and_tests() {
    assert_contains_all(
        PROOF_CROSSWALK,
        &[
            "# Proof Implementation Crosswalk",
            "## Scope",
            "## Crosswalk",
            "## Manifest Anchors",
            "Transcript binding and Fiat-Shamir challenge derivation",
            "Canonical validator, commitment, and partial-share sets",
            "Wire encoding and untrusted-frame rejection",
            "Aggregation boundary and transcript consistency",
            "Simulation-only backend and production proof gates",
            "`src/transcript.rs`",
            "`src/adapter/wire.rs`",
            "`src/aggregation.rs`",
            "`src/backend.rs`",
            "`tests/transcript_determinism.rs`",
            "`tests/simulation.rs`",
            "`tests/simulated_flow.rs`",
            "`tests/validation.rs`",
        ],
    );
}

#[test]
fn proof_crosswalk_mentions_current_source_docs() {
    assert_contains_all(
        PROOF_CROSSWALK,
        &[
            "`formal-security-theorem.md`",
            "`formal-threshold-mldsa-transcript.md`",
            "`proof-obligations.md`",
            "`claims-matrix.md`",
            "`side-channel-boundary.md`",
            "`protocol-code-crosswalk.md`",
        ],
    );
    assert_not_contains_all(
        PROOF_CROSSWALK,
        &[
            "Those files were not present in this checkout when this crosswalk was written",
            "`protocol-code-crosswalk.md` is still absent",
        ],
    );
}

#[test]
fn protocol_code_crosswalk_maps_protocol_phases_to_code_and_tests() {
    assert_contains_all(
        PROTOCOL_CODE_CROSSWALK,
        &[
            "# Protocol Code Crosswalk",
            "deterministic simulation backend",
            "not a production threshold ML-DSA proof",
            "does not produce or verify real ML-DSA signatures",
            "`src/protocol.rs`",
            "`src/transcript.rs`",
            "`src/aggregation.rs`",
            "`src/backend.rs`",
            "`src/dkg.rs`",
            "`src/adapter/wire.rs`",
            "`src/adapter/actor.rs`",
            "`src/adapter/evidence.rs`",
            "`src/main.rs`",
            "`src/utils/exporter.rs`",
            "`tests/simulated_flow.rs`",
            "`tests/transcript_determinism.rs`",
            "`tests/simulation.rs`",
            "`tests/validation.rs`",
            "`tests/type_state.rs`",
        ],
    );
}

#[test]
fn proof_model_states_current_security_boundary() {
    assert_contains_all(
        PHASE_1_NOISE_MODEL,
        &[
            "# Phase 1 Threshold ML-DSA-65 Noise-Bound Model",
            "## Scope",
            "## ML-DSA-65 Constraint",
            "## Threshold Signing Requirement",
            "## Rejection Requirement",
            "## Production Gates",
        ],
    );
}

#[test]
fn local_markdown_links_resolve() {
    let mut markdown_files = vec![
        PathBuf::from("README.md"),
        PathBuf::from("CONTRIBUTING.md"),
        PathBuf::from("SECURITY.md"),
    ];
    collect_markdown_files(Path::new("docs"), &mut markdown_files);

    let mut missing = Vec::new();
    for file in markdown_files {
        let doc = fs::read_to_string(&file)
            .unwrap_or_else(|err| panic!("failed to read markdown file {file:?}: {err}"));

        for line in doc.lines() {
            let mut remaining = line;
            while let Some(link_start) = remaining.find("](") {
                let after_open = &remaining[link_start + 2..];
                let Some(link_end) = after_open.find(')') else {
                    break;
                };
                let target = &after_open[..link_end];
                if let Some((path, anchor)) = local_target(&file, target) {
                    if !path.exists() {
                        missing.push(format!("{} -> {target}", file.display()));
                    } else if let Some(anchor) = anchor {
                        let anchors = markdown_anchors(&path);
                        if !anchors.contains(&anchor) {
                            missing.push(format!(
                                "{} -> {target} (missing anchor #{anchor})",
                                file.display()
                            ));
                        }
                    }
                }
                remaining = &after_open[link_end + 1..];
            }
        }
    }

    assert!(
        missing.is_empty(),
        "local markdown links point to missing files:\n{}",
        missing.join("\n")
    );
}
