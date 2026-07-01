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
const SIMULATION_RESULTS: &str = "docs/benchmarks/simulation-results.md";
const REAL_WORLD_BENCHMARK_PROTOCOL: &str = "docs/benchmarks/real-world-benchmark-protocol.md";
const LOCALNET_VALIDATOR_RUNNER: &str = "docs/benchmarks/localnet-validator-runner.md";

const REQUIRED_CRYPTOGRAPHY_DOCS: &[&str] = &[
    "docs/cryptography/active-adversary-model.md",
    "docs/cryptography/abort-retry-bias-evidence.md",
    "docs/cryptography/claims-matrix.md",
    "docs/cryptography/correctness-lemmas.md",
    "docs/cryptography/criterion-1-proof-substance.md",
    "docs/cryptography/criterion-2-proof-substance.md",
    "docs/cryptography/criterion-3-proof-substance.md",
    "docs/cryptography/validator-10000-standard-verifier-gate.md",
    "docs/cryptography/formal-security-theorem.md",
    "docs/cryptography/formal-threshold-mldsa-transcript.md",
    "docs/cryptography/hypothesis-outcome-taxonomy.md",
    "docs/cryptography/ideal-functionality.md",
    "docs/cryptography/mask-distribution-evidence.md",
    "docs/cryptography/noise-rejection-proof-plan.md",
    "docs/cryptography/partial-soundness-evidence.md",
    "docs/cryptography/phase-1-noise-bound-model.md",
    "docs/cryptography/proof-implementation-crosswalk.md",
    "docs/cryptography/protocol-code-crosswalk.md",
    "docs/cryptography/proof-obligations.md",
    "docs/cryptography/random-oracle-game.md",
    "docs/cryptography/rejection-equivalence-evidence.md",
    "docs/cryptography/side-channel-boundary.md",
    "docs/cryptography/thesis-operating-parameters.md",
    "docs/cryptography/unauthorized-aggregate-reduction.md",
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
        "docs/cryptography/abort-retry-bias-evidence.md",
        &[
            "# Abort/Retry Bias Evidence Checks",
            "## Scope",
            "## Evidence Model",
            "## What This Rejects",
            "## Claim Boundary",
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
        "docs/cryptography/criterion-1-proof-substance.md",
        &[
            "# Criterion 1 Proof Substance",
            "## Scope and Claim Boundary",
            "## Proof Payload Statement",
            "## Required Artifact Slots",
            "## Theorem Links",
            "## Promotion Requirements",
            "## Failure Conditions",
            "## Assessment Boundary",
            "aggregate_mask_distribution",
            "formalized_open_proof_payload",
            "criterion1_proof_payload_formalized",
            "Noise Lemma B",
            "Noise Lemma H",
            "Correctness Lemma 8",
            "FST-L7",
            "selected_mask_construction_digest",
            "centralized_distribution_artifact_digest",
            "aggregate_distribution_artifact_digest",
            "renyi_bound_proof_digest",
            "min_entropy_review_digest",
            "parameter_selection_digest",
            "external_review_digest",
            "required_unclosed",
            "p1_criterion1_mask_construction_artifact_gate",
            "p1_criterion1_renyi_bound_proof_artifact_gate",
            "p1_criterion1_proof_payload_package",
            "conformance/proof-review evidence only",
            "partially_met",
            "partially_proven",
            "not selected-backend proof closure",
            "not production threshold ML-DSA security",
            "not CAVP/ACVTS validation",
            "not FIPS validation",
            "not rejection-distribution preservation",
            "not a completed mask-distribution proof",
        ],
    ),
    (
        "docs/cryptography/criterion-2-proof-substance.md",
        &[
            "# Criterion 2 Proof Substance",
            "## Scope and Claim Boundary",
            "## Proof Payload Statement",
            "## Required Artifact Slots",
            "## Theorem Links",
            "## Promotion Requirements",
            "## Failure Conditions",
            "## Assessment Boundary",
            "aggregate_rejection_equivalence",
            "formalized_open_proof_payload",
            "criterion2_proof_payload_formalized",
            "Correctness Lemma 7",
            "Correctness Lemma 8",
            "Noise Lemma D",
            "Noise Lemma F",
            "Noise Lemma H",
            "FST-L5",
            "FST-L7",
            "threshold_output_certificate_digest",
            "real_recomputation_evidence_digest",
            "standard_verifier_compatibility_artifact_digest",
            "evidence_present_unclosed",
            "p1_criterion2_threshold_output_certificate_artifact_gate",
            "p1_criterion2_real_recomputation_evidence_artifact_gate",
            "p1_standard_verifier_compatibility_artifact_gate",
            "Typed Criterion 2 proof-slot artifact packages",
            "p1_criterion2_proof_slot_artifact_package",
            "p1_criterion2_full_kat_validation_artifact_gate",
            "p1_criterion2_rejection_distribution_review_artifact_gate",
            "p1_criterion2_norm_bound_artifact_gate",
            "p1_criterion2_hint_bound_artifact_gate",
            "p1_criterion2_challenge_bound_artifact_gate",
            "p1_criterion2_transcript_binding_artifact_gate",
            "p1_criterion2_theorem_linkage_artifact_gate",
            "p1_criterion2_external_review_artifact_gate",
            "All Criterion 2 proof slots now have typed `evidence_present_unclosed` wrappers",
            "durable certificate evidence",
            "`P1SelectedBackendProofClosureArtifactCertificate::threshold_output_certificate_artifact_digest`",
            "`P1SelectedBackendProofClosureArtifactCertificate::real_recomputation_evidence_artifact_digest`",
            "evidence_present_unclosed only",
            "conformance/proof-review evidence only",
            "tests/fixtures/p1_threshold_output_certificate_artifact_fixture.json",
            "tests/fixtures/p1_real_recomputation_artifact_fixture.json",
            "tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json",
            "tests/fixtures/p1_rejection_distribution_review_artifact_fixture.json",
            "tests/fixtures/p1_theorem_linkage_artifact_fixture.json",
            "rejection_distribution_review_digest",
            "theorem_linkage_artifact_digest",
            "partially_met",
            "partially_proven",
            "not selected-backend proof closure",
            "not production threshold ML-DSA security",
            "not CAVP/ACVTS validation",
            "not FIPS validation",
            "not rejection-distribution preservation",
            "not a completed standard-verifier compatibility proof",
        ],
    ),
    (
        "docs/cryptography/criterion-3-proof-substance.md",
        &[
            "# Criterion 3 Proof Substance",
            "## Scope and Claim Boundary",
            "## Proof Payload Statement",
            "## Required Artifact Slots",
            "## Theorem Links",
            "## Promotion Requirements",
            "## Failure Conditions",
            "## Assessment Boundary",
            "abort_retry_bias",
            "formalized_open_proof_payload",
            "criterion3_proof_payload_formalized",
            "Noise Lemma G",
            "Noise Lemma H",
            "FST-L7",
            "FST-L9",
            "session_id + attempt_id + retry_counter",
            "accepted threshold signatures remain unbiased under the reviewed abort and retry policy",
            "retry_domain_separation_proof_digest",
            "formal_abort_leakage_model_digest",
            "accepted_signature_distribution_proof_digest",
            "adversarial_abort_policy_corpus_digest",
            "sample_size_bucket_rationale_digest",
            "timeout_retry_policy_digest",
            "external_review_digest",
            "required_unclosed",
            "p1_criterion3_retry_domain_separation_artifact_gate",
            "p1_criterion3_accepted_signature_distribution_artifact_gate",
            "p1_criterion3_proof_payload_package",
            "conformance/proof-review evidence only",
            "partially_met",
            "partially_proven",
            "not selected-backend proof closure",
            "not production threshold ML-DSA security",
            "not CAVP/ACVTS validation",
            "not FIPS validation",
            "not accepted-signature distribution preservation",
            "not a completed Fiat-Shamir-with-aborts preservation proof",
            "not a completed abort/retry-bias proof",
        ],
    ),
    (
        "docs/cryptography/validator-10000-standard-verifier-gate.md",
        &[
            "# 10,000 Validator Standard-Verifier Gate",
            "Status: `blocked_fail_closed`, not standard-verifier equivalence.",
            "## Scope",
            "## Current Executable Gate",
            "## Future Pass Condition",
            "## Promotion Requirements",
            "## Relationship To The Large Simulation Profile",
            "10,000-validator deterministic fan-in telemetry only",
            "not cryptographic proof",
            "not standard-verifier equivalence",
            "not byte-identical to one validator signature",
            "blocked until a real threshold ML-DSA backend emits a verifier-accepted aggregate signature",
            "cargo test --test validator_10000_standard_verifier_gate",
            "validators = 10000",
            "threshold = 6667",
            "aggregate_signature.len() = 3309",
            "SimulatedBackend::verify_standard(...) = BackendUnavailable",
            "MLDSA65.Verify(aggregate_public_key, message, aggregate_signature) == accept",
            "HazmatMldsa65Provider::verify",
            "real threshold ML-DSA aggregation backend",
            "Criterion 2 standard-verifier compatibility artifact",
            "`Large Validator Set 10000` with threshold 6,667",
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
        "docs/cryptography/hypothesis-outcome-taxonomy.md",
        &[
            "# Hypothesis Outcome Taxonomy",
            "## Scope",
            "## Outcome Vocabulary",
            "## Criterion Status Vocabulary",
            "## Failure",
            "## Partial Success",
            "## Full Success",
            "## Per-Criterion Outcome Guide",
            "## Decision Rules",
            "completely_proven",
            "partially_proven",
            "partially_disproven",
            "completely_disproven",
            "partially_met",
            "blocked",
            "failed",
            "grant submissions",
            "research-preview",
            "full hypothesis success is not production release readiness",
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
        "docs/cryptography/mask-distribution-evidence.md",
        &[
            "# Mask Distribution Evidence",
            "## Evidence Gate",
            "## Accepted Evidence Requirements",
            "## Claim Boundary",
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
        "docs/cryptography/partial-soundness-evidence.md",
        &[
            "# Partial Contribution Soundness Evidence",
            "## Scope",
            "## Evidence Classes",
            "## Checks Added",
            "## Current Boundary",
            "## Remaining Work",
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
            "## Production Coordinator Candidate",
            "## Selected Backend Direction",
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
        "docs/cryptography/rejection-equivalence-evidence.md",
        &[
            "# Aggregate Rejection-Equivalence Evidence",
            "## Implemented Gate",
            "## Claim Boundary",
            "## What Remains",
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
        "docs/cryptography/thesis-operating-parameters.md",
        &[
            "# Thesis and Operating Parameters",
            "## Thesis Statement",
            "## Operating Parameters",
            "## Promotion Criteria",
            "## Failure Criteria",
            "## Fallback Trigger",
            "research scaffold only",
            "native-threshold-mldsa65-aggregation-p1",
            "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
            "one standard-sized ML-DSA-65 signature if proven",
            "partially_proven",
            "partially_met",
            "not selected-backend proof closure",
            "not production threshold ML-DSA security",
            "not CAVP/ACVTS validation",
            "not FIPS validation",
            "Falcon/LaBRADOR-style proof aggregation",
            "evaluate only",
        ],
    ),
    (
        "docs/cryptography/unauthorized-aggregate-reduction.md",
        &[
            "# Unauthorized Aggregate Reduction Manifest",
            "## Scope and Claim Boundary",
            "## Reduction Target",
            "## Assumptions Named by Case",
            "## Reduction Cases",
            "## Manifest Checklist",
            "## What Remains to Close Blocker 5",
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
fn thesis_operating_parameters_avoids_release_claim_phrasing() {
    assert_not_contains_all(
        "docs/cryptography/thesis-operating-parameters.md",
        &[
            "production-ready",
            "proof closure achieved",
            "validated implementation",
            "selected production backend",
            "fallback release path",
        ],
    );
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
fn benchmark_docs_keep_simulation_and_real_world_boundaries() {
    assert_contains_all(
        SIMULATION_RESULTS,
        &[
            "# Simulation Benchmark Results",
            "deterministic research telemetry",
            "not security evidence",
            "not real-world validator performance",
            "docs/benchmarks/generated/latest-simulation/manifest.json",
            "10,000",
            "cargo run -- --profile large --format csv --no-wall-sleep",
            "## External Comparator Baseline",
            "LaBRADOR",
            "Falcon",
            "74.07 KB",
            "2.65s",
            "proof-wrapper aggregation",
            "not a benchmark",
            "produced by this repository",
        ],
    );
    assert_contains_all(
        REAL_WORLD_BENCHMARK_PROTOCOL,
        &[
            "# Real-World Benchmark Protocol",
            "## Required Inputs",
            "## Collection Procedure",
            "## Claim Boundary",
            "production threshold backend",
            "must not claim real-world benchmark results",
            "FIPS validation",
            "external validator deployment",
        ],
    );
    assert_contains_all(
        LOCALNET_VALIDATOR_RUNNER,
        &[
            "# Local Validator-Network Runner",
            "local validator-network engineering telemetry",
            "not security evidence",
            "not real-world validator performance",
            "not production-readiness evidence",
            "not production network liveness, authenticated transport, or consensus safety",
            "not production threshold ML-DSA security",
            "cargo run --example validator_localnet",
            "python3 scripts/run_localnet_runner.py --out artifacts/localnet/latest",
            "manifest.json",
            "events.jsonl",
            "node-logs/README.md",
            "fault_profile",
            "withheld-partial",
            "quorum-participation",
            "triggered_validator_count",
            "passive validator",
            "authenticated-transport",
            "authenticated-envelope-tamper",
            "tampered authenticated envelope",
            "local tamper-rejection telemetry only",
            "authenticated local envelope",
            "authentication_policy",
            "rejected_envelope_count",
            "fault-injection telemetry",
            "all_validators_finalized",
            "dropped_message_count",
            "SHA256SUMS",
            "artifacts/localnet/",
        ],
    );
    assert_contains_all(
        "README.md",
        &[
            "[Simulation Benchmark Results](docs/benchmarks/simulation-results.md)",
            "[Real-World Benchmark Protocol](docs/benchmarks/real-world-benchmark-protocol.md)",
            "[Local Validator-Network Runner](docs/benchmarks/localnet-validator-runner.md)",
        ],
    );
    assert_contains_all(
        RELEASE_READINESS_CHECKLIST,
        &[
            "simulation-results.md",
            "real-world-benchmark-protocol.md",
            "localnet-validator-runner.md",
        ],
    );
}

#[test]
fn related_work_comparator_docs_keep_claim_boundary() {
    assert_contains_all(
        "docs/cryptography/claims-matrix.md",
        &[
            "## Related Work Comparator",
            "Falcon/LaBRADOR-style proof-wrapper aggregation",
            "many independent Falcon signatures",
            "native threshold",
            "ML-DSA-65 signing",
            "standard-verifier-compatible ML-DSA-65 signature",
            "higher-risk",
            "ordinary ML-DSA verifier",
            "standard-sized aggregate",
            "comparative only",
        ],
    );
    assert_contains_all(
        RELEASE_READINESS_CHECKLIST,
        &[
            "fallback architecture to evaluate",
            "Falcon/LaBRADOR-style",
            "proof-wrapper aggregation",
            "not a selected backend",
            "not a production release path",
            "separate scheme",
            "selection",
            "prover and verifier benchmarks",
            "consensus-latency analysis",
            "updated claim-boundary docs",
        ],
    );
}

#[test]
fn production_coordinator_docs_keep_claim_boundary() {
    assert_contains_all(
        "docs/cryptography/claims-matrix.md",
        &[
            "Profile P1 coordinator-assisted ML-DSA-65 direction",
            "hazmat conformance only",
            "ordinary provider conformance evidence",
            "aggregate standard-verifier compatibility remains a target",
            "real threshold recomputation, full KAT, bridge-test, proof, and audit gates pass",
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
            "NIST ACVP-Server FIPS204",
            "validation claims require lab/Prod-server vector sets",
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
            "bounded NIST ACVP-Server FIPS204 ML-DSA-65 sigVer sample fixture",
            "not aggregate threshold verification",
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
            "`HazmatMldsa65Provider`",
            "checked-in NIST ACVP-Server FIPS204",
            "not threshold proof",
            "aggregate threshold verification",
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
            "bounded ACVP sample fixture",
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
            "opt-in hazmat ML-DSA-65 provider verifier",
            "no production aggregate verifier",
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
fn readme_tracks_hypothesis_closure_requirements() {
    assert_contains_all(
        "README.md",
        &[
            "## Current Status",
            "publishable as a research artifact and exploratory implementation",
            "not publishable as production cryptography",
            "## Known Limitations",
            "## Reproduce Evidence",
            "## Release Tag",
            "Tags must point at merged `main` commits",
            "`v0.1.0` remains the historical protocol-conformance tag",
            "`v0.2.0-research-preview`",
            "## Hypothesis Closure Requirements",
            "docs/cryptography/thesis-operating-parameters.md",
            "docs/cryptography/thesis-operating-parameters.json",
            "docs/cryptography/hypothesis-outcome-taxonomy.md",
            "docs/cryptography/criterion-1-proof-substance.md",
            "docs/cryptography/criterion-1-proof-substance.json",
            "docs/cryptography/criterion-2-proof-substance.md",
            "docs/cryptography/criterion-2-proof-substance.json",
            "docs/cryptography/criterion-3-proof-substance.md",
            "docs/cryptography/criterion-3-proof-substance.json",
            "docs/cryptography/validator-10000-standard-verifier-gate.md",
            "native-threshold-mldsa65-aggregation-p1",
            "research scaffold only",
            "thesis_operating_parameters_manifest",
            "criterion1_proof_substance_manifest",
            "criterion2_proof_substance_manifest",
            "criterion3_proof_substance_manifest",
            "validator_10000_standard_verifier_gate",
            "aggregate_mask_distribution",
            "aggregate_rejection_equivalence",
            "abort_retry_bias",
            "blocked_fail_closed",
            "renyi_bound_proof_digest",
            "retry_domain_separation_proof_digest",
            "required_unclosed",
            "The five requirements below are the closure criteria used by",
            "failure, partial success, and full success",
            "scripts/assess_lattice_hypothesis.py",
            "Latest local assessment run:",
            "Latest verification commands:",
            "overall hypothesis verdict was `partially_proven`",
            "Aggregate masks match or closely approximate centralized ML-DSA masks.",
            "Aggregate rejection checks match centralized ML-DSA rejection checks.",
            "tests/fixtures/p1_standard_verifier_bridge_fixture.json",
            "fixture-backed bridge evidence package",
            "fixture-backed bridge conformance evidence",
            "stricter blocker-2/criterion-2 release gate",
            "necessary but not sufficient for criterion-2 promotion",
            "selected-backend aggregate-output artifact gate",
            "real standard-provider selected-backend aggregate-output package derivation for P1",
            "selected-backend threshold-output artifact gate for P1",
            "selected-backend proof-closure artifact package gate for P1",
            "full KAT/validation artifact slots",
            "theorem-linkage artifact digest",
            "tests/fixtures/p1_theorem_linkage_artifact_fixture.json",
            "checked theorem-linkage proof-slot fixture",
            "one provider-verified ML-DSA-65 candidate signature",
            "conformance/proof-review evidence only",
            "not selected-backend proof closure",
            "Selective aborts and retries do not bias accepted signatures.",
            "Every accepted partial contribution is sound, context-bound, and hiding enough for the chosen leakage model.",
            "Every unauthorized accepting aggregate output reduces to a base ML-DSA forgery or a named threshold-side assumption violation.",
            "`epsilon_mask` remains a release blocker",
            "P1 aggregate recomputation artifact gate, bounded ACVP/FIPS204 sample-vector provider conformance, a fixture-backed bridge evidence package with fixture-backed bridge conformance evidence, a selected-backend aggregate-output artifact gate, real standard-provider aggregate-output package evidence, a selected-backend threshold-output artifact gate, and a selected-backend proof-closure artifact package gate are present",
            "abort leakage and retry-bias distribution analysis remain proof obligations",
            "production local acceptance, partial verification, and hiding proof evidence are not complete",
            "the threshold unforgeability reduction remains a target",
            "Current closure determination: `partially_proven`",
            "full hypothesis success is not production release readiness",
            "Partially proven.",
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
fn selected_backend_direction_docs_keep_claim_boundary() {
    let selected_backend_anchors = &[
        "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "TEE/HSM coordinator assumption",
        "standard-verifier-compatible output",
        "P2/MPC",
        "TALUS",
        "selection artifact",
        "not proof closure",
        "not production approval",
        "`scripts/assess_lattice_hypothesis.py`",
        "`script_tests/test_assess_lattice_hypothesis.py`",
        "`tests/proof_documentation_manifest.rs`",
        "five hypothesis criteria",
    ];
    assert_contains_all(PROOF_CROSSWALK, selected_backend_anchors);
    assert_contains_all(PROTOCOL_CODE_CROSSWALK, selected_backend_anchors);
}

#[test]
fn blocker_evidence_docs_keep_claim_boundary() {
    assert_contains_all(
        "docs/cryptography/claims-matrix.md",
        &[
            "Five-criterion evidence gates",
            "closure-framework coverage",
            "`mask_distribution`",
            "`rejection_equivalence`",
            "`abort_bias`",
            "`partial_soundness`",
            "checked-in standard-verifier bridge fixture package",
            "bridge fixture conformance evidence",
            "fixture-backed bridge digest drift rejection",
            "selected-backend aggregate-output artifact gate",
            "selected-backend threshold-output artifact gate",
            "selected-backend proof-closure artifact package gate",
            "full KAT/validation artifact slots",
            "theorem-linkage artifact digest",
            "checked `tests/fixtures/p1_theorem_linkage_artifact_fixture.json` theorem-linkage fixture",
            "conformance/proof-review gate only",
            "not production threshold ML-DSA security",
            "not CAVP/ACVTS validation",
            "not FIPS validation",
            "not rejection-distribution preservation",
            "not selected-backend proof closure",
            "not a completed standard-verifier compatibility proof",
            "stricter release-gate coverage",
            "necessary but not sufficient",
            "hazmat conformance only",
            "must not claim completed Renyi proof",
            "must not claim completed standard-verifier compatibility proof",
            "threshold EUF-CMA reduction",
        ],
    );
    assert_contains_all(
        "docs/cryptography/proof-implementation-crosswalk.md",
        &[
            "Five-criterion blocker evidence gates and closure frameworks",
            "`src/production/mask_distribution.rs`",
            "`src/production/rejection_equivalence.rs`",
            "`src/production/abort_bias.rs`",
            "`src/production/partial_soundness.rs`",
            "`docs/cryptography/unauthorized-aggregate-reduction.md`",
            "`tests/production_mask_distribution.rs`",
            "`tests/production_rejection_equivalence.rs`",
            "`tests/production_abort_bias.rs`",
            "`tests/production_partial_soundness.rs`",
            "`tests/unauthorized_aggregate_reduction_manifest.rs`",
            "Evidence gates, sample-vector provider conformance, fixture-backed bridge conformance evidence, selected-backend aggregate-output artifact gate coverage, selected-backend threshold-output artifact gate coverage, selected-backend proof-closure artifact package gate coverage, and closure frameworks only",
            "P1 aggregate recomputation artifact gate",
            "sample-vector provider conformance",
            "`tests/fixtures/p1_standard_verifier_bridge_fixture.json`",
            "fixture-backed bridge conformance evidence",
            "selected-backend aggregate-output artifact gate",
            "selected-backend threshold-output artifact gate",
            "selected-backend proof-closure artifact package gate",
            "conformance/proof-review evidence only",
            "not selected-backend proof closure",
            "not production threshold ML-DSA security",
            "not CAVP/ACVTS validation",
            "not FIPS validation",
            "not a completed standard-verifier compatibility proof",
            "stricter release gate",
            "not selected-backend aggregate recomputation",
        ],
    );
    assert_contains_all(
        "docs/cryptography/protocol-code-crosswalk.md",
        &[
            "Hypothesis blocker evidence gates and closure frameworks",
            "`src/production/mask_distribution.rs`",
            "`src/production/rejection_equivalence.rs`",
            "`src/production/abort_bias.rs`",
            "`src/production/partial_soundness.rs`",
            "`docs/cryptography/unauthorized-aggregate-reduction.md`",
            "Typed assessment evidence, a P1 aggregate recomputation artifact gate",
            "selected-backend aggregate-output artifact gate",
            "P1 aggregate recomputation artifact gate",
            "selected-backend threshold-output artifact gate",
            "selected-backend proof-closure artifact package gate",
            "sample-vector provider conformance",
            "`tests/fixtures/p1_standard_verifier_bridge_fixture.json`",
            "fixture-backed bridge conformance evidence",
            "conformance/proof-review evidence only",
            "not selected-backend proof closure",
            "not production threshold ML-DSA security",
            "not CAVP/ACVTS validation",
            "not FIPS validation",
            "not a completed standard-verifier compatibility proof",
            "stricter release gate",
            "not selected-backend aggregate recomputation",
        ],
    );
    assert_contains_all(
        "docs/cryptography/rejection-equivalence-evidence.md",
        &[
            "`P1AggregateRecomputationClosurePackage`",
            "`assess_p1_aggregate_recomputation_closure`",
            "selected profile binding digest",
            "standard-verifier bridge evidence digest",
            "checked-in standard-verifier bridge fixture package",
            "fixture-backed bridge evidence package",
            "raw fixture-package digest",
            "`tests/fixtures/p1_standard_verifier_bridge_fixture.json`",
            "conformance evidence only",
            "selected-backend aggregate-output artifact gate",
            "selected-backend threshold-output artifact gate",
            "selected-backend proof-closure artifact package gate",
            "Typed Criterion 2 proof-slot artifact packages",
            "`P1Criterion2ProofSlotArtifact`",
            "`P1Criterion2ProofSlotArtifacts`",
            "`derive_p1_criterion2_proof_slot_artifacts`",
            "`derive_p1_criterion2_proof_slot_artifact`",
            "`p1_criterion2_proof_slot_artifact_package` evidence",
            "conformance/proof-review evidence only",
            "stronger than real standard-provider aggregate-output package evidence",
            "stronger than the selected-backend threshold-output artifact gate",
            "full KAT/validation artifact slots",
            "theorem-linkage artifact digest",
            "stricter blocker-2 release gate",
            "necessary but not sufficient for criterion-2 promotion",
            "not selected-backend proof closure",
            "not production threshold ML-DSA security",
            "not production threshold ML-DSA recomputation",
            "not rejection-distribution preservation",
            "not a completed standard-verifier compatibility proof",
            "ACVP-Server FIPS204",
            "sample-vector conformance",
            "not CAVP/ACVTS production validation",
            "not FIPS validation",
            "real threshold aggregate recomputation",
        ],
    );
    assert_contains_all(
        "docs/benchmarks/release-readiness-checklist.md",
        &[
            "five hypothesis blocker evidence gates and closure frameworks",
            "`tests/production_mask_distribution.rs`",
            "`tests/production_rejection_equivalence.rs`",
            "`tests/production_abort_bias.rs`",
            "`tests/production_partial_soundness.rs`",
            "`tests/unauthorized_aggregate_reduction_manifest.rs`",
            "closure-package frameworks as partial scaffold",
            "closure does not replace reviewed proof artifacts",
            "P1 aggregate recomputation artifact gate",
            "NIST ACVP-Server FIPS204",
            "sample-vector conformance",
            "selected profile binding digest",
            "standard-verifier bridge evidence digest",
            "checked-in standard-verifier bridge fixture package",
            "selected-backend aggregate-output artifact gate",
            "`P1SelectedBackendAggregateArtifactPackage`",
            "`assess_p1_selected_backend_aggregate_artifact`",
            "`p1_selected_backend_aggregate_artifact_gate`",
            "`derive_p1_selected_backend_aggregate_artifact_package`",
            "`derive_p1_real_recomputation_evidence_digest`",
            "`p1_selected_backend_real_output_package`",
            "`P1SelectedBackendThresholdOutputArtifactPackage`",
            "`assess_p1_selected_backend_threshold_output_artifact`",
            "`derive_p1_selected_backend_threshold_output_artifact_package`",
            "`derive_p1_selected_backend_threshold_output_source_digest`",
            "`derive_p1_selected_backend_threshold_output_source_package_digest`",
            "`derive_p1_selected_backend_aggregate_certificate_digest`",
            "`p1_selected_backend_threshold_output_artifact_gate`",
            "`P1SelectedBackendProofClosureArtifactPackage`",
            "`assess_p1_selected_backend_proof_closure_artifact`",
            "`derive_p1_selected_backend_proof_closure_artifact_package`",
            "`derive_p1_selected_backend_threshold_output_certificate_digest`",
            "`p1_selected_backend_proof_closure_artifact_gate`",
            "Batch 4 proof-closure artifact package boundary",
            "full KAT/validation artifact slots",
            "theorem-linkage artifact digest",
            "Batch 3 threshold-output artifact boundary",
            "real standard-provider aggregate-output package path",
            "selected-backend threshold-output source evidence",
            "reviewed source-package digest",
            "conformance/proof-review evidence only",
            "criterion-2 remains partial",
            "not selected-backend proof closure",
            "not production threshold ML-DSA security",
            "not CAVP/ACVTS validation",
            "not FIPS validation",
            "not rejection-distribution preservation",
            "not a completed standard-verifier compatibility proof",
            "mandatory criterion-2 release gate",
            "negative-corpus cases",
            "necessary but not sufficient",
            "real threshold selected-backend accepted aggregate signatures remain a release blocker",
            "not selected-backend aggregate recomputation",
            "not production threshold ML-DSA recomputation",
        ],
    );
    assert_contains_all(
        "src/production/rejection_equivalence.rs",
        &[
            "P1SelectedBackendThresholdOutputArtifactPackage",
            "P1SelectedBackendThresholdOutputArtifactCertificate",
            "P1SelectedBackendThresholdOutputArtifactAssessment",
            "P1ThresholdOutputClaimBoundary",
            "P1ThresholdOutputEvidenceSource",
            "P1SelectedBackendProofClosureArtifactPackage",
            "P1SelectedBackendProofClosureArtifactCertificate",
            "P1SelectedBackendProofClosureArtifactAssessment",
            "P1SelectedBackendProofClosureClaimBoundary",
            "assess_p1_selected_backend_threshold_output_artifact",
            "assess_p1_selected_backend_proof_closure_artifact",
            "derive_p1_selected_backend_threshold_output_artifact_package",
            "derive_p1_selected_backend_proof_closure_artifact_package",
            "derive_p1_selected_backend_threshold_output_source_digest",
            "derive_p1_selected_backend_threshold_output_source_package_digest",
            "threshold_output_source_package_digest",
            "derive_p1_selected_backend_aggregate_certificate_digest",
            "derive_p1_selected_backend_threshold_output_certificate_digest",
            "transcript_binding_evidence_digest",
            "standard_verifier_compatibility_artifact_digest",
            "ThresholdOutputCertificate",
            "RealRecomputationEvidence",
            "threshold_output_certificate_artifact",
            "real_recomputation_evidence_artifact",
            "threshold_output_certificate_artifact_digest",
            "real_recomputation_evidence_artifact_digest",
            "claims_real_threshold_signer",
            "claims_selected_backend_production",
            "claims_selected_backend_proof_closure",
            "claims_rejection_distribution_preservation",
            "claims_cavp_acvts_validation",
            "claims_fips_validation",
            "claims_standard_verifier_compatibility",
            "claims_completed_cryptographic_proof",
        ],
    );
    assert_contains_all(
        "tests/production_rejection_equivalence.rs",
        &[
            "p1_selected_backend_threshold_output_artifact_accepts_bound_source_and_aggregate_certificate",
            "p1_selected_backend_threshold_output_artifact_accepts_arbitrary_source_package_bytes",
            "p1_selected_backend_threshold_output_artifact_accepts_real_mldsa_package",
            "p1_selected_backend_threshold_output_artifact_rejects_stale_source_digest",
            "p1_selected_backend_threshold_output_artifact_rejects_production_claim_boundary",
            "p1_selected_backend_proof_closure_artifact_accepts_reviewed_threshold_output_and_proof_artifacts",
            "p1_selected_backend_proof_closure_artifact_rejects_stale_threshold_certificate_digest",
            "p1_selected_backend_proof_closure_artifact_rejects_stale_proof_transcript_binding",
            "p1_selected_backend_proof_closure_artifact_rejects_missing_validation_artifact",
            "p1_selected_backend_proof_closure_artifact_rejects_missing_distribution_review_artifact",
            "p1_selected_backend_proof_closure_artifact_rejects_missing_standard_verifier_compatibility_artifact",
            "p1_selected_backend_proof_closure_artifact_rejects_missing_theorem_linkage_artifact",
            "p1_selected_backend_proof_closure_artifact_rejects_threshold_slot_source_tamper",
            "p1_selected_backend_proof_closure_artifact_rejects_threshold_slot_review_tamper",
            "p1_selected_backend_proof_closure_artifact_rejects_recomputation_slot_source_tamper",
            "p1_selected_backend_proof_closure_artifact_rejects_recomputation_slot_review_tamper",
            "p1_selected_backend_proof_closure_artifact_rejects_production_claim_boundary",
        ],
    );
    assert_contains_all(
        "scripts/assess_lattice_hypothesis.py",
        &[
            "p1_selected_backend_aggregate_artifact_gate",
            "P1SelectedBackendAggregateArtifactPackage",
            "standard_verifier_bridge_fixture_package_digest",
            "raw fixture-package digest",
            "assess_p1_selected_backend_aggregate_artifact",
            "derive_p1_selected_backend_aggregate_artifact_package",
            "derive_p1_real_recomputation_evidence_digest",
            "p1_selected_backend_real_output_package",
            "p1_selected_backend_threshold_output_artifact_gate",
            "p1_selected_backend_proof_closure_artifact_gate",
            "p1_criterion2_threshold_output_certificate_artifact_gate",
            "p1_criterion2_real_recomputation_evidence_artifact_gate",
            "ThresholdOutputCertificate",
            "RealRecomputationEvidence",
            "P1SelectedBackendThresholdOutputArtifactPackage",
            "P1SelectedBackendProofClosureArtifactPackage",
            "assess_p1_selected_backend_threshold_output_artifact",
            "assess_p1_selected_backend_proof_closure_artifact",
            "derive_p1_selected_backend_threshold_output_artifact_package",
            "derive_p1_selected_backend_threshold_output_source_package_digest",
            "derive_p1_selected_backend_proof_closure_artifact_package",
            "derive_p1_selected_backend_threshold_output_certificate_digest",
            "Selected-backend aggregate-output artifact gate",
            "Real standard-provider selected-backend aggregate-output package",
            "Selected-backend threshold-output artifact gate",
            "Selected-backend proof-closure artifact package gate",
            "validator_10000_standard_verifier_fail_closed_gate",
            "10,000-validator standard-verifier fail-closed gate",
            "BackendUnavailable",
            "not standard-verifier equivalence",
            "real threshold ML-DSA backend emits a verifier-accepted aggregate signature",
            "stronger than fixture-only bridge confidence",
            "stronger than real standard-provider aggregate-output package evidence",
            "full KAT/validation artifact slots",
            "theorem-linkage artifact digest",
            "reviewed source package digest",
            "conformance/proof-review evidence only",
            "not selected-backend proof closure",
            "not production threshold ML-DSA security",
            "not CAVP/ACVTS validation",
            "not FIPS validation",
            "not a completed standard-verifier compatibility proof",
            "Selected-backend proof-closure artifact package gating",
        ],
    );
    assert_contains_all(
        "script_tests/test_assess_lattice_hypothesis.py",
        &[
            "test_selected_backend_aggregate_artifact_gate_updates_report_without_closing_proofs",
            "test_selected_backend_proof_closure_gate_requires_artifact_slot_tokens",
            "test_validator_10000_gate_updates_report_without_claiming_equivalence",
            "test_validator_10000_gate_rejects_missing_fail_closed_boundary",
            "write_validator_10000_standard_verifier_gate",
            "validator_10000_standard_verifier_fail_closed_gate",
            "p1_selected_backend_aggregate_artifact_gate",
            "p1_selected_backend_real_output_package",
            "p1_selected_backend_threshold_output_artifact_gate",
            "p1_selected_backend_proof_closure_artifact_gate",
            "accepts_real_mldsa_output_package",
            "threshold_output_artifact_accepts_real_mldsa_package",
            "threshold_output_artifact_accepts_arbitrary_source_package_bytes",
            "proof_closure_artifact_accepts_reviewed_threshold_output_and_proof_artifacts",
            "proof_closure_artifact_rejects_stale_threshold_certificate_digest",
            "proof_closure_artifact_rejects_stale_proof_transcript_binding",
            "proof_closure_artifact_rejects_missing_validation_artifact",
            "proof_closure_artifact_rejects_missing_distribution_review_artifact",
            "proof_closure_artifact_rejects_missing_standard_verifier_compatibility_artifact",
            "proof_closure_artifact_rejects_missing_theorem_linkage_artifact",
            "proof_closure_artifact_rejects_threshold_slot_source_tamper",
            "proof_closure_artifact_rejects_threshold_slot_review_tamper",
            "proof_closure_artifact_rejects_recomputation_slot_source_tamper",
            "proof_closure_artifact_rejects_recomputation_slot_review_tamper",
            "proof_closure_artifact_rejects_production_claim_boundary",
            "rejects_stale_recomputation_output",
            "rejects_stale_source_digest",
            "rejects_stale_bridge_for_changed_outputs",
            "rejects_unreviewed_package",
            "selected-backend proof closure",
        ],
    );
    assert_contains_all(
        "tests/validator_10000_standard_verifier_gate.rs",
        &[
            "simulated_10000_validator_aggregate_is_standard_sized_but_verifier_blocked",
            "const VALIDATOR_COUNT: u16 = 10_000",
            "const THRESHOLD: u16 = 6_667",
            "MLDSA65_SIGNATURE_BYTES",
            "SimulatedBackend::verify_standard",
            "BackendUnavailable",
            "simulation backend does not implement standard ML-DSA verification",
        ],
    );
}

#[test]
fn cryptography_readme_indexes_current_proof_docs() {
    assert_contains_all(
        CRYPTOGRAPHY_README,
        &[
            "active-adversary-model.md",
            "abort-retry-bias-evidence.md",
            "claims-matrix.md",
            "correctness-lemmas.md",
            "criterion-1-proof-substance.md",
            "criterion-2-proof-substance.md",
            "criterion-3-proof-substance.md",
            "validator-10000-standard-verifier-gate.md",
            "formal-security-theorem.md",
            "formal-threshold-mldsa-transcript.md",
            "hypothesis-outcome-taxonomy.md",
            "ideal-functionality.md",
            "mask-distribution-evidence.md",
            "noise-rejection-proof-plan.md",
            "partial-soundness-evidence.md",
            "phase-1-noise-bound-model.md",
            "proof-implementation-crosswalk.md",
            "protocol-code-crosswalk.md",
            "proof-obligations.md",
            "random-oracle-game.md",
            "rejection-equivalence-evidence.md",
            "side-channel-boundary.md",
            "thesis-operating-parameters.md",
            "unauthorized-aggregate-reduction.md",
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
            "## Selected Backend Direction",
            "## Manifest Anchors",
            "Transcript binding and Fiat-Shamir challenge derivation",
            "Canonical validator, commitment, and partial-share sets",
            "Wire encoding and untrusted-frame rejection",
            "Aggregation boundary and transcript consistency",
            "Simulation-only backend and production proof gates",
            "Selected backend direction artifact",
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
