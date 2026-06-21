use std::{fs, path::Path};

const REDUCTION_MANIFEST: &str = "docs/cryptography/unauthorized-aggregate-reduction.md";

fn read_manifest() -> String {
    fs::read_to_string(REDUCTION_MANIFEST)
        .unwrap_or_else(|err| panic!("failed to read {REDUCTION_MANIFEST}: {err}"))
}

fn assert_contains_all(doc: &str, required: &[&str]) {
    for needle in required {
        assert!(
            doc.contains(needle),
            "{REDUCTION_MANIFEST} is missing required text: {needle}"
        );
    }
}

fn assert_not_contains_any(doc: &str, forbidden: &[&str]) {
    for needle in forbidden {
        assert!(
            !doc.contains(needle),
            "{REDUCTION_MANIFEST} contains overclaiming text: {needle}"
        );
    }
}

fn manifest_line<'a>(doc: &'a str, marker: &str) -> &'a str {
    doc.lines()
        .find(|line| line.contains(marker))
        .unwrap_or_else(|| panic!("{REDUCTION_MANIFEST} is missing line marker: {marker}"))
}

fn assert_line_contains_all(doc: &str, marker: &str, required: &[&str]) {
    let line = manifest_line(doc, marker);
    for needle in required {
        assert!(
            line.contains(needle),
            "{REDUCTION_MANIFEST} line for {marker} is missing {needle}: {line}"
        );
    }
}

#[test]
fn reduction_manifest_file_exists() {
    assert!(
        Path::new(REDUCTION_MANIFEST).is_file(),
        "unauthorized aggregate reduction manifest is missing"
    );
}

#[test]
fn reduction_manifest_keeps_required_sections() {
    let doc = read_manifest();
    assert_contains_all(
        &doc,
        &[
            "# Unauthorized Aggregate Reduction Manifest",
            "Status: reduction-case manifest, not a completed proof.",
            "## Scope and Claim Boundary",
            "## Closure Package Framework",
            "## Reduction Target",
            "## Assumptions Named by Case",
            "## Reduction Cases",
            "## Protocol Event Grammar",
            "## Deterministic UAR Classifier",
            "## Base ML-DSA Theorem Citation Placeholder",
            "## Threshold-Side Assumption Proof and Citation Slots",
            "## Simulator Obligations",
            "## Hybrid Bound Table",
            "## External Review Signoff",
            "## Manifest Checklist",
            "## What Remains to Close Blocker 5",
        ],
    );
}

#[test]
fn reduction_manifest_names_required_assumptions() {
    let doc = read_manifest();
    assert_contains_all(
        &doc,
        &[
            "FST-A1, ML-DSA-65 unforgeability",
            "FST-A2, threshold sharing soundness",
            "FST-A3, verifiable share binding",
            "FST-A4, commitment binding and hiding",
            "FST-A5, abort and noise-bound preservation",
            "FST-A6, partial signature correctness and extractability",
            "FST-A7, transcript collision resistance and domain separation",
            "FST-A8, canonical collection validation",
            "IF-S1, threshold authorization",
            "IF-S2, message authorization",
            "IF-R6, aggregate mapping",
        ],
    );
}

#[test]
fn reduction_manifest_has_base_forgery_case() {
    let doc = read_manifest();
    assert_line_contains_all(
        &doc,
        "| UAR-C0 |",
        &[
            "Base ML-DSA forgery",
            "MLDSA65.Verify(pk, m*, sigma*) = accept",
            "m* was not authorized",
            "FST-A1",
            "base-signature forgery",
        ],
    );
}

#[test]
fn reduction_manifest_has_threshold_side_violation_cases() {
    let doc = read_manifest();
    let required_cases = [
        (
            "| UAR-C1 |",
            &[
                "Subthreshold share reconstruction",
                "fewer than t",
                "FST-A2",
                "FST-L6",
            ][..],
        ),
        (
            "| UAR-C2 |",
            &[
                "Rogue or unbound share admission",
                "FST-A3",
                "FST-A8",
                "FST-G4",
            ][..],
        ),
        (
            "| UAR-C3 |",
            &["Invalid partial accepted", "FST-A6", "FST-L4", "IF-E3"][..],
        ),
        (
            "| UAR-C4 |",
            &[
                "Transcript or random-oracle rebinding",
                "FST-A7",
                "FST-L1",
                "FST-L2",
            ][..],
        ),
        (
            "| UAR-C5 |",
            &[
                "Canonical collection bypass",
                "duplicate",
                "unknown",
                "FST-A8",
                "FST-L3",
            ][..],
        ),
        (
            "| UAR-C6 |",
            &[
                "Abort or distribution preservation failure",
                "FST-A5",
                "FST-L7",
                "Noise Lemma H",
            ][..],
        ),
        (
            "| UAR-C7 |",
            &[
                "Ideal-functionality release mismatch",
                "IF-S1",
                "IF-S2",
                "IF-R6",
                "FST-L8",
            ][..],
        ),
        (
            "| UAR-C8 |",
            &[
                "Commitment binding or hiding failure",
                "FST-A4",
                "Noise Lemma A",
            ][..],
        ),
    ];

    for (marker, required) in required_cases {
        assert_line_contains_all(&doc, marker, required);
    }
}

#[test]
fn reduction_manifest_defines_protocol_event_grammar() {
    let doc = read_manifest();
    assert_contains_all(
        &doc,
        &[
            "UnauthorizedAggregateEvent ::= EventEnvelope PublicObjects CommitmentSet PartialSet AggregateOutput VerifierResult EvidenceSet",
            "EventEnvelope ::= key_id sid epoch_id threshold validator_set corruption_bound",
            "PublicObjects ::= pk validator_public_keys authorization_policy domain_separation_tag",
            "CommitmentRecord ::= signer_id commitment commitment_opening_status transcript_binding",
            "PartialRecord ::= signer_id partial_signature partial_verification_result signer_evidence",
            "AggregateOutput ::= pk message sigma aggregate_metadata",
            "VerifierResult ::= MLDSA65.Verify(pk, message, sigma)",
            "EvidenceSet ::= public transcript-bound evidence only",
            "AbortRecord ::= signer_id abort_reason round transcript_prefix",
        ],
    );
}

#[test]
fn reduction_manifest_has_complete_deterministic_classifier() {
    let doc = read_manifest();
    assert_contains_all(
        &doc,
        &[
            "The classifier must be total, deterministic, and single-valued.",
            "First matching case wins; no event may be assigned to more than one case.",
            "Unclassified events keep blocker 5 open.",
        ],
    );

    let required_rows = [
        (
            "| UAR-CLASS-C1 |",
            &["UAR-C1", "fewer than `t`", "valid contributions", "FST-A2"][..],
        ),
        (
            "| UAR-CLASS-C2 |",
            &["UAR-C2", "outside `V`", "unbound", "FST-A3", "FST-A8"][..],
        ),
        (
            "| UAR-CLASS-C3 |",
            &["UAR-C3", "partial verification fails", "counted", "FST-A6"][..],
        ),
        (
            "| UAR-CLASS-C4 |",
            &["UAR-C4", "two distinct typed tuples", "FST-A7"][..],
        ),
        (
            "| UAR-CLASS-C5 |",
            &[
                "UAR-C5",
                "duplicate",
                "unknown",
                "threshold-mismatched",
                "FST-A8",
            ][..],
        ),
        (
            "| UAR-CLASS-C6 |",
            &["UAR-C6", "abort", "distribution", "FST-A5"][..],
        ),
        (
            "| UAR-CLASS-C7 |",
            &["UAR-C7", "ideal release", "IF-S1", "IF-S2", "IF-R6"][..],
        ),
        (
            "| UAR-CLASS-C8 |",
            &["UAR-C8", "commitment", "binding", "hiding", "FST-A4"][..],
        ),
        (
            "| UAR-CLASS-C0 |",
            &[
                "UAR-C0",
                "all threshold-side predicates are false",
                "FST-A1",
            ][..],
        ),
    ];

    for (marker, required) in required_rows {
        assert_line_contains_all(&doc, marker, required);
    }
}

#[test]
fn reduction_manifest_has_base_theorem_placeholder_and_digest_slot() {
    let doc = read_manifest();
    assert_contains_all(
        &doc,
        &[
            "Base theorem citation status: PLACEHOLDER - no theorem imported yet.",
            "Theorem identifier slot: `PENDING-FST-A1-ML-DSA-65-EUF-CMA`",
            "Source citation slot: `PENDING`",
            "Model compatibility slot: `PENDING`",
            "Base ML-DSA theorem digest: `sha256:<pending>`",
            "Digest algorithm: SHA-256 over the final cited theorem artifact.",
            "Reviewer must replace this placeholder before FST-A1 can close.",
        ],
    );
}

#[test]
fn reduction_manifest_has_threshold_assumption_slots_for_each_nonbase_case() {
    let doc = read_manifest();
    let required_slots = [
        (
            "| SLOT-UAR-C1 |",
            &["UAR-C1", "FST-A2", "Proof/citation slot: PENDING"][..],
        ),
        (
            "| SLOT-UAR-C2 |",
            &["UAR-C2", "FST-A3", "FST-A8", "Proof/citation slot: PENDING"][..],
        ),
        (
            "| SLOT-UAR-C3 |",
            &["UAR-C3", "FST-A6", "Proof/citation slot: PENDING"][..],
        ),
        (
            "| SLOT-UAR-C4 |",
            &["UAR-C4", "FST-A7", "Proof/citation slot: PENDING"][..],
        ),
        (
            "| SLOT-UAR-C5 |",
            &["UAR-C5", "FST-A8", "Proof/citation slot: PENDING"][..],
        ),
        (
            "| SLOT-UAR-C6 |",
            &["UAR-C6", "FST-A5", "Proof/citation slot: PENDING"][..],
        ),
        (
            "| SLOT-UAR-C7 |",
            &[
                "UAR-C7",
                "IF-S1",
                "IF-S2",
                "IF-R6",
                "Proof/citation slot: PENDING",
            ][..],
        ),
        (
            "| SLOT-UAR-C8 |",
            &["UAR-C8", "FST-A4", "Proof/citation slot: PENDING"][..],
        ),
    ];

    for (marker, required) in required_slots {
        assert_line_contains_all(&doc, marker, required);
    }
}

#[test]
fn reduction_manifest_has_simulator_obligations_hybrid_bounds_and_signoff() {
    let doc = read_manifest();
    assert_contains_all(
        &doc,
        &[
            "SIM-O1 Static corruption schedule",
            "SIM-O2 Ideal release extraction",
            "SIM-O3 Evidence translation",
            "SIM-O4 Abort scheduling and distribution accounting",
            "SIM-O5 Random-oracle programming and accounting",
            "SIM-O6 Standard-verifier bridge",
            "SIM-O7 Failure-to-case audit log",
            "Every bound term is pending and must be replaced with a concrete advantage expression.",
            "| HYB-0 | Real unauthorized aggregate event |",
            "| HYB-1 | Grammar parse and canonicalization |",
            "| HYB-2 | Transcript binding and random-oracle programming |",
            "| HYB-3 | Partial validation and extraction |",
            "| HYB-4 | Commitment and distribution preservation |",
            "| HYB-5 | Ideal release mapping |",
            "| HYB-6 | Base ML-DSA forgery extraction |",
            "No external review signoff has been recorded in this repository.",
            "| Cryptographer reduction review | reviewer identity, date, scope, verdict | PENDING |",
            "| Base theorem artifact review | cited theorem digest and model match | PENDING |",
            "| Threshold assumption review | proof/citation slots for UAR-C1 through UAR-C8 | PENDING |",
            "| Implementation-binding review | conformance/KAT trace to final interfaces | PENDING |",
        ],
    );
}

#[test]
fn reduction_manifest_enforces_claim_boundary_language() {
    let doc = read_manifest();
    assert_contains_all(
        &doc,
        &[
            "This manifest does not prove FST-T1 or FST-T2.",
            "It is a checklist for a future reduction, not a theorem statement.",
            "The deterministic simulation backend is not evidence for this reduction.",
            "Conformance tests are necessary traceability gates, not cryptographic proof.",
            "Do not claim threshold EUF-CMA security from this manifest.",
            "This closure package is an outline only; it is not an accepted reduction.",
            "Placeholders, digest slots, and signoff slots are not citations or proof.",
            "No classifier row closes a theorem without its proof/citation slot and bound term.",
            "No UAR-C case is closed by this document.",
        ],
    );
    assert_not_contains_any(
        &doc,
        &[
            "This proves FST-T1",
            "This proves FST-T2",
            "threshold EUF-CMA security is complete",
            "production threshold ML-DSA security is complete",
            "the simulation backend proves",
            "This document completes the reduction",
            "Blocker 5 is closed",
        ],
    );
}
