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
            "## Reduction Target",
            "## Assumptions Named by Case",
            "## Reduction Cases",
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
        ],
    );
}
