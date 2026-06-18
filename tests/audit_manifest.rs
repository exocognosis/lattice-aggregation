use std::{fs, path::Path};

const PROOF_OBLIGATIONS: &str = "docs/cryptography/proof-obligations.md";
const AUDIT_README: &str = "docs/audit/README.md";
const ATTACK_SURFACE: &str = "docs/audit/attack-surface.md";
const TCB: &str = "docs/audit/tcb.md";

#[test]
fn proof_obligations_document_exists_and_tracks_required_items() {
    let doc = read_required_doc(PROOF_OBLIGATIONS);
    let normalized = doc.to_ascii_lowercase();

    for required in [
        "po-1",
        "malicious-secure dkg/vss",
        "po-2",
        "contribution proof soundness",
        "po-3",
        "selective-abort",
        "po-4",
        "aggregation/noise correctness",
        "po-5",
        "transcript/challenge unbiasability",
        "po-6",
        "side-channel",
        "po-7",
        "production slashing/evidence soundness",
        "current evidence",
        "missing proof work",
        "closure criteria",
        "production security claims",
    ] {
        assert!(
            normalized.contains(required),
            "proof obligations doc missing required anchor: {required}"
        );
    }
}

#[test]
fn audit_packet_exists_and_maps_required_surfaces() {
    for path in [AUDIT_README, ATTACK_SURFACE, TCB] {
        assert!(Path::new(path).exists(), "missing audit document: {path}");
    }

    let attack_surface = read_required_doc(ATTACK_SURFACE).to_ascii_lowercase();
    for required in [
        "feature gates",
        "hazmat ml-dsa internals",
        "actor/network boundaries",
        "wire decoding",
        "evidence/slashing artifacts",
        "benchmark/export pipeline",
        "docs/claim drift",
        "research scaffold",
    ] {
        assert!(
            attack_surface.contains(required),
            "attack-surface doc missing required anchor: {required}"
        );
    }

    let tcb = read_required_doc(TCB).to_ascii_lowercase();
    for required in [
        "trusted computing base",
        "dependency assumptions",
        "feature-gate risks",
        "review files",
        "non-production boundaries",
        "not production-ready",
    ] {
        assert!(
            tcb.contains(required),
            "TCB doc missing required anchor: {required}"
        );
    }
}

#[test]
fn audit_readme_links_supporting_claim_boundary_docs() {
    let readme = read_required_doc(AUDIT_README);

    for required in [
        "attack-surface.md",
        "tcb.md",
        "../cryptography/claims-matrix.md",
        "../cryptography/protocol-code-crosswalk.md",
        "../benchmarks/release-readiness-checklist.md",
    ] {
        assert!(
            readme.contains(required),
            "audit README missing required link: {required}"
        );
    }
}

fn read_required_doc(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
}
