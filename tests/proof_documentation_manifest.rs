use std::{fs, path::Path};

const PROOF_CROSSWALK: &str = "docs/cryptography/proof-implementation-crosswalk.md";
const FORMAL_THEOREM: &str = "docs/cryptography/formal-security-theorem.md";
const IDEAL_FUNCTIONALITY: &str = "docs/cryptography/ideal-functionality.md";
const REAL_IDEAL_SIMULATOR: &str = "docs/cryptography/real-ideal-simulator.md";
const CORRECTNESS_LEMMAS: &str = "docs/cryptography/correctness-lemmas.md";
const NOISE_REJECTION: &str = "docs/cryptography/noise-rejection-proof-plan.md";
const REJECTION_HYBRID_PROOF: &str = "docs/cryptography/rejection-sampling-hybrid-proof.md";
const REJECTION_BOUNDS: &str = "docs/cryptography/rejection-sampling-bounds.md";
const VSS_DKG_PLAN: &str = "docs/cryptography/vss-dkg-security-plan.md";
const VSS_BACKEND_SELECTION: &str = "docs/cryptography/vss-backend-selection.md";
const VSS_IDEALIZATION_SELECTION: &str = "docs/cryptography/vss-idealization-and-selection.md";
const ACTIVE_ADVERSARY: &str = "docs/cryptography/active-adversary-model.md";
const RANDOM_ORACLE_GAME: &str = "docs/cryptography/random-oracle-game.md";
const SIDE_CHANNEL_BOUNDARY: &str = "docs/cryptography/side-channel-boundary.md";
const FORMAL_TRANSCRIPT: &str = "docs/cryptography/formal-threshold-mldsa-transcript.md";
const CONTRIBUTION_SOUNDNESS: &str = "docs/cryptography/contribution-soundness-relation.md";
const PROOF_OBLIGATIONS: &str = "docs/cryptography/proof-obligations.md";
const CLAIMS_MATRIX: &str = "docs/cryptography/claims-matrix.md";
const SIMULATOR_HYBRID_REDUCTIONS: &str = "docs/cryptography/simulator-hybrid-reductions.md";
const PROOF_BIBLIOGRAPHY: &str = "docs/cryptography/proof-bibliography.md";
const PHASE_1_NOISE_MODEL: &str = "docs/cryptography/phase-1-noise-bound-model.md";

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

#[test]
fn proof_documentation_manifest_tracks_required_docs() {
    for path in [
        PROOF_CROSSWALK,
        FORMAL_THEOREM,
        IDEAL_FUNCTIONALITY,
        REAL_IDEAL_SIMULATOR,
        CORRECTNESS_LEMMAS,
        NOISE_REJECTION,
        REJECTION_HYBRID_PROOF,
        REJECTION_BOUNDS,
        VSS_DKG_PLAN,
        VSS_BACKEND_SELECTION,
        VSS_IDEALIZATION_SELECTION,
        ACTIVE_ADVERSARY,
        RANDOM_ORACLE_GAME,
        SIDE_CHANNEL_BOUNDARY,
        FORMAL_TRANSCRIPT,
        CONTRIBUTION_SOUNDNESS,
        PROOF_OBLIGATIONS,
        CLAIMS_MATRIX,
        SIMULATOR_HYBRID_REDUCTIONS,
        PROOF_BIBLIOGRAPHY,
        PHASE_1_NOISE_MODEL,
    ] {
        assert!(
            Path::new(path).is_file(),
            "required proof documentation file is missing: {path}"
        );
    }
}

#[test]
fn full_proof_surface_exposes_stable_anchors() {
    assert_contains_all(
        FORMAL_THEOREM,
        &[
            "# Formal Security Theorem for Threshold ML-DSA-65",
            "theorem-tmldsa-euf-cma",
            "assumptions",
            "limitations",
            "Theorem FST-T1",
            "Theorem FST-T1-IdealVSS",
            "FST-H0-IdealVSS",
            "Proof status: not proved in this repository.",
        ],
    );
    assert_contains_all(
        IDEAL_FUNCTIONALITY,
        &[
            "# Ideal Functionality F_TMLDSA",
            "ideal-functionality-ftmldsa",
            "## IF-3. Interfaces",
            "## IF-8. Simulator Obligations",
        ],
    );
    assert_contains_all(
        REAL_IDEAL_SIMULATOR,
        &[
            "# Real/Ideal Simulator Skeleton for Threshold ML-DSA-65",
            "real-ideal-simulator-skeleton",
            "## RIS-2. Simulator State",
            "## RIS-4. Oracle Programming Points",
            "## RIS-5. Corruption Handling",
            "## RIS-6. DKG Simulation",
            "## RIS-7. Signing Simulation",
            "## RIS-8. Abort and Evidence Simulation",
            "## RIS-9. Hybrid Sequence S0..S8",
            "simulator skeleton, not a completed proof",
        ],
    );
    assert_contains_all(
        CORRECTNESS_LEMMAS,
        &[
            "lemma-lagrange-reconstruction",
            "lemma-coefficient-lane-shamir",
            "lemma-transcript-challenge-binding",
            "lemma-infinity-norm-preservation",
            "lemma-standard-verification",
            "Current evidence vs remaining proof:",
            "## Lemma 3: Coefficient-Lane Shamir Reconstruction over `R_q`",
            "## Lemma 5: Transcript Challenge Binding",
            "## Lemma 7: Standard ML-DSA Verification Compatibility",
            "## Lemma 8: Infinity-Norm Bound Preservation under Accepted Aggregation",
        ],
    );
    assert_contains_all(
        NOISE_REJECTION,
        &[
            "noise-bound-obligations",
            "rejection-sampling-gap",
            "rejection-sampling-hybrid-proof.md",
            "## Lemma D: Infinity-Norm Bound Preservation",
            "## Exactly What Remains to Be Proven",
        ],
    );
    assert_contains_all(
        REJECTION_HYBRID_PROOF,
        &[
            "# Rejection-Sampling Hybrid Proof Skeleton",
            "rejection-hybrid-proof",
            "rsh-h0-centralized-mldsa",
            "rsh-h1-shared-secret-decomposition",
            "rsh-h2-shared-mask-generation",
            "rsh-h3-commit-before-challenge",
            "rsh-h4-partial-response-reconstruction",
            "rsh-h5-aggregate-rejection-predicate",
            "rsh-h6-accepted-signature-distribution",
            "Distribution equivalence is not complete.",
        ],
    );
    assert_contains_all(
        REJECTION_BOUNDS,
        &[
            "# Rejection-Sampling Bounds Worksheet",
            "rejection-sampling-bounds",
            "Status: bound-oriented proof worksheet, not a completed proof.",
            "eps_mask",
            "eps_withhold",
            "eps_rej",
            "## Theorem T1: Conditional Accepted-Distribution Bound",
            "Delta_accept",
            "eps_commit",
            "epsilon-closure-dependency-graph",
            "eps-mask-closure-route",
            "eps-rej-closure-route",
            "eps-withhold-closure-route",
            "## Top Missing Mathematical Bounds",
        ],
    );
    assert_contains_all(
        VSS_DKG_PLAN,
        &[
            "vss-security-properties",
            "dkg-key-bias-resistance",
            "vss-dkg-backend-selection-checklist",
            "production-replacement-obligations",
            "## Current Non-Claims",
        ],
    );
    assert_contains_all(
        VSS_BACKEND_SELECTION,
        &[
            "# VSS/DKG Backend Selection Framework",
            "vss-backend-selection",
            "backend-selection-required-properties",
            "candidate-feldman-pedersen",
            "candidate-lattice-vector-commitments",
            "candidate-ideal-functionality-placeholder",
            "backend-selection-comparison-matrix",
            "backend-selection-checklist",
            "vss-backend-decision-record",
            "Current decision: no backend selected.",
        ],
    );
    assert_contains_all(
        VSS_IDEALIZATION_SELECTION,
        &[
            "# VSS Idealization and Backend Selection",
            "vss-idealization-and-selection",
            "Ideal Functionality `F_VSS_DKG`",
            "The `F_TMLDSA` proof may cite `F_VSS_DKG`",
            "## Decision Record: Immediate IdealVSS Route",
            "not a production backend selection",
        ],
    );
    assert_contains_all(
        ACTIVE_ADVERSARY,
        &[
            "active-adversary-model",
            "## Corruption Options",
            "## Rushing Behavior",
            "## Complaint and Evidence Semantics",
        ],
    );
    assert_contains_all(
        RANDOM_ORACLE_GAME,
        &[
            "# Random-Oracle Game for Threshold ML-DSA-65",
            "ROG-D1. Message-Binding Oracle `H_mu`",
            "ROG-D2. Commitment and `w`-Binding Oracle `H_w`",
            "ROG-D3. Signing-Challenge Oracle `H_c`",
            "ROG-D4. VSS and DKG Proof Oracle `H_vss`",
            "ROG-D5. Signing Contribution-Proof Oracle `H_contrib`",
        ],
    );
    assert_contains_all(
        SIDE_CHANNEL_BOUNDARY,
        &[
            "# Side-Channel and Constant-Time Boundary",
            "## Boundary Statement",
            "## Empirical Obligations",
            "## Production Gate",
        ],
    );
    assert_contains_all(
        FORMAL_TRANSCRIPT,
        &[
            "ftmt-0-scope",
            "ftmt-2-random-oracle-alignment",
            "random-oracle-game.md",
        ],
    );
    assert_contains_all(
        CONTRIBUTION_SOUNDNESS,
        &[
            "# Contribution Soundness Relation Worksheet",
            "contribution-soundness-relation",
            "csr-production-statement",
            "csr-soundness-game",
            "csr-extraction-target",
            "csr-witness-hiding-target",
            "csr-non-claims",
        ],
    );
    assert_contains_all(
        PROOF_OBLIGATIONS,
        &[
            "## Full-Proof Surface Status Overlay",
            "FST-T1 threshold unforgeability",
            "Side-channel and constant-time discipline",
        ],
    );
    assert_contains_all(
        CLAIMS_MATRIX,
        &[
            "## Full-Proof Surface Claim Overlay",
            "Threshold EUF-CMA security",
            "Rejection-sampling distribution preservation",
        ],
    );
    assert_contains_all(
        SIMULATOR_HYBRID_REDUCTIONS,
        &[
            "# Simulator Hybrid Reductions Worksheet",
            "simulator-hybrid-reductions",
            "This is a reduction worksheet, not a completed proof.",
            "## SHR-1. Hybrid Restatement S0..S8",
            "## SHR-1A. Worksheet Advantage Terms",
            "Adv_real_ideal(A,Z)",
            "eps_classify",
            "unauthorized-output-classifier",
            "eps-classify-decomposition",
            "classifier-totality-obligation",
            "classifier-disjointness-obligation",
            "## SHR-5. Hardest Remaining Reductions",
        ],
    );
    assert_contains_all(
        PROOF_BIBLIOGRAPHY,
        &[
            "# Proof Dependency Bibliography and Citation Map",
            "proof-bibliography",
            "## FIPS 204 / ML-DSA",
            "## Fiat-Shamir With Aborts",
            "## VSS/DKG",
            "## Unresolved Citation Targets",
            "## Citation Closure Checklist",
            "Citation needed",
        ],
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
            "Contribution soundness relation target",
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
