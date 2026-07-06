# Phase 1 Theorem Linkage Fixture Ref Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a checked Criterion 2 theorem-linkage proof-slot fixture reference without promoting Criterion 2 beyond partial evidence.

**Architecture:** Reuse the existing Criterion 2 proof-slot fixture pattern for a new `theorem_linkage_artifact_digest` fixture. Keep the fixture file-backed, digest-pinned, assessor-visible, and documentation-tracked while preserving the `evidence_present_unclosed` and proof-review-only boundary.

**Tech Stack:** Rust integration tests, JSON fixtures, Python assessor unit tests, Markdown/JSON docs.

---

### Task 1: Red Tests

**Files:**
- Modify: `tests/production_rejection_equivalence.rs`
- Modify: `tests/criterion2_proof_substance_manifest.rs`
- Modify: `script_tests/test_assess_lattice_hypothesis.py`

- [x] **Step 1: Add fixture loader and digest test references**

Add a theorem-linkage fixture loader and package-digest helper following the existing rejection-distribution pattern. The fixture file must not exist yet so the Rust test fails on `include_str!`.

- [x] **Step 2: Add typed-slot fixture test**

Add `theorem_linkage_artifact_fixture_parses_and_matches_typed_slot`, asserting the fixture metadata, `TheoremLinkage` kind, source digest `36...36`, review digest `30...30`, artifact digest `3aff...36d3`, package/certificate theorem-linkage accessor, and non-claim flags.

- [x] **Step 3: Add manifest and assessor expectations**

Add expected theorem-linkage fixture refs to the Rust manifest test and Python assessor test:

```text
slot_id: theorem_linkage_artifact_digest
fixture_path: tests/fixtures/p1_theorem_linkage_artifact_fixture.json
schema: lattice-aggregation:p1-theorem-linkage-artifact:v1
current_status: evidence_present_unclosed
claim_boundary: conformance/proof-review evidence only
```

- [x] **Step 4: Run red checks**

Run:

```bash
python3 -m unittest script_tests.test_assess_lattice_hypothesis.DocumentClassificationTests.test_criterion2_status_surfaces_real_recomputation_fixture_reference
CARGO_NET_OFFLINE=true CARGO_TARGET_DIR=/private/tmp/lattice-phase1-theorem-red-target cargo test --features coordinator-assisted --test criterion2_proof_substance_manifest criterion2_manifest_links_checked_fixture_refs
CARGO_NET_OFFLINE=true CARGO_TARGET_DIR=/private/tmp/lattice-phase1-theorem-red-target cargo test --features coordinator-assisted --test production_rejection_equivalence theorem_linkage_artifact_fixture
```

Expected: Python/Rust checks fail because docs, assessor constants, and the fixture file have not been updated yet.

### Task 2: Implement Fixture and Traceability

**Files:**
- Create: `tests/fixtures/p1_theorem_linkage_artifact_fixture.json`
- Modify: `tests/production_rejection_equivalence.rs`
- Modify: `docs/cryptography/criterion-2-proof-substance.json`
- Modify: `docs/cryptography/criterion-2-proof-substance.md`
- Modify: `scripts/assess_lattice_hypothesis.py`
- Modify: `script_tests/test_assess_lattice_hypothesis.py`
- Modify: `tests/criterion2_proof_substance_manifest.rs`
- Modify: `tests/proof_documentation_manifest.rs`
- Modify: `README.md`
- Modify: `docs/cryptography/claims-matrix.md`

- [x] **Step 1: Add theorem-linkage fixture**

Create `tests/fixtures/p1_theorem_linkage_artifact_fixture.json` with schema `lattice-aggregation:p1-theorem-linkage-artifact:v1`, proof-review-only claim boundary, source predecessor fixture paths, source digest `3636...3636`, review digest `3030...3030`, and artifact digest `3aff2f1e9e0bd4e98d89d0135af9b8b7e57437b27ff30e82a5817d81647736d3`.

- [x] **Step 2: Pin fixture package digest**

Compute the SHA3-256 digest using domain separator:

```text
lattice-aggregation:p1-theorem-linkage-artifact-fixture-package:v1
```

Set `EXPECTED_P1_THEOREM_LINKAGE_ARTIFACT_FIXTURE_PACKAGE_DIGEST_HEX` to the computed digest.

- [x] **Step 3: Update docs and assessor constants**

Add the theorem-linkage fixture to `artifact_fixture_refs`, `evidence_refs`, Markdown required-slot prose, README status flow, claims matrix, and the assessor's pinned `CRITERION2_ARTIFACT_FIXTURE_REFS` plus expected Markdown tokens.

- [x] **Step 4: Preserve claim boundary**

All new prose must keep `partially_met`, `partially_proven`, `evidence_present_unclosed`, and `conformance/proof-review evidence only`. Do not claim Criterion 2 closure, selected-backend proof closure, production threshold ML-DSA security, CAVP/ACVTS validation, FIPS validation, rejection-distribution preservation, or completed standard-verifier compatibility.

### Task 3: Verification and Publication

**Files:**
- All files touched by Tasks 1 and 2

- [x] **Step 1: Run focused green checks**

Run:

```bash
cargo fmt --all -- --check
python3 -m unittest script_tests.test_assess_lattice_hypothesis script_tests.test_run_simulation_benchmarks
CARGO_NET_OFFLINE=true CARGO_TARGET_DIR=/private/tmp/lattice-phase1-theorem-target cargo test --features coordinator-assisted --test criterion2_proof_substance_manifest --test proof_documentation_manifest --test production_rejection_equivalence
python3 scripts/assess_lattice_hypothesis.py --root . --out /private/tmp/lattice-phase1-theorem-assessment --offline --target-dir /private/tmp/lattice-phase1-theorem-assessment-target
git diff --check
```

- [ ] **Step 2: Review and commit**

Request final agent review, fix any actionable issues, stage only intended files, run `git diff --cached --check`, and commit:

```bash
git commit -m "Add Criterion 2 theorem-linkage fixture ref"
```

- [ ] **Step 3: Push and open PR**

Push `codex/phase1-theorem-linkage-fixture-ref`, open a non-draft PR, and watch GitHub checks to completion.
