# Phase 1 Criterion 2 Threshold-Output Fixture Reference Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Promote the P1 threshold-output certificate proof slot into the checked Criterion 2 `artifact_fixture_refs` contract.

**Architecture:** Add one checked JSON fixture for the existing `threshold_output_certificate_digest` typed slot, wire it into the Criterion 2 manifest and assessor constant, and update docs without changing production logic or promoting Criterion 2 beyond `partially_met`.

**Tech Stack:** Rust typed-slot tests, Rust manifest/docs tests, Python unittest assessor tests, Markdown/JSON proof docs.

---

### Task 1: Add Red Contract Tests

**Files:**
- Modify: `script_tests/test_assess_lattice_hypothesis.py`
- Modify: `tests/criterion2_proof_substance_manifest.rs`
- Modify: `tests/production_rejection_equivalence.rs`

- [x] **Step 1: Add Python failing assertion**

Extend `test_criterion2_status_surfaces_real_recomputation_fixture_reference` so it also expects:

```python
{
    "slot_id": "threshold_output_certificate_digest",
    "fixture_path": "tests/fixtures/p1_threshold_output_certificate_artifact_fixture.json",
    "schema": "lattice-aggregation:p1-threshold-output-certificate-artifact:v1",
    "current_status": "evidence_present_unclosed",
    "claim_boundary": "conformance/proof-review evidence only",
}
```

- [x] **Step 2: Add Rust manifest failing assertion**

Extend `criterion2_manifest_links_checked_fixture_refs` so it requires the threshold-output certificate fixture ref and verifies the fixture file exists.

- [x] **Step 3: Add Rust typed fixture failing test**

Add a threshold-output certificate fixture parser and typed-slot match test parallel to `real_recomputation_artifact_fixture_parses_and_matches_typed_slot`, plus a fixture package drift test.

- [x] **Step 4: Verify red**

Run the focused tests and confirm failure before implementation:

```sh
python3 -m unittest script_tests.test_assess_lattice_hypothesis.DocumentClassificationTests.test_criterion2_status_surfaces_real_recomputation_fixture_reference
CARGO_TARGET_DIR=/private/tmp/lattice-phase1-threshold-red-target cargo test --features coordinator-assisted --test criterion2_proof_substance_manifest criterion2_manifest_links_checked_fixture_refs
CARGO_TARGET_DIR=/private/tmp/lattice-phase1-threshold-red-target cargo test --features coordinator-assisted --test production_rejection_equivalence threshold_output_certificate_artifact_fixture_parses_and_matches_typed_slot
```

### Task 2: Add The Checked Fixture

**Files:**
- Add: `tests/fixtures/p1_threshold_output_certificate_artifact_fixture.json`
- Modify: `tests/production_rejection_equivalence.rs`

- [x] **Step 1: Create fixture JSON**

Use schema `lattice-aggregation:p1-threshold-output-certificate-artifact:v1`, claim boundary `conformance/proof-review evidence only`, source package `coordinator-assisted threshold-output transcript package v1`, and expected digest fields derived from the existing selected-backend threshold-output certificate path.

- [x] **Step 2: Implement Rust fixture structs and helpers**

Parse the fixture, bind it to `proof_slot_artifacts.threshold_output_certificate_artifact`, check the source package digest, certificate digest, source evidence digest, review digest, artifact digest, predecessor bridge digest, recomputation digest, and negative-case names.

- [x] **Step 3: Add drift guard**

Add a deterministic package digest test using domain separator `lattice-aggregation:p1-threshold-output-certificate-artifact-fixture-package:v1`.

### Task 3: Wire Fixture Ref Into Assessor And Manifest

**Files:**
- Modify: `scripts/assess_lattice_hypothesis.py`
- Modify: `docs/cryptography/criterion-2-proof-substance.json`
- Modify: `script_tests/test_assess_lattice_hypothesis.py`

- [x] **Step 1: Add assessor fixture ref constant**

Append the threshold-output fixture metadata to `CRITERION2_ARTIFACT_FIXTURE_REFS`.

- [x] **Step 2: Add manifest fixture ref**

Append matching metadata to `proof_payload.artifact_fixture_refs` in `criterion-2-proof-substance.json`.

- [x] **Step 3: Update synthetic report fixture**

Add the same fixture metadata to `write_criterion2_proof_substance_formalization`.

### Task 4: Update Reader-Facing Docs Without Overclaiming

**Files:**
- Modify: `README.md`
- Modify: `docs/cryptography/criterion-2-proof-substance.md`
- Modify: `docs/cryptography/claims-matrix.md`
- Modify as needed: `tests/proof_documentation_manifest.rs`

- [x] **Step 1: Add additive wording only**

Use this pattern:

```text
checked threshold-output certificate proof-slot fixture for Criterion 2 at tests/fixtures/p1_threshold_output_certificate_artifact_fixture.json; this is conformance/proof-review evidence only, not selected-backend proof closure, not production threshold ML-DSA security, not CAVP/ACVTS validation, not FIPS validation, not rejection-distribution preservation, and not a completed standard-verifier compatibility proof.
```

- [x] **Step 2: Preserve existing boundaries**

Do not remove or weaken `partially_met`, `partially_proven`, `formalized_open_proof_payload`, `evidence_present_unclosed`, or the explicit non-claims.

### Task 5: Verify Batch B

**Files:** No edits expected.

- [x] **Step 1: Run formatting and Python tests**

```sh
cargo fmt --all -- --check
python3 -m unittest script_tests.test_assess_lattice_hypothesis script_tests.test_run_simulation_benchmarks
```

- [x] **Step 2: Run Rust proof/docs/fixture tests**

```sh
CARGO_TARGET_DIR=/private/tmp/lattice-phase1-threshold-target cargo test --features coordinator-assisted --test criterion2_proof_substance_manifest --test proof_documentation_manifest --test production_rejection_equivalence
```

- [x] **Step 3: Run assessment**

```sh
python3 scripts/assess_lattice_hypothesis.py --root . --out /private/tmp/lattice-phase1-threshold-assessment --offline --target-dir /private/tmp/lattice-phase1-threshold-assessment-target
```

Expected: command summary passes, `overall_verdict` remains `partially_proven`, and `aggregate_rejection_equivalence` remains `partially_met`.

- [x] **Step 4: Run diff hygiene**

```sh
git diff --check
```
