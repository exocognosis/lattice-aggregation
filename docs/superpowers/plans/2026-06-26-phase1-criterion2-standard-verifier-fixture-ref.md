# Phase 1 Criterion 2 Standard-Verifier Fixture Reference Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Promote the existing P1 standard-verifier compatibility artifact fixture into the checked Criterion 2 `artifact_fixture_refs` contract.

**Architecture:** The existing fixture file stays authoritative. This batch only wires that fixture into the Criterion 2 manifest, assessor constant, docs, README, and tests. It must not change production logic or promote Criterion 2 beyond `partially_met`.

**Tech Stack:** Rust manifest tests, Python unittest assessor tests, Markdown/JSON proof docs.

---

### Task 1: Add Red Contract Tests

**Files:**
- Modify: `script_tests/test_assess_lattice_hypothesis.py`
- Modify: `tests/criterion2_proof_substance_manifest.rs`

- [ ] **Step 1: Add Python failing assertion**

Extend `test_criterion2_status_surfaces_real_recomputation_fixture_reference` so it also expects:

```python
{
    "slot_id": "standard_verifier_compatibility_artifact_digest",
    "fixture_path": "tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json",
    "schema": "lattice-aggregation:p1-standard-verifier-compatibility-artifact:v1",
    "current_status": "evidence_present_unclosed",
    "claim_boundary": "conformance/proof-review evidence",
}
```

- [ ] **Step 2: Verify Python red**

Run:

```sh
python3 -m unittest script_tests.test_assess_lattice_hypothesis.DocumentClassificationTests.test_criterion2_status_surfaces_real_recomputation_fixture_reference
```

Expected: fail because the fixture ref is not yet returned by the assessor.

- [ ] **Step 3: Add Rust failing manifest assertion**

Generalize `criterion2_manifest_links_real_recomputation_fixture` so it checks both the real recomputation fixture and the standard-verifier compatibility fixture path/schema/status/boundary and fixture existence.

- [ ] **Step 4: Verify Rust red**

Run:

```sh
CARGO_TARGET_DIR=/private/tmp/lattice-phase1-red-target cargo test --test criterion2_proof_substance_manifest criterion2_manifest_links_checked_fixture_refs
```

Expected: fail because the manifest does not yet list the standard-verifier fixture in `artifact_fixture_refs`.

### Task 2: Wire Fixture Ref Into Assessor And Manifest

**Files:**
- Modify: `scripts/assess_lattice_hypothesis.py`
- Modify: `docs/cryptography/criterion-2-proof-substance.json`
- Modify: `script_tests/test_assess_lattice_hypothesis.py`

- [ ] **Step 1: Add assessor fixture ref constant**

Append the standard-verifier fixture metadata to `CRITERION2_ARTIFACT_FIXTURE_REFS`.

- [ ] **Step 2: Add manifest fixture ref**

Append matching metadata to `proof_payload.artifact_fixture_refs` in `criterion-2-proof-substance.json`.

- [ ] **Step 3: Update synthetic report fixture**

Add the same fixture metadata to `write_criterion2_proof_substance_formalization`.

- [ ] **Step 4: Verify green**

Run both focused red tests again. Expected: pass.

### Task 3: Update Reader-Facing Docs Without Overclaiming

**Files:**
- Modify: `README.md`
- Modify: `docs/cryptography/criterion-2-proof-substance.md`
- Modify: `docs/cryptography/claims-matrix.md`

- [ ] **Step 1: Add additive wording only**

Use this pattern:

```text
checked standard-verifier compatibility proof-slot fixture for Criterion 2 at tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json; this is conformance/proof-review evidence, requires selected-backend proof closure evidence, requires production threshold ML-DSA security evidence, requires CAVP/ACVTS validation evidence, requires FIPS validation evidence, requires rejection-distribution preservation proof, and requires a completed standard-verifier compatibility proof.
```

- [ ] **Step 2: Preserve existing anchors**

Do not remove or reorder existing required phrases in README or proof docs.

### Task 4: Verify Batch A

**Files:** No edits expected.

- [ ] **Step 1: Run formatting and unit tests**

```sh
cargo fmt --all -- --check
python3 -m unittest script_tests.test_assess_lattice_hypothesis script_tests.test_run_simulation_benchmarks
```

- [ ] **Step 2: Run manifest/docs Rust tests**

```sh
CARGO_TARGET_DIR=/private/tmp/lattice-phase1-target cargo test --features coordinator-assisted --test criterion2_proof_substance_manifest --test proof_documentation_manifest
```

- [ ] **Step 3: Run assessment**

```sh
python3 scripts/assess_lattice_hypothesis.py --root . --out /private/tmp/lattice-phase1-assessment --offline --target-dir /private/tmp/lattice-phase1-assessment-target
```

Expected: command summary passes, `overall_verdict` remains `partially_proven`, and `aggregate_rejection_equivalence` remains `partially_met`.

- [ ] **Step 4: Run diff hygiene**

```sh
git diff --check
```
