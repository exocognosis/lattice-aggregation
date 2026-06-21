# Lattice Hypothesis Assessment Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a command-line assessor that runs current checkout evidence, maps it to the five lattice aggregation hypothesis criteria, and writes JSON and Markdown verdict reports.

**Architecture:** Add a Python standard-library script under `scripts/` with pure functions for criteria, document scanning, command execution, verdict aggregation, and report writing. Add unit tests under `script_tests/` so Python tests do not interfere with Cargo integration tests. Keep generated assessment output ignored under `artifacts/hypothesis/`.

**Tech Stack:** Python 3.12 standard library, Cargo commands, existing Rust tests and docs.

---

### Task 1: Python Test Skeleton And Verdict Rules

**Files:**
- Create: `script_tests/test_assess_lattice_hypothesis.py`
- Create: `scripts/assess_lattice_hypothesis.py`

- [ ] **Step 1: Write failing tests for verdict aggregation and criterion shape**

Add tests that import `scripts/assess_lattice_hypothesis.py` by path and assert:

```python
criteria = module.default_criteria()
self.assertEqual(len(criteria), 5)
self.assertEqual(module.overall_verdict([{"status": "met"}] * 5), "completely_proven")
self.assertEqual(module.overall_verdict([{"status": "partially_met"}, {"status": "blocked"}]), "partially_proven")
self.assertEqual(module.overall_verdict([{"status": "failed"}, {"status": "blocked"}]), "partially_disproven")
self.assertEqual(module.overall_verdict([{"status": "failed"}] * 5), "completely_disproven")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest script_tests/test_assess_lattice_hypothesis.py`

Expected: FAIL or ERROR because `scripts/assess_lattice_hypothesis.py` and the functions do not exist.

- [ ] **Step 3: Add minimal module with criteria and verdict functions**

Add `scripts/assess_lattice_hypothesis.py` with:

```python
def default_criteria():
    return [...]

def overall_verdict(criteria):
    ...
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest script_tests/test_assess_lattice_hypothesis.py`

Expected: PASS.

### Task 2: Document Scanning And Evidence Classification

**Files:**
- Modify: `script_tests/test_assess_lattice_hypothesis.py`
- Modify: `scripts/assess_lattice_hypothesis.py`

- [ ] **Step 1: Write failing tests for document scanning**

Add tests that create temporary doc files and assert:

```python
docs = module.scan_documents(temp_root)
self.assertTrue(docs["readme_research_boundary"])
self.assertTrue(docs["standard_verifier_blocked"])
self.assertEqual(module.classify_criteria(module.default_criteria(), docs)[0]["status"], "blocked")
self.assertEqual(module.classify_criteria(module.default_criteria(), docs)[3]["status"], "partially_met")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest script_tests/test_assess_lattice_hypothesis.py`

Expected: FAIL because `scan_documents` and `classify_criteria` do not exist.

- [ ] **Step 3: Implement scanning and classification**

Scan required docs for README research boundaries, proof obligation statuses, standard verifier blockers, Renyi evidence blockers, local partial blockers, and unforgeability reduction blockers. Return explicit blockers when files are missing.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest script_tests/test_assess_lattice_hypothesis.py`

Expected: PASS.

### Task 3: Command Runner And Report Output

**Files:**
- Modify: `script_tests/test_assess_lattice_hypothesis.py`
- Modify: `scripts/assess_lattice_hypothesis.py`
- Modify: `.gitignore`

- [ ] **Step 1: Write failing tests for report output**

Add tests that use a fake command runner and assert:

```python
report = module.build_report(temp_root, run_commands=False, command_runner=fake_runner)
self.assertIn("testing_statement", report)
self.assertIn("commands", report)
self.assertEqual(report["overall_verdict"], "partially_proven")
module.write_reports(report, out_dir)
self.assertTrue((out_dir / "assessment.json").exists())
self.assertTrue((out_dir / "assessment.md").exists())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest script_tests/test_assess_lattice_hypothesis.py`

Expected: FAIL because report building and writing are incomplete.

- [ ] **Step 3: Implement command execution, metadata, JSON, and Markdown**

Implement:

```python
def run_command(...)
def default_commands()
def build_report(...)
def write_reports(...)
def render_markdown(...)
def main(...)
```

Add `/artifacts/hypothesis/` to `.gitignore`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest script_tests/test_assess_lattice_hypothesis.py`

Expected: PASS.

### Task 4: End-To-End Verification

**Files:**
- Modify: `scripts/assess_lattice_hypothesis.py`
- Modify: `script_tests/test_assess_lattice_hypothesis.py`

- [ ] **Step 1: Run focused Python tests**

Run: `python3 -m unittest script_tests/test_assess_lattice_hypothesis.py`

Expected: PASS.

- [ ] **Step 2: Run assessor without Cargo commands for fast report validation**

Run: `python3 scripts/assess_lattice_hypothesis.py --out artifacts/hypothesis/latest --skip-commands`

Expected: report files are written and overall verdict is `partially_proven`.

- [ ] **Step 3: Run Rust formatting check**

Run: `cargo fmt --all -- --check`

Expected: PASS.

- [ ] **Step 4: Run the full assessor with an isolated target directory**

Run: `python3 scripts/assess_lattice_hypothesis.py --out artifacts/hypothesis/latest --offline --target-dir /tmp/lattice-aggregation-hypothesis-target`

Expected: report files are written. Current checkout verdict remains `partially_proven` unless executable evidence fails.

- [ ] **Step 5: Inspect git status**

Run: `git status --short --branch`

Expected: only source, plan, test, and ignore changes are present; generated `artifacts/hypothesis/latest` output is ignored.

## Self-Review

- Spec coverage: covers testing statement, five criteria, script framework, data collection, README comparison, and verdict rubric.
- Placeholder scan: no placeholders remain.
- Type consistency: function names in tests and implementation steps match.
