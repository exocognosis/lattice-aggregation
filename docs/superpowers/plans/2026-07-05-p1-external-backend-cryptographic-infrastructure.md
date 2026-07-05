# P1 External Backend Cryptographic Infrastructure Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Work task-by-task. Do not add readiness-only gates unless they directly protect backend ingestion, external capture admissibility, or artifact import.

**Goal:** Build the backend-facing infrastructure needed to acquire, run, ingest, and review a real P1 threshold ML-DSA backend capture bundle for the selected profile.

**Boundary:** This plan does not claim theorem closure. Code can make the ingestion path strict and reproducible, but theorem closure still requires actual external captures, reviewed backend source/operator evidence, rejection-distribution analysis, and proof review. All generated artifacts remain `conformance/proof-review evidence only` until those inputs exist.

**Selected profile:** `ML-DSA-65 coordinator-assisted Shamir nonce DKG P1`, 10,000 validators, threshold 6,667, standard ML-DSA-65 signature length 3,309 bytes.

---

### Task 1: Close Backend-Emission Ingestion Holes

**Files:**
- Modify: `scripts/run_backend_emission_capture.py`
- Modify: `script_tests/test_run_backend_emission_capture.py`

- [x] **Step 1: Reject repo-local backend commands**

Mirror the nonce-producer command-origin guard. `scripts/run_backend_emission_capture.py` must reject executable/script paths inside the lattice repository before running the command, including Python script wrappers.

- [x] **Step 2: Record backend command origin**

Persist `backend_command_origin = outside_repo_executable_or_script` in the manifest and external capture provenance when the command is admissibly outside-repo.

- [x] **Step 3: Test fail-closed behavior**

Add tests that prove a repo-local command is rejected before execution and that an outside-repo command records the expected origin.

### Task 2: Build the External Backend Workspace Bridge

**Files:**
- Create: `scripts/scaffold_p1_external_backend_workspace.py`
- Create: `script_tests/test_scaffold_p1_external_backend_workspace.py`

- [x] **Step 1: Require external workspace and backend crate paths**

The scaffold must refuse both an output workspace and a backend crate path that resolve inside the lattice repository.

- [x] **Step 2: Reuse the maintained threshold emitter source**

Generate a standalone Cargo workspace outside the repo using the existing request-bound Rust emitter source from `scripts/run_hazmat_threshold_backend_capture.py`. Depend by path on the external `dytallix-pq-threshold` crate and this lattice checkout.

- [x] **Step 3: Emit an outside-repo wrapper command**

Write an executable `run_capture.sh` in the external workspace. The backend-emission importer can use this wrapper as its `--backend-command`, so command-origin classification sees an outside-repo executable instead of a repo-local helper.

### Task 3: Acquire and Run a Real Backend Candidate

**Files:**
- Existing: `scripts/build_backend_emission_request.py`
- Existing: `scripts/run_backend_emission_capture.py`
- Existing: `scripts/run_hazmat_rejection_equivalence_batch.py`
- Existing: `scripts/build_p1_external_backend_cryptographic_closure_candidate.py`
- Existing: `scripts/run_p1_external_backend_evidence_attempt.py`

- [ ] **Step 1: Locate or clone the backend crate**

Find an external `dytallix-pq-threshold` checkout with `raw-real-mldsa` support. Record its path and commit. This must not live inside the lattice repository.

- [ ] **Step 2: Scaffold the external backend workspace**

Run:

```bash
python3 scripts/scaffold_p1_external_backend_workspace.py \
  --repo-root . \
  --workspace /path/outside/repo/p1-external-backend-emitter \
  --backend-crate /path/outside/repo/dytallix-pq-threshold
```

- [ ] **Step 3: Build the backend-emission request**

Run `scripts/build_backend_emission_request.py` to create the canonical request JSON for the 10,000/6,667 selected profile.

- [ ] **Step 4: Capture backend emission through the importer**

Run `scripts/run_backend_emission_capture.py` with the generated outside-repo `run_capture.sh` wrapper. The manifest must record `backend_command_origin = outside_repo_executable_or_script`.

- [ ] **Step 5: Generate rejection-equivalence evidence**

Run `scripts/run_hazmat_rejection_equivalence_batch.py` against the same backend crate with `--validator-count 10000`, `--threshold 6667`, and `--distributed-nonce-prf-domain`. The resulting comparison must be reviewed before being treated as a closure candidate.

### Task 4: Fill the Remaining External Evidence Slots

**Files:**
- Existing: `scripts/run_admissible_nonce_producer_capture_attempt.py`
- Existing: `scripts/stage_external_nonce_producer_capture.py`
- Existing: `scripts/verify_actual_nonce_producer_capture.py`
- Existing: `scripts/run_p1_external_backend_evidence_attempt.py`

- [ ] **Step 1: Obtain actual external nonce-producer capture**

The current repo-reference CLI replay is quarantined. Replace it with an admissible outside-repo nonce-producer capture or a reviewed capture-file intake.

- [ ] **Step 2: Obtain reviewed evidence package**

Create an outside-repo review manifest binding the nonce gate, backend emission capture, backend capture JSON, rejection-equivalence batch, and closure-candidate digest. The package must keep all theorem-closure and production-security claim flags false unless a separate proof review supports changing them.

- [ ] **Step 3: Run the grouped evidence attempt**

Run `scripts/run_p1_external_backend_evidence_attempt.py` after the nonce, backend emission, rejection, and review package inputs exist. A ready result means the repo has a close-candidate evidence bundle, not theorem closure.

### Task 5: Theorem-Closure Assessment

- [ ] **Step 1: Re-run closure readiness**

Run `scripts/assess_theorem_closure_readiness.py` only after the external evidence bundle is present and review-bound.

- [ ] **Step 2: Decide whether theorem assessment can begin**

The assessment can begin only if the strict external nonce slot, backend emission slot, rejection-equivalence slot, and reviewed external evidence package all pass. If they pass, the next work is mathematical/proof review against the selected backend, not more local scaffolding.
