# Lattice Hypothesis Assessment Harness Design

Approved direction for a current-checkout assessor that tests the lattice
aggregation hypothesis against explicit success criteria without upgrading
simulation evidence into production cryptographic proof.

## Testing Statement

The harness will test this statement:

If a threshold ML-DSA-65 lattice aggregation protocol emits an accepted
aggregate output, then the output should behave like a centralized ML-DSA-65
signature under the same public key and message, while preserving threshold
soundness, rejection-sampling distribution, contribution validity, leakage
boundaries, and unforgeability reduction claims.

In this checkout, the executable scope is narrower. The default backend is a
deterministic simulation backend. The harness can collect scaffold telemetry,
run conformance checks, and inspect proof/readiness documents. It cannot prove
ML-DSA distributional equivalence, standard-verifier compatibility, or
threshold unforgeability until a reviewed production backend and proof package
exist.

## Success Criteria

The harness treats the following five criteria as the canonical assessment
surface:

1. Aggregate masks match or closely approximate centralized ML-DSA masks.
2. Aggregate rejection checks match centralized ML-DSA rejection checks.
3. Selective aborts and retries do not bias accepted signatures.
4. Every accepted partial contribution is sound, context-bound, and hiding
   enough for the chosen leakage model.
5. Every unauthorized accepting aggregate output reduces to a base ML-DSA
   forgery or a named threshold-side assumption violation.

Each criterion will be mapped to existing proof surfaces:

| Criterion | Primary proof anchors | Current expected result |
| --- | --- | --- |
| Aggregate mask distribution | Noise Lemma B, Noise Lemma H, `epsilon_mask` readiness gate | Blocked unless a selected construction and Renyi-divergence evidence exist. |
| Aggregate rejection equivalence | Noise Lemmas D and F, Correctness Lemmas 7 and 8 | Blocked unless real aggregate recomputation and standard verifier bridge tests exist. |
| Abort and retry bias | Noise Lemmas G and H, FST-L7, active adversary rushing model | Blocked unless abort leakage and retry transcript analysis exist. |
| Partial contribution soundness and hiding | FST-L4, Noise Lemma E, VSS hiding/binding/extractability obligations | Partially supported by scaffold context binding, but cryptographically blocked without real local acceptance and proof-system evidence. |
| Unauthorized aggregate reduction | FST-L6, FST-T1, IF-R6, base ML-DSA theorem dependency | Blocked unless a reduction proof and named threshold assumptions are linked. |

## Approach Options

### Option A: Current-Checkout Evidence Assessor

This is the selected approach. The script runs executable repo checks, collects
simulation telemetry, inspects proof/readiness documents, and produces a JSON
and Markdown assessment. It reports current evidence and blockers separately.

Trade-off: it gives useful evidence now, but almost certainly classifies the
overall hypothesis as partially proven at most because the repository correctly
marks several cryptographic criteria open.

### Option B: Strict Production-Proof Harness

This approach would require a real ML-DSA backend, standard verifier bridge
tests, proof artifacts, side-channel evidence, and audit sign-off before it
returns anything other than failed.

Trade-off: it is the right long-term release gate, but not useful in the
current checkout because the necessary backend and proof artifacts do not
exist.

### Option C: Simulator-Only Benchmark Script

This approach would only run `cargo run`, collect latency, abort, and bandwidth
measurements, and compare output size to ML-DSA-65 constants.

Trade-off: it is easy to build, but too weak. It can support benchmark shape
and scalability telemetry, not the five hypothesis criteria.

## Architecture

The implementation should add a small command-line assessor rather than
changing protocol behavior. The script should live outside the library core and
call existing Cargo commands plus a focused Rust experiment binary or test
helpers.

Recommended file shape:

- `scripts/assess_lattice_hypothesis.py`: orchestration, command execution,
  evidence parsing, verdict generation, and artifact writing.
- `artifacts/hypothesis/`: generated JSON, Markdown, and raw command-output
  files. Generated artifacts should remain out of normal source commits unless
  the user asks to check in a specific result.
- Optional later Rust binary: `src/bin/hypothesis_harness.rs` if the Python
  wrapper needs cleaner structured telemetry than `src/main.rs` prints today.

The first implementation should avoid adding a Rust binary unless parsing the
existing harness proves brittle. The Python script is sufficient for running
Cargo checks, extracting current README criteria, collecting command metadata,
and writing structured assessment output.

## Script Execution Framework

The script will expose a deterministic command:

```sh
python3 scripts/assess_lattice_hypothesis.py --out artifacts/hypothesis/latest
```

It will run these checks in order:

1. Record commit, branch, feature set, tool versions, and timestamp.
2. Parse top-level `README.md` for the hypothesis framing and claim boundary.
3. Parse `docs/cryptography/proof-obligations.md`,
   `docs/cryptography/noise-rejection-proof-plan.md`,
   `docs/cryptography/formal-security-theorem.md`,
   `docs/cryptography/ideal-functionality.md`, and
   `docs/benchmarks/release-readiness-checklist.md`.
4. Run scaffold verification commands:

```sh
cargo test --test simulated_flow
cargo test --test simulation
cargo test --test proof_documentation_manifest
cargo test --features coordinator-assisted --test production_epsilon --test production_prefilter --test production_hints --test production_wire --test production_transcript --test production_coordinator
cargo run
```

5. Capture all stdout, stderr, exit status, duration, and command metadata.
6. Extract evidence items:
   - simulated aggregate signature length equals `MLDSA65_SIGNATURE_BYTES`;
   - standard verifier is unavailable for the simulated backend;
   - transcript, collection, type-state, and production guardrail tests pass;
   - harness telemetry includes duration, abort/retry count, and bandwidth;
   - proof docs mark each criterion as implemented, proof sketch, external
     dependency, open, or blocked.
7. Compare evidence to the five success criteria.
8. Emit machine-readable JSON plus a human-readable Markdown report.

The implementation should support `--offline` to set `CARGO_NET_OFFLINE=true`
and `--target-dir` to use an isolated Cargo target directory for flaky local
state.

## Data Model

The JSON report should contain:

```json
{
  "testing_statement": "...",
  "commit": "...",
  "branch": "...",
  "criteria": [
    {
      "id": "aggregate_mask_distribution",
      "statement": "Aggregate masks match or closely approximate centralized ML-DSA masks.",
      "required_evidence": ["selected construction", "Renyi divergence bound", "mask distribution test"],
      "observed_evidence": [],
      "blockers": [],
      "status": "blocked",
      "verdict_contribution": "pending_evidence"
    }
  ],
  "commands": [],
  "overall_verdict": "partially_proven",
  "claim_boundary": "closure-run implementation track"
}
```

Status values should be:

- `met`: criterion is satisfied by executable evidence and required proof
  artifacts.
- `partially_met`: scaffold evidence supports part of the criterion, but
  cryptographic proof or production backend evidence is missing.
- `blocked`: the criterion cannot be satisfied in this checkout because a
  required backend, proof, audit, or external theorem link is absent.
- `failed`: executable evidence contradicts the criterion.

Overall verdict values should be:

- `completely_proven`: all five criteria are `met`.
- `partially_proven`: at least one criterion is `met` or `partially_met`, none
  are `failed`, and at least one remains `blocked` or `partially_met`.
- `partially_disproven`: at least one criterion is `failed`, but not all
  criteria fail.
- `completely_disproven`: all five criteria are `failed`, or one failed
  criterion logically invalidates all others.

Given the current README and proof documents, the expected initial result is
`partially_proven`: the repo supports protocol-shape and guardrail evidence, but
the main cryptographic success criteria remain blocked rather than disproven.

## README Comparison

The report must explicitly compare the result to the top-level README:

- README lists the current evidence track for threshold backend work.
- README ties assessment to reviewed threshold backend artifacts and standard
  ML-DSA verification.
- Remaining proof artifacts should be recorded as implementation-track inputs.
- Any future README claim of production readiness should link release-readiness
  gates and selected-backend evidence.

## Error Handling

Command failures should not crash the report writer. A failed command should be
captured as evidence and included in the affected criteria. A missing required
source document should mark all criteria that depend on that source as
`blocked` unless an executable failure proves `failed`.

The script should return:

- `0` when the assessment completes, even if the hypothesis is only partially
  proven or blocked.
- `1` when the script cannot produce a valid report.
- `2` when `--strict` is passed and the overall verdict is not
  `completely_proven`.

## Testing

Implementation should include tests for:

- criterion mapping and verdict aggregation;
- parsing command results into evidence records;
- handling a missing proof document as `blocked`;
- treating `SimulatedBackend::verify_standard` unavailability as an expected
  blocker rather than a failed theorem;
- writing deterministic JSON and Markdown output.

The final verification pass should run:

```sh
cargo fmt --all -- --check
cargo test --all-features
python3 scripts/assess_lattice_hypothesis.py --out artifacts/hypothesis/latest --offline
```

## Non-Goals

This work will not implement real threshold ML-DSA, generate production masks,
prove rejection-sampling equivalence, complete a reduction proof, run
side-channel tooling, or change the README claim boundary.

## Spec Self-Review

- Placeholder scan: no placeholder requirements remain.
- Internal consistency: the selected approach matches the current README
  research boundary and the five user-defined criteria.
- Scope check: the work is one implementation slice: a script plus optional
  structured output helpers.
- Ambiguity check: missing cryptographic artifacts are classified as
  `blocked`; executable contradictions are classified as `failed`.
