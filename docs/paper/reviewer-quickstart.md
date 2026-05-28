# Reviewer Quickstart

Date: 2026-05-27

## Scope

This quickstart is for artifact reviewers who want to reproduce the Section V
outputs and inspect the implementation-to-claim boundary. The artifact is a
research scaffold with hazmat internals. It is not production-ready and not a
security proof.

## Fast Path

From the repository root:

```bash
export CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target
export CARGO_INCREMENTAL=0
scripts/reproduce-section-v.sh
```

The script verifies the checked sample bundle:

- [../benchmarks/artifacts/section-v-sample-output.txt](../benchmarks/artifacts/section-v-sample-output.txt)
- [../benchmarks/artifacts/SHA256SUMS](../benchmarks/artifacts/SHA256SUMS)

## What To Inspect First

1. Proof closure ledger:
   [../cryptography/proof-closure-ledger.md](../cryptography/proof-closure-ledger.md)
2. Claim boundary:
   [../cryptography/claims-matrix.md](../cryptography/claims-matrix.md)
3. Protocol-to-code map:
   [../cryptography/protocol-code-crosswalk.md](../cryptography/protocol-code-crosswalk.md)
4. Proof blockers:
   [../cryptography/proof-obligations.md](../cryptography/proof-obligations.md)
5. Audit packet:
   [../audit/README.md](../audit/README.md)
6. Reproducibility commands:
   [../benchmarks/reproducibility-manifest.md](../benchmarks/reproducibility-manifest.md)

## Expected Result

The fast path should:

- regenerate Section V output into a temporary file,
- check the checked-in sample SHA-256 sidecar,
- run artifact verifier tests,
- print a digest for the regenerated output, and
- exit successfully.

Fresh benchmark timings may differ by machine. Schema, headings, profile
labels, digest fields, and checked fixture hashes are the stable review
targets.

## Full Verification

For full local verification, run:

```bash
cargo fmt --check
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
  CARGO_INCREMENTAL=0 \
  cargo clippy -j1 --all-targets --all-features -- -D warnings
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
  CARGO_INCREMENTAL=0 \
  cargo test -j1 --all-features
```

## Non-Goals

The quickstart does not validate malicious-secure DKG, contribution proof
soundness, side-channel resistance, FIPS validation, external cryptographic
review, or production deployment readiness.
