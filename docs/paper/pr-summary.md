# Draft PR Summary

## Summary

This draft PR packages the repository as a reproducible research artifact for
threshold-style ML-DSA-65 protocol integration. The artifact includes typed
session boundaries, deterministic simulations, feature-gated hazmat ML-DSA-65
paths, actor and wire-frame scaffolding, Section V-style artifact export, and
claim-boundary documentation for review.

The intended review target is narrow: implementation and reproducibility
evidence for a research scaffold. This PR does not claim production readiness,
does not provide a security proof for threshold ML-DSA-65, and does not close
the proof, audit, side-channel, backend replacement, or external review
obligations tracked in the cryptography documentation.

## Verification

Use this section to paste the final release-command outputs before marking the
PR ready for review.

```text
$ export CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target
$ export CARGO_INCREMENTAL=0
$ scripts/reproduce-section-v.sh
RESULT: <paste command result, regenerated digest, and checked sample checksum>

$ cargo fmt --check
RESULT: <paste result>

$ cargo clippy -j1 --all-targets --all-features -- -D warnings
RESULT: <paste result>

$ cargo test -j1 --all-features
RESULT: <paste result>

$ git rev-parse HEAD
RESULT: <paste final verified commit>
```

## Files Changed By Area

- Release and reviewer entry points:
  - `README.md`
  - `CHANGELOG.md`
  - `docs/paper/reviewer-quickstart.md`
  - `docs/paper/archive-manifest.md`
- Paper and claim-boundary documentation:
  - `docs/paper/*`
  - `docs/cryptography/claims-matrix.md`
  - `docs/cryptography/protocol-code-crosswalk.md`
  - `docs/cryptography/proof-obligations.md`
  - `docs/audit/README.md`
- Reproducibility artifacts and scripts:
  - `scripts/reproduce-section-v.sh`
  - `docs/benchmarks/reproducibility-manifest.md`
  - `docs/benchmarks/artifacts/section-v-sample-output.txt`
  - `docs/benchmarks/artifacts/SHA256SUMS`
- Implementation and verification surface:
  - `src/`
  - `tests/`

## Explicit Non-Claims

- Not production-ready.
- Not a security proof for threshold ML-DSA-65.
- Not a malicious-secure DKG or production VSS implementation.
- Not a sound, hidden, zero-knowledge, or production-ready contribution-proof
  relation.
- Not a proof of selective-abort resistance, aggregation/noise correctness, or
  static active threshold ML-DSA security.
- Not side-channel audited or timing-leakage certified.
- Not FIPS validated and not an independently certified cryptographic module.
- Not production slashing evidence or a production deployment package.

## Reviewer Notes

- Start with `docs/paper/reviewer-quickstart.md` for the reproduction path and
  expected outputs.
- Use `docs/cryptography/claims-matrix.md` as the authoritative map from
  publication-facing language to implementation evidence and blockers.
- Use `docs/cryptography/protocol-code-crosswalk.md` to move from protocol
  rounds to source modules and tests.
- Use `docs/cryptography/proof-obligations.md` to identify what remains open
  before any production or security-proof claim can be made.
- Use `docs/audit/README.md` for audit packet navigation and trusted-computing
  base review.
- Treat the `hazmat-real-mldsa` backend as experimental implementation
  evidence only. It is useful for artifact generation and regression checks,
  but it is not a production cryptographic module.
