# Research Artifact Release Checklist

Date: 2026-05-27

## Purpose

This checklist is for packaging the current repository as a research artifact.
It does not authorize production deployment. The release remains a research
scaffold with a feature-gated hazmat backend until the blockers in
[../cryptography/proof-obligations.md](../cryptography/proof-obligations.md)
and [../benchmarks/release-readiness-checklist.md](../benchmarks/release-readiness-checklist.md)
are closed.

## Required Commands

Run from the repository root:

```bash
export CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target
export CARGO_INCREMENTAL=0

scripts/reproduce-section-v.sh
cargo fmt --check
cargo clippy -j1 --all-targets --all-features -- -D warnings
cargo test -j1 --all-features
git rev-parse HEAD
```

Record the final commit hash in the submitted artifact notes.

## Required Files

Paper-facing docs:

- [artifact-overview.md](artifact-overview.md)
- [evaluation-appendix.md](evaluation-appendix.md)
- [limitations.md](limitations.md)
- [reviewer-quickstart.md](reviewer-quickstart.md)
- [archive-manifest.md](archive-manifest.md)

Evidence and boundary docs:

- [../cryptography/claims-matrix.md](../cryptography/claims-matrix.md)
- [../cryptography/proof-obligations.md](../cryptography/proof-obligations.md)
- [../cryptography/protocol-code-crosswalk.md](../cryptography/protocol-code-crosswalk.md)
- [../audit/README.md](../audit/README.md)
- [../benchmarks/reproducibility-manifest.md](../benchmarks/reproducibility-manifest.md)
- [../benchmarks/artifacts/section-v-sample-output.txt](../benchmarks/artifacts/section-v-sample-output.txt)
- [../benchmarks/artifacts/SHA256SUMS](../benchmarks/artifacts/SHA256SUMS)
- [../../scripts/reproduce-section-v.sh](../../scripts/reproduce-section-v.sh)

## Release Boundary

Before release, verify manuscript and README wording says:

- research scaffold,
- hazmat ML-DSA-65 backend,
- reproducible Section V artifact,
- implementation evidence, and
- open proof obligations.

Before release, verify manuscript and README wording does not say:

- production-ready,
- malicious-secure threshold ML-DSA,
- audited,
- side-channel safe,
- production slashing proof, or
- FIPS validated.

## Final Archive Notes

The archive should include:

- final commit hash from `git rev-parse HEAD`,
- command outputs or logs from the required commands,
- checked sample bundle checksum,
- any environment notes that affect benchmark timing, and
- an explicit statement that the artifact is not production-ready and not a
  security proof.
