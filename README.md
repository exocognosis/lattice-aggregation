# ML-DSA Lattice Aggregator

Research scaffold for threshold-style ML-DSA-65 protocol integration in Rust.
The crate provides typed signing-session boundaries, simulated and hazmat
backend paths, actor/wire adapters, deterministic Section V artifact exporters,
and claim-boundary documentation for review.

## Warning

This repository is a publishable research artifact scaffold. It is not
production-ready, not an audited implementation, and not a security proof for
threshold ML-DSA-65. The current code and tests provide engineering evidence for
the documented artifact boundary only. Production security still depends on the
open proof, backend replacement, audit, side-channel, and external review work
tracked in the linked proof obligations.
Those obligations include malicious-secure DKG, contribution proof soundness,
side-channel review, and external cryptographic review.

## Quickstart

Run from the repository root:

```bash
export CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target
export CARGO_INCREMENTAL=0

scripts/reproduce-section-v.sh
```

The reproduction script regenerates Section V output into a temporary file,
checks the checked-in sample bundle checksum, runs artifact verifier tests, and
prints a digest for the regenerated output.

Useful local checks:

```bash
cargo fmt --check
cargo clippy -j1 --all-targets --all-features -- -D warnings
cargo test -j1 --all-features
```

## Review Map

- [Reviewer quickstart](docs/paper/reviewer-quickstart.md)
- [Claims matrix](docs/cryptography/claims-matrix.md)
- [Audit packet](docs/audit/README.md)
- [Proof obligations](docs/cryptography/proof-obligations.md)
- [Reproducibility manifest](docs/benchmarks/reproducibility-manifest.md)
- [Section V sample bundle](docs/benchmarks/artifacts/section-v-sample-output.txt)
- [Section V sample checksum](docs/benchmarks/artifacts/SHA256SUMS)

## Feature Gates

- `hazmat-real-mldsa`: enables the local hazmat ML-DSA-65 backend used for
  experiments, verifier-compatibility checks, actor simulations, and Section V
  artifact generation. This is implementation evidence only and is not a
  production cryptographic module or FIPS validation claim.
- `experimental-vss`: enables experimental VSS complaint-evidence artifacts and
  structural checks. These artifacts are research scaffolding only and are not a
  production VSS relation proof, malicious-secure DKG, or production slashing
  mechanism.

## Artifact Boundary

The supported claim is narrow: this repository demonstrates a reproducible Rust
research scaffold with feature-gated hazmat ML-DSA-65 conformance paths,
deterministic simulations, transcript artifacts, evidence-shaping paths, and
fail-closed production policy boundaries.

Do not describe the current artifact as a secure, production-ready,
malicious-secure threshold ML-DSA-65 signature scheme.
