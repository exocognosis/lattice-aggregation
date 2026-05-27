# ML-DSA Lattice Aggregator

Research scaffold for threshold-style ML-DSA-65 protocol integration in Rust.
The crate provides typed signing-session boundaries, simulated and hazmat
backend paths, actor/wire adapters, deterministic Section V artifact exporters,
and claim-boundary documentation for review.

## Current Status

The repository is now organized as a proof-oriented research artifact, not just
an implementation sketch. Since the last README update, the proof package has
been expanded with:

- local `hazmat-real-mldsa` ML-DSA-65 internals, KAT-style fixtures,
  differential checks, threshold bridge tests, and standard-verifying hazmat
  signing paths for controlled experiments;
- formal theorem targets, ideal functionality, real/ideal simulator skeletons,
  random-oracle domains, adversary models, correctness lemmas, and a
  proof-to-code crosswalk;
- an idealized `F_VSS_DKG` route for isolating setup assumptions from the
  signing proof, while keeping concrete production VSS/DKG security open;
- rejection-sampling hybrid worksheets with explicit `eps_mask`, `eps_rej`,
  `eps_withhold`, `eps_ro`, `eps_commit`, and `Delta_accept` closure routes;
- a contribution soundness relation worksheet for the future production proof
  backend, plus fail-closed production policy gates for scaffold backends;
- an unauthorized-output classifier route that decomposes `eps_classify` into
  named reduction cases rather than hiding the remaining gap.

In practical terms, this is approximately a publishable research scaffold with
strong reproducibility and review boundaries. It is not yet a cryptographically
proven threshold ML-DSA-65 construction.

## Warning

This repository is a publishable research artifact scaffold. It is not
production-ready, not an audited implementation, and not a security proof for
threshold ML-DSA-65. The current code and tests provide engineering evidence for
the documented artifact boundary only. Production security still depends on the
open proof, backend replacement, audit, side-channel, and external review work
tracked in the linked proof obligations.
Those obligations include malicious-secure DKG, contribution proof soundness,
rejection-sampling distribution preservation, selective-abort bounds,
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
- [Formal security theorem](docs/cryptography/formal-security-theorem.md)
- [Ideal functionality](docs/cryptography/ideal-functionality.md)
- [Real/ideal simulator skeleton](docs/cryptography/real-ideal-simulator.md)
- [Rejection-sampling bounds worksheet](docs/cryptography/rejection-sampling-bounds.md)
- [Contribution soundness relation](docs/cryptography/contribution-soundness-relation.md)
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
fail-closed production policy boundaries. The formal documents now also define
the theorem targets, idealized setup boundary, rejection-sampling closure
routes, contribution-proof replacement relation, and remaining reduction gaps.

Do not describe the current artifact as a secure, production-ready,
malicious-secure threshold ML-DSA-65 signature scheme.

## Remaining Cryptographic Gaps

The next work is theorem closure, not more scaffold construction:

- prove or explicitly bound `eps_mask` for the aggregate threshold mask
  distribution;
- prove or explicitly bound `eps_rej` by showing threshold aggregate rejection
  matches standard ML-DSA-65 rejection on the same candidate values;
- prove or explicitly bound `eps_withhold` for selective aborts, timeout
  behavior, retries, and observable abort labels;
- instantiate the production contribution proof or MPC relation described in
  [contribution-soundness-relation.md](docs/cryptography/contribution-soundness-relation.md);
- eliminate `eps_classify` by mapping every unauthorized accepting output to
  either a base ML-DSA forgery or a named threshold-side assumption violation.
