# Changelog

All notable research-artifact packaging changes are tracked here.

## Unreleased - Research Artifact Packaging

Latest verified commit: to be filled by the release checklist after
`git rev-parse HEAD` is run for the final archived artifact.

### Major Capabilities

- Rust research scaffold for threshold-style ML-DSA-65 protocol integration.
- Type-state signing-session API boundary with simulated backend coverage.
- Feature-gated `hazmat-real-mldsa` backend for experimental ML-DSA-65 artifact
  generation, verifier-compatibility checks, KAT-style and differential
  regression paths, and actor simulation telemetry.
- Adapter actor and canonical wire-frame scaffolding for transcript binding,
  replay metadata, malformed-contribution handling, and evidence candidates.
- Feature-gated `experimental-vss` structural path for experimental VSS
  statement, opening, proof, and complaint-evidence artifacts.
- Fail-closed production policy gates for scaffold VSS and contribution-proof
  backend declarations.
- Reproducible Section V artifact path via `scripts/reproduce-section-v.sh`,
  including LaTeX tables, PGFPlots CSV, transcript JSONL/CSV, complaint
  artifacts when enabled, and checksum-pinned sample bundle verification.
- Paper, audit, cryptography, and benchmark documentation that separates
  implementation evidence from proof and production obligations.

### Explicit Non-Claims

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

### Release Checklist Notes

- Fill the latest verified commit from the final release checklist instead of
  hardcoding a moving development commit here.
- Archive command outputs for `scripts/reproduce-section-v.sh`,
  `cargo fmt --check`, `cargo clippy -j1 --all-targets --all-features -- -D warnings`,
  `cargo test -j1 --all-features`, and `git rev-parse HEAD`.
- Include the checked Section V sample-bundle checksum and any environment notes
  that affect benchmark timing.
