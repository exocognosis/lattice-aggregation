# Audit Packet

Date: 2026-05-27

## Purpose

This packet gives reviewers a compact map of the current research scaffold,
hazmat ML-DSA-65 backend, and publication claim boundary. It supports audit and
paper review. It does not certify the crate as production-ready and does not
close the proof obligations required for secure threshold ML-DSA-65.

Start here:

- [attack-surface.md](attack-surface.md) maps the main review surfaces and
  failure modes.
- [tcb.md](tcb.md) lists the current trusted computing base, dependency
  assumptions, feature-gate risks, review files, and non-production boundaries.

Supporting claim-boundary documents:

- [../cryptography/claims-matrix.md](../cryptography/claims-matrix.md)
- [../cryptography/protocol-code-crosswalk.md](../cryptography/protocol-code-crosswalk.md)
- [../cryptography/proof-obligations.md](../cryptography/proof-obligations.md)
- [../benchmarks/release-readiness-checklist.md](../benchmarks/release-readiness-checklist.md)

## Review Scope

The current repository may be reviewed as a reproducible research artifact with
feature-gated hazmat internals, deterministic simulations, transcript/artifact
checks, and fail-closed production policy boundaries.

It must not be reviewed as a production deployment package. Production security
requires the proof, implementation, side-channel, operational, and external
review closures tracked in the documents above.
