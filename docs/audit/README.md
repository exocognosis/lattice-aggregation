# Audit Packet

Date: 2026-05-26

This packet is a reviewer/security triage aid for the current research
scaffold and deterministic ML-DSA-65 simulation backend. It does not certify
production readiness.

Start here:

- [Attack Surface Map](attack-surface.md): where untrusted inputs, feature
  gates, hazmat internals, evidence artifacts, benchmarks, and documentation
  claims should be inspected first.
- [Trusted Computing Base](tcb.md): what the current scaffold asks reviewers to
  trust, dependency assumptions, feature-gate risks, high-priority files, and
  explicit non-production boundaries.

Related review material:

- [Release Readiness Checklist](../benchmarks/release-readiness-checklist.md)
- [Phase 1 Noise Bound Model](../cryptography/phase-1-noise-bound-model.md)
- [Threshold ML-DSA Core API Design](../superpowers/specs/2026-05-22-threshold-mldsa-core-api-design.md)
- [Threshold Adapter Scaffold Design](../superpowers/specs/2026-05-22-threshold-adapter-scaffold-design.md)
