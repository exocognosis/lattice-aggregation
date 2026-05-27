# Recommended Review Order

## Purpose

This document gives reviewers an ordered path through the release artifact. It
is a navigation aid only. The repository remains a research scaffold with a
feature-gated hazmat backend; it is not production-ready and not a security
proof for threshold ML-DSA-65.

## Review Path

1. Repository scope and warnings:
   - [../../README.md](../../README.md)
   - Confirm the top-level warning, feature-gate descriptions, and artifact
     boundary before reading implementation evidence.

2. Reproduction fast path:
   - [reviewer-quickstart.md](reviewer-quickstart.md)
   - Run or inspect `scripts/reproduce-section-v.sh`.
   - Check that the expected review targets are schema, headings, profile
     labels, digest fields, and checked fixture hashes. Fresh timing values are
     machine-dependent.

3. Publication claim boundary:
   - [../cryptography/claims-matrix.md](../cryptography/claims-matrix.md)
   - Read this before evaluating manuscript or PR language. It separates
     implemented engineering evidence, experimental support, scaffold-only
     boundaries, production blockers, and non-claims.

4. Protocol-to-code navigation:
   - [Protocol-to-code crosswalk](../cryptography/protocol-code-crosswalk.md)
   - Use the table to move from protocol areas to source modules and test
     coverage. Treat scaffold entries as review anchors, not production
     security claims.

5. Open proof and production blockers:
   - [../cryptography/proof-obligations.md](../cryptography/proof-obligations.md)
   - Review the malicious-secure DKG/VSS, contribution proof, selective-abort,
     aggregation/noise, side-channel, and external-review blockers before
     accepting any stronger security wording.

6. Audit packet:
   - [../audit/README.md](../audit/README.md)
   - Then read `docs/audit/attack-surface.md` and `docs/audit/tcb.md` for the
     current trusted computing base, feature-gate risks, and review surfaces.

7. Reproducibility and archive materials:
   - [archive-manifest.md](archive-manifest.md)
   - `docs/benchmarks/reproducibility-manifest.md`
   - `docs/benchmarks/artifacts/section-v-sample-output.txt`
   - `docs/benchmarks/artifacts/SHA256SUMS`
   - Confirm the archived command set, checked sample bundle, and final commit
     metadata match the release checklist.

8. Key tests:
   - `tests/section_v_sample_bundle.rs`
   - `tests/reproducibility_manifest.rs`
   - `tests/hazmat_mldsa65.rs`
   - `tests/hazmat_mldsa65_kat.rs`
   - `tests/hazmat_mldsa65_differential.rs`
   - `tests/hazmat_mldsa65_threshold_bridge.rs`
   - `tests/hazmat_mldsa65_wire.rs`
   - `tests/hazmat_mldsa65_actor.rs`
   - `tests/hazmat_mldsa65_simulation_grid.rs`
   - `tests/production_policy.rs`
   - `tests/contribution_proof.rs`
   - `tests/dkg_vss_soundness.rs`
   - `tests/transcript_determinism.rs`
   - `tests/protocol_spec_manifest.rs`

9. Key source files:
   - `src/low_level/mldsa65.rs`
   - `src/adapter/actor.rs`
   - `src/adapter/wire.rs`
   - `src/adapter/evidence.rs`
   - `src/crypto/vss.rs`
   - `src/crypto/interpolation.rs`
   - `src/crypto/contribution_proof.rs`
   - `src/crypto/production_policy.rs`
   - `src/utils/hazmat_artifacts.rs`
   - `src/utils/hazmat_simulation.rs`
   - `src/utils/exporter.rs`
   - `src/main.rs`

## Review Discipline

- Keep the claim boundary tied to the claims matrix.
- Treat hazmat paths as research instrumentation and regression evidence.
- Treat deterministic simulations and Section V artifacts as reproducibility
  evidence, not security evidence.
- Treat production policy gates as fail-closed configuration guards, not as
  proofs that a backend is secure.
- Do not upgrade manuscript or PR language from "research scaffold" to
  "production-ready", "malicious-secure", or "security proof" without closing
  the proof obligations and audit blockers.
