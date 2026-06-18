# Batch H Claim Hardening Matrix
<a id="batch-h-claim-hardening-matrix"></a>

Date: 2026-06-15

## Purpose

This Batch H claim taxonomy separates implementation evidence, proof-draft
evidence, backend-conditional statements, and claims that remain explicitly
unproven. It is a publication and reviewer-facing guardrail for conservative
language around the threshold aggregation architecture.

This project has tested engineering paths for a standard ML-DSA-65 verification
surface and a documented proof route for malicious-secure threshold ML-DSA.
Those facts do not establish a production cryptographic proof. The current
state is no production backend selected, not a production proof, and
implementation evidence is not cryptographic proof.

Global manuscript constraints:

- do not claim production-ready
- do not claim thesis proven

## Claim Categories

- `implemented-and-tested`: code, tests, fixtures, or reproducibility artifacts
  support a narrow engineering claim.
- `documented-proof-draft`: proof documents define theorem targets,
  reductions, simulators, or closure routes, but do not prove the final
  production theorem.
- `conditional-on-backend`: wording depends on selecting, implementing,
  auditing, and proving a concrete production backend.
- `explicitly-unproven`: the repository names the claim as out of scope, future
  work, or unsupported by current evidence.

## Matrix

| Claim | Current status | Evidence | Allowed wording |
| --- | --- | --- | --- |
| H-CLAIM-1: Standard verifier compatibility for tested artifacts on the standard ML-DSA-65 verification surface. | `implemented-and-tested` | Hazmat ML-DSA-65 tests and fixtures exercise byte layout, verification, bridge, KAT-style, and differential paths; see `tests/hazmat_mldsa65.rs`, `tests/hazmat_mldsa65_kat.rs`, `tests/hazmat_mldsa65_differential.rs`, `tests/hazmat_mldsa65_threshold_bridge.rs`, and `tests/fixtures/ml_dsa_65_sigver_acvp.json`. | Say tested hazmat paths produce and verify standard-size ML-DSA-65 artifacts. Do not generalize this to a completed threshold proof or production certification. |
| H-CLAIM-2: Proof route for malicious-secure threshold ML-DSA within the threshold aggregation architecture. | `documented-proof-draft` | Proof documents define the formal target, ideal-functionality route, transcript grammar, residual ledger, and theorem closure worksheets; see `formal-security-theorem.md`, `idealvss-signing-theorem-closure.md`, `proof-closure-ledger.md`, `formal-threshold-mldsa-transcript.md`, and the FST and epsilon closure notes. | Say the repository contains a structured proof draft and closure taxonomy for malicious-secure threshold ML-DSA. Also say not a production proof. |
| H-CLAIM-3: Production threshold security after replacing scaffold components with a selected VSS/DKG and contribution backend. | `conditional-on-backend` | Backend documents identify replacement requirements, idealization boundaries, production policy gates, and dependency graphs; see `production-vss-backend.md`, `vss-idealization-and-selection.md`, `vss-dkg-production-obligation-split.md`, `vss-dkg-backend-dependency-graph.md`, `contribution-backend-selection.md`, and `contribution-backend-instantiation.md`. | Say production-facing security is conditional because there is no production backend selected. Do not claim production-ready until a concrete backend is selected, implemented, proven, audited, and externally reviewed. |
| H-CLAIM-4: Final thesis-level security and deployment readiness for a production threshold ML-DSA-65 system. | `explicitly-unproven` | The repository documents open proof, backend, side-channel, certification, transport, identity-binding, and operational gates in `claims-matrix.md`, `security-model.md`, `side-channel-boundary.md`, `backend-selection.md`, and `formal-proof-scaffold.md`. | Say these are open obligations. Do not claim thesis proven, do not claim production-ready, and state that implementation evidence is not cryptographic proof. |

## Safe Summary

Safe Batch H language:

> The repository contains tested engineering scaffolding for standard
> ML-DSA-65 verification paths, plus a documented proof-draft taxonomy for a
> malicious-secure threshold ML-DSA target under explicit backend and proof
> assumptions.

Unsafe Batch H language:

> The repository proves and implements a production-ready malicious-secure
> threshold ML-DSA-65 signature system.

The unsafe statement is unsupported because there is no production backend
selected, the formal closure is not a production proof, and implementation
evidence is not cryptographic proof.
