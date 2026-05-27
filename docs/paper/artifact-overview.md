# Artifact Overview

Date: 2026-05-27

## Scope

This repository is a publishable research scaffold for threshold-style
ML-DSA-65 protocol integration. It includes a feature-gated hazmat backend,
typed transcript and actor boundaries, artifact exporters, replay checks, and
claim-boundary documentation.

It is not production-ready. It is not a security proof for threshold ML-DSA-65.
Production security still requires the malicious-secure DKG, contribution proof
soundness, selective-abort, aggregation/noise, side-channel, slashing-evidence,
and external cryptographic review obligations tracked in
[../cryptography/proof-obligations.md](../cryptography/proof-obligations.md).

## Main Components

| Component | Purpose | Primary references |
| --- | --- | --- |
| Core crate API | Type-state signing session, simulated backend, threshold API boundary | `src/lib.rs`, `src/protocol.rs`, `src/backend.rs` |
| Hazmat ML-DSA-65 backend | Local FIPS 204 parameter work for experiments and verifier compatibility | `src/low_level/mldsa65.rs`, [../cryptography/claims-matrix.md](../cryptography/claims-matrix.md) |
| Adapter actor and wire protocol | Asynchronous protocol scaffold, canonical frames, evidence shaping | `src/adapter/`, [../cryptography/protocol-code-crosswalk.md](../cryptography/protocol-code-crosswalk.md) |
| Artifact export pipeline | Section V LaTeX, CSV, transcript JSONL/CSV, and complaint artifacts | `src/utils/`, [../benchmarks/reproducibility-manifest.md](../benchmarks/reproducibility-manifest.md) |
| Audit and claim boundary | Reviewer map, TCB, attack surface, proof blockers | [../audit/README.md](../audit/README.md) |

## Reproducible Outputs

The checked-in Section V sample bundle is:

- [../benchmarks/artifacts/section-v-sample-output.txt](../benchmarks/artifacts/section-v-sample-output.txt)
- [../benchmarks/artifacts/SHA256SUMS](../benchmarks/artifacts/SHA256SUMS)

The one-command reproduction path is:

```bash
../../scripts/reproduce-section-v.sh
```

The script regenerates Section V output into a temporary file, checks the
checked-in sample checksum, verifies artifact schemas, and prints a digest for
the regenerated output.

## Safe Artifact Claim

Safe wording: the artifact demonstrates a reproducible Rust research scaffold
with hazmat ML-DSA-65 conformance paths, simulations, transcript artifacts, and
fail-closed production policy boundaries.

Unsafe wording: the artifact implements a secure, production-ready,
malicious-secure threshold ML-DSA-65 signature scheme.
