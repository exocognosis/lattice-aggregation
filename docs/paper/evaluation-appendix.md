# Evaluation Appendix

Date: 2026-05-27

## Purpose

This appendix summarizes how to interpret the Section V evaluation artifacts.
The evaluation is engineering evidence for reproducibility, protocol tracing,
and benchmark behavior. It is not a security proof and does not establish
production readiness.

For exact commands and feature gates, use
[../benchmarks/reproducibility-manifest.md](../benchmarks/reproducibility-manifest.md).
For claim status, use
[../cryptography/claims-matrix.md](../cryptography/claims-matrix.md).

## Profiles

The Section V runner emits three deterministic profiles:

| Profile | Validators | Threshold | Purpose |
| --- | ---: | ---: | --- |
| Small-Scale Consensus | 3 | 2 | Ideal local mesh sanity profile |
| Mid-Scale Distributed Fabric | 7 | 5 | Byzantine malformed-contribution and complaint-artifact profile |
| Adversarial WAN Cluster | 15 | 10 | High-latency retry-pressure profile |

The profile outputs include LaTeX tables, PGFPlots CSV, transcript JSONL,
transcript CSV, and, when `experimental-vss` is enabled, experimental VSS
complaint artifacts.

## Artifact Files

Checked-in publication fixture:

- [../benchmarks/artifacts/section-v-sample-output.txt](../benchmarks/artifacts/section-v-sample-output.txt)
- [../benchmarks/artifacts/SHA256SUMS](../benchmarks/artifacts/SHA256SUMS)

Regeneration command:

```bash
../../scripts/reproduce-section-v.sh
```

The checked-in sample is checksum-pinned for structural review. Fresh latency
values are machine-dependent and should not be treated as bit-stable constants.

## Interpretation Rules

- Transcript artifacts show canonical frame layout, ordering checks, digest
  binding, and production statement digest export.
- Complaint artifacts show structured evidence candidates for malformed
  contributions under the experimental VSS scaffold.
- Baseline comparison rows compare threshold profile telemetry to ordinary
  ML-DSA-65 internal-`mu` signing and verification in tested paths.
- Retry and abort counts describe modeled experiment behavior, not a proven
  selective-abort bound.

## Non-Claims

The evaluation does not prove:

- malicious-secure DKG,
- contribution proof soundness,
- aggregation/noise correctness for all possible transcripts,
- side-channel resistance,
- production slashing soundness,
- FIPS validation, or
- external cryptographic review.

Those obligations are tracked in
[../cryptography/proof-obligations.md](../cryptography/proof-obligations.md)
and summarized for reviewers in [../audit/README.md](../audit/README.md).
