# Grant Submission Package

Submission-ready materials for funding the `lattice-aggregation` research effort
(native threshold ML-DSA-65 signature aggregation). The package preserves the
repository's research-stage boundary: the latest hypothesis assessment reports
`partially_proven`, with all five criteria `partially_met`, and nothing here is
a security or production claim.

## Documents

- [One-page executive summary](one-pager.md) — the quick read for program staff.
- [Full proposal](proposal.md) — the complete package, with these sections:
  - [Abstract](proposal.md#abstract)
  - [Specific Aims and Milestones](proposal.md#specific-aims-and-milestones)
  - [Novelty and Related-Work Comparison](proposal.md#novelty-and-related-work-comparison)
  - [Current Evidence vs Remaining Proof Obligations](proposal.md#current-evidence-vs-remaining-proof-obligations)
  - [Work Plan (6 to 12 Months)](proposal.md#work-plan-6-to-12-months)
  - [Risk Register](proposal.md#risk-register)
  - [Budget Justification](proposal.md#budget-justification)

## How to use

- Tailor the [Budget Justification](proposal.md#budget-justification) placeholders
  (FTE-months, amounts, rates) to the target funder before submission.
- Funder fit: Ethereum Foundation ESP and PQ teams (see
  [Alignment with Ethereum Post-Quantum Priorities](../../README.md#alignment-with-ethereum-post-quantum-priorities)),
  PQCA / Open Quantum Safe, Arbitrum, Rust Foundation, and academic programs.
- Every milestone gate is the reproducible
  [assessment](../../scripts/assess_lattice_hypothesis.py) plus the
  [Release Readiness Checklist](../benchmarks/release-readiness-checklist.md), so
  progress is externally verifiable.

## Context in the repository

- [Hypothesis Closure Requirements](../../README.md#hypothesis-closure-requirements)
  and [Path to Full Hypothesis Closure](../../README.md#path-to-full-hypothesis-closure)
- [Cryptographic Claims Matrix](../cryptography/claims-matrix.md)
- [Maintainer & contact](../../AUTHORS.md) and
  [funding channels](../../.github/FUNDING.yml)
