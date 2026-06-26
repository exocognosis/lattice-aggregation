# Research Grant Proposal — lattice-aggregation

**Native threshold ML-DSA-65 signature aggregation for post-quantum validator sets.**

> Status: research preview (`v0.2.0-research-preview`). This proposal describes a
> pre-proof research scaffold whose latest hypothesis assessment reports
> `partially_proven`, with all five criteria `partially_met`. Nothing here is a
> security claim or a production system. Funding is requested to close, or
> rigorously bound, the open obligations — not to certify a finished primitive.

This document is the full proposal package. For a quick read, see the
[one-page executive summary](one-pager.md). The seven sections below are
self-contained and reusable across funders (Ethereum Foundation ESP, PQCA /
Open Quantum Safe, Arbitrum, Rust Foundation, and academic programs).

## Contents

- [Abstract](#abstract)
- [Specific Aims and Milestones](#specific-aims-and-milestones)
- [Novelty and Related-Work Comparison](#novelty-and-related-work-comparison)
- [Current Evidence vs Remaining Proof Obligations](#current-evidence-vs-remaining-proof-obligations)
- [Work Plan (6 to 12 Months)](#work-plan-6-to-12-months)
- [Risk Register](#risk-register)
- [Budget Justification](#budget-justification)

---

## Abstract

Post-quantum migration breaks the signature-aggregation property that BLS gives
today. ML-DSA (NIST FIPS 204), the leading standardized lattice signature, does
not compose algebraically: structured lattice secrets, masking vectors,
Fiat-Shamir challenges, hint vectors, and rejection sampling mean that naively
summing validator signatures leaves the distribution and norm bounds that
standard verification relies on. An L1 that adopts ML-DSA for validator signing
must therefore choose between storing one large signature per validator (`O(N)`
state and bandwidth growth) or wrapping attestations in a separate proof system
that adds a SNARK/STARK verifier to the consensus-critical path.

This project studies a third option: an **interactive / threshold ML-DSA-65
protocol whose output is itself a single, standard-size ML-DSA-65 signature**
against an epoch threshold public key. If the construction's obligations close,
an *unmodified* ML-DSA-65 verifier accepts the aggregate, so verification cost
becomes independent of validator count (`O(1)` in the quorum) and no new
verifier enters consensus. This is the post-quantum analogue of the operational
ergonomics that made BLS aggregation attractive.

The repository is built audit-first. It models an "Epsilon Residual Ledger" of
five security boundaries that must each be proved or explicitly bounded before
any production claim, encodes them as five machine-checkable hypothesis
criteria, and ships a reproducible assessment
([scripts/assess_lattice_hypothesis.py](../../scripts/assess_lattice_hypothesis.py))
that today reports `partially_proven`. Production-labeled configurations fail
closed against scaffold backends, so research machinery cannot be presented as
production security.

We request funding to move the five criteria from `partially_met` toward closed
(or explicitly bounded), to deliver an apples-to-apples comparison against the
hash-based + SNARK aggregation path the Ethereum post-quantum roadmap is also
evaluating, and to fund the independent cryptographic review that any such
primitive requires. The work is deliberately structured so that **even a
negative result is valuable**: it would tell the ecosystem precisely which
assumptions gate any native post-quantum signature aggregator.

## Specific Aims and Milestones

The aims map to the five hypothesis criteria plus two enabling deliverables.
Success is measured against the reproducible assessment and the
[Release Readiness Checklist](../benchmarks/release-readiness-checklist.md), not
against subjective progress. "Closed" means proved or bounded with reviewed
evidence; where full closure is out of reach in the period, the success
criterion is an explicit, reviewed quantitative bound.

**Aim 1 — Mask and rejection distribution closure (criteria 1 and 2).**
Select a production `CombineMask` / blinded pre-filter family and supply the
Renyi-divergence evidence bounding the distance between aggregate masks (and
public high bits) and centralized ML-DSA-65, then close the Criterion 2
`aggregate_rejection_equivalence` payload with real (not fixture) threshold
recomputation.
*Deliverables:* a written `epsilon_mask` bound; a real-recomputation
rejection-equivalence artifact; updated
[mask-distribution-evidence.md](../cryptography/mask-distribution-evidence.md)
and [rejection-equivalence-evidence.md](../cryptography/rejection-equivalence-evidence.md).
*Success:* a reviewed `epsilon_mask` bound and real-recomputation evidence that
close the technical gap for criteria 1 and 2; their status remains
`partially_met` until external review completes per the repository's gates.

**Aim 2 — Abort-bias and partial-soundness closure (criteria 3 and 4).**
Fix a concrete retry-domain and timeout policy with an accepted-sample bound,
and specify production local-acceptance / partial-verification predicates with
soundness and hiding evidence for the chosen leakage model.
*Deliverables:* a retry/timeout policy with a proved acceptance bound; production
acceptance predicates with soundness/hiding evidence; updated
[abort-retry-bias-evidence.md](../cryptography/abort-retry-bias-evidence.md) and
[partial-soundness-evidence.md](../cryptography/partial-soundness-evidence.md).
*Success:* reviewed acceptance and soundness/hiding bounds that close the
technical gap for criteria 3 and 4; their status remains `partially_met` until
external review completes. (Partial soundness is the long pole; see the
[Risk Register](#risk-register).)

**Aim 3 — Unforgeability reduction and theorem assembly (criterion 5).**
Complete the per-case reductions in the unauthorized-aggregate reduction
manifest and assemble a threshold EUF-CMA reduction to base ML-DSA forgery or a
named threshold-side assumption violation.
*Deliverables:* completed reduction cases in
[unauthorized-aggregate-reduction.md](../cryptography/unauthorized-aggregate-reduction.md);
an assembled theorem consistent with
[formal-security-theorem.md](../cryptography/formal-security-theorem.md) and
[proof-obligations.md](../cryptography/proof-obligations.md).
*Success:* completed reduction cases and an assembled theorem for criterion 5,
with any residual named and bounded; criterion 5 remains `partially_met` and the
overall verdict remains `partially_proven` until external review completes.

**Aim 4 — Comparative evaluation and reference specification.**
Produce an apples-to-apples comparison against the hash-based + SNARK
aggregation path on verification cost, signing-round liveness, trust
assumptions, and audit surface, and publish a reference Rust protocol spec and
conformance suite other PQ efforts can reuse or adversarially test.
*Deliverables:* a comparison report; a reference spec; an extended conformance
suite. *Success:* the report and spec are published and externally reviewable.

**Aim 5 — External review and audit preparation.**
Commission independent cryptographic review of Aims 1–3, scope a side-channel and
randomness review, and produce a malicious-secure DKG realization plan.
*Deliverables:* external review findings; a side-channel review scope; a DKG
realization plan referencing
[vss-dkg-security-plan.md](../cryptography/vss-dkg-security-plan.md).
*Success:* review is commissioned and findings are triaged into the checklist.

## Novelty and Related-Work Comparison

**What is novel.**

- **Native-signature aggregation with no verifier fork.** The aggregate is an
  ordinary ML-DSA-65 signature; no proof system enters the consensus-critical
  verification path. This is distinct from proving signatures inside a SNARK.
- **Transparent, fail-closed methodology.** Every security-loss boundary is
  enumerated as an "Epsilon Residual Ledger" and tracked, per criterion, in the
  [Cryptographic Claims Matrix](../cryptography/claims-matrix.md) and the
  [Hypothesis Closure Requirements](../../README.md#hypothesis-closure-requirements),
  with a reproducible assessment and production-policy gates that reject scaffold
  backends.
- **Apples-to-apples evaluation as a deliverable.** The project commits to a
  bounded comparison against the hash-based + SNARK path, which is useful to the
  ecosystem regardless of which path wins.

**Comparison.** The table is qualitative and comparative only; it is not a
benchmark claim. Falcon/LaBRADOR-style proof-wrapper aggregation is tracked in
this repository as related work and a fallback architecture, not as a selected
backend (see the Related Work Comparator in
[claims-matrix.md](../cryptography/claims-matrix.md)).

| Approach | Aggregate verifier surface | Output size scaling | Verify cost vs validator count `N` | Key trust / assumptions | Maturity |
| --- | --- | --- | --- | --- | --- |
| BLS aggregation (pre-quantum) | Pairing check | One aggregate signature | `O(1)` | Not post-quantum secure | Production |
| Naive per-validator ML-DSA | Standard ML-DSA verify, `N` times | `O(N)` signatures | `O(N)` | FIPS 204 only | Standardized primitive |
| Hash-based + SNARK / `leanMultisig`-style | SNARK/STARK verifier | One succinct proof | `O(1)` verify; prover cost grows | Hash-based signatures + proving-stack trust | Active ecosystem research |
| Falcon / LaBRADOR proof-wrapper aggregation | Proof-wrapper verifier | One wrapped proof | `O(1)` verify; higher-risk wrapper | Falcon + lattice proof system; separate scheme | Comparative / fallback |
| **Native threshold ML-DSA-65 (this work)** | **Unmodified ML-DSA-65 verify** | **One standard-size signature** | **`O(1)` (design target)** | **ML-DSA-65 + threshold/DKG assumptions; interactive signing rounds** | **Research scaffold (`partially_proven`)** |

The trade-off is explicit: the native-threshold path keeps the verifier surface
equal to standardized ML-DSA-65 and avoids a proving stack, at the cost of
interactive signing-round liveness and threshold assumptions; the SNARK path
removes interaction at the cost of prover work and proof-stack trust. A robust
post-quantum roadmap benefits from a rigorously bounded read on both.

## Current Evidence vs Remaining Proof Obligations

The table maps each area to evidence already on `main` and the obligation that
remains. Status words follow the assessment: every criterion is `partially_met`,
overall `partially_proven`. Evidence is engineering / conformance / proof-review
material; it is not proof.

| Area | Current evidence on `main` | Status | Remaining proof obligation | Closing aim |
| --- | --- | --- | --- | --- |
| Mask distribution (`epsilon_mask`) | `src/production/mask_distribution.rs`, `tests/production_mask_distribution.rs`, [mask-distribution-evidence.md](../cryptography/mask-distribution-evidence.md), [phase-1-noise-bound-model.md](../cryptography/phase-1-noise-bound-model.md); evidence gates present | `partially_met` | Renyi-divergence bound on aggregate-vs-centralized mask distance | Aim 1 |
| Rejection equivalence | `src/production/rejection_equivalence.rs`, `src/production/provider.rs`, `tests/production_rejection_equivalence.rs`, bounded ACVP/FIPS204 sample fixture, bridge fixtures, [criterion-2-proof-substance.md](../cryptography/criterion-2-proof-substance.md), [rejection-equivalence-evidence.md](../cryptography/rejection-equivalence-evidence.md) | `partially_met` | Real (not fixture) threshold recomputation; completed standard-verifier compatibility proof | Aim 1 |
| Abort / retry bias | `src/production/abort_bias.rs`, `tests/production_abort_bias.rs`, [abort-retry-bias-evidence.md](../cryptography/abort-retry-bias-evidence.md) | `partially_met` | Concrete retry/timeout policy with a proved accepted-sample bound | Aim 2 |
| Partial-contribution soundness | `src/production/acceptance.rs`, `src/production/partial_soundness.rs`, `tests/production_partial_soundness.rs`, [partial-soundness-evidence.md](../cryptography/partial-soundness-evidence.md) | `partially_met` | Production partial verification + hiding proof for the leakage model | Aim 2 |
| Unauthorized-output reduction | `tests/unauthorized_aggregate_reduction_manifest.rs`, [unauthorized-aggregate-reduction.md](../cryptography/unauthorized-aggregate-reduction.md), [formal-security-theorem.md](../cryptography/formal-security-theorem.md), [proof-obligations.md](../cryptography/proof-obligations.md) | `partially_met` | Completed per-case reductions; threshold EUF-CMA reduction | Aim 3 |
| Malicious-secure DKG (precondition) | [vss-dkg-security-plan.md](../cryptography/vss-dkg-security-plan.md), [active-adversary-model.md](../cryptography/active-adversary-model.md), simulated DKG scaffold | open | Concrete reviewed DKG realization | Aim 5 |
| Side-channel / constant-time | [side-channel-boundary.md](../cryptography/side-channel-boundary.md) | not claimed | Constant-time audit, leakage tests (`dudect`/`ctgrind`) | Aim 5 |
| Validation / FIPS | bounded NIST ACVP-Server FIPS204 sample fixture | not claimed | CAVP/ACVTS validation vectors and campaign | Aim 5 (scope) |

## Work Plan (6 to 12 Months)

The plan is staged so each quarter ends at a reviewable gate tied to the
assessment and checklist. Aims 1–3 are the criterion-closing critical path;
Aims 4–5 run alongside. Estimates are planning-grade for an experienced
cryptographer and assume the staffing in the [Budget Justification](#budget-justification).

| Period | Primary work | Gate / checkpoint | Dependencies |
| --- | --- | --- | --- |
| Months 1–3 (Q1) | Aim 1: select `CombineMask` family; draft `epsilon_mask` Renyi bound; begin real-recomputation rejection equivalence. Aim 4: start comparison methodology. | Mask-distribution bound draft reviewed internally; comparison methodology fixed | None |
| Months 4–6 (Q2) | Aim 1 close-out; Aim 2 begins: retry/timeout policy and abort-bias bound. Aim 5: commission external review of Aim 1. | Reviewed bounds/evidence for criteria 1–2 in the assessment (status still `partially_met`); external review of Aim 1 underway | Aim 1 draft |
| Months 7–9 (Q3) | Aim 2 close-out (partial soundness is the long pole); Aim 3 begins: per-case reductions. Aim 4: comparison report draft + reference spec. | Reviewed bounds/evidence for criteria 3–4 (status still `partially_met`); reduction cases drafted | Aims 1–2 |
| Months 10–12 (Q4) | Aim 3 close-out: threshold EUF-CMA reduction assembly. Aim 5: side-channel review scope, DKG realization plan, triage external findings. | Criterion 5 reduction assembled with any residual bounded (status still `partially_met`); checklist updated; comparison + spec published | Aims 1–3 |

A 6-month variant funds Aims 1–2 and the comparison deliverable (Aim 4),
deferring Aims 3 and 5; a 12-month variant funds the full critical path plus
external review. Each quarter's gate is the reproducible
[assessment](../../scripts/assess_lattice_hypothesis.py) plus the
[Release Readiness Checklist](../benchmarks/release-readiness-checklist.md), so
progress is externally checkable rather than self-reported.

## Risk Register

Likelihood and impact are L/M/H. The defining feature of this risk profile is
that the central technical risks have **named fallbacks already tracked in the
repository**, and that a negative result is still an informative deliverable.

| ID | Risk | Likelihood | Impact | Mitigation | Fallback / decision |
| --- | --- | --- | --- | --- | --- |
| R1 | `epsilon_mask` distance cannot be acceptably bounded for a practical `CombineMask` family | M | H | Explore multiple mask-combination families; target a quantified bound rather than exact equivalence | Document the bound as a hard limit; pivot to Falcon/LaBRADOR proof-wrapper aggregation (tracked as fallback) |
| R2 | Partial-soundness / hiding proof for a production contribution backend slips (long pole) | M | H | Stage as ideal functionality first, then realize; isolate hiding from soundness | Carry the ideal-functionality boundary and publish the realization gap honestly |
| R3 | Selective-abort bias has no acceptable bound under the active-adversary model | L–M | H | Constrain retry-domain and timeout policy; bound acceptance probability | Restrict the deployment model (e.g. permissioned aggregator) and document the limitation |
| R4 | No reviewed malicious-secure DKG is available in the period | M | M | Treat DKG as a setup precondition; deliver a realization plan, not a realization | Compose with an external DKG once available; scope explicitly out of the core proof |
| R5 | External review or side-channel audit surfaces blocking findings | M | M | Build audit-first; fail-closed gates; budget contingency for remediation | Re-scope deliverables; publish findings transparently |
| R6 | The ecosystem prefers the hash-based + SNARK path | M | L | The comparative evaluation (Aim 4) is valuable either way; it surfaces which assumptions gate any native PQ aggregator | Deliver the comparison and reference spec as the primary output; native-threshold remains a documented fallback/hybrid option |
| R7 | Schedule risk on the criterion-closing critical path | M | M | Quarterly gates tied to the assessment; 6-month variant de-scopes Aims 3 and 5 | Re-baseline at each gate; prioritize bounds over full closure |

No risk in this register is mitigated by overclaiming: where an obligation
cannot close, the deliverable is an explicit, reviewed bound or a documented
limitation, consistent with the repository's research-stage boundary.

## Budget Justification

The figures below are **template language with placeholders**; tailor the
specific amounts, FTE fractions, and rates to the target funder's limits and
the local cost base before submission. The justification ties each category to
the aims and deliverables above. No category presumes a successful proof; each
funds the *work to attempt and review* closure.

- **Personnel — cryptography research lead ([X] FTE-months).** Primary effort on
  Aims 1–3 (mask/rejection bounds, abort-bias and partial-soundness, and the
  unforgeability reduction). This is the project's critical path and the largest
  line; justified by the depth of the lattice and Fiat-Shamir-with-aborts proof
  work required.
- **Personnel — Rust protocol engineer ([X] FTE-months).** Implements the
  production `CombineMask` / acceptance predicates, extends the conformance suite
  and reproducible assessment, and produces the reference specification (Aim 4).
  Justified by the audit-first methodology: every proof obligation is backed by
  re-runnable evidence and fail-closed gates.
- **Personnel — PI / oversight ([X] FTE-months).** Direction, milestone review,
  reporting against the reproducible gates, and coordination with reviewers.
- **External cryptographic review and audit ([amount]).** Independent review of
  the Aim 1–3 theorem text and a scoped side-channel / randomness review
  (Aim 5). Justified because no `eps_*`-style boundary is credible without
  outside review; this is a hard requirement for any production path, not an
  optional extra.
- **Compute and infrastructure ([amount]).** CI, fuzzing, deterministic
  benchmark regeneration, and the assessment pipeline. Modest; the work is
  proof-and-evidence heavy rather than compute heavy.
- **Dissemination and travel ([amount]).** Presenting the comparative evaluation
  and reference spec at post-quantum / Ethereum venues and engaging EF/PQ and
  PQCA/OQS reviewers. Justified by Aim 4's goal of informing the ecosystem's
  aggregation decision.
- **Contingency ([percentage]).** Reserved for remediation of review/audit
  findings (R5) and for re-baselining if the critical path slips (R7).

Reporting is milestone-based: funds are justified against the quarterly gates in
the [Work Plan](#work-plan-6-to-12-months), each of which is the reproducible
assessment verdict plus the
[Release Readiness Checklist](../benchmarks/release-readiness-checklist.md), so a
funder can verify progress independently rather than relying on narrative
self-report.
