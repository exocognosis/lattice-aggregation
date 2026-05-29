# Proof Gap Priority Map
<a id="proof-gap-priority-map"></a>

Status: priority map, not a completed proof.

This document prioritizes the remaining cryptographic proof work after the
FST-L1 through FST-L7, FST-L10, contribution-boundary, and IdealVSS closure
worksheets. It is an execution map for reviewers and future proof work. It does
not close any residual term.

## PGPM-0. Scope and Non-Claim
<a id="pgpm-scope-non-claim"></a>

The map distinguishes the immediate `FST-T1-IdealVSS` theorem route from
production `FST-T1 threshold unforgeability`. The immediate route may use
`F_VSS_DKG` and `F_CONTRIB` as ideal boundaries. Production claims remain
blocked until those boundaries are replaced by concrete, reviewed realization
theorems.

Implementation evidence is not cryptographic proof. The current repository is
a research scaffold, not production-ready, not audited, and not a proven
threshold ML-DSA-65 implementation.

## PGPM-1. Priority Tiers
<a id="priority-tiers"></a>

### Tier 0: Immediate Post-Consolidation Proof Path

Close the `FST-T1-IdealVSS` signing-side route with all residuals visible.
Dependencies are the fixed `F_VSS_DKG` interface, explicit `F_CONTRIB`
idealization, `FST-L1..FST-L7`, `FST-L10`, and the residual ledger.

Source anchors:

- [fst-t1-idealvss-theorem.md](fst-t1-idealvss-theorem.md)
- [epsilon-residual-ledger-final-form.md](epsilon-residual-ledger-final-form.md)
- [idealvss-signing-theorem-closure.md](idealvss-signing-theorem-closure.md)
- [idealvss-lemma-skeleton.md](idealvss-lemma-skeleton.md)
- [proof-closure-ledger.md](proof-closure-ledger.md)

### Tier 1: Signing Theorem Blockers

Close or explicitly carry `eps_ro`, `eps_commit`, `eps_collect`,
`eps_contrib_ideal`, `eps_mask`, `eps_rej`, `eps_verify`, `eps_withhold`, and
`eps_classify`. The highest-risk single blocker is classifier completion:
`eps_cls_unmapped = 0` must be proved before `eps_classify` can be removed.

Source anchors:

- [random-oracle-commitment-closure.md](random-oracle-commitment-closure.md)
- [rejection-sampling-closure-plan.md](rejection-sampling-closure-plan.md)
- [unauthorized-output-classifier-elimination.md](unauthorized-output-classifier-elimination.md)
- [contribution-backend-decision-record.md](contribution-backend-decision-record.md)

### Tier 2: Production Realization Blockers
<a id="production-realization-blockers"></a>

Replace ideal `F_VSS_DKG` with concrete `eps_vss`, replace ideal `F_CONTRIB`
with a selected proof, MPC, or interactive backend, select the production
`CombineMask` family, and lock production verifier grammar and evidence
semantics.

Source anchors:

- [vss-backend-selection.md](vss-backend-selection.md)
- [production-vss-backend.md](production-vss-backend.md)
- [contribution-backend-selection.md](contribution-backend-selection.md)
- [contribution-backend-decision-record.md](contribution-backend-decision-record.md)
- [production-transcript-grammar.md](production-transcript-grammar.md)

### Tier 3: Audit and Deployment Blockers
<a id="audit-blockers"></a>

Close side-channel review, leakage modeling, randomness review, transport
identity binding, operational key management, consensus and slashing
integration, and external cryptographic review. These items are captured by
`implementation_residual` and `audit_residual`.

Source anchors:

- [side-channel-boundary.md](side-channel-boundary.md)
- [../audit/README.md](../audit/README.md)
- [proof-implementation-crosswalk.md](proof-implementation-crosswalk.md)
- [claims-matrix.md](claims-matrix.md)

### Tier 4: Publication and Operational Review

After Tier 0 through Tier 3 are closed, publication work should check that the
claims matrix, README, audit packet, reproducibility bundle, and proof
bibliography all use the same theorem status and non-claim language.

## PGPM-2. Blocker Dependencies
<a id="blocker-dependencies"></a>

The immediate proof path is blocked by:

- `eps_cls_unmapped = 0` classifier totality and disjointness.
- `eps_contrib_ideal` interface exactness and non-production wording.
- `eps_vss_ideal` leakage exactness under ideal setup.
- `eps_mask`, `eps_rej`, `eps_withhold`, and `eps_verify` rejection route
  closure.
- `eps_commit`, `eps_ro_prior`, and `eps_ro_sep` transcript and
  random-oracle closure.
- `eps_collect` active-set and collection-soundness closure.

The production proof path is additionally blocked by concrete `eps_vss`,
concrete `eps_contrib`, production side-channel analysis, and external audit.

## PGPM-3. Next Proof Work Order
<a id="next-proof-work-order"></a>

1. Turn `FST-T1-IdealVSS` and `IVLS` from skeletons into theorem text with all
   residuals visible.
2. Close `FST-L1..FST-L3`: transcript injectivity, challenge binding, and
   collection soundness, using
   [fst-l1-l3-theorem-closure.md](fst-l1-l3-theorem-closure.md) as the batch
   index.
3. Close `FST-L4` using ideal `F_CONTRIB`, explicitly carrying
   `eps_contrib_ideal`.
4. Close `FST-L5` with aggregation correctness, `eps_rej`, and `eps_verify`
   treatment, using
   [fst-l4-l7-theorem-closure.md](fst-l4-l7-theorem-closure.md) as the
   middle-layer batch index.
5. Close `FST-L7` through rejection, withholding, abort, evidence, and release
   modeling.
6. Close `FST-L10` by proving `eps_cls_unmapped = 0`.
   Use [fst-l10-classifier-theorem-closure.md](fst-l10-classifier-theorem-closure.md)
   as the classifier batch index.
7. Only after the ideal theorem is stable, start concrete VSS/DKG and
   contribution backend replacement.

## PGPM-4. Acceptance Criteria
<a id="acceptance-criteria"></a>

This map is acceptable only if it:

- says it is a priority map, not a proof;
- links every tier to controlling source documents;
- preserves the research scaffold and not production-ready status;
- states that implementation evidence is not cryptographic proof;
- distinguishes IdealVSS theorem closure from production `FST-T1`;
- states that production claims remain blocked until concrete VSS/DKG,
  contribution backend, rejection distribution, classifier, side-channel, and
  external audit work are closed.

## PGPM-5. Non-Claims
<a id="non-claims"></a>

This priority map does not claim:

- any `eps_*` term is negligible, zero, or bounded;
- a production VSS/DKG backend is selected;
- a production contribution backend is selected;
- current tests, simulations, transcript hashes, and policy gates are
  cryptographic proof;
- the crate is production-ready;
- the repository proves threshold ML-DSA-65.

## PGPM-6. Manifest Anchors
<a id="manifest-anchors"></a>

Stable anchors and text markers:

- `# Proof Gap Priority Map`
- `proof-gap-priority-map`
- `Status: priority map, not a completed proof.`
- `priority-tiers`
- `blocker-dependencies`
- `next-proof-work-order`
- `production-realization-blockers`
- `audit-blockers`
- `acceptance-criteria`
- `non-claims`
- `manifest-anchors`
- `Tier 0`
- `Tier 1`
- `Tier 2`
- `Tier 3`
- `Tier 4`
- `FST-T1-IdealVSS`
- `FST-T1 threshold unforgeability`
- `F_CONTRIB`
- `F_VSS_DKG`
- `eps_vss`
- `eps_vss_ideal`
- `eps_contrib`
- `eps_contrib_ideal`
- `eps_mask`
- `eps_rej`
- `eps_withhold`
- `eps_classify`
- `eps_cls_unmapped = 0`
- `implementation_residual`
- `audit_residual`
- `implementation evidence is not cryptographic proof`
- `not a proof`
- `not production-ready`
