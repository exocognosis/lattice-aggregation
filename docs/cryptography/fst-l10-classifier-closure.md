# FST-L10 Classifier Closure Worksheet
<a id="fst-l10-classifier-closure"></a>

Date: 2026-05-28

Status: FST-L10 worksheet, not a completed classifier proof.

## FSTL10-0. Scope and Non-Claim
<a id="fstl10-scope-non-claim"></a>

This worksheet expands the `FST-L10` unauthorized-output classifier closure
lemma from [formal-security-theorem.md](formal-security-theorem.md) and
[idealvss-lemma-skeleton.md](idealvss-lemma-skeleton.md). It refines the S7 to
S8 route in
[unauthorized-output-classifier-closure.md](unauthorized-output-classifier-closure.md)
and [unauthorized-output-classifier-elimination.md](unauthorized-output-classifier-elimination.md).

This worksheet does not prove `eps_cls_unmapped = 0`. It does not eliminate
`eps_classify`, prove ML-DSA unforgeability, or prove any threshold-side
assumption.

## FSTL10-1. Theorem Context
<a id="fstl10-theorem-context"></a>

`FST-L10` closes the S7 to S8 unauthorized-output extraction route. After
authorized outputs are replaced by `F_TMLDSA` releases, every remaining
accepting aggregate output for an unauthorized message must be mapped to
exactly one named reduction case or to `Unmapped`.

The final theorem may remove `eps_classify` only after the production grammar
and classifier prove `eps_cls_unmapped = 0`.

## FSTL10-2. Input Domain and Production Grammar
<a id="fstl10-input-domain-production-grammar"></a>

The classifier consumes the production `AggregateOutputRecord`, `EvidenceRecord`,
`ReleaseSignature`, standard verification result, contribution records,
contribution proofs, VSS/DKG references, commitment records, random-oracle
inputs, collection metadata, evidence records, and `authorized_release_log`.

```text
Out* = (
  m*,
  sigma*,
  pk_epoch,
  epoch_id,
  session_id,
  block_height,
  attempt,
  validator_set_digest,
  active_set,
  threshold,
  contribution_frames,
  contribution_statements,
  contribution_proofs,
  VSS_DKG_references,
  commitment_records,
  random_oracle_queries,
  collection_metadata,
  evidence_records,
  authorized_release_log
)
```

Every field must be canonical and injectively encoded by the production
transcript grammar.

## FSTL10-3. Theorem Statement
<a id="fstl10-theorem-statement"></a>

```text
Theorem FST-L10-classifier-closure. Conditioned on S0 through S7 obligations,
the fixed production verifier grammar, deterministic authorized-release log
semantics, and the ordered classifier grammar, every accepting aggregate output
for an unauthorized message is assigned to exactly one classifier case:
AuthorizedReplay, MldsaForgery, ThresholdShareBreak, VssDkgBreak,
CommitmentBreak, ContributionBreak, RoTranscriptBreak, CollectionBreak,
EvidenceBreak, or Unmapped.

The closure target is to prove Pr[Classify(Out*) = Unmapped] = 0 from the
production verification relation and transcript grammar.
```

Until the final sentence is proved, the theorem must retain `eps_classify` and
`eps_cls_unmapped`.

## FSTL10-4. Ordered Classifier Cases
<a id="fstl10-ordered-classifier-cases"></a>

The ordered classifier cases are:

1. `AuthorizedReplay`.
2. `MldsaForgery` charged to `eps_cls_mldsa`.
3. `ThresholdShareBreak` charged to `eps_cls_threshold`.
4. `VssDkgBreak` charged to `eps_cls_vss_dkg`.
5. `CommitmentBreak` charged to `eps_cls_commit`.
6. `ContributionBreak` charged to `eps_cls_contrib`.
7. `RoTranscriptBreak` charged to `eps_cls_ro_transcript`.
8. `CollectionBreak` charged to `eps_cls_collect`.
9. `EvidenceBreak` charged to `eps_cls_evid`.
10. `Unmapped` charged to `eps_cls_unmapped`.

## FSTL10-5. Totality and Disjointness Obligations
<a id="fstl10-totality-disjointness-obligations"></a>

The totality target is the `classifier-totality-obligation`: every accepting
unauthorized `Out*` is classified as one of the ordered cases. The disjointness
target is the `classifier-disjointness-obligation`: ordered first-match
semantics charge one output once and no open proof term silently absorbs
another.

## FSTL10-6. Per-Case Reduction Map
<a id="fstl10-per-case-reduction-map"></a>

Each case must name a reduction algorithm, runtime loss, success probability,
and assumption target:

| Case | Reduction target |
| --- | --- |
| `eps_cls_mldsa` | ML-DSA-65 EUF-CMA or strong unforgeability. |
| `eps_cls_threshold` | Threshold-share soundness or ideal signing authorization violation. |
| `eps_cls_vss_dkg` | VSS/DKG binding, agreement, extractability, privacy, or key-bias theorem. |
| `eps_cls_commit` | Commitment binding, hiding, equivocation, or opening-set equality theorem. |
| `eps_cls_contrib` | Production contribution backend soundness, extraction, or replacement theorem. |
| `eps_cls_ro_transcript` | Random-oracle domain separation, prior-query, replay, or transcript injectivity theorem. |
| `eps_cls_collect` | Canonical collection, validator-set, active-set, and aggregation validation theorem. |
| `eps_cls_evid` | Evidence noninterference and anti-framing theorem. |
| `eps_cls_unmapped` | Open proof gap; must be zero before final theorem closure. |

## FSTL10-7. Residual Terms
<a id="fstl10-residual-terms"></a>

```text
eps_classify(A,Z)
 <= eps_cls_mldsa(A,Z)
  + eps_cls_threshold(A,Z)
  + eps_cls_vss_dkg(A,Z)
  + eps_cls_commit(A,Z)
  + eps_cls_contrib(A,Z)
  + eps_cls_ro_transcript(A,Z)
  + eps_cls_collect(A,Z)
  + eps_cls_evid(A,Z)
  + eps_cls_unmapped(A,Z)
```

The worksheet does not bound any summand. It records the route for deleting
`eps_cls_unmapped` after production grammar closure.

## FSTL10-8. Dependencies
<a id="fstl10-dependencies"></a>

`FST-L10` depends on:

- production transcript grammar for `AggregateOutputRecord`, `EvidenceRecord`,
  `ReleaseSignature`, and classifier inputs;
- ideal functionality release semantics;
- `FST-L1` through `FST-L7`;
- contribution backend decision and selected theorem;
- VSS/DKG ideal or concrete backend theorem;
- unauthorized-output classifier closure and elimination routes;
- proof closure ledger status language.

## FSTL10-9. Proof Skeleton
<a id="fstl10-proof-skeleton"></a>

The intended proof is:

1. Fix the production input domain and authorized release log.
2. Prove parser totality over every accepted `Out*`.
3. Apply ordered first-match classifier predicates.
4. Attach one reduction to every non-gap case.
5. Prove the `Unmapped` predicate is unreachable.
6. Replace `eps_classify` only after `eps_cls_unmapped = 0`.

## FSTL10-10. Acceptance Criteria
<a id="fstl10-acceptance-criteria"></a>

Before `FST-L10` can be treated as proved:

- the classifier input tuple exactly matches the production grammar;
- every accepted field is canonical and injectively encoded;
- authorized replay is byte-level deterministic;
- each non-gap case has a reduction target, runtime loss, success probability,
  and assumption target;
- collection, contribution, transcript, and evidence overlaps are resolved by
  ordering;
- `eps_cls_unmapped = 0` is proved from grammar, not tests;
- `eps_classify` is retained until that proof exists.

## FSTL10-11. Non-Claims
<a id="fstl10-non-claims"></a>

This worksheet does not prove ML-DSA unforgeability, threshold-share soundness,
VSS/DKG security, contribution soundness, commitment security, random-oracle
separation, collection soundness, evidence noninterference, final
unforgeability, or production readiness. It does not prove final
unforgeability and is not a completed classifier proof.

## FSTL10-12. Manifest Anchors
<a id="fstl10-manifest-anchors"></a>

- `# FST-L10 Classifier Closure Worksheet`
- `fst-l10-classifier-closure`
- `Status: FST-L10 worksheet, not a completed classifier proof.`
- `FSTL10-0. Scope and Non-Claim`
- `FSTL10-1. Theorem Context`
- `FSTL10-2. Input Domain and Production Grammar`
- `FSTL10-3. Theorem Statement`
- `FSTL10-4. Ordered Classifier Cases`
- `FSTL10-5. Totality and Disjointness Obligations`
- `FSTL10-6. Per-Case Reduction Map`
- `FSTL10-7. Residual Terms`
- `FSTL10-8. Dependencies`
- `FSTL10-9. Proof Skeleton`
- `FSTL10-10. Acceptance Criteria`
- `FSTL10-11. Non-Claims`
- `FSTL10-12. Manifest Anchors`
- `FST-L10`
- `FST-T1-IdealVSS`
- `S7 to S8`
- `AggregateOutputRecord`
- `EvidenceRecord`
- `ReleaseSignature`
- `authorized_release_log`
- `Out*`
- `AuthorizedReplay`
- `MldsaForgery`
- `ThresholdShareBreak`
- `VssDkgBreak`
- `ContributionBreak`
- `RoTranscriptBreak`
- `CollectionBreak`
- `EvidenceBreak`
- `Unmapped`
- `eps_classify`
- `eps_cls_mldsa`
- `eps_cls_threshold`
- `eps_cls_vss_dkg`
- `eps_cls_commit`
- `eps_cls_contrib`
- `eps_cls_ro_transcript`
- `eps_cls_collect`
- `eps_cls_evid`
- `eps_cls_unmapped`
- `eps_cls_unmapped = 0`
- `classifier-totality-obligation`
- `classifier-disjointness-obligation`
- `not a completed classifier proof`
- `does not prove final unforgeability`
