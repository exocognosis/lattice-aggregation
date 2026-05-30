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

The claim boundary is conservative: this is only a conditional classifier
closure route under a fixed production transcript grammar and completed
`FST-L1` through `FST-L7` routes. It is not a final production-security theorem.

This worksheet does not itself prove `eps_cls_unmapped = 0`. It does not
eliminate `eps_classify`, prove ML-DSA unforgeability, or prove any
threshold-side assumption.

## FSTL10-1. Theorem Context
<a id="fstl10-theorem-context"></a>

`FST-L10` closes the S7 to S8 unauthorized-output extraction route. After
authorized outputs are replaced by `F_TMLDSA` releases, every remaining
accepting unauthorized `AggregateOutputRecord`, `ReleaseSignature`,
`EvidenceRecord`, or canonical `Out*` must be mapped to exactly one ordered
classifier case, or the proof must stop at the explicit `Unmapped` case and
charge `eps_cls_unmapped`.

The final theorem may remove `eps_classify` only after the production grammar
and classifier prove `eps_cls_unmapped = 0`.

## FSTL10-2. Input Domain and Production Grammar
<a id="fstl10-input-domain-production-grammar"></a>

The classifier input domain is the set of accepted, production-parsed records
that can expose an unauthorized output:

- `AggregateOutputRecord` values that pass production aggregate verification;
- `ReleaseSignature` values accepted as production releases;
- `EvidenceRecord` values accepted by the production evidence verifier;
- canonical `Out*` tuples derived from the same production parser.

The classifier consumes the standard verification result, contribution records,
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

Every field must be canonical and injectively encoded by the fixed production
transcript grammar. Records outside this production grammar are not part of the
classifier input domain; accepted records inside the domain must either classify
or force the proof to expose `eps_cls_unmapped`.

## FSTL10-3. Theorem Statement
<a id="fstl10-theorem-statement"></a>

```text
Theorem FST-L10-classifier-closure. Conditioned on S0 through S7 obligations,
the fixed production verifier grammar, deterministic authorized-release log
semantics, completed FST-L1 through FST-L7 routes, and the ordered classifier
grammar, every accepting unauthorized AggregateOutputRecord, ReleaseSignature,
EvidenceRecord, or Out* is assigned to exactly one ordered classifier case:
AuthorizedReplay, MldsaForgery, ThresholdShareBreak, VssDkgBreak,
ContributionBreak, RoTranscriptBreak, CollectionBreak, EvidenceBreak, or
Unmapped.

If none of the non-gap cases applies, the proof explicitly fails with
eps_cls_unmapped. The closure target is eps_cls_unmapped = 0, equivalently
Pr[Classify(Out*) = Unmapped] = 0, under the listed prerequisites.
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

The classifier is ordered. Later predicates are evaluated only after all
earlier predicates fail, so a single accepted input cannot be charged twice.

## FSTL10-5. Totality and Disjointness Obligations
<a id="fstl10-totality-disjointness-obligations"></a>

The totality route for `classifier-totality-obligation` is:

1. Parse the accepted production record into the canonical classifier input
   domain.
2. Normalize the input to `Out*` using the fixed production transcript grammar.
3. Prove that each verifier acceptance path exposes one of the ordered
   predicates.
4. If no predicate fires, classify as `Unmapped` and charge
   `eps_cls_unmapped`.

The target closure proof shows the final branch is unreachable, so
`eps_cls_unmapped = 0`.

The disjointness route for `classifier-disjointness-obligation` is:

1. Define every case predicate over canonical transcript fields, not over
   parser side effects.
2. Apply deterministic first-match semantics in the listed order.
3. Prove that reductions consume the first matched predicate and cannot also
   consume a later predicate for the same accepted input.
4. Keep `Unmapped` as the only residual branch until the totality proof removes
   it.

## FSTL10-6. Per-Case Reduction Map
<a id="fstl10-per-case-reduction-map"></a>

Each case must name a reduction algorithm, runtime loss, success probability,
and assumption target. The map below records the required destination for each
ordered classifier branch.

| Ordered case | Residual term | Reduction target and dependencies |
| --- | --- | --- |
| `AuthorizedReplay` | none if byte-equal authorization is present | Deterministic `authorized_release_log` lookup under the production transcript grammar and completed S7 replacement route. |
| `MldsaForgery` | `eps_cls_mldsa` | ML-DSA-65 EUF-CMA or strong unforgeability; depends on the `FST-L1` through `FST-L7` routing that exposes a fresh accepted signature. |
| `ThresholdShareBreak` | `eps_cls_threshold` | Threshold-share soundness or ideal signing authorization violation; depends on completed `FST-L1` through `FST-L7` extraction routes. |
| `VssDkgBreak` | `eps_cls_vss_dkg` | `F_VSS_DKG` binding, agreement, extractability, privacy, or key-bias theorem; depends on production VSS/DKG references and the completed predecessor routes. |
| `CommitmentBreak` | `eps_cls_commit` | Commitment binding, opening-set equality, or context-binding failure; depends on production commitment records and `FST-L1` through `FST-L3`. |
| `ContributionBreak` | `eps_cls_contrib` | `F_CONTRIB` soundness, extraction, replacement, and contribution relation consistency; depends on production contribution frames, contribution proofs, and `FST-L4` through `FST-L7`. |
| `RoTranscriptBreak` | `eps_cls_ro_transcript` | Random-oracle domain separation, prior-query, replay, or transcript injectivity theorem; depends on the production transcript grammar and random-oracle query log. |
| `CollectionBreak` | `eps_cls_collect` | Canonical collection, validator-set, active-set, threshold, and aggregation-validation theorem; depends on production collection metadata. |
| `EvidenceBreak` | `eps_cls_evid` | Evidence noninterference and anti-framing theorem; depends on production `EvidenceRecord` grammar and evidence verifier semantics. |
| `Unmapped` | `eps_cls_unmapped` | Open proof gap; must be proved unreachable, `eps_cls_unmapped = 0`, before final theorem closure. |

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
`eps_cls_unmapped` after production grammar closure. The intended closed
classifier theorem has `eps_cls_unmapped = 0`; until then `eps_classify`
remains part of the top-level bound.

## FSTL10-8. Dependencies
<a id="fstl10-dependencies"></a>

`FST-L10` depends on:

- production transcript grammar for `AggregateOutputRecord`, `EvidenceRecord`,
  `ReleaseSignature`, and classifier inputs;
- ideal functionality release semantics;
- `FST-L1` through `FST-L7`;
- `F_CONTRIB` backend decision and selected theorem;
- `F_VSS_DKG` ideal or concrete backend theorem;
- unauthorized-output classifier closure and elimination routes;
- proof closure ledger status language.

## FSTL10-9. Proof Skeleton
<a id="fstl10-proof-skeleton"></a>

The intended proof is:

1. Fix the production input domain and authorized release log.
2. Prove parser totality over every accepted `Out*`.
3. Apply ordered first-match classifier predicates.
4. Attach one reduction to every non-gap case.
5. Prove disjointness from deterministic ordering and canonical transcript
   fields.
6. Prove the `Unmapped` predicate is unreachable.
7. Replace `eps_classify` only after `eps_cls_unmapped = 0`.

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
unforgeability unless all predecessor lemmas and backend assumptions are
closed, and it is not a completed classifier proof. Implementation evidence is
not cryptographic proof.

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
- `CommitmentBreak`
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
