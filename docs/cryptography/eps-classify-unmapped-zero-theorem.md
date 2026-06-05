# eps_classify Unmapped-Zero Theorem Draft
<a id="eps-classify-unmapped-zero-theorem"></a>

Status: Batch E formal-reduction draft, not a completed classifier proof.

This document records the theorem shape needed to remove the final
`eps_cls_unmapped` residual from `eps_classify`. It is a draft proof route and
does not close the classifier.

## Theorem Target
<a id="ek4-theorem-target"></a>

```text
Theorem K4-eps-cls-unmapped-zero.

Under completed classifier totality, first-match disjointness, and per-case
reduction premises for the production verifier grammar, every accepted
unauthorized output in the classifier coverage domain maps to one of the named
reduction cases before the final Unmapped branch.

Therefore:

  eps_cls_unmapped(A, Z) = 0.
```

`eps_cls_unmapped = 0` is a target theorem and remains unproved here.

## Accepted Unauthorized Output Domain
<a id="ek4-accepted-unauthorized-output-domain"></a>

The accepted unauthorized output domain is the set of production verifier
outputs `Out*` that:

1. parse under the canonical production transcript grammar,
2. are accepted by the production verifier,
3. are not removed by the authorized-release filter, and
4. expose every field needed by the ordered classifier predicates.

An accepted output that cannot be represented in this domain is not ignored. It
is a classifier coverage failure and remains charged to the totality or
`Unmapped` obligation until a grammar theorem rules it out.

## Authorized-Release Complement
<a id="ek4-authorized-release-complement"></a>

The authorized-release complement is the post-filter set of accepted outputs
that are not byte-identical authorized releases for the same message, public
epoch key, epoch, session, attempt, active set, threshold, collection metadata,
and release context.

Only this complement is classified by `eps_classify`. Authorized outputs are
removed before classifier ownership is assigned; unauthorized accepted outputs
must be owned by exactly one classifier case or by the final `Unmapped` branch.

## Classifier Coverage Grammar
<a id="ek4-classifier-coverage-grammar"></a>

The classifier coverage grammar must deterministically parse all accepted
unauthorized outputs into the fields consumed by the ordered cases:

```text
MldsaForgery
ThresholdAuthorizationBreak
VssDkgBreak
CommitmentBreak
ContributionBreak
RoTranscriptBreak
CollectionBreak
EvidenceBreak
Unmapped
```

The grammar premise must cover canonical encodings, optional field defaults,
collection ordering, validator-set binding, evidence records, contribution
frames, commitment records, VSS/DKG references, and random-oracle transcript
material. Ambiguous or omitted accepted verifier paths keep
`eps_cls_totality` open.

## Totality Premises
<a id="ek4-totality-premises"></a>

The totality premises required by `Theorem K4-eps-cls-unmapped-zero` are:

1. every accepted unauthorized production output is in the classifier coverage
   domain or is charged to `eps_cls_totality`,
2. the classifier returns one of the nine listed cases for every covered
   output,
3. each classifier predicate is defined over canonical `Out*` fields, and
4. no verifier acceptance branch is left outside the grammar.

These premises are expected to discharge `eps_cls_totality` before the
unmapped-zero conclusion can be used.

## Disjointness Premises
<a id="ek4-disjointness-premises"></a>

The disjointness premises required by the theorem are:

1. classifier evaluation is deterministic,
2. first-match ordering assigns a single owner when multiple semantic
   predicates are true,
3. equivalent encodings cannot change ownership, and
4. no output is charged to two residual terms.

These premises are expected to discharge `eps_cls_disjointness`.

## Per-Case Reduction Premises
<a id="ek4-per-case-reduction-premises"></a>

Each non-`Unmapped` case must have a completed reduction or assumption boundary:

```text
eps_cls_mldsa          -> MldsaForgery
eps_cls_threshold     -> ThresholdAuthorizationBreak
eps_cls_vss_dkg       -> VssDkgBreak
eps_cls_commit        -> CommitmentBreak
eps_cls_contrib       -> ContributionBreak
eps_cls_ro_transcript -> RoTranscriptBreak
eps_cls_collect       -> CollectionBreak
eps_cls_evid          -> EvidenceBreak
```

The theorem does not prove these per-case reductions. It assumes their
predicates are complete enough that any accepted unauthorized output matching
their semantic failure modes is consumed before `Unmapped`.

## Unmapped Contradiction Strategy
<a id="ek4-unmapped-contradiction-strategy"></a>

The proof strategy is by contradiction:

1. assume an adversary contributes positive mass to `eps_cls_unmapped`,
2. extract an accepted unauthorized `Out*` with `Classify(Out*) = Unmapped`,
3. use totality and the coverage grammar to show `Out*` is a well-formed
   classifier-domain output,
4. inspect the verifier acceptance dependency that makes `Out*` accepted, and
5. show that dependency satisfies at least one earlier case predicate.

The last step contradicts first-match disjointness because `Unmapped` is
reached only when none of the earlier predicates match. Therefore no accepted
unauthorized output can be owned by `Unmapped`, yielding the target
`eps_cls_unmapped(A, Z) = 0` once all premises are proved.

## Proof Skeleton
<a id="ek4-proof-skeleton"></a>

```text
Given adversary A and environment Z:

1. Start from eps_classify(A, Z).
2. Apply classifier totality:
     all accepted unauthorized outputs are classified, except
     eps_cls_totality(A, Z).
3. Apply first-match disjointness:
     each classified output has one owner, except
     eps_cls_disjointness(A, Z).
4. Split by ordered classifier case:
     eps_cls_mldsa(A, Z)
   + eps_cls_threshold(A, Z)
   + eps_cls_vss_dkg(A, Z)
   + eps_cls_commit(A, Z)
   + eps_cls_contrib(A, Z)
   + eps_cls_ro_transcript(A, Z)
   + eps_cls_collect(A, Z)
   + eps_cls_evid(A, Z)
   + eps_cls_unmapped(A, Z).
5. Use the contradiction strategy to prove:
     eps_cls_unmapped(A, Z) = 0.
6. Leave the per-case residuals to their reductions or assumption boundaries.
```

The resulting accounting target is:

```text
eps_classify(A, Z)
 <= eps_cls_totality(A, Z)
  + eps_cls_disjointness(A, Z)
  + eps_cls_mldsa(A, Z)
  + eps_cls_threshold(A, Z)
  + eps_cls_vss_dkg(A, Z)
  + eps_cls_commit(A, Z)
  + eps_cls_contrib(A, Z)
  + eps_cls_ro_transcript(A, Z)
  + eps_cls_collect(A, Z)
  + eps_cls_evid(A, Z)
  + eps_cls_unmapped(A, Z)
```

Only after the totality, disjointness, per-case, and unmapped-zero obligations
are separately proved may the `Unmapped` residual be removed from
`eps_classify`.

## Non-Claims
<a id="ek4-non-claims"></a>

This document does not prove classifier totality.
It does not prove classifier disjointness.
It does not prove any per-case reduction.
It does not prove `eps_cls_unmapped = 0`.
It does not prove final unforgeability.
Implementation evidence is not cryptographic proof.

## Manifest Anchors
<a id="ek4-manifest-anchors"></a>

Stable strings for manifest integration:

```text
eps-classify-unmapped-zero-theorem
Theorem K4-eps-cls-unmapped-zero
ek4-theorem-target
ek4-accepted-unauthorized-output-domain
ek4-authorized-release-complement
ek4-classifier-coverage-grammar
ek4-totality-premises
ek4-disjointness-premises
ek4-per-case-reduction-premises
ek4-unmapped-contradiction-strategy
ek4-proof-skeleton
ek4-non-claims
ek4-manifest-anchors
eps_cls_totality
eps_cls_disjointness
eps_cls_mldsa
eps_cls_threshold
eps_cls_vss_dkg
eps_cls_commit
eps_cls_contrib
eps_cls_ro_transcript
eps_cls_collect
eps_cls_evid
eps_cls_unmapped
eps_classify
```
