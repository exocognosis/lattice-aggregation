# FST-L6 No Subthreshold Signing Worksheet
<a id="fst-l6-no-subthreshold-signing"></a>

Date: 2026-05-28

Status: reduction worksheet for `FST-L6`, not a completed no-subthreshold
signing proof.

## FSTL6-0. Scope and Non-Claim
<a id="fstl6-scope-non-claim"></a>

This worksheet expands the `FST-L6` no-subthreshold signing lemma from
[formal-security-theorem.md](formal-security-theorem.md) and
[idealvss-lemma-skeleton.md](idealvss-lemma-skeleton.md). It connects the
IdealVSS theorem route, partial-share validity, collection soundness, and the
unauthorized-output classifier.

This document does not prove threshold unforgeability, subthreshold secrecy,
or the project thesis. This worksheet does not prove the thesis. It does not eliminate `eps_classify`,
`eps_threshold`, `eps_vss_ideal`, or `eps_cls_unmapped = 0`.

## FSTL6-1. Theorem Context
<a id="fstl6-theorem-context"></a>

`FST-L6` is the bridge from valid aggregation to unforgeability. In the S7 to
S8 simulator step, every accepting aggregate output for an unauthorized message
must become either:

- a base ML-DSA forgery;
- a threshold-share soundness violation;
- a concrete VSS/DKG or IdealVSS-boundary violation;
- a commitment, contribution, random-oracle, collection, or evidence failure;
- or an explicitly visible classifier residual.

## FSTL6-2. Adversary and Authorization Model
<a id="fstl6-adversary-authorization-model"></a>

The adversary model is static active corruption of at most `t - 1` validators,
with the scheduling and rushing powers recorded in the active-adversary model.
The proof route is for `FST-T1-IdealVSS`; any use of `F_VSS_DKG` is an ideal
boundary and is not production VSS/DKG security.

### Authorization Model
<a id="fstl6-authorization-model"></a>

The proof must define authorization over:

- `epoch_id`;
- `session_id`;
- `attempt`;
- `message_binding` or `(M, mu)`;
- `pk_epoch`;
- `validator_set_digest`;
- `active_set`;
- `ReleaseSignature` records from `F_TMLDSA`;
- authorized release logs and replay policy.

An output is unauthorized if it verifies under `pk_epoch` for a message/context
not released by the ideal functionality and not byte-identical to an allowed
authorized replay.

## FSTL6-3. Theorem Statement
<a id="fstl6-lemma-statement"></a>
<a id="fstl6-theorem-statement"></a>

Target lemma:

```text
Theorem FSTL6-no-subthreshold-signing. In the FST-T1-IdealVSS theorem route,
conditioned on F_VSS_DKG setup, static active corruption of at most t - 1
validators, valid transcript binding, contribution validity, collection
soundness, and partial-signature extractability, any accepting aggregate output
for an unauthorized message is charged to exactly one of:

1. base ML-DSA-65 EUF-CMA forgery,
2. eps_threshold,
3. eps_classify, or
4. eps_vss_ideal when the proof step depends on the ideal setup boundary.
```

For the immediate IdealVSS theorem path, the residual is:

```text
eps_classify + eps_threshold + eps_vss_ideal
```

This worksheet does not prove the term negligible or zero.

## FSTL6-4. Proof Route
<a id="fstl6-proof-route"></a>

### Subthreshold Barrier
<a id="fstl6-subthreshold-barrier"></a>

With fewer than `t` corrupt validators, the adversary should not be able to
construct `t` valid, unique, in-set, contribution-proof-bound shares for a new
unauthorized message. Any accepting output that appears to do so must be
classified as one of:

- `BadThresholdShare`;
- `BadRogueSigner`;
- `BadContribSound`;
- `BadCollect`;
- `BadChallengeBinding`;
- `BadVssIdealLeak`;
- `BadMLDSAForge`;
- `BadExtractFail`.

The exact threshold-share soundness statement must specify whether it is
proved from IdealVSS, a concrete VSS/DKG theorem, the contribution backend, or
a separate threshold assumption.

## FSTL6-5. Residual Terms
<a id="fstl6-residual-terms"></a>

Residual routing:

- `eps_threshold` is only for subthreshold signing or share-soundness failures.
- `eps_classify` is only for accepting unauthorized outputs not yet mapped to
  ML-DSA forgery or a named threshold-side failure.
- `eps_vss_ideal` is only for reliance on `F_VSS_DKG` setup properties and
  must not be silently folded into `eps_threshold`.

## FSTL6-6. Dependency Map
<a id="fstl6-dependency-map"></a>

Hard dependencies include `FST-A0`, `FST-A2`, `FST-A6`, `FST-L3`, `FST-L4`,
`FST-L5`, `FST-T1-IdealVSS`, the `F_VSS_DKG` ideal boundary,
contribution-backend selection, the active-adversary model, production
transcript grammar, and simulator S7/S8 unauthorized-output accounting.

## FSTL6-7. Classifier Interaction
<a id="fstl6-classifier-interaction"></a>

### Classifier Reduction Map
<a id="fstl6-classifier-reduction-map"></a>

The classifier decomposition is:

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

`FST-L6` may rely on this map only after every accepted unauthorized output is
assigned to exactly one ordered case and `eps_cls_unmapped = 0` is proved.

### Bad Events and Accounting
<a id="fstl6-bad-events-accounting"></a>

The worksheet tracks:

- `BadUnauthorizedAccept`: an unauthorized `(M*, sigma*)` verifies.
- `BadThresholdShare`: fewer than `t` corrupt validators yield enough valid
  signing material.
- `BadRogueSigner`: an unknown, duplicate, unverified, or out-of-set validator
  is counted.
- `BadExtractFail`: the simulator cannot map an accepting output to a release,
  ML-DSA forgery, or named assumption break.
- `BadIdealMismatch`: `F_TMLDSA` rejects a release that the real protocol
  accepts without a prior bad event.
- `BadClassifierUnmapped`: the classifier reaches the unmapped case.

### Proof Skeleton
<a id="fstl6-proof-skeleton"></a>

The intended proof is:

1. Condition on fewer than `t` static corruptions and the IdealVSS setup
   interface.
2. Use `FST-L3` and `FST-L4` to show any accepted aggregate counts at least
   `t` valid, unique, in-set contributions for one bound transcript.
3. Use `FST-L5` to show the output verifies as standard ML-DSA-65.
4. If the message was authorized, map the output to an ideal release.
5. If the message was not authorized, run the classifier and reduce the case
   to ML-DSA forgery or a named threshold-side failure.
6. Keep `eps_classify`, `eps_threshold`, and `eps_vss_ideal` visible until the
   classifier and backend theorems close them.

### Dependencies
<a id="fstl6-dependencies"></a>

`FST-L6` depends on:

- `FST-L3` collection soundness;
- `FST-L4` contribution validity;
- `FST-L5` aggregation correctness;
- `F_VSS_DKG` ideal setup or a concrete VSS/DKG theorem;
- base ML-DSA-65 EUF-CMA or strong unforgeability;
- unauthorized-output classifier totality and disjointness;
- evidence and release noninterference.

## FSTL6-9. Acceptance Criteria
<a id="fstl6-acceptance-criteria"></a>

Before `FST-L6` can be treated as proved:

- authorization is defined over the exact production verifier grammar;
- replay and release semantics are deterministic;
- threshold-share soundness is stated under IdealVSS or a concrete backend;
- every unauthorized accepting output maps to exactly one classifier case;
- `eps_cls_unmapped = 0` is proved before removing `eps_classify`;
- the final theorem says whether `eps_threshold` is a derived bound or a
  remaining assumption.
- `eps_threshold`, `eps_classify`, and `eps_vss_ideal` are not merged.

## FSTL6-10. Non-Claims
<a id="fstl6-non-claims"></a>

This worksheet does not prove the thesis. It does not prove subthreshold
signing is impossible, classifier totality, VSS/DKG security, contribution
soundness, evidence noninterference, or production unforgeability.
It is not production VSS/DKG security and does not replace independent audit or
implementation residual review.

## FSTL6-11. Manifest Anchors
<a id="fstl6-manifest-anchors"></a>

- `# FST-L6 No Subthreshold Signing Worksheet`
- `fst-l6-no-subthreshold-signing`
- `FSTL6-0. Scope and Non-Claim`
- `FSTL6-1. Theorem Context`
- `FSTL6-2. Adversary and Authorization Model`
- `FSTL6-3. Theorem Statement`
- `FSTL6-4. Proof Route`
- `FSTL6-5. Residual Terms`
- `FSTL6-6. Dependency Map`
- `FSTL6-7. Classifier Interaction`
- `FSTL6-9. Acceptance Criteria`
- `FSTL6-10. Non-Claims`
- `FST-L6`
- `FST-T1-IdealVSS`
- `F_TMLDSA`
- `F_VSS_DKG`
- `AggregateOutputRecord`
- `ReleaseSignature`
- `eps_classify`
- `eps_threshold`
- `eps_vss_ideal`
- `eps_cls_threshold`
- `eps_cls_contrib`
- `eps_cls_unmapped = 0`
- `BadUnauthorizedAccept`
- `BadThresholdShare`
- `BadRogueSigner`
- `BadExtractFail`
- `BadIdealMismatch`
- `static active corruption of at most t - 1 validators`
- `This worksheet does not prove the thesis.`
- `not a completed proof`
- `not production VSS/DKG security`
