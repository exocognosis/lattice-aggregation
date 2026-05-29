# FST-L6 No Subthreshold Signing Worksheet
<a id="fst-l6-no-subthreshold-signing"></a>

Date: 2026-05-29

Status: theorem-closure worksheet for `FST-L6` under ideal `F_VSS_DKG` and
ideal `F_CONTRIB`, not a completed no-subthreshold signing proof.

## FSTL6-0. Scope and Non-Claim
<a id="fstl6-scope-non-claim"></a>

This worksheet expands the `FST-L6` no-subthreshold signing lemma from
[formal-security-theorem.md](formal-security-theorem.md) and
[idealvss-lemma-skeleton.md](idealvss-lemma-skeleton.md). It connects the
IdealVSS theorem route under ideal `F_VSS_DKG` setup, partial-share validity,
ideal contribution validity, collection soundness, and the unauthorized-output
classifier.

This document does not prove threshold unforgeability, subthreshold secrecy,
or the project thesis. This worksheet does not prove the thesis. It does not
eliminate `eps_classify`, `eps_threshold`, `eps_vss_ideal`, or
`eps_cls_unmapped = 0`.

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
Let `C` be the corrupted set and require `|C| < t`. The proof route is for
`FST-T1-IdealVSS`; any use of `F_VSS_DKG` is an ideal boundary and is not
production VSS/DKG security.

### Authorization Model
<a id="fstl6-authorization-model"></a>

The proof must define authorization over:

- `epoch_id`;
- `session_id`;
- `attempt`;
- `message_binding` or `(M, mu)`;
- `pk_epoch`;
- `validator_set_digest`;
- `active_set`, the validator identities eligible to contribute for the
  release context;
- threshold `t`, meaning the minimum number of valid, unique, in-set
  validators whose accepted shares may authorize an aggregate release;
- corrupted set `C`, with `|C| < t`;
- `ReleaseSignature` records from `F_TMLDSA`;
- `authorized_release_log`, the append-only ideal log of release records and
  replay policy.

`F_TMLDSA` is the ideal threshold ML-DSA release functionality. It accepts a
release only when the release context is bound to the active set, the ideal
`F_VSS_DKG` setup for the epoch, the contribution-validity predicate, and at
least `t` valid validators. Each successful ideal release appends a
`ReleaseSignature` record to `authorized_release_log`.

`AggregateOutputRecord` is the real-world verifier-visible record containing
the aggregate signature, message binding, epoch/session/attempt context,
validator-set binding, contribution evidence, and accepted share attribution
used by the collector. An `AggregateOutputRecord` is authorized only if it
matches a `ReleaseSignature` in `authorized_release_log`, or is byte-identical
to a replay permitted by that log's deterministic replay policy.

An output is unauthorized if its `AggregateOutputRecord` verifies under
`pk_epoch` for a message/context not released by `F_TMLDSA`, not present in
`authorized_release_log`, and not byte-identical to an allowed authorized
replay.

## FSTL6-3. Theorem Statement
<a id="fstl6-lemma-statement"></a>
<a id="fstl6-theorem-statement"></a>

Target theorem-closure statement:

```text
Theorem FSTL6-no-subthreshold-signing. In the FST-T1-IdealVSS theorem route,
conditioned on ideal F_VSS_DKG setup, ideal contribution validity through
F_CONTRIB, static active corruption of a set C with |C| < t, valid transcript
binding, collection soundness, and partial-signature extractability, no
accepting AggregateOutputRecord can be authorized by fewer than t valid
validators unless one of the following occurs:

1. an ideal functionality violation in F_TMLDSA or F_VSS_DKG,
2. a contribution-validity break for F_CONTRIB,
3. a collection-soundness break, including the threshold-share branch recorded
   as eps_threshold,
4. a classifier-totality or classifier-disjointness break,
5. a base ML-DSA-65 forgery case.
```

For the immediate IdealVSS theorem path, the residual is:

```text
eps_classify
 + eps_threshold
 + eps_vss_ideal
 + eps_cls_threshold
 + eps_cls_contrib
 + eps_cls_unmapped
```

The intended closure target is to route all accepting unauthorized aggregate
outputs into the named cases, with `eps_cls_unmapped = 0` only after classifier
totality and disjointness have been proved. This worksheet does not prove the
term negligible or zero.

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

### Ordered Proof Cases
<a id="fstl6-ordered-proof-cases"></a>

The closure proof must order unauthorized accepting `AggregateOutputRecord`
cases so each record is charged once:

1. Fewer than `t` accepted shares. If extraction finds fewer than `t` valid,
   unique, in-set accepted shares bound to the same context, the accepting
   record is charged to `BadThresholdShare` and `eps_threshold`.
2. Rogue signer outside validator set. If any counted signer is not in
   `active_set`, or is not bound to the epoch's `validator_set_digest`, the
   record is charged to `BadRogueSigner` and then to collection or classifier
   soundness, as applicable.
3. Duplicate signer counted twice. If the collector counts the same validator
   identity more than once toward `t`, the record is charged to
   `BadRogueSigner` or `BadThresholdShare` depending on whether the duplicate
   passes the in-set check.
4. Stale release replay. If the aggregate is byte-identical to a prior release
   but the replay policy, `epoch_id`, `session_id`, `attempt`, or
   `message_binding` does not permit reuse, the record is unauthorized and is
   charged to collection soundness, classifier failure, or base forgery after
   replay extraction.
5. Ideal setup mismatch. If the accepted record binds to a different ideal
   setup, active set, public key, or epoch than the one registered in
   `F_VSS_DKG`, the record is charged to `BadIdealMismatch` and
   `eps_vss_ideal`.
6. Extraction or classification failure. If the simulator cannot extract the
   accepted share set, release mapping, replay mapping, or unique classifier
   case, the record is charged to `BadExtractFail`, `BadUnauthorizedAccept`,
   and the visible classifier residual, including `eps_cls_unmapped` until it
   is proved zero.
7. Base ML-DSA forgery route. If the record verifies under `pk_epoch`, has no
   authorized release in `authorized_release_log`, and the threshold-side
   events above do not occur, the simulator uses the aggregate as the candidate
   base ML-DSA-65 forgery.

## FSTL6-5. Residual Terms
<a id="fstl6-residual-terms"></a>

Residual routing:

- `eps_threshold` is only for subthreshold signing or share-soundness failures.
- `eps_classify` is only for accepting unauthorized outputs not yet mapped to
  ML-DSA forgery or a named threshold-side failure.
- `eps_vss_ideal` is only for reliance on `F_VSS_DKG` setup properties and
  must not be silently folded into `eps_threshold`.
- `eps_cls_threshold` is the classifier branch for threshold-side failures
  such as fewer than `t` valid, unique, in-set shares.
- `eps_cls_contrib` is the classifier branch for `F_CONTRIB` contribution
  validity failures.
- `eps_cls_unmapped = 0` remains an explicit obligation; it is not assumed by
  the theorem statement.

The visible bad-event surface for this worksheet is:

```text
BadUnauthorizedAccept
BadThresholdShare
BadRogueSigner
BadExtractFail
BadIdealMismatch
```

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
   interface under ideal `F_VSS_DKG` and ideal contribution validity under
   `F_CONTRIB`.
2. Use `FST-L3` and `FST-L4` to show any accepted aggregate counts at least
   `t` valid, unique, in-set contributions for one bound transcript.
3. Use `FST-L5` to show the output verifies as standard ML-DSA-65.
4. If the message was authorized, map the output to a `ReleaseSignature` in
   `authorized_release_log`.
5. If the message was not authorized, run the classifier and reduce the case
   to ML-DSA forgery or a named threshold-side failure.
6. Keep `eps_classify`, `eps_threshold`, `eps_vss_ideal`,
   `eps_cls_threshold`, `eps_cls_contrib`, and `eps_cls_unmapped` visible
   until the classifier and backend theorems close them.

### Dependencies
<a id="fstl6-dependencies"></a>

`FST-L6` depends on:

- `FST-L3` collection soundness;
- `FST-L4` contribution validity;
- `FST-L5` aggregation correctness;
- ideal `F_CONTRIB` contribution-validity interface for the theorem route;
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
- the ideal setup, active set, and `authorized_release_log` bindings are
  checked before treating an output as authorized;
- `eps_cls_unmapped = 0` is proved before removing `eps_classify`;
- the final theorem says whether `eps_threshold` is a derived bound or a
  remaining assumption.
- `eps_threshold`, `eps_classify`, and `eps_vss_ideal` are not merged.

## FSTL6-10. Non-Claims
<a id="fstl6-non-claims"></a>

This worksheet does not prove the thesis. It is not a completed proof. It does
not prove subthreshold signing is impossible, classifier totality, production
VSS/DKG security, contribution soundness, evidence noninterference, final
unforgeability, or production unforgeability. It is not production VSS/DKG
security and does not replace independent audit or implementation residual
review.

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
