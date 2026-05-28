# Unauthorized Output Classifier Closure Route
<a id="unauthorized-output-classifier-closure"></a>

Date: 2026-05-28

Status: proof-route worksheet for eliminating `eps_classify`, not a completed
unforgeability reduction.

This worksheet refines the S7 -> S8 unauthorized-output classifier in
[simulator-hybrid-reductions.md](simulator-hybrid-reductions.md). Its purpose
is to define the classifier grammar and ordering needed before every accepting
unauthorized aggregate output can be mapped to either a base ML-DSA forgery or
a named threshold-side assumption violation.

## UOCC-0. Scope and Non-Claims
<a id="uocc-scope"></a>

The classifier is a reduction device. It is not a runtime verifier and does not
replace production contribution proofs, VSS/DKG soundness, rejection-sampling
equivalence, transcript binding, or standard ML-DSA verification compatibility.

`eps_classify` remains open until the classifier is total and disjoint over the
final production transcript grammar.

## UOCC-1. Classifier Input Tuple
<a id="uocc-input-tuple"></a>
<a id="eps-classify-closure-route"></a>
<a id="theorem-c-close-unauthorized-output-classifier"></a>

Theorem C-close-unauthorized-output-classifier. Conditioned on the prior S0
through S7 obligations, a fixed production verification grammar, and the
authorized release log semantics in
[ideal-functionality.md](ideal-functionality.md), every accepting unauthorized
aggregate output is assigned by the deterministic classifier below to exactly
one named case or to `Unmapped`.

For each adversarial accepting output, the classifier receives:

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

All fields must be canonical byte strings or references with injective
encodings. If the production grammar leaves any accepted field ambiguous,
`eps_cls_unmapped` remains nonzero.

## UOCC-2. Ordered Case Grammar
<a id="uocc-case-grammar"></a>

The classifier uses an ordered grammar so one accepting output is charged once:

1. **Authorized release replay**: `sigma*` is byte-identical to an authorized
   ideal release for the same message and context. Not a forgery; classify as
   authorized replay.
2. **Base ML-DSA forgery**: standard ML-DSA verification accepts `(pk_epoch,
   m*, sigma*)`, and no threshold-side validation failure is needed to explain
   acceptance. Charge `eps_cls_mldsa`.
3. **Threshold-share violation**: fewer than `t` valid in-set contributors are
   needed for the accepting output. Charge `eps_cls_threshold`.
4. **VSS/DKG violation**: a counted share or epoch public key is inconsistent
   with accepted setup material. Charge `eps_cls_vss_dkg`.
5. **Commitment violation**: a masking or secret commitment is equivocated,
   rebound, or opened outside its statement. Charge `eps_cls_commit`.
6. **Contribution-proof violation**: a counted contribution lacks a valid
   production contribution relation witness or replacement proof. Charge
   `eps_cls_contrib`.
7. **Random-oracle/transcript violation**: accepted verification relies on
   reused, rebound, malformed, or inconsistently programmed transcript inputs.
   Charge `eps_cls_ro_transcript`.
8. **Collection violation**: the aggregate counts unknown, duplicate,
   out-of-set, stale, malformed, or incorrectly weighted contribution records.
   Charge `eps_cls_collect`.
9. **Evidence violation**: evidence omission, reordering, replay, or rebinding
   changes authorization or acceptance without a prior case. Charge
   `eps_cls_evid`.
10. **Unmapped gap**: no prior case applies. Charge `eps_cls_unmapped`.

The final proof eliminates `eps_classify` only after proving case 10 is
unreachable for the selected production grammar.

## UOCC-3. Totality and Disjointness Targets
<a id="uocc-totality-disjointness"></a>

Totality target:

```text
For every accepting unauthorized Out*,
  Classify(Out*) in {
    AuthorizedReplay,
    MldsaForgery,
    ThresholdShareBreak,
    VssDkgBreak,
    CommitmentBreak,
    ContributionBreak,
    RoTranscriptBreak,
    CollectionBreak,
    EvidenceBreak,
    Unmapped
  }.
```

Disjointness target:

```text
The ordered predicates are deterministic and charge exactly one first
applicable case for each Out*.
```

The route is closed only when `Pr[Classify(Out*) = Unmapped] = 0` under the
production verifier grammar.

## UOCC-4. Reduction Map
<a id="uocc-reduction-map"></a>

| Classifier case | Reduction target |
| --- | --- |
| `eps_cls_mldsa` | ML-DSA-65 EUF-CMA or strong unforgeability. |
| `eps_cls_threshold` | Threshold-share soundness or ideal signing authorization violation. |
| `eps_cls_vss_dkg` | VSS/DKG binding, agreement, extractability, or key-bias theorem. |
| `eps_cls_commit` | Commitment binding, hiding, or opening-set equality theorem. |
| `eps_cls_contrib` | Production contribution backend soundness/extraction theorem. |
| `eps_cls_ro_transcript` | Typed random-oracle domain separation, prior-query, or transcript injectivity theorem. |
| `eps_cls_collect` | Canonical collection, validator-set, active-set, and aggregation validation theorem. |
| `eps_cls_evid` | Evidence noninterference and anti-framing theorem. |
| `eps_cls_unmapped` | Open proof gap; must be zero before final theorem closure. |

## UOCC-5. Acceptance Criteria
<a id="uocc-acceptance-criteria"></a>
<a id="classifier-acceptance-criteria"></a>

Before `eps_cls_unmapped` can be removed:

- The production verifier grammar fixes every field in `Out*`.
- The classifier ordering is cited by the S7 -> S8 reduction.
- Every case has a concrete reduction algorithm, runtime loss, success
  probability, and assumption target.
- Contribution failures cite the backend route in
  [contribution-backend-instantiation.md](contribution-backend-instantiation.md).
- Authorized-release replay is distinguishable from a new unauthorized
  signature attempt.
- Active-set, collection, evidence, and transcript failures cannot overlap in a
  way that double-charges the same output.
- `eps_cls_unmapped = 0` is proved from the accepted production grammar, not
  assumed from tests.

## UOCC-6. Non-Claims
<a id="uocc-non-claims"></a>
<a id="classifier-non-claims"></a>

This worksheet does not prove ML-DSA unforgeability, threshold-share
soundness, contribution proof soundness, VSS/DKG security, or collection
validation. It only fixes the classifier route needed to connect those
assumptions without leaving an unclassified accepting unauthorized output.
