# Unauthorized Output Classifier Closure Route
<a id="unauthorized-output-classifier-closure"></a>

Date: 2026-05-28

Status: theorem-closure route for eliminating `eps_classify`, not a completed
unforgeability reduction.

This worksheet refines the S7 -> S8 unauthorized-output classifier in
[simulator-hybrid-reductions.md](simulator-hybrid-reductions.md). Its purpose
is to define the classifier grammar, ordering, and reduction map needed before
every accepting unauthorized aggregate output can be mapped to either a base
ML-DSA forgery or a named threshold-side assumption violation.

## UOCC-0. Scope and Non-Claims
<a id="uocc-scope"></a>

The classifier is a reduction device for the theorem route. It is not a runtime
verifier and does not replace production contribution proofs, VSS/DKG
soundness, rejection-sampling equivalence, transcript binding, or standard
ML-DSA verification compatibility.

The conservative claim boundary is classifier closure only. `eps_classify`
remains open until the classifier is total and disjoint over the final
production transcript grammar, all ordered cases have concrete reductions, and
`eps_cls_unmapped = 0` is proved from that grammar. This route does not claim a
complete security proof unless those prerequisites close.

## UOCC-1. Classifier Input Tuple
<a id="uocc-input-tuple"></a>
<a id="eps-classify-closure-route"></a>
<a id="theorem-c-close-unauthorized-output-classifier"></a>

Theorem C-close-unauthorized-output-classifier. Fix the production verification
grammar, the authorized release log semantics in
[ideal-functionality.md](ideal-functionality.md), and the S0 through S7
obligations used by the S7 -> S8 reduction in
[simulator-hybrid-reductions.md](simulator-hybrid-reductions.md). Assume the
`FST-L1` transcript injectivity, `FST-L2` challenge binding, and `FST-L3`
collection soundness closure batch from
[fst-l1-l3-theorem-closure.md](fst-l1-l3-theorem-closure.md), and assume the
`FST-L4` through `FST-L7` signing-side closure batch from
[fst-l4-l7-theorem-closure.md](fst-l4-l7-theorem-closure.md). Then the
classifier closure target is:

```text
For every production-accepted unauthorized aggregate output Out*,
  Classify(Out*) is total and disjoint:
    total:    Classify(Out*) returns one case in the ordered grammar below;
    disjoint: Classify(Out*) returns exactly the first applicable case;
and Pr[Classify(Out*) = Unmapped] = 0.
```

This theorem statement is a closure target, not a completed proof in this
worksheet. If any prerequisite closure, per-case reduction, or
`eps_cls_unmapped = 0` proof remains open, the residual remains charged to
`eps_classify`.

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

The tuple fields have the following role in the classifier:

- `m*`, `sigma*`, and `pk_epoch` are the candidate ML-DSA message, signature,
  and epoch verification key.
- `epoch_id`, `session_id`, `block_height`, `attempt`,
  `validator_set_digest`, `active_set`, and `threshold` identify the typed
  signing context and collection policy.
- `contribution_frames`, `contribution_statements`, and
  `contribution_proofs` are the accepted partial contribution objects and
  their relation witnesses or replacement proof artifacts.
- `VSS_DKG_references` and `commitment_records` bind epoch setup material,
  shares, public key material, and masking or secret commitments.
- `random_oracle_queries` records the typed oracle transcript relevant to
  `H_mu`, `H_w`, `H_c`, VSS/DKG domains, and contribution domains.
- `collection_metadata`, `evidence_records`, and
  `authorized_release_log` define validator-set membership, aggregation
  counts, abort/retry/evidence behavior, and authorized release status.

All fields must be canonical byte strings or references with injective
encodings. The accepted grammar is ordered: the classifier first checks
whether `Out*` is an authorized replay, then checks for standard ML-DSA
forgery, then checks each threshold-side violation class in the order below.
If the production grammar leaves any accepted field ambiguous, or accepts an
output outside this ordered grammar, `eps_cls_unmapped` remains nonzero.

## UOCC-2. Ordered Case Grammar
<a id="uocc-case-grammar"></a>

The classifier uses an ordered grammar so one accepting output is charged once.
Each predicate is evaluated against the full tuple `Out*`; the output case is
the first predicate that holds:

1. **Authorized release replay**: `sigma*` is byte-identical to an authorized
   ideal release for the same message, epoch key, session, attempt, active set,
   threshold, collection metadata, and release context. Not a forgery; classify
   as `AuthorizedReplay`.
2. **Base ML-DSA forgery**: standard ML-DSA verification accepts `(pk_epoch,
   m*, sigma*)`, and no threshold-side validation failure is needed to explain
   acceptance. Classify as `MldsaForgery` and charge `eps_cls_mldsa`.
3. **Threshold-share violation**: fewer than `t` valid in-set contributors are
   needed for the accepting output, or the output is accepted despite not being
   derivable from `threshold` authorized shares after collection closure.
   Classify as `ThresholdAuthorizationBreak` and charge `eps_cls_threshold`.
4. **VSS/DKG violation**: a counted share or epoch public key is inconsistent
   with accepted setup material, epoch references, public commitments, or the
   ideal setup boundary. Classify as `VssDkgBreak` and charge
   `eps_cls_vss_dkg`.
5. **Commitment violation**: a masking or secret commitment is equivocated,
   rebound, or opened outside its statement. Classify as `CommitmentBreak` and
   charge `eps_cls_commit`.
6. **Contribution-proof violation**: a counted contribution lacks a valid
   production contribution relation witness or replacement proof, or is not
   bound to the accepted statement. Classify as `ContributionBreak` and charge
   `eps_cls_contrib`.
7. **Random-oracle/transcript violation**: accepted verification relies on
   reused, rebound, malformed, or inconsistently programmed transcript inputs.
   Classify as `RoTranscriptBreak` and charge `eps_cls_ro_transcript`.
8. **Collection violation**: the aggregate counts unknown, duplicate,
   out-of-set, stale, malformed, or incorrectly weighted contribution records.
   Classify as `CollectionBreak` and charge `eps_cls_collect`.
9. **Evidence violation**: evidence omission, reordering, replay, or rebinding
   changes authorization, abort/retry state, or acceptance without a prior case.
   Classify as `EvidenceBreak` and charge `eps_cls_evid`.
10. **Unmapped gap**: no prior case applies. Classify as `Unmapped` and charge
   `eps_cls_unmapped`.

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
    ThresholdAuthorizationBreak,
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

Equivalently, after `FST-L1` through `FST-L7`, the verifier must accept no
unauthorized aggregate output outside the ordered grammar in UOCC-2. The
condition `eps_cls_unmapped = 0` is exactly this no-outside-grammar statement:
every accepted unauthorized `Out*` is either an authorized replay filtered out
of the forgery event, a base ML-DSA forgery, or one of the named threshold-side
breaks.

## UOCC-4. Reduction Map
<a id="uocc-reduction-map"></a>

| Classifier case | Reduction map |
| --- | --- |
| `MldsaForgery` / `eps_cls_mldsa` | Build an ML-DSA-65 EUF-CMA or strong-unforgeability adversary that outputs `(pk_epoch, m*, sigma*)` from the accepted unauthorized output after authorized replays are excluded. |
| `ThresholdAuthorizationBreak` / `eps_cls_threshold` | Build a threshold-share soundness or ideal signing authorization adversary showing that acceptance was obtained with fewer than `threshold` valid authorized in-set contributions. |
| `VssDkgBreak` / `eps_cls_vss_dkg` | Build a VSS/DKG binding, agreement, extractability, or key-bias adversary from the inconsistent `VSS_DKG_references`, share metadata, or epoch key material. |
| `CommitmentBreak` / `eps_cls_commit` | Build a commitment binding/opening-set equality adversary, or the selected commitment-assumption adversary, from equivocated, rebound, or out-of-statement commitment records. |
| `ContributionBreak` / `eps_cls_contrib` | Build a production contribution backend soundness or extraction adversary from a counted contribution with no valid relation witness or replacement proof. |
| `RoTranscriptBreak` / `eps_cls_ro_transcript` | Build a typed random-oracle or transcript-injectivity adversary from a prior-query, domain-separation, encoding, replay, rebinding, or inconsistent-programming failure. |
| `CollectionBreak` / `eps_cls_collect` | Build a canonical collection, validator-set, active-set, or aggregation-validation adversary from unknown, duplicate, stale, malformed, out-of-set, or incorrectly weighted records. |
| `EvidenceBreak` / `eps_cls_evid` | Build an evidence noninterference or anti-framing adversary from evidence omission, reordering, replay, or rebinding that changes authorization or acceptance. |
| `Unmapped` / `eps_cls_unmapped` | No reduction target. This is an open proof gap and must be proved unreachable before theorem closure. |

The reduction map is intentionally conditional. Each row must be supplied with
a concrete algorithm, runtime loss, and success-probability relation before the
classifier route can be consumed as a closed theorem.

## UOCC-5. Acceptance Criteria
<a id="uocc-acceptance-criteria"></a>
<a id="classifier-acceptance-criteria"></a>

Before `eps_cls_unmapped` can be removed:

- The production verifier grammar fixes every field in `Out*`.
- The classifier ordering is cited by the S7 -> S8 reduction.
- The closure is explicitly conditioned on
  [fst-l1-l3-theorem-closure.md](fst-l1-l3-theorem-closure.md) and
  [fst-l4-l7-theorem-closure.md](fst-l4-l7-theorem-closure.md).
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
- No production-accepted output remains outside the ordered grammar after
  `FST-L1` through `FST-L7`.

## UOCC-6. Non-Claims
<a id="uocc-non-claims"></a>
<a id="classifier-non-claims"></a>

This worksheet does not prove final unforgeability, production backend
security, ML-DSA unforgeability, threshold-share soundness, contribution proof
soundness, VSS/DKG security, or collection validation. It only fixes the
classifier route needed to connect those assumptions without leaving an
unclassified accepting unauthorized output.

Implementation tests, manifests, and crosswalks can provide evidence that code
matches the intended grammar, but implementation evidence is not a
cryptographic proof of classifier totality, disjointness, or
`eps_cls_unmapped = 0`.
