# eps_classify Per-Case Reduction Obligations
<a id="eps-classify-per-case-reductions"></a>

Status: Batch C per-case reduction roadmap for eps_classify; this is not a
completed classifier proof and not a proof of eps_cls_unmapped = 0.

This document expands the ordered classifier table from
[eps-classify-elimination-route.md](eps-classify-elimination-route.md) into the
per-case obligations needed before the final unmapped branch can be eliminated.
Each case below records the trigger, reduction target or residual, witness,
extractor, or simulator output that a proof must produce, and the blocker that
keeps the case open.

Batch D tightens the totality, disjointness, and unmapped-elimination route in
[eps-classify-totality-disjointness-closure.md](eps-classify-totality-disjointness-closure.md).

## Theorem Target
<a id="epcr-theorem-target"></a>

```text
Theorem K2-classifier-case-reductions.

Conditioned on the fixed production verifier grammar, deterministic
authorized-release semantics, and the ordered first-match classifier from
Theorem K1-classifier-totality-disjointness, each non-authorized classifier
case has a concrete reduction, residual boundary, witness extractor, or
simulator output that explains the accepted unauthorized output:

  MldsaForgery,
  ThresholdAuthorizationBreak,
  VssDkgBreak,
  CommitmentBreak,
  ContributionBreak,
  RoTranscriptBreak,
  CollectionBreak,
  EvidenceBreak,
  or Unmapped.

The target is to make every non-Unmapped case chargeable to its named residual
and then prove that Unmapped is unreachable.
```

`Theorem K2-classifier-case-reductions` is a target theorem name. This roadmap
does not prove the theorem.

## Residual Accounting
<a id="epcr-residual-accounting"></a>

The Batch C accounting keeps every classifier summand visible:

```text
eps_classify(A, Z)
 <= eps_cls_mldsa(A, Z)
  + eps_cls_threshold(A, Z)
  + eps_cls_vss_dkg(A, Z)
  + eps_cls_commit(A, Z)
  + eps_cls_contrib(A, Z)
  + eps_cls_ro_transcript(A, Z)
  + eps_cls_collect(A, Z)
  + eps_cls_evid(A, Z)
  + eps_cls_unmapped(A, Z)
```

Per-case reductions can replace a summand only when the corresponding
extractor, simulator, or adversary construction is stated with its event,
runtime, query, and probability loss. The final addend is not replaced by a
reduction; `eps_cls_unmapped` is removed only by a totality and disjointness
proof that makes the `Unmapped` branch unreachable.

## Reduction-Loss Requirements
<a id="epcr-reduction-loss-requirements"></a>

Every future non-`Unmapped` reduction must state the loss data below before the
corresponding classifier summand can be removed or related to a base theorem.
This table is a checklist for proof authors; it does not prove any per-case
reduction.

| Requirement | Meaning |
| --- | --- |
| `event` | The exact accepted unauthorized event owned by the classifier case, including the production verifier path and authorized-release filter state. |
| `runtime` | The runtime of the constructed reducer, extractor, simulator, or distinguisher as a function of adversary runtime, validator count, threshold, sessions, attempts, and oracle queries. |
| `query` | The number and type of signing, random-oracle, DKG/setup, contribution, evidence, and verifier queries made by the reduction. |
| `probability loss` | The displayed success-probability loss or residual term introduced by guessing, rewinding, extraction failure, abort conditioning, or oracle programming. |

If any row is omitted for a case, that case remains an open residual and must
not be treated as closed in the final `eps_classify` accounting.

## Per-Case Obligations
<a id="epcr-per-case-obligations"></a>

### MldsaForgery
<a id="epcr-case-mldsa-forgery"></a>

- Trigger: the production verifier accepts `(pk_epoch, m*, sigma*)` after the
  authorized threshold transcript filter has removed every byte-identical
  authorized release for the same release context.
- Reduction target/residual: charge `eps_cls_mldsa` to the selected base
  ML-DSA EUF-CMA or strong-unforgeability theorem, including the exact
  reduction loss from classifier queries and output attempts.
- Required witness/extractor/simulator output: an extractor outputs
  `(pk_epoch, m*, sigma*)`, the accepted verifier transcript, and the evidence
  that no authorized threshold transcript for that exact tuple was logged.
- Open blocker: the route remains open until authorized-release equality,
  message binding, key binding, and ML-DSA verification compatibility are
  deterministic enough to turn the accepted tuple into a valid base forgery.

### ThresholdAuthorizationBreak
<a id="epcr-case-threshold-authorization-break"></a>

- Trigger: ML-DSA acceptance is explained only by an invalid threshold release
  context, such as too few valid in-set contributors, an unauthorized signer
  set, replay outside policy, or threshold/context mismatch.
- Reduction target/residual: charge `eps_cls_threshold` to the threshold
  authorization, signer-set validity, replay authorization, or signing-policy
  residual.
- Required witness/extractor/simulator output: an extractor outputs the
  claimed active set, threshold, counted contributors, release context,
  authorization record, and the failed predicate showing that acceptance used
  an unauthorized threshold transcript.
- Open blocker: the route remains open until contribution counting,
  active-set membership, replay policy, and threshold-context equality are
  fixed under production parsing.

### VssDkgBreak
<a id="epcr-case-vss-dkg-break"></a>

- Trigger: the accepted output depends on epoch key material, share origin, DKG
  agreement, setup binding, extractability, or key-bias behavior inconsistent
  with the selected VSS/DKG boundary.
- Reduction target/residual: charge `eps_cls_vss_dkg` to a concrete VSS/DKG
  theorem if selected, or keep it at the ideal `F_VSS_DKG` boundary.
- Required witness/extractor/simulator output: an extractor or simulator
  outputs the inconsistent `VSS_DKG_references`, epoch key, share-origin
  records, setup transcript, and the violated binding, agreement,
  extractability, or key-bias predicate.
- Open blocker: the route remains open until the production verifier grammar
  ties accepted epoch keys and counted shares to one canonical setup transcript
  or explicitly preserves the ideal boundary.

### CommitmentBreak
<a id="epcr-case-commitment-break"></a>

- Trigger: acceptance requires commitment equivocation, rebinding, inconsistent
  openings, an opening-set mismatch, or a context-binding failure not owned by
  an earlier case.
- Reduction target/residual: charge `eps_cls_commit` to commitment binding,
  opening-set equality, or context-binding security for the selected
  commitment scheme.
- Required witness/extractor/simulator output: an extractor outputs the
  commitment records, claimed openings, statement contexts, and either two
  distinct valid openings for one commitment or a canonical opening-set
  mismatch accepted by the verifier.
- Open blocker: the route remains open until every accepted opening and
  statement is tied to one canonical committed value set under deterministic
  context encoding.

### ContributionBreak
<a id="epcr-case-contribution-break"></a>

- Trigger: a counted contribution is accepted without a valid statement,
  proof, relation witness, transcript binding, or selected contribution
  backend guarantee, after earlier setup and commitment cases fail to match.
- Reduction target/residual: charge `eps_cls_contrib` to the production
  contribution theorem if selected, or keep it at the ideal `F_CONTRIB`
  boundary.
- Required witness/extractor/simulator output: an extractor outputs the
  counted contribution frame, statement, proof object, relation instance,
  expected witness form, and the failed soundness or binding predicate.
- Open blocker: the route remains open until the selected contribution backend
  has a stated relation, witness extractor or simulator, context binding, and
  accepted-proof soundness theorem.

### RoTranscriptBreak
<a id="epcr-case-ro-transcript-break"></a>

- Trigger: acceptance depends on random-oracle or transcript behavior such as
  missing domain separation, prior-query failure, challenge rebinding,
  serialization collision, malformed transcript acceptance, or inconsistent
  programming.
- Reduction target/residual: charge `eps_cls_ro_transcript` to random-oracle
  separation, challenge binding, transcript injectivity, or canonical
  serialization residuals.
- Required witness/extractor/simulator output: an extractor outputs the typed
  oracle queries, serialized transcript fields, challenge inputs and outputs,
  domain tags, and the collision, rebinding, or prior-query violation.
- Open blocker: the route remains open until every surviving accepted
  transcript field has injective serialization, fixed domain separation, and
  deterministic challenge derivation.

### CollectionBreak
<a id="epcr-case-collection-break"></a>

- Trigger: acceptance requires noncanonical collection behavior, including
  duplicate acceptance, out-of-set records, stale records, malformed records,
  invalid quorum counting, nondeterministic ordering, or validator-set
  mismatch.
- Reduction target/residual: charge `eps_cls_collect` to canonical collection,
  active-set validation, quorum accounting, duplicate rejection, stale-record
  rejection, ordering, or validator-set binding residuals.
- Required witness/extractor/simulator output: an extractor outputs the
  collection metadata, validator-set digest, active set, threshold, counted
  records, ordering rule, and the exact collection predicate violated by the
  accepted output.
- Open blocker: the route remains open until collection validation is
  deterministic over the production grammar and every counted record has one
  canonical membership, freshness, and ordering status.

### EvidenceBreak
<a id="epcr-case-evidence-break"></a>

- Trigger: acceptance relies on evidence behavior that authorizes an otherwise
  unauthorized output, suppresses required rejection evidence, fabricates
  attribution, rebinds evidence to a different context, or frames an honest
  participant.
- Reduction target/residual: charge `eps_cls_evid` to evidence
  noninterference, evidence availability, attribution binding, or anti-framing
  residuals.
- Required witness/extractor/simulator output: an extractor outputs the
  evidence records, linked contribution or release context, attribution data,
  rejection or abort state, and the violated noninterference or anti-framing
  predicate.
- Open blocker: the route remains open until evidence handling is proved unable
  to change authorization, suppress mandatory rejection, fabricate blame, or
  alter acceptance outside the earlier classifier cases.

### Unmapped
<a id="epcr-case-unmapped"></a>

- Trigger: an unauthorized production-accepted output survives the authorized
  threshold transcript filter and none of the ordered cases
  `MldsaForgery`, `ThresholdAuthorizationBreak`, `VssDkgBreak`,
  `CommitmentBreak`, `ContributionBreak`, `RoTranscriptBreak`,
  `CollectionBreak`, or `EvidenceBreak` matches.
- Reduction target/residual: no reduction target; charge
  `eps_cls_unmapped`.
- Required witness/extractor/simulator output: for roadmap accounting, the
  classifier must output the full `Out*` tuple, the failed predicate result for
  every earlier ordered case, and the accepted production verifier path.
- Open blocker: `Unmapped` is eliminated only after proving no production
  verifier acceptance path can produce such a tuple.

## Unmapped Elimination Requirement
<a id="epcr-unmapped-elimination-requirement"></a>

To make `Unmapped` unreachable and prove `eps_cls_unmapped = 0`, the final
proof must show all of the following:

- Every production-accepted output is parsed into the exact classifier input
  tuple with injective, deterministic field encodings.
- The authorized threshold transcript filter is byte-level deterministic for
  the same message, key, epoch, session, attempt, active set, threshold,
  collection metadata, and release context.
- Each ordered case predicate is total over the parsed `Out*` fields it
  consumes and has no undefined, optional-without-default, or order-dependent
  accepted state.
- For every unauthorized accepting `Out*`, either `MldsaForgery` matches or at
  least one threshold-side predicate among `ThresholdAuthorizationBreak`,
  `VssDkgBreak`, `CommitmentBreak`, `ContributionBreak`,
  `RoTranscriptBreak`, `CollectionBreak`, and `EvidenceBreak` matches.
- First-match disjointness is proved, so if multiple predicates are true, the
  earliest ordered case owns the output and no later residual is also charged.
- Any verifier acceptance path not covered by those predicates contradicts the
  fixed production verifier grammar and therefore cannot occur.

Only those obligations together justify:

```text
Pr[Classify(Out*) = Unmapped] = eps_cls_unmapped = 0.
```

## Acceptance Criteria
<a id="epcr-acceptance-criteria"></a>

This Batch C roadmap is acceptable only if:

- `Theorem K2-classifier-case-reductions` is named as a target, not as a
  completed theorem.
- Each required case has a trigger, reduction target or residual, required
  witness, extractor, or simulator output, and open blocker.
- The residual accounting lists `eps_cls_mldsa`, `eps_cls_threshold`,
  `eps_cls_vss_dkg`, `eps_cls_commit`, `eps_cls_contrib`,
  `eps_cls_ro_transcript`, `eps_cls_collect`, `eps_cls_evid`, and
  `eps_cls_unmapped`.
- The exact requirements for proving `eps_cls_unmapped = 0` are explicit.
- The document preserves `Unmapped` as an open proof gap until totality and
  disjointness are proved.
- Implementation traces, tests, manifests, and code paths are not treated as
  cryptographic proof.

## Non-Claims
<a id="epcr-non-claims"></a>

This document does not prove any per-case reduction.
It does not prove classifier totality.
It does not prove classifier disjointness.
It does not prove `eps_cls_unmapped = 0`.
It makes no zero or negligible claim for any residual
except as an explicitly labeled target. It does not prove production ML-DSA
unforgeability, threshold authorization soundness, VSS/DKG security,
commitment security, contribution soundness, random-oracle separation,
collection soundness, evidence noninterference, final unforgeability, or
production readiness. It is not production-ready.
Implementation evidence is not cryptographic proof.

## Manifest Anchors
<a id="epcr-manifest-anchors"></a>

Stable strings for downstream references:

- `# eps_classify Per-Case Reduction Obligations`
- `eps-classify-per-case-reductions`
- `Status: Batch C per-case reduction roadmap for eps_classify; this is not a completed classifier proof and not a proof of eps_cls_unmapped = 0.`
- `epcr-theorem-target`
- `Theorem K2-classifier-case-reductions`
- `epcr-residual-accounting`
- `epcr-reduction-loss-requirements`
- `event`
- `runtime`
- `query`
- `probability loss`
- `eps_cls_mldsa`
- `eps_cls_threshold`
- `eps_cls_vss_dkg`
- `eps_cls_commit`
- `eps_cls_contrib`
- `eps_cls_ro_transcript`
- `eps_cls_collect`
- `eps_cls_evid`
- `eps_cls_unmapped`
- `epcr-per-case-obligations`
- `MldsaForgery`
- `ThresholdAuthorizationBreak`
- `VssDkgBreak`
- `CommitmentBreak`
- `ContributionBreak`
- `RoTranscriptBreak`
- `CollectionBreak`
- `EvidenceBreak`
- `Unmapped`
- `epcr-unmapped-elimination-requirement`
- `eps_cls_unmapped = 0`
- `epcr-acceptance-criteria`
- `epcr-non-claims`
- `epcr-manifest-anchors`
