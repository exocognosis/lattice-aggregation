# eps_classify Elimination Route
<a id="eps-classify-elimination-route"></a>

Status: Residual Closure Batch B classifier-elimination roadmap for
eps_classify; this is not a completed classifier proof.

This roadmap sharpens the unauthorized-output classifier into explicit proof
obligations for driving the unmapped residual toward the theorem target
`eps_cls_unmapped = 0`. It does not assert that target is already proved.

## Core Definitions
<a id="ecls-core-definitions"></a>

An **unauthorized accepting output** is a production-parsed output record
accepted by the verifier for `(pk_epoch, m*, sigma*)` whose transcript is not a
byte-equal authorized threshold release for the same epoch, session, attempt,
active set, threshold, collection metadata, and release context.

The **classifier input tuple** is:

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

The **verifier grammar** is the fixed production grammar that parses accepted
`AggregateOutputRecord`, `ReleaseSignature`, `EvidenceRecord`, and canonical
`Out*` records into injective, deterministic field encodings. Ambiguous,
optional-without-default, or order-dependent accepted fields keep the unmapped
case open.

An **authorized threshold transcript** is a verifier-accepted transcript whose
`(m*, sigma*)` and all release-context fields match an entry in
`authorized_release_log` under byte-level deterministic replay semantics. This
case is filtered before charging any unauthorized residual.

The **base ML-DSA forgery case** is a verifier-accepted unauthorized
`(pk_epoch, m*, sigma*)` that passes the standard ML-DSA verifier and can be
converted into an ML-DSA forgery after authorized threshold transcripts are
excluded.

The **threshold-side violation cases** are the ordered non-ML-DSA explanations
for an unauthorized accepted output: threshold authorization, VSS/DKG setup,
commitment binding, contribution proof soundness, random-oracle transcript
binding, collection soundness, and evidence noninterference failures.

The **unmapped case** is the residual event that an unauthorized accepting
output survives the authorized-transcript filter and fails to match every
ordered classifier case. It is charged to `eps_cls_unmapped` until a separate
totality and disjointness proof makes the branch unreachable.

## Theorem Target
<a id="ecls-theorem-target"></a>

```text
Theorem K1-classifier-totality-disjointness.

Conditioned on the fixed production verifier grammar, deterministic
authorized-release semantics, and completed per-case reduction routes, every
unauthorized accepting output Out* is assigned to exactly one first matching
case in the ordered classifier grammar:

  MldsaForgery,
  ThresholdAuthorizationBreak,
  VssDkgBreak,
  CommitmentBreak,
  ContributionBreak,
  RoTranscriptBreak,
  CollectionBreak,
  EvidenceBreak,
  or Unmapped.

The closure target is to prove the final branch unreachable:

  Pr[Classify(Out*) = Unmapped] = eps_cls_unmapped = 0.
```

`Theorem K1-classifier-totality-disjointness` is a target theorem name for the
Batch B route. This document records the roadmap and obligations for proving
it; it does not complete the theorem.

## Residual Decomposition
<a id="ecls-residual-decomposition"></a>

The visible Batch B residual decomposition is:

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

The intended elimination route removes only the final unmapped addend, and
only after totality and disjointness are proved over the production verifier
grammar. The other summands remain visible until their own reductions or
assumption boundaries close.

## Ordered Classifier Table
<a id="ecls-ordered-classifier-table"></a>

The classifier is first-match ordered. Later rows are evaluated only after all
earlier rows fail.

| Order | Case | Charged residual or reduction | Required closure work |
| --- | --- | --- | --- |
| 0 | `AuthorizedThresholdTranscript` | No unauthorized residual. | Prove byte-level equality with `authorized_release_log` under the same message, key, epoch, session, attempt, active set, threshold, collection metadata, and release context. |
| 1 | `MldsaForgery` | `eps_cls_mldsa`; reduction to base ML-DSA EUF-CMA or strong unforgeability. | Extract `(pk_epoch, m*, sigma*)` from an unauthorized acceptance after authorized transcripts are removed and state the exact reduction loss. |
| 2 | `ThresholdAuthorizationBreak` | `eps_cls_threshold`; threshold authorization or signing-policy residual. | Prove acceptance requires an invalid threshold transcript: insufficient valid in-set contributors, unauthorized signer set, invalid replay authorization, or mismatched threshold context. |
| 3 | `VssDkgBreak` | `eps_cls_vss_dkg`; concrete VSS/DKG theorem or ideal `F_VSS_DKG` boundary. | Show the accepted output depends on inconsistent epoch key, share-origin, setup, agreement, binding, extractability, or key-bias behavior. |
| 4 | `CommitmentBreak` | `eps_cls_commit`; commitment binding, opening-set, or context-binding residual. | Tie every accepted opening and statement to one canonical committed value set, or expose equivocation, rebinding, or opening-set mismatch. |
| 5 | `ContributionBreak` | `eps_cls_contrib`; production contribution theorem or ideal `F_CONTRIB` boundary. | Show each counted contribution has a valid statement, proof, relation witness, and transcript binding, or charge the selected backend boundary. |
| 6 | `RoTranscriptBreak` | `eps_cls_ro_transcript`; random-oracle, challenge-binding, and transcript-injectivity residuals. | Prove domain separation, prior-query handling, challenge binding, and serialization injectivity for all surviving accepted transcript fields. |
| 7 | `CollectionBreak` | `eps_cls_collect`; canonical collection and quorum residual. | Prove deterministic active-set validation, duplicate rejection, quorum counting, ordering, stale-record rejection, and validator-set binding. |
| 8 | `EvidenceBreak` | `eps_cls_evid`; evidence noninterference and anti-framing residual. | Prove evidence cannot authorize an otherwise unauthorized output, suppress required rejection evidence, fabricate attribution, or frame an honest participant. |
| 9 | `Unmapped` | `eps_cls_unmapped`; no reduction target. | To prove `eps_cls_unmapped = 0`, prove every production-accepted unauthorized output either matched an earlier row or contradicts the verifier grammar; prove first-match disjointness so the same output is charged once. |

The `Unmapped` row is deliberately retained as a proof gap. Eliminating it
requires a complete grammar induction over every verifier acceptance path,
canonical field parsing, deterministic authorized-release replay, and fixed
case predicates that cover the full unauthorized acceptance domain.

Batch C expands these rows into per-case reduction obligations in
[eps-classify-per-case-reductions.md](eps-classify-per-case-reductions.md);
that roadmap is a prerequisite for proving `eps_cls_unmapped = 0`, not a proof
of the equality.

## Acceptance Criteria
<a id="ecls-acceptance-criteria"></a>

The Batch B route is acceptable as a roadmap only if:

- the classifier input tuple exactly matches the production verifier grammar;
- unauthorized accepting output and authorized threshold transcript are
  byte-level deterministic notions;
- `Theorem K1-classifier-totality-disjointness` is named as a target, not as a
  completed theorem;
- every visible summand in the residual decomposition remains explicit;
- each non-unmapped case has a named residual or reduction boundary;
- the ordered classifier table makes first-match ownership clear;
- the requirements for proving `eps_cls_unmapped = 0` are stated as future
  totality and disjointness obligations;
- implementation traces, tests, and manifests are not treated as
  cryptographic proof.

## Non-Claims
<a id="ecls-non-claims"></a>

This document does not prove classifier totality or classifier disjointness.
It does not prove `eps_cls_unmapped = 0`. It makes no negligible or zero claim
for any residual except as an explicitly labeled target. It does not prove
final unforgeability, ML-DSA unforgeability, threshold authorization soundness,
VSS/DKG security, commitment security, contribution soundness, random-oracle
separation, collection soundness, evidence noninterference, or production
readiness. It is not production-ready. Implementation evidence is not
cryptographic proof.

## Manifest Anchors
<a id="ecls-manifest-anchors"></a>

Stable strings for downstream references:

- `# eps_classify Elimination Route`
- `eps-classify-elimination-route`
- `Status: Residual Closure Batch B classifier-elimination roadmap for eps_classify; this is not a completed classifier proof.`
- `ecls-core-definitions`
- `ecls-theorem-target`
- `Theorem K1-classifier-totality-disjointness`
- `ecls-residual-decomposition`
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
- `ecls-ordered-classifier-table`
- `AuthorizedThresholdTranscript`
- `MldsaForgery`
- `ThresholdAuthorizationBreak`
- `VssDkgBreak`
- `CommitmentBreak`
- `ContributionBreak`
- `RoTranscriptBreak`
- `CollectionBreak`
- `EvidenceBreak`
- `Unmapped`
- `ecls-acceptance-criteria`
- `ecls-non-claims`
