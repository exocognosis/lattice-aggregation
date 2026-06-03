# eps_classify Totality and Disjointness Closure Route
<a id="eps-classify-totality-disjointness-closure"></a>

Status: Batch D theorem-closure route, not a completed proof.

This document tightens the Batch C classifier route into the final theorem
shape needed before `eps_classify` can be closed. It records obligations and
accounting targets only. It does not claim classifier closure.

## Theorem Target
<a id="ectdc-theorem-target"></a>

```text
Theorem K3-classifier-totality-disjointness-closure.

Conditioned on the fixed production verifier grammar, deterministic
authorized-release filtering, and completed per-case reduction obligations,
every production-accepted unauthorized output in the classifier domain is
assigned to exactly one first matching case:

  MldsaForgery,
  ThresholdAuthorizationBreak,
  VssDkgBreak,
  CommitmentBreak,
  ContributionBreak,
  RoTranscriptBreak,
  CollectionBreak,
  EvidenceBreak,
  or Unmapped.

The closure target is to prove the Unmapped branch unreachable and therefore
prove eps_cls_unmapped = 0.
```

`Theorem K3-classifier-totality-disjointness-closure` is a target theorem
name. This file does not prove it.

## Classifier Domain
<a id="ectdc-classifier-domain"></a>

The classifier domain is the set of verifier-accepted, production-parsed
`Out*` tuples that survive the authorized threshold transcript filter:

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

Domain membership requires all tuple fields to be parsed under injective,
deterministic production encodings. An output that is accepted by production
verification but cannot be represented in this tuple is not outside the proof
problem; it remains an `Unmapped` witness until the grammar rules out such an
accepted path.

The authorized threshold transcript filter is pre-classification: it removes
byte-identical authorized releases for the same message, key, epoch, session,
attempt, active set, threshold, collection metadata, and release context. The
classifier covers only accepted outputs that remain unauthorized after that
filter.

## Classifier Output Cases
<a id="ectdc-classifier-output-cases"></a>

The classifier is ordered and first-match:

1. `MldsaForgery`: accepted ML-DSA tuple not explained by an authorized
   threshold release.
2. `ThresholdAuthorizationBreak`: acceptance depends on invalid threshold
   authorization, signer-set, replay, or release-policy semantics.
3. `VssDkgBreak`: acceptance depends on VSS/DKG setup, epoch-key,
   share-origin, agreement, binding, extractability, or key-bias behavior
   outside the selected boundary.
4. `CommitmentBreak`: acceptance depends on commitment equivocation,
   rebinding, inconsistent openings, opening-set mismatch, or context-binding
   failure.
5. `ContributionBreak`: acceptance depends on an invalid counted contribution,
   contribution statement, proof, relation witness, transcript binding, or
   selected contribution backend guarantee.
6. `RoTranscriptBreak`: acceptance depends on random-oracle or transcript
   behavior such as missing domain separation, prior-query failure, challenge
   rebinding, serialization collision, malformed transcript acceptance, or
   inconsistent programming.
7. `CollectionBreak`: acceptance depends on noncanonical collection behavior,
   duplicate acceptance, out-of-set records, stale records, malformed records,
   invalid quorum counting, nondeterministic ordering, or validator-set
   mismatch.
8. `EvidenceBreak`: acceptance depends on evidence behavior that authorizes an
   otherwise unauthorized output, suppresses required rejection evidence,
   fabricates attribution, rebinds evidence, or frames an honest participant.
9. `Unmapped`: the output survives the authorized filter and no earlier case
   predicate matches.

## Totality Obligation
<a id="ectdc-totality-obligation"></a>

Totality requires a proof that every accepted unauthorized `Out*` in the
classifier domain returns one of the ordered cases:

```text
Classify(Out*) in {
  MldsaForgery,
  ThresholdAuthorizationBreak,
  VssDkgBreak,
  CommitmentBreak,
  ContributionBreak,
  RoTranscriptBreak,
  CollectionBreak,
  EvidenceBreak,
  Unmapped
}
```

The proof route must cover every production verifier acceptance path, every
canonical parse branch, every optional field default, and every release or
evidence interaction that can affect acceptance. Undefined predicates,
ambiguous encodings, and order-dependent accepted states keep the totality
obligation open.

## Disjointness Obligation
<a id="ectdc-disjointness-obligation"></a>

Disjointness requires a proof that the ordered classifier charges exactly one
case per accepted unauthorized `Out*`. If more than one semantic predicate is
true, the earliest ordered case owns the output and later cases are not
charged.

The proof route must show that each case predicate is deterministic over the
canonical tuple, that first-match ownership is stable under equivalent
encodings, and that no output can be counted by two residual terms. This is
the accounting condition needed before `eps_cls_disjointness` can be removed.

## Unmapped-Elimination Obligation
<a id="ectdc-unmapped-elimination-obligation"></a>

Unmapped elimination requires a theorem proof that the final branch is
unreachable:

```text
Pr[Classify(Out*) = Unmapped] = eps_cls_unmapped = 0.
```

The statement `eps_cls_unmapped = 0` is a theorem target, not proven here. To
prove it, the final closure must show that every production-accepted
unauthorized output either matches `MldsaForgery` or matches at least one of
`ThresholdAuthorizationBreak`, `VssDkgBreak`, `CommitmentBreak`,
`ContributionBreak`, `RoTranscriptBreak`, `CollectionBreak`, or
`EvidenceBreak`, and that first-match disjointness assigns the output to one
owner.

Batch E records this unmapped-zero target as
`Theorem K4-eps-cls-unmapped-zero` in
[`eps-classify-unmapped-zero-theorem.md`](eps-classify-unmapped-zero-theorem.md).

## Epsilon Accounting
<a id="ectdc-epsilon-accounting"></a>

Batch D keeps the closure obligations visible as separate accounting terms:

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

The totality and disjointness terms are proof-route obligations, not final
residuals. The theorem target is to discharge `eps_cls_totality`,
`eps_cls_disjointness`, and `eps_cls_unmapped`, while leaving the named
per-case summands to their own reductions or assumption boundaries. In
particular, `eps_cls_unmapped = 0` is a theorem target, not proven here.

## Non-Claims
<a id="ectdc-non-claims"></a>

This document does not prove classifier totality.
It does not prove classifier disjointness.
It does not prove unmapped elimination or `eps_cls_unmapped = 0`.
It does not prove final unforgeability.
Implementation evidence, tests, traces, and manifest coverage are not cryptographic proof.
