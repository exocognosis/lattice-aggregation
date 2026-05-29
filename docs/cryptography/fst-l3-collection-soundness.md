# FST-L3 Collection Soundness Theorem Closure
<a id="fst-l3-collection-soundness"></a>

Date: 2026-05-29

Status: theorem-closure text for the `FST-L3` collection-soundness route under
canonical collection semantics and fixed transcript grammar.

## FSTL3-0. Scope and Non-Claim
<a id="fstl3-scope-non-claim"></a>

This document closes the `FST-L3` validator-set soundness route from
[formal-security-theorem.md](formal-security-theorem.md) and
[idealvss-lemma-skeleton.md](idealvss-lemma-skeleton.md) for accepted
commitment sets, partial-share sets, aggregate output records, evidence
records, release signatures, active validator inventories, and classifier input
records.

The closure is conditional: it holds only under canonical collection semantics
and a fixed transcript grammar. The grammar must bind the same session id,
attempt, `dkg_digest`, threshold, active validator inventory, public key,
message, commitment digest, partial-share digest, aggregate output record,
evidence record, and release-signature context in every round that consumes the
collection. This is not the whole security proof. It does not prove production
P2P liveness, production slashing, contribution validity, threshold-share
soundness, aggregation correctness, evidence anti-framing, release-log
noninterference, or classifier totality.

Implementation evidence supports this route, but implementation evidence is
not a cryptographic proof. The closed claim is that any accepted collection
outside the canonical route is assigned to one of the named bad events below,
so the collection residual is exposed as `eps_collect` and the classifier
handoff remains exposed as `eps_cls_collect` until `FST-L10` discharges it.

## FSTL3-1. Theorem Context
<a id="fstl3-theorem-context"></a>

`FST-L3` supports `FST-A8`: collection processing must be deterministic,
canonical, and independent of network arrival order. The lemma also supplies
the active-set equality facts consumed by `FST-L2`, aggregation correctness,
release logs, evidence records, and unauthorized-output classification.

The theorem is stated over accepted objects, not over network delivery. A
record can arrive in any order, be duplicated in transport, or be omitted by
peers; `FST-L3` only reasons about the collection that the verifier accepts
after parsing, validation, canonicalization, and transcript binding.

## FSTL3-2. Collection Objects
<a id="fstl3-collection-objects"></a>

The proof covers the following collection objects.

- `CommitmentSet`: the accepted map from validator id to commitment payload for
  the commitment round.
- `PartialShareSet`: the accepted map from validator id to partial-share
  payload for the signing or aggregation round.
- `AggregateOutputRecord`: the canonical record describing the aggregate output,
  threshold, active validator inventory, participant set, message, transcript
  context, and collection digests consumed by aggregation.
- `EvidenceRecord`: the canonical record that cites collection state when an
  output or participant behavior is classified as bad.
- `ReleaseSignature`: the release-log signature or release acknowledgement that
  binds the released output to the same session, active set, aggregate record,
  and evidence context.
- Active validator inventory: the validator universe `V`, threshold `t`,
  epoch/session metadata, and active-set identity used to determine whether a
  validator id is known and eligible for this collection.

The legacy proof vocabulary maps into these objects as follows.

- `OrderedMaskCommitSet`;
- `OrderedMaskOpenSet`;
- `OrderedContributionStatementSet`;
- `active_set`;
- `collection_metadata`;
- `AggregateOutputRecord`;
- `EvidenceRecord` references to collection state;
- classifier input tuples containing collection records.

Canonicalization is by `BTreeMap` and `BTreeSet` semantics: validator ids are
unique keys, iteration order is sorted by the canonical validator-id ordering,
and the transcript digest is computed over the sorted key/value encoding, not
over network arrival order. Extra valid records beyond `t` are not sampled or
implicitly truncated. They are either included in the canonical map or rejected
by the fixed grammar for that collection type; the accepted policy is
deterministic and transcript-bound.

## FSTL3-3. Theorem Statement
<a id="fstl3-theorem-statement"></a>

The closed lemma is:

```text
FST-L3:
  Fix canonical collection semantics and a fixed transcript grammar.
  For any accepted CommitmentSet, PartialShareSet, AggregateOutputRecord,
  EvidenceRecord, and ReleaseSignature in session sid with active validator
  inventory (V, t), either:

    1. the accepted set is canonical;
    2. every accepted validator id is in the active inventory V;
    3. the accepted participant set has size at least t;
    4. no accepted validator id appears more than once;
    5. every record is bound to sid and the same transcript context;
    6. the active set used by commitment validation, partial-share validation,
       aggregation, evidence, release, and classifier input is the same
       canonical BTreeSet; and
    7. the aggregate, evidence, release, and classifier records cite the same
       canonical collection digests;

  or one of BadCollection, BadActiveSetRebind, BadDuplicateShare, or
  BadStaleRecord is triggered.
```

Equivalently, every accepted commitment/partial/evidence/release set is
canonical, threshold-valid, duplicate-free, session-bound, and
active-set-consistent, or a named bad event is triggered. This statement closes
the collection-soundness route only for collection formation and metadata
binding. It does not assert that the underlying cryptographic shares are valid
or that the final aggregate signature is unforgeable.

## FSTL3-4. Proof Obligations
<a id="fstl3-proof-obligations"></a>

For each accepted collection, the production verifier must enforce:

```text
ValidateCollection(V, t, active_set, records) =
  all validator IDs are in V
  and no validator ID appears twice
  and |records| >= t
  and active_set = sorted validator IDs(records)
  and every record binds the same SigningContext
  and every record binds the same attempt
  and every record binds the same dkg_digest
```

The proof proceeds by cases on a verifier-accepted record that violates the
canonical route.

- Duplicate validator id: because accepted maps are keyed by validator id and
  duplicate source records are rejected before canonical digesting, a duplicate
  accepted id triggers `BadDuplicateShare`. If the duplicate is hidden by a
  non-canonical overwrite or last-writer policy, the accepted digest differs
  from the fixed `BTreeMap` grammar and triggers `BadCollection`.
- Unknown validator id: membership is checked against the active validator
  inventory. An accepted id not in `V` contradicts validation and triggers
  `BadCollection`.
- Stale session id: each commitment, partial share, aggregate output, evidence
  record, and release signature binds `sid` and the round transcript. A record
  accepted from another session, attempt, epoch, or `dkg_digest` triggers
  `BadStaleRecord`.
- Inconsistent active set across rounds: the commitment, partial-share,
  aggregation, evidence, release, and classifier phases all bind the same
  canonical active-set digest. Accepting different active sets across these
  phases triggers `BadActiveSetRebind`.
- Insufficient quorum: threshold validation requires `1 <= t <= |V|` and
  `|records| >= t` for the accepted participant set. An accepted set with fewer
  than `t` participants triggers `BadCollection`.
- Reordered records: network order is erased by `BTreeMap` and `BTreeSet`
  canonicalization before digesting. A verifier that accepts a distinct output
  only because records were reordered has accepted a non-canonical digest and
  triggers `BadCollection`.
- Malformed payload: parsing precedes collection acceptance. A malformed
  commitment, partial share, aggregate output record, evidence record, or
  release signature that is nevertheless accepted triggers `BadCollection`.
- Evidence/release mismatch: evidence records and release signatures cite the
  same session, active set, aggregate output record, participant set, and
  collection digests. A release accepted against nonmatching evidence, or
  evidence accepted for a different released output, triggers `BadCollection`
  unless the mismatch is specifically an active-set rebinding
  (`BadActiveSetRebind`) or stale-context reuse (`BadStaleRecord`).

## FSTL3-5. Implementation Crosswalk
<a id="fstl3-implementation-crosswalk"></a>

The current Rust scaffold provides useful implementation evidence:

- `src/collections.rs::CommitmentSet::new` rejects unknown validators,
  duplicates, invalid thresholds, and insufficient commitments.
- `src/collections.rs::PartialShareSet::new` rejects unknown validators,
  duplicate signers, invalid thresholds, and insufficient partial shares.
- `set_from_validators` rejects duplicate validator IDs.
- `validate_threshold` rejects `t = 0` and `t > n`.
- `BTreeMap` and `BTreeSet` provide canonical validator order.

These checks support the `Adv_collection_validation(B_coll)` branch. They do
not by themselves prove stale-contributor rejection, transcript-rebinding
exclusion, evidence semantics, release-log semantics, or classifier totality.
Those properties are discharged only when the fixed transcript grammar binds
the collection digests across the theorem objects named above.

## FSTL3-6. eps_collect Decomposition
<a id="fstl3-eps-collect-decomposition"></a>

The top-level simulator worksheet route is:

```text
eps_collect(A,Z)
  <= Adv_aggregation_correctness(B_agg)
   + Adv_collection_validation(B_coll)
   + Adv_challenge_binding(B_ro)
```

This worksheet refines the same route as:

```text
eps_collect
  <= eps_collect_agg
   + eps_collect_validate
   + eps_collect_challenge
```

where:

- `eps_collect_validate` covers duplicate, unknown, out-of-set, insufficient,
  stale, malformed, or incorrectly weighted contributors being accepted;
- `eps_collect_agg` covers aggregation accepting a collection inconsistent
  with the selected active set or threshold;
- `eps_collect_challenge` covers challenge or transcript binding that permits
  collection rebinding across `sid`, `t`, `V`, `pk`, message, commitments, or
  contribution statements.

The classifier-side residual `eps_cls_collect` remains separate until the
unauthorized-output classifier proof proves totality and disjointness.

For this closure text, the named residuals are visible as:

```text
eps_collect
  <= Pr[BadCollection]
   + Pr[BadActiveSetRebind]
   + Pr[BadDuplicateShare]
   + Pr[BadStaleRecord]
   + eps_cls_collect
```

`eps_cls_unmapped = 0` is not asserted by `FST-L3`; it is a required
postcondition of the classifier closure. The collection theorem gives the
classifier a finite, named set of bad collection events rather than an
unstructured residual.

## FSTL3-7. Classifier Interaction
<a id="fstl3-classifier-interaction"></a>

Collection soundness must feed the unauthorized-output classifier. If an
aggregate output is accepted with bad collection metadata, the classifier must
map it to a unique case rather than leaving it in `eps_cls_unmapped = 0`
without proof. Until classifier totality is proved, `eps_cls_collect` remains
visible.

The interaction with `FST-L10` is therefore contractual. `FST-L3` supplies the
classifier with canonical collection facts for the ordinary case and the named
bad events for the exceptional case:

- `BadCollection` covers malformed payloads, unknown validators, insufficient
  quorum, non-canonical ordering, and evidence/release digest mismatches not
  otherwise classified.
- `BadActiveSetRebind` covers any aggregate, evidence, release, or classifier
  input that uses a different active-set digest from the accepted collection
  route.
- `BadDuplicateShare` covers duplicate validator ids, duplicate partial shares,
  duplicate commitments, or any accepted duplicate contribution for one
  validator id.
- `BadStaleRecord` covers cross-session, cross-attempt, cross-epoch, or
  cross-`dkg_digest` reuse.

`FST-L10` must map collection failures to these classifier cases, prove that
the cases are total for accepted unauthorized outputs with bad collection
metadata, and prove that no such output remains in `eps_cls_unmapped = 0`.
Until that proof is present, `eps_cls_collect` remains a separate residual even
though the collection route itself has named all collection failures.

## FSTL3-8. Acceptance Criteria
<a id="fstl3-acceptance-criteria"></a>

For this theorem-closure route, `FST-L3` can be treated as closed only under the
following criteria:

- the production grammar defines active-set and collection encodings;
- the extra-record policy is deterministic and transcript-bound;
- every collection validation failure has a unique error or bad-event class;
- active-set equality is proved across all transcript phases;
- stale contributors are rejected by transcript context, not just local set
  validation;
- `eps_collect` is retained as a visible theorem term and decomposed into the
  named bad events above;
- `eps_cls_collect` remains visible until `FST-L10` proves classifier totality
  for collection failures;
- `eps_cls_unmapped = 0` is claimed only by the classifier proof, not by this
  document.

## FSTL3-9. Non-Claims
<a id="fstl3-non-claims"></a>

This closure does not prove `eps_collect = 0`; it names and bounds the route by
bad events. It does not prove contribution validity, threshold-share soundness,
aggregation correctness, evidence anti-framing, release-log noninterference, or
classifier totality.

It also does not claim production P2P liveness, because no network-delivery,
peer-scheduling, retry, gossip, or availability model is proved here. It does
not claim production slashing, because no complete penalty policy,
accountability workflow, evidence adjudication procedure, or on-chain/off-chain
enforcement model is proved here. Finally, Rust checks, scaffold tests, and
crosswalk references are implementation evidence only; they are not themselves
cryptographic proof.

## FSTL3-10. Manifest Anchors
<a id="fstl3-manifest-anchors"></a>

- `# FST-L3 Collection Soundness Worksheet`
- `fst-l3-collection-soundness`
- `FSTL3-0. Scope and Non-Claim`
- `FSTL3-1. Theorem Context`
- `FSTL3-2. Collection Objects`
- `FSTL3-3. Theorem Statement`
- `FSTL3-4. Proof Obligations`
- `FSTL3-5. Implementation Crosswalk`
- `FSTL3-6. eps_collect Decomposition`
- `FSTL3-7. Classifier Interaction`
- `FSTL3-8. Acceptance Criteria`
- `FSTL3-9. Non-Claims`
- `FST-L3`
- `FST-A8`
- `eps_collect`
- `eps_cls_collect`
- `eps_cls_unmapped = 0`
- `CommitmentSet`
- `PartialShareSet`
- `AggregateOutputRecord`
- `EvidenceRecord`
- `ReleaseSignature`
- `BTreeMap`
- `BTreeSet`
- `UnknownValidator`
- `DuplicateValidator`
- `InsufficientCommitments`
- `InsufficientPartialShares`
- `BadCollection`
- `BadActiveSetRebind`
- `BadDuplicateShare`
- `BadStaleRecord`
