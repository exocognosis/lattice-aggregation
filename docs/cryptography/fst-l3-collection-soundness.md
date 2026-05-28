# FST-L3 Collection Soundness Worksheet
<a id="fst-l3-collection-soundness"></a>

Date: 2026-05-28

Status: reduction worksheet for `FST-L3`, not a completed collection theorem.

## FSTL3-0. Scope and Non-Claim
<a id="fstl3-scope-non-claim"></a>

This worksheet expands the `FST-L3` validator-set soundness lemma from
[formal-security-theorem.md](formal-security-theorem.md) and
[idealvss-lemma-skeleton.md](idealvss-lemma-skeleton.md). It turns the
canonical collection requirements into a proof plan for accepted commitment
sets, contribution sets, active sets, aggregate output records, and classifier
records.

This document does not prove collection soundness. It does not claim the Rust
collection checks alone establish production security, and it does not close
`eps_collect`, `eps_cls_collect`, or `eps_cls_unmapped = 0`.

## FSTL3-1. Theorem Context
<a id="fstl3-theorem-context"></a>

`FST-L3` supports `FST-A8`: collection processing must be deterministic,
canonical, and independent of network arrival order. The lemma also supplies
the active-set equality facts consumed by `FST-L2`, aggregation correctness,
release logs, evidence records, and unauthorized-output classification.

## FSTL3-2. Collection Objects
<a id="fstl3-collection-objects"></a>

The proof must cover:

- `OrderedMaskCommitSet`;
- `OrderedMaskOpenSet`;
- `OrderedContributionStatementSet`;
- `active_set`;
- `collection_metadata`;
- `AggregateOutputRecord`;
- `EvidenceRecord` references to collection state;
- classifier input tuples containing collection records.

The code-level analogues are `CommitmentSet` and `PartialShareSet`, but those
types are implementation evidence, not the theorem itself.

## FSTL3-3. Theorem Statement
<a id="fstl3-theorem-statement"></a>

Target lemma:

```text
FST-L3:
  Under the production collection validation rules, every accepted commitment
  set and partial-share set contains only unique validators from V and at
  least t accepted entries, and the same active set is used by challenge,
  contribution validation, aggregation, evidence, release, and classifier
  records except through a listed bad event.
```

The theorem must reject duplicate validators, unknown validators,
out-of-epoch validators, stale contributors, insufficient collections, malformed
records, and active-set rebinding.

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

The proof must specify whether extra valid records beyond `t` are ignored,
canonicalized, or included. The choice must be deterministic and bound into
the challenge and aggregate output records.

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
not prove stale-contributor rejection, transcript-rebinding exclusion,
evidence semantics, release-log semantics, or classifier totality.

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

## FSTL3-7. Classifier Interaction
<a id="fstl3-classifier-interaction"></a>

Collection soundness must feed the unauthorized-output classifier. If an
aggregate output is accepted with bad collection metadata, the classifier must
map it to a unique case rather than leaving it in `eps_cls_unmapped = 0`
without proof. Until classifier totality is proved, `eps_cls_collect` remains
visible.

## FSTL3-8. Acceptance Criteria
<a id="fstl3-acceptance-criteria"></a>

Before `FST-L3` can be treated as proved:

- the production grammar defines active-set and collection encodings;
- the extra-record policy is deterministic;
- every collection validation failure has a unique error or bad-event class;
- active-set equality is proved across all transcript phases;
- stale contributors are rejected by transcript context, not just local set
  validation;
- `eps_collect` is either eliminated or retained as a visible theorem term.

## FSTL3-9. Non-Claims
<a id="fstl3-non-claims"></a>

This worksheet does not prove `eps_collect = 0`. It does not prove
contribution validity, threshold-share soundness, aggregation correctness,
evidence anti-framing, release-log noninterference, or classifier totality. It
does not turn scaffold tests into cryptographic proof.

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
- `BTreeMap`
- `BTreeSet`
- `UnknownValidator`
- `DuplicateValidator`
- `InsufficientCommitments`
- `InsufficientPartialShares`
