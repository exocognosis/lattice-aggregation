# FST-L1..FST-L3 Theorem Closure Batch
<a id="fst-l1-l3-theorem-closure"></a>

Status: foundational theorem-closure batch, not a full cryptographic proof.

This document consolidates the first three signing-side lemmas needed by
`FST-T1-IdealVSS`: transcript injectivity, challenge binding, and collection
soundness. These lemmas are the cleanest proof layer because they reason about
typed grammar, canonical encoding, random-oracle inputs, and deterministic
collection rules before the harder lattice-distribution and contribution-proof
terms are reached.

The batch does not prove production threshold ML-DSA-65 security. It locally
closes subject to listed residuals: malformed, ambiguous, stale, reordered, or
rebound transcript material is either rejected by the production grammar or
charged to a named residual term.

## L13-0. Scope and Non-Claim
<a id="l13-scope-non-claim"></a>

The closure target is:

```text
FST-L1 + FST-L2 + FST-L3:
  Under the pinned production transcript grammar, fixed random-oracle domains,
  canonical collection rules, and explicit commitment/opening assumptions,
  every accepted early signing transcript has one canonical parse, one
  challenge input, and one active-set-consistent collection view, except through
  named residual events.
```

This is not the full `FST-T1-IdealVSS` proof. It does not close `eps_mask`,
`eps_rej`, `eps_withhold`, `eps_contrib_ideal`, `eps_verify`,
`eps_classify`, `eps_vss_ideal`, `implementation_residual`, or
`audit_residual`.

Implementation evidence is not cryptographic proof.

## L13-1. Lemma Dependency Chain
<a id="l13-lemma-dependency-chain"></a>

The dependency chain is:

```text
production-transcript-grammar.md
  -> FST-L1 transcript injectivity
  -> FST-L2 challenge binding
  -> FST-L3 collection soundness
  -> FST-L4/FST-L5/FST-L10 signing-side proof obligations
```

`FST-L1` provides unique parsing and typed-domain separation for every
transcript record. `FST-L2` uses that uniqueness to bind `H_c` to exactly one
`ChallengeRecord`. `FST-L3` uses both facts to show accepted collections are
canonical, active-set-consistent, threshold-valid, duplicate-free, and
session-bound.

## L13-2. Theorem Statements Under Closure
<a id="l13-theorem-statements"></a>

`FST-L1` target:

```text
For every pair of accepted production transcript records R and R',
Enc(R) = Enc(R') implies R = R', unless BadTranscriptCollision,
BadRoDomain, or BadCrossSession occurs.
```

`FST-L2` target:

```text
For every pair of accepted signing views deriving challenge c, either the
canonical ChallengeRecord inputs are identical or the execution is charged to
BadHcPrior, FailPriorHc, eps_ro_replay, eps_commit_context, or
eps_commit_open_set.
```

`FST-L3` target:

```text
Every accepted CommitmentSet, PartialShareSet, AggregateOutputRecord,
EvidenceRecord, and ReleaseSignature collection is canonical, threshold-valid,
duplicate-free, validator-set-bound, session-bound, and active-set-consistent,
or the execution is charged to eps_collect or a classifier-side collection
case.
```

### Batch I Status Accounting
<a id="l13-batch-i-status-accounting"></a>

| Lemma | Batch I status | Residuals retained |
| --- | --- | --- |
| FST-L1 | Locally closeable under pinned grammar/audit assumptions | Byte-level encoder/parser audit, `eps_ro_sep`, `eps_ro_injective_encoding`, `eps_ro_domain_separation`, `BadTranscriptCollision`, `BadRoDomain`, `BadCrossSession`. |
| FST-L2 | Conditional local route | Depends on FST-L1, ROM prior-query/replay accounting, commitment/open-set equality, `eps_ro_prior`, `eps_ro_replay`, `eps_commit_context`, and `eps_commit_open_set`. |
| FST-L3 | Locally closed for collection metadata/canonicalization | Retains `eps_collect`; classifier handoff remains visible as `eps_cls_collect` until `FST-L10` proves totality/disjointness and `eps_cls_unmapped = 0`. |

## L13-3. Shared Definitions
<a id="l13-shared-definitions"></a>

The batch shares these objects:

- `SigningContext`: parameter set, session id, epoch id, block height, attempt,
  threshold, validator-set digest, epoch public key, DKG digest, and message
  binding.
- `ChallengeRecord`: `SigningContext`, `active_set`, ordered mask
  commitments, ordered mask openings, and aggregate public `w1` or digest;
  the `H_c` domain consumes this canonical record and is not an extra
  free-form field inside it.
- `CommitmentSet`: canonical validator-index map of round-one commitments.
- `PartialShareSet`: canonical validator-index map of accepted partial
  contributions.
- `AggregateOutputRecord`: active set, contribution statements, output
  signature bytes, verification result, and release metadata.
- `EvidenceRecord`: accused validator, offending frame, verifier context,
  evidence kind, and error code.
- `ReleaseSignature`: public release record for a finalized aggregate output.

`BTreeMap` and `BTreeSet` are implementation evidence for canonical ordering,
but the proof obligation is the abstract unique-order rule in the production
grammar.

## L13-4. Residual Ledger
<a id="l13-residual-ledger"></a>

The batch carries these terms:

```text
eps_l1_l3
 <= eps_ro_sep
  + eps_ro_injective_encoding
  + eps_ro_domain_separation
  + eps_ro_prior
  + eps_ro_replay
  + eps_commit_context
  + eps_commit_open_set
  + eps_collect
  + eps_cls_collect
```

The classifier interaction remains visible because a malformed but accepting
collection must map to a unique unauthorized-output classifier case before
`eps_cls_unmapped = 0` can be claimed.

No term in this ledger is claimed negligible, zero, or numerically bounded by
this document.

## L13-5. Proof Route
<a id="l13-proof-route"></a>

The proof route is case-based:

1. Same-kind record equality reduces to field-by-field equality under
   fixed-width integers, explicit lengths, tags, counts, labels, and version
   fields.
2. Cross-record replay is rejected by typed labels and random-oracle domain
   separation, or charged to `BadRoDomain`.
3. Cross-session, cross-epoch, cross-attempt, and cross-message reuse is
   rejected by `SigningContext` binding, or charged to `BadCrossSession`.
4. Prior `H_c` queries are charged to `BadHcPrior` / `FailPriorHc`.
5. Commitment-set or opening-set mismatch is charged to `eps_commit_context` or
   `eps_commit_open_set`.
6. Duplicate, unknown, stale, insufficient, malformed, or reordered collection
   records are rejected by canonical collection validation, or charged to
   `eps_collect`.
7. Any accepted collection failure that reaches the final output path must be
   mapped by `FST-L10` to `eps_cls_collect` and cannot remain in
   `eps_cls_unmapped`.

## L13-6. Acceptance Criteria
<a id="l13-acceptance-criteria"></a>

This batch can be treated as locally closed only if:

- [fst-l1-transcript-injectivity.md](fst-l1-transcript-injectivity.md)
  contains a field-level injectivity argument for all record kinds.
- [fst-l2-challenge-binding.md](fst-l2-challenge-binding.md) contains a
  challenge-binding argument with prior-query and commitment-set cases.
- [fst-l3-collection-soundness.md](fst-l3-collection-soundness.md) contains a
  canonical collection argument with duplicate, stale, quorum, active-set,
  evidence, and release cases.
- [production-transcript-grammar.md](production-transcript-grammar.md) remains
  the controlling source grammar.
- [proof-closure-ledger.md](proof-closure-ledger.md) continues to carry all
  unresolved residual terms.

## L13-7. Non-Claims
<a id="l13-non-claims"></a>

This batch does not claim:

- the full `FST-T1-IdealVSS` theorem is proved;
- random-oracle programmability is fully reduced;
- a production commitment scheme is binding or hiding;
- production P2P liveness or slashing soundness is proved;
- `eps_classify` or `eps_cls_unmapped = 0` is closed;
- tests, actor simulations, or Rust collection types are cryptographic proof;
- the repository is production-ready.

## L13-8. Manifest Anchors
<a id="l13-manifest-anchors"></a>

Stable anchors and text markers:

- `# FST-L1..FST-L3 Theorem Closure Batch`
- `fst-l1-l3-theorem-closure`
- `Status: foundational theorem-closure batch, not a full cryptographic proof.`
- `L13-0. Scope and Non-Claim`
- `L13-1. Lemma Dependency Chain`
- `L13-2. Theorem Statements Under Closure`
- `Batch I Status Accounting`
- `L13-3. Shared Definitions`
- `L13-4. Residual Ledger`
- `L13-5. Proof Route`
- `L13-6. Acceptance Criteria`
- `L13-7. Non-Claims`
- `L13-8. Manifest Anchors`
- `FST-L1`
- `FST-L2`
- `FST-L3`
- `ChallengeRecord`
- `CommitmentSet`
- `PartialShareSet`
- `AggregateOutputRecord`
- `EvidenceRecord`
- `ReleaseSignature`
- `eps_ro_sep`
- `eps_ro_prior`
- `eps_commit_open_set`
- `eps_collect`
- `eps_cls_collect`
- `eps_cls_unmapped = 0`
- `implementation evidence is not cryptographic proof`
- `not a full cryptographic proof`
- `not production-ready`
