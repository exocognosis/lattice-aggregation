# FST-L2 Challenge Binding Worksheet
<a id="fst-l2-challenge-binding"></a>

Date: 2026-05-28

Status: theorem-closure route for `FST-L2`, conditional on `FST-L1`
transcript injectivity and the random-oracle model; not a completed global
security proof.

## FSTL2-0. Scope and Non-Claim
<a id="fstl2-scope-non-claim"></a>

This document upgrades the `FST-L2` challenge-binding worksheet from
[formal-security-theorem.md](formal-security-theorem.md) and
[idealvss-lemma-skeleton.md](idealvss-lemma-skeleton.md). It depends on
`FST-L1` transcript injectivity and the closure routes in
[random-oracle-commitment-closure.md](random-oracle-commitment-closure.md).

The claim boundary is deliberately narrow: this is a formal closure route for
challenge binding under canonical transcript injectivity and the
random-oracle model. It does not complete the global security proof. It does
not prove random-oracle programmability, production commitment binding,
commitment hiding, challenge unbiasability, or replay resistance. It names the
bad events and accounting required before `FST-L2` can be treated as closed in
a production theorem route, conditional on the listed residuals.

## FSTL2-1. Theorem Context
<a id="fstl2-theorem-context"></a>

The challenge-binding lemma sits between transcript injectivity and collection
soundness:

```text
FST-L1 + commitment opening equality + H_c prior-query accounting
  -> FST-L2 challenge binding
  -> FST-L3 active-set and collection soundness dependencies
```

The residual term in the IdealVSS lemma skeleton remains visible:

```text
eps_ro_prior + eps_ro_replay + eps_commit_context
```

with the commitment-context component retaining the explicit subterm:

```text
eps_commit_open_set
```

## FSTL2-2. Inputs and Transcript Records
<a id="fstl2-inputs-transcript-records"></a>

The challenge input is `H_c(ChallengeRecord)`, where `ChallengeRecord` is the
canonical record from
[production-transcript-grammar.md](production-transcript-grammar.md):

```text
ChallengeRecord = Enc(
  "lattice-aggregation/threshold-mldsa65/challenge",
  version,
  SigningContext,
  active_set,
  OrderedMaskCommitSet,
  OrderedMaskOpenSet,
  aggregate_public_w1_or_digest
)
```

The `H_c` random-oracle domain consumes this canonical record; it is not an
extra top-level field inside the record. `SigningContext` binds message
binding, epoch key, DKG digest, threshold, validator-set digest, session, and
attempt. `version`, `active_set`, the ordered commitment/opening sets, and
`aggregate_public_w1_or_digest` are the remaining top-level canonical record
fields. Downstream proof text must refer to those bound fields through
`SigningContext` or the listed record fields, rather than appending
`transcript_grammar_version`, `message_digest`, `epoch_key_or_digest`, or
`attempt_id` as separate free-form challenge inputs.

Every accepted `ContributionStatement_i` must contain the digest of the same
challenge and the same `SigningContext`. The binding proof also tracks
`MaskCommitRecord_i`, `MaskOpenStatement_i`, and `SecretCommitRecord_i`.

## FSTL2-3. Challenge-Binding Statement
<a id="fstl2-challenge-binding-statement"></a>

Theorem statement:

```text
FST-L2:
  Fix the transcript grammar version and the random-oracle domain H_c.
  Under FST-L1 transcript injectivity, canonical encoding of
  ChallengeRecord, and the random-oracle model, let View and View' be two
  accepting transcript views that derive the same signing challenge c from H_c.

  Then either:
    (1) View and View' contain identical canonical ChallengeRecord inputs to H_c;
        or
    (2) the execution triggers a named bad event charged to the FST-L2
        residual accounting.
```

The identical-input conclusion covers equality of `SigningContext`,
commitment set, opening set, active set, aggregate public `w1` or digest,
message binding, epoch key/digest, attempt, transcript grammar version, and
the `H_c` random-oracle domain.
Equivalently, an accepted contribution for challenge `c` is bound to exactly
one canonical `ChallengeRecord` and cannot be reused across different session,
threshold, validator set, epoch key, message binding, DKG/epoch digest, retry
attempt, active set, commitment set, or opening set except through a listed
bad event.

The residual events kept visible for this theorem-closure route are
`BadHcPrior`, `FailPriorHc`, transcript-collision events covered by `FST-L1`,
replay events charged to `eps_ro_replay`, and commitment-context events
charged to `eps_commit_context`, including `eps_commit_open_set`.

## FSTL2-4. Proof Skeleton
<a id="fstl2-proof-skeleton"></a>

The proof argues by comparing the two accepting transcript views at the
canonical `ChallengeRecord` input to `H_c`.

1. `FST-L1` to parse and compare challenge records field by field.
2. Commitment binding to prevent accepted openings from changing after `H_c`.
3. Random-oracle prior-query accounting for programmed challenge inputs.
4. Contribution statement binding to force every accepted partial to the same
   challenge digest.
5. Active-set validation from `FST-L3` to prevent set substitution.

The proof must not silently reprogram `H_c` after the S6 to S7 transition.
Any prior-query conflict is charged before the challenge is fixed.

Case analysis:

1. Prior-query event. If the adversary queried the exact candidate
   `ChallengeRecord` input to `H_c` before the commitment/opening context was
   fixed, the execution is charged to `BadHcPrior`. If the simulator cannot
   continue while preserving the already-returned oracle value, it raises
   `FailPriorHc`. The loss remains in `eps_ro_prior`; this document does not
   instantiate a concrete query-bound parameterization.

2. Transcript collision. If the two views have distinct byte strings that
   parse to the same canonical fields, or the same bytes that parse to
   different fields, the event contradicts the `FST-L1` transcript-injectivity
   premise. This route therefore discharges the case only conditionally on
   `FST-L1`; any residual from `FST-L1` remains outside this document.

3. Commitment-set mismatch. If the ordered commitment set differs while the
   challenge is accepted as the same `c`, then either the canonical
   `ChallengeRecord` inputs differ and the random-oracle equality is a
   collision/prior-query case, or the commitment backend admits a context
   rebind/equivocation. The latter is charged to `eps_commit_context`, with
   open-set equality obligations kept visible as `eps_commit_open_set`.

4. Active-set mismatch. If the active signer set differs, `FST-L1` exposes a
   different canonical `active_set` field. Acceptance under the same challenge
   is therefore rejected by active-set validation or routed to the residual
   dependency that `FST-L3` closes for active-set and collection-soundness
   equality.

5. Message or context rebinding. If the views differ in `SigningContext`,
   message binding, session, threshold, validator-set digest, epoch key/digest,
   DKG digest, contribution backend, relation, or statement schema, then the
   canonical `ChallengeRecord` inputs differ. An accepting same-challenge use
   is charged to `eps_commit_context` when the mismatch is mediated by a
   commitment-context rebind, or to the relevant random-oracle prior/replay
   accounting otherwise.

6. Stale or replay records. If an old record is reused across `epoch_id`,
   `sid`, `attempt`, validator-set digest, threshold, epoch key/digest,
   DKG digest, message binding, ordered commitment set, or ordered opening set,
   the canonical tuple changes. A non-rejected accepting replay is charged to
   `eps_ro_replay` or, when the replay is enabled by commitment-context
   ambiguity, `eps_commit_context`.

7. Malformed encoding. If a view relies on non-canonical field order, duplicate
   entries, ambiguous lengths, an unsupported transcript grammar version, or
   an incorrect `H_c` domain, it is rejected by the parser. If it is not
   rejected and still aliases a valid canonical record, the event is a
   transcript-injectivity failure under `FST-L1`.

Outside the named bad events, both accepting views have the same canonical
`ChallengeRecord` input to `H_c`, so they bind to the same challenge input
tuple.

## FSTL2-5. Prior-Query and Replay Accounting
<a id="fstl2-prior-query-replay-accounting"></a>

The random-oracle accounting layer is:

```text
eps_ro_prior
  <= Pr[BadHmuPrior]
   + Pr[BadHwPrior]
   + Pr[BadHcPrior]
   + Pr[BadHvssPrior]
   + Pr[BadHcontribPrior]
   + Pr[BadCrossSession]
```

For `FST-L2`, the critical event is `BadHcPrior`: the adversary queried the
exact `H_c` input before the commitment and opening context was fixed. The
simulator branch is `FailPriorHc` when the proof cannot continue with the
existing oracle value.

The replay layer must reject or charge replays across:

- different `epoch_id`;
- different `sid`;
- different `attempt`;
- different `validator_set_digest`;
- different `threshold`;
- different `pk_epoch`;
- different `dkg_digest`;
- different message binding;
- different ordered mask commitment or opening set;
- different contribution backend, relation, or statement schema.

Any accepting replay that is not rejected must be charged to `eps_ro_replay`,
`eps_commit_context`, `eps_contrib_context`, or `eps_classify`.

## FSTL2-6. Commitment-Set Equality Obligations
<a id="fstl2-commitment-set-equality-obligations"></a>

Commitment-side accounting is:

```text
eps_commit_context
  <= eps_commit_open_set
   + eps_commit_context_rebind
   + eps_commit_equivocate
```

The proof must show:

- the ordered mask commitment set is fixed before `H_c`;
- the opened set used by contribution validation equals the challenged set or
  mismatches are rejected;
- a secret contribution frame is accepted only if its challenge digest matches
  the accepted `ChallengeRecord`;
- retry attempts use a fresh `attempt` context and cannot reuse prior
  commitments as valid current-attempt commitments;
- `eps_commit_open_set` is either closed by the backend theorem or remains
  visible.

For theorem closure, the commitment proof must supply two production-facing
facts that are not established here: the concrete commitment scheme binds
openings to the challenged commitment records, and the ordered opening-set
equality check is itself bound to the same `SigningContext`, `active_set`,
grammar version, ordered commitment/opening sets, and `H_c(ChallengeRecord)`
domain. Message binding, epoch key/digest, and attempt are compared through
the canonical `SigningContext`, not as separate free-form challenge inputs.

## FSTL2-7. Dependencies
<a id="fstl2-dependencies"></a>

`FST-L2` depends on:

- `FST-L1` transcript injectivity for `ChallengeRecord`;
- production commitment binding and opening-set equality;
- random-oracle domain separation and prior-query accounting for `H_c`;
- contribution statement context binding;
- `FST-L3` active-set equality across challenge, contribution, and aggregate
  output records.

The dependencies are used only to close the local challenge-binding route.
They do not by themselves prove collection soundness, aggregate correctness,
or end-to-end signature security.

## FSTL2-8. Acceptance Criteria
<a id="fstl2-acceptance-criteria"></a>

Before `FST-L2` can be treated as proved:

- `FST-L1` is proved or its residual is visible;
- the commitment backend or ideal commitment assumption is selected;
- `H_c` prior-query losses are parameterized by sessions, attempts,
  validators, oracle queries, and retries;
- contribution statements bind to `ChallengeRecord`;
- replay cases are rejected or assigned to exactly one residual term;
- no claim is made that SHAKE256 labels alone close the ROM proof.

What remains open for production is exact and limited:

- a concrete commitment scheme proof covering binding, context binding, and
  ordered opening-set equality for the deployed commitment grammar;
- query-bound parameterization of `eps_ro_prior`, especially `BadHcPrior` and
  `FailPriorHc`, across sessions, attempts, validators, retries, and
  random-oracle queries;
- query-bound parameterization of `eps_ro_replay` for stale records and
  accepted cross-context replays.

## FSTL2-9. Non-Claims
<a id="fstl2-non-claims"></a>

This document does not provide a completed random-oracle-model reduction. It
does not prove `eps_ro_prior`, `eps_commit`, `eps_commit_context`,
`eps_commit_open_set`, or `eps_ro_replay` is negligible, zero, or concretely
bounded. It does not claim scaffold commitment digests are production binding
or hiding commitments.

Implementation evidence, parser tests, transcript fixtures, and SHAKE256
domain labels are useful engineering checks, but they are not cryptographic
proofs. No production commitment proof is claimed here, and no implementation
test result should be read as closing the commitment or random-oracle
residuals.

## FSTL2-10. Manifest Anchors
<a id="fstl2-manifest-anchors"></a>

- `# FST-L2 Challenge Binding Worksheet`
- `fst-l2-challenge-binding`
- `FSTL2-0. Scope and Non-Claim`
- `FSTL2-1. Theorem Context`
- `FSTL2-2. Inputs and Transcript Records`
- `FSTL2-3. Challenge-Binding Statement`
- `FSTL2-4. Proof Skeleton`
- `FSTL2-5. Prior-Query and Replay Accounting`
- `FSTL2-6. Commitment-Set Equality Obligations`
- `FSTL2-7. Dependencies`
- `FSTL2-8. Acceptance Criteria`
- `FSTL2-9. Non-Claims`
- `FST-L2`
- `ChallengeRecord`
- `SigningContext`
- `MaskCommitRecord_i`
- `MaskOpenStatement_i`
- `SecretCommitRecord_i`
- `ContributionStatement_i`
- `H_c`
- `eps_ro_prior`
- `eps_ro_replay`
- `eps_commit_context`
- `eps_commit_open_set`
- `BadHcPrior`
- `FailPriorHc`
- `BadCrossSession`
