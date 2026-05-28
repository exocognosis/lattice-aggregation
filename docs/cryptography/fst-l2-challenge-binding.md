# FST-L2 Challenge Binding Worksheet
<a id="fst-l2-challenge-binding"></a>

Date: 2026-05-28

Status: reduction worksheet for `FST-L2`, not a completed challenge-binding
proof.

## FSTL2-0. Scope and Non-Claim
<a id="fstl2-scope-non-claim"></a>

This worksheet expands the `FST-L2` challenge-binding lemma from
[formal-security-theorem.md](formal-security-theorem.md) and
[idealvss-lemma-skeleton.md](idealvss-lemma-skeleton.md). It depends on
`FST-L1` transcript injectivity and the closure routes in
[random-oracle-commitment-closure.md](random-oracle-commitment-closure.md).

This document does not prove random-oracle programmability, commitment
binding, commitment hiding, challenge unbiasability, or replay resistance. It
names the bad events and accounting required before `FST-L2` can be proved.

## FSTL2-1. Theorem Context
<a id="fstl2-theorem-context"></a>

The challenge-binding lemma sits between transcript injectivity and collection
soundness:

```text
FST-L1 + commitment opening equality + H_c prior-query accounting
  -> FST-L2 challenge binding
  -> FST-L3 active-set and collection soundness dependencies
```

The residual term in the IdealVSS lemma skeleton is:

```text
eps_ro_prior + eps_ro_replay + eps_commit_context
```

## FSTL2-2. Inputs and Transcript Records
<a id="fstl2-inputs-transcript-records"></a>

The challenge input is the `ChallengeRecord` from the production grammar:

```text
ChallengeRecord = Enc(
  label,
  version,
  SigningContext,
  OrderedMaskCommitSet,
  OrderedMaskOpenSet,
  aggregate_public_w1_or_digest
)
```

Every accepted `ContributionStatement_i` must contain the digest of the same
challenge and the same `SigningContext`. The binding proof also tracks
`MaskCommitRecord_i`, `MaskOpenStatement_i`, and `SecretCommitRecord_i`.

## FSTL2-3. Challenge-Binding Statement
<a id="fstl2-challenge-binding-statement"></a>

Target lemma:

```text
FST-L2:
  Under FST-L1 and the commitment/RO assumptions, an accepted contribution
  for challenge c is bound to exactly one ChallengeRecord and cannot be reused
  across different sid, t, V, pk_epoch, message_binding, dkg_digest,
  attempt, active set, or commitment set except through a listed bad event.
```

The statement must cover session, message, key, active set, commitment set,
opening set, attempt, epoch, and validator-set binding.

## FSTL2-4. Proof Skeleton
<a id="fstl2-proof-skeleton"></a>

The intended proof uses:

1. `FST-L1` to parse and compare challenge records field by field.
2. Commitment binding to prevent accepted openings from changing after `H_c`.
3. Random-oracle prior-query accounting for programmed challenge inputs.
4. Contribution statement binding to force every accepted partial to the same
   challenge digest.
5. Active-set validation from `FST-L3` to prevent set substitution.

The proof must not silently reprogram `H_c` after the S6 to S7 transition.
Any prior-query conflict is charged before the challenge is fixed.

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
exact `H_c` input before the commitment set was fixed. The simulator branch is
`FailPriorHc` when the proof cannot continue with the existing oracle value.

The replay layer must reject or charge replays across:

- different `epoch_id`;
- different `sid`;
- different `attempt`;
- different `validator_set_digest`;
- different `threshold`;
- different `pk_epoch`;
- different `dkg_digest`;
- different `message_binding`;
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

## FSTL2-7. Dependencies
<a id="fstl2-dependencies"></a>

`FST-L2` depends on:

- `FST-L1` transcript injectivity for `ChallengeRecord`;
- production commitment binding and opening-set equality;
- random-oracle domain separation and prior-query accounting for `H_c`;
- contribution statement context binding;
- `FST-L3` active-set equality across challenge, contribution, and aggregate
  output records.

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

## FSTL2-9. Non-Claims
<a id="fstl2-non-claims"></a>

This worksheet does not prove `eps_ro_prior`, `eps_commit`,
`eps_commit_context`, `eps_commit_open_set`, or `eps_ro_replay` is negligible,
zero, or bounded. It does not claim scaffold commitment digests are production
binding or hiding commitments.

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
