# Simulator Hybrid Reductions Worksheet
<a id="simulator-hybrid-reductions"></a>

Status: reduction worksheet, not a completed proof.

Date: 2026-05-27

## SHR-0. Scope and Non-Claim

This document expands the simulator skeleton in
[real-ideal-simulator.md](real-ideal-simulator.md) into a reduction-oriented
hybrid worksheet for the real/ideal theorem target in
[formal-security-theorem.md](formal-security-theorem.md). It restates the S0..S8
hybrids and records the transition lemmas, bad events, reduction targets, and
advantage terms that a later proof must instantiate.

This is a reduction worksheet, not a completed proof. It does not prove
ML-DSA-65 unforgeability, malicious-secure VSS/DKG, contribution-proof
soundness, commitment security, random-oracle programmability, rejection
sampling equivalence, abort compatibility, or evidence noninterference for the
current repository.

The worksheet assumes the first proof setting from the surrounding documents:
static active corruption of at most `t - 1` validators before DKG, rushing and
scheduling control from
[active-adversary-model.md](active-adversary-model.md), random-oracle domains
from [random-oracle-game.md](random-oracle-game.md), and the ideal functionality
`F_TMLDSA` from [ideal-functionality.md](ideal-functionality.md).

## SHR-1. Hybrid Restatement S0..S8

The simulator proof is organized as the following game sequence.

| Hybrid | Restatement | Primary difference from previous hybrid |
| --- | --- | --- |
| S0 | Real production protocol with real DKG, real commitments, real partial shares, real aggregation, real aborts, real evidence surfaces, and adversarial scheduling. | Starting game. |
| S1 | Same public protocol trace, but the simulator mediates delivery and scheduling while preserving every adversary-visible message, omission, duplication, delay, and release decision allowed by the active network model. | Network scheduling is abstracted. |
| S2 | Malformed, duplicate, replayed, equivocated, and invalid public messages are mapped to ideal evidence events when the public transcript supports attribution. | Evidence replaces rejected public fault handling. |
| S3 | DKG is replaced with a simulated public DKG transcript and one ideal `RegisterKey(key_id, t, V, pk)` call. Corrupted dealers' visible behavior is preserved. | VSS/DKG internals are simulated. |
| S4 | Honest masking commitments, openings, and commitment proofs are replaced by simulated commitment transcripts, with `H_w` answered or programmed consistently. | Honest commitment witnesses are removed. |
| S5 | Honest partial-share frames and contribution proofs are replaced by simulated proof-bound frames that verify under the accepted context. | Honest share witnesses are removed from signing. |
| S6 | Challenge derivation is replaced by global lazy random-oracle tables for `H_mu`, `H_w`, `H_c`, `H_vss`, and `H_contrib`, with prior-query conflicts recorded as bad events. | Oracle programming is made explicit. |
| S7 | Accepting aggregate signatures for authorized messages are replaced by signatures released through `F_TMLDSA`. Abort and retry behavior remains transcript-preserving. | Authorized output is idealized. |
| S8 | Ideal execution with `F_TMLDSA`, simulated DKG/signing/evidence trace, and extraction or reduction for every unauthorized accepting aggregate output. | Final ideal game. |

## SHR-2. Transition Lemmas

### Lemma SHR-L1, S0 to S1 Scheduling Abstraction

Claim target: `S0` and `S1` are indistinguishable if the simulator preserves the
same authenticated wire frames, relative adversarial choices, delivered honest
messages, omissions, duplications, timeout notifications, and release policy
outputs that the real active network exposes.

Reduction target or assumption: active-adversary network model equivalence and
canonical message authentication from
[active-adversary-model.md](active-adversary-model.md).

Bad events:

- `BadSchedAuth`: an unauthenticated or context-free frame is accepted in one
  game but not the other.
- `BadSchedFairness`: the simulator adds liveness, fairness, or delivery that
  the real network model does not guarantee.
- `BadSchedOrder`: canonical transcript state depends on arrival order rather
  than typed ordered fields.

Transition bound placeholder:

```text
|Pr[Z(S0)=1] - Pr[Z(S1)=1]| <= Adv_sched(A,Z) + Pr[BadSchedAuth or BadSchedFairness or BadSchedOrder]
```

### Lemma SHR-L2, S1 to S2 Evidence Replacement

Claim target: replacing rejected malformed, duplicate, replayed, equivocated,
or invalid public messages with ideal evidence events does not change the
environment view except when the evidence predicate is unsound, frameable, or
leaks non-public state.

Reduction target or assumption: evidence noninterference, evidence soundness,
anti-framing, canonical transcript binding, commitment binding for signing
frames, VSS binding for DKG frames, and contribution-proof context binding.

Bad events:

- `BadEvidenceSound`: an ideal evidence event is emitted without a public real
  verification predicate that would reject the same frame.
- `BadEvidenceFrame`: an honest validator can be attributed for a frame it did
  not authenticate in the exact typed context.
- `BadEvidenceLeak`: evidence reveals honest secret shares, honest one-time
  masks, unopened complaint material, or rejection-sampling internals.
- `BadReplayCredit`: a replayed frame is credited in a distinct session,
  message, validator set, public key, challenge, commitment set, or DKG digest.

Transition bound placeholder:

```text
Delta_12 <= Adv_evidence_noninterference(A,Z)
          + Adv_transcript_binding(A)
          + Adv_commit_bind(A)
          + Adv_vss_bind(A)
          + Adv_contrib_bind(A)
```

### Lemma SHR-L3, S2 to S3 DKG/VSS Simulation

Claim target: simulated DKG public transcripts and ideal registration of
`(key_id, t, V, pk)` are indistinguishable from real DKG output for static
active corruptions below threshold, while preserving corrupted dealer and
receiver behavior.

Reduction target or assumption: VSS binding, VSS hiding, VSS extractability,
DKG output agreement, DKG key-bias resistance, complaint soundness,
anti-framing, and threshold-share secrecy as described in
[vss-dkg-security-plan.md](vss-dkg-security-plan.md).

Bad events:

- `BadVssBind`: one accepted dealer transcript opens to two different
  degree-`< t` polynomials or key contributions.
- `BadVssHide`: fewer than `t` corrupt validators distinguish honest dealer
  secrets or shares beyond the public key distribution.
- `BadVssExtract`: an accepted dealer transcript has no unique extractable
  polynomial and is not rejected with public evidence.
- `BadDkgAgree`: honest validators finalize different accepted-dealer sets,
  transcript digests, shares, or public keys.
- `BadDkgBias`: the rushing adversary biases the joint key distribution beyond
  the selected DKG theorem.

Transition bound placeholder:

```text
Delta_23 <= Adv_vss_bind(A) + Adv_vss_hide(A) + Adv_vss_extract(A)
          + Adv_dkg_agreement(A) + Adv_dkg_key_bias(A)
          + Adv_complaint_soundness(A)
```

### Lemma SHR-L4, S3 to S4 Commitment Simulation

Claim target: replacing honest signing commitments and openings with simulated
commitment transcripts is indistinguishable until an adversary breaks
commitment hiding, commitment binding, or the simulator's `H_w` programming
preconditions.

Reduction target or assumption: commitment hiding, commitment binding, and
random oracle programming for `H_w`.

Bad events:

- `BadCommitHide`: the adversary distinguishes simulated honest commitments
  from real honest commitments.
- `BadCommitBind`: one accepted commitment admits two different openings or
  masking statements after `H_c` is known.
- `BadHwPrior`: the adversary queried the exact `H_w` programming input before
  the simulator fixed the target value and the proof cannot use the existing
  value.
- `BadCommitEquiv`: a corrupted signer equivocates in a way accepted as one
  honest-consistent commitment without public evidence.

Transition bound placeholder:

```text
Delta_34 <= Adv_commit_hide(A) + Adv_commit_bind(A)
          + Adv_ro_program_Hw(A) + Pr[BadHwPrior]
```

### Lemma SHR-L5, S4 to S5 Partial and Contribution-Proof Simulation

Claim target: simulated honest partial-share frames and contribution proofs are
indistinguishable from real honest partial-share frames, and every accepted
corrupted contribution is bound to one validator, one session, one challenge,
one commitment, one DKG digest, and one public key.

Reduction target or assumption: contribution-proof zero-knowledge or
witness-hiding, contribution-proof soundness and extractability, VSS
extractability for signer shares, random oracle programming for `H_contrib`,
and partial-share validity from [formal-security-theorem.md](formal-security-theorem.md).

Bad events:

- `BadContribHide`: a simulated honest contribution proof is distinguishable
  from a real honest proof.
- `BadContribSound`: an invalid partial verifies under the production
  contribution relation.
- `BadContribExtract`: an accepted corrupted contribution cannot be extracted
  or tied to the committed share metadata required by the proof.
- `BadContribPortable`: a proof or partial generated for one typed context
  verifies in another.
- `BadHcontribPrior`: a prior `H_contrib` query prevents required programming.

Transition bound placeholder:

```text
Delta_45 <= Adv_contrib_zk_or_hiding(A) + Adv_contrib_sound(A)
          + Adv_contrib_extract(A) + Adv_vss_extract(A)
          + Adv_ro_program_Hcontrib(A) + Pr[BadHcontribPrior]
```

### Lemma SHR-L6, S5 to S6 Random-Oracle Table Exposure

Claim target: replacing implicit challenge derivations with explicit global
lazy random-oracle tables is indistinguishable except for transcript collisions,
domain-separation failures, or prior-query/programming conflicts.

Reduction target or assumption: random oracle programming for `H_mu`, `H_w`,
`H_c`, `H_vss`, and `H_contrib`; transcript injectivity; domain separation; and
challenge binding from [random-oracle-game.md](random-oracle-game.md).

Bad events:

- `BadRoDomain`: two oracle domains are not independent because encodings are
  not prefix-free or labels collide.
- `BadHmuPrior`: the message-binding value must be programmed after a prior
  adversarial query fixed it inconsistently.
- `BadHcPrior`: the accepted `H_c(sid, t, V, pk, m or mu, Com)` input was
  queried before the simulator fixed the commitment set and the proof cannot
  continue with the sampled value.
- `BadTranscriptCollision`: two distinct typed transcript tuples produce the
  same accepted challenge input.
- `BadCrossSession`: a programmed oracle value is reused across concurrent
  sessions, retries, validator sets, public keys, messages, or DKG digests.

Transition bound placeholder:

```text
Delta_56 <= Adv_ro_program(A) + Adv_domain_sep(A)
          + Adv_transcript_injective(A)
          + Pr[BadHmuPrior or BadHcPrior or BadCrossSession]
```

### Lemma SHR-L7, S6 to S7 Authorized Signature Replacement

Claim target: replacing accepting threshold aggregate signatures on authorized
messages with signatures released by `F_TMLDSA` preserves the view if accepted
threshold signatures have the standard ML-DSA-65 distribution and abort
transcripts reveal no extra information beyond the ideal leakage profile.

Reduction target or assumption: ML-DSA distributional equivalence,
rejection-sampling bound, abort compatibility, aggregation correctness,
commit-before-challenge ordering, and evidence noninterference from
[rejection-sampling-hybrid-proof.md](rejection-sampling-hybrid-proof.md).

Bad events:

- `BadRejectDist`: the accepted threshold signature distribution differs from
  centralized ML-DSA-65 beyond the stated rejection-sampling bound.
- `BadAbortBias`: selective aborts, retries, malformed commitments, or omitted
  partials bias accepted signatures beyond the allowed bound.
- `BadAggCorrect`: an aggregate is accepted but does not correspond to the
  centralized ML-DSA verification relation for `(pk, m)`.
- `BadReleaseLeak`: replacing a real aggregate with an ideal signature changes
  release, timing, retry, or evidence leakage beyond the ideal functionality.
- `BadEvidenceReject`: rejection-sampling failure is exposed as slashable
  evidence rather than an ordinary retry or abort condition.

Transition bound placeholder:

```text
Delta_67 <= Adv_rejection_sampling(A,Z)
          + Adv_abort_bias(A,Z)
          + Adv_aggregation_correctness(A)
          + Adv_evidence_noninterference(A,Z)
```

### Lemma SHR-L8, S7 to S8 Unauthorized Output Extraction

Claim target: in the final ideal execution, every accepting aggregate signature
for an unauthorized message yields either an ML-DSA EUF-CMA forgery or a
violation of a listed threshold, VSS, commitment, contribution-proof,
random-oracle, or evidence assumption.

Reduction target or assumption: ML-DSA EUF-CMA, threshold-share soundness,
VSS binding/hiding/extractability, commitment binding/hiding,
contribution-proof soundness/extractability, random-oracle challenge binding,
canonical collection validation, and evidence noninterference.

Bad events:

- `BadUnauthorizedAccept`: `MLDSA65.Verify(pk, m*, sigma*) = accept` for an
  unauthorized `m*`.
- `BadThresholdShare`: fewer than `t` corrupt validators produce enough
  honest-consistent signing material without an ideal signing authorization.
- `BadRogueSigner`: an unknown, duplicate, unverified, or out-of-set validator
  is counted toward an accepting aggregate.
- `BadExtractFail`: the simulator cannot map an accepting output to an
  authorized ideal release, an ML-DSA forgery, or a concrete assumption break.
- `BadIdealMismatch`: `F_TMLDSA` rejects a release that the real protocol would
  accept without one of the preceding bad events.

Transition bound placeholder:

```text
Delta_78 <= Adv_MLDSA_EUF_CMA(B_mldsa)
          + Adv_threshold_share(B_share)
          + Adv_vss_bind_extract(B_vss)
          + Adv_commit_bind(B_commit)
          + Adv_contrib_sound_extract(B_contrib)
          + Adv_ro_challenge_binding(B_ro)
          + Adv_collection_validation(B_coll)
          + Adv_evidence_noninterference(B_evid)
```

## SHR-3. Explicit Simulator Failure Events

The simulator must halt, switch to a reduction, or charge the advantage
decomposition when any of the following events occurs.

| Event | Meaning | Charged to |
| --- | --- | --- |
| `FailThresholdCompromise` | `|C| >= t` in a theorem that only claims static corruption below threshold. | Outside theorem scope or threshold-share assumption. |
| `FailPriorHmu` | `H_mu` was queried before message binding and prevents required programming. | Random oracle programming for `H_mu`. |
| `FailPriorHw` | `H_w` was queried before simulated commitment programming. | Random oracle programming for `H_w`; commitment hiding. |
| `FailPriorHc` | Accepted challenge input was queried before commitments were fixed. | Random oracle programming for `H_c`; challenge binding. |
| `FailPriorHvss` | VSS proof challenge was fixed before the simulated DKG statement was committed. | Random oracle programming for `H_vss`; VSS simulation. |
| `FailPriorHcontrib` | Contribution proof challenge was fixed before the simulated proof statement was committed. | Random oracle programming for `H_contrib`; contribution-proof simulation. |
| `FailVssExtract` | Accepted VSS/DKG transcript lacks a unique extractable share polynomial. | VSS extractability or binding. |
| `FailDkgBias` | Simulated DKG public key distribution cannot match the real DKG distribution. | DKG key-bias resistance. |
| `FailCommitEquivocation` | A commitment can be opened to two accepted masking statements. | Commitment binding. |
| `FailCommitLeak` | Simulated honest commitments reveal a distributional difference. | Commitment hiding. |
| `FailContribExtract` | Accepted partial contribution cannot be tied to the signer share and context. | Contribution-proof extractability or VSS extractability. |
| `FailContribPortable` | A contribution verifies outside its typed context. | Random-oracle domain separation or contribution-proof binding. |
| `FailRejectDistribution` | Accepted threshold signatures deviate from standard ML-DSA signatures. | Rejection-sampling bound. |
| `FailAbortBias` | Selective abort or retry behavior biases final signatures or leaks extra state. | Abort compatibility and rejection-sampling analysis. |
| `FailEvidenceLeak` | Evidence exposes honest secrets, masks, complaint witnesses, or rejection internals. | Evidence noninterference. |
| `FailEvidenceFrame` | Honest parties can be framed by omitted, reordered, replayed, or rebound frames. | Evidence anti-framing and transcript binding. |
| `FailUnauthorizedAccept` | The adversary outputs a valid unauthorized aggregate signature. | ML-DSA EUF-CMA or a threshold-assumption violation. |
| `FailExtractionGap` | The simulator cannot classify an accepting output as authorized or as one listed assumption break. | Missing reduction. |

## SHR-4. Advantage Decomposition

Let `Exec_i` denote the environment's output bit in hybrid `Si`. The intended
real/ideal distinguishing advantage is bounded by a telescoping sum:

```text
Adv_real_ideal(A,Z) =
    |Pr[Exec_0 = 1] - Pr[Exec_8 = 1]|
 <= Delta_01 + Delta_12 + Delta_23 + Delta_34
  + Delta_45 + Delta_56 + Delta_67 + Delta_78.
```

The transition terms are placeholders until concrete reductions and theorem
bounds are supplied:

```text
Delta_01 = scheduling abstraction and authenticated network equivalence
Delta_12 = evidence soundness, anti-framing, and noninterference
Delta_23 = VSS/DKG binding, hiding, extractability, agreement, and key-bias resistance
Delta_34 = commitment binding/hiding plus H_w programming loss
Delta_45 = contribution-proof hiding, soundness, extractability, and H_contrib programming loss
Delta_56 = random-oracle programming, domain separation, transcript injectivity, and prior-query loss
Delta_67 = rejection-sampling bound, abort compatibility, aggregation correctness, and release leakage
Delta_78 = ML-DSA EUF-CMA or listed threshold-assumption violations for unauthorized outputs
```

Equivalently, later proof work should instantiate a bound of the following
shape:

```text
Adv_real_ideal(A,Z)
 <= Adv_MLDSA_EUF_CMA(B_mldsa)
  + Adv_ro_program(B_ro)
  + Adv_vss_bind_hide_extract(B_vss)
  + Adv_commit_bind_hide(B_commit)
  + Adv_contrib_sound_hide_extract(B_contrib)
  + Adv_rejection_sampling(B_reject)
  + Adv_evidence_noninterference(B_evid)
  + Adv_network_sched(B_sched)
  + Adv_collection_transcript(B_transcript)
  + negl(lambda).
```

Every term must be parameterized by the number of sessions, oracle queries,
validators, corruptions, retries, evidence records, and aggregate verification
attempts allowed by the final theorem.

## SHR-5. Hardest Remaining Reductions

The hardest remaining reductions are:

- DKG/VSS simulation: S2 to S3 needs a concrete malicious-secure VSS/DKG
  theorem with binding, hiding, extractability, complaint anti-framing,
  agreement, and key-bias resistance.
- Honest partial simulation: S4 to S5 needs a real contribution relation that
  is simulatable for honest shares while extractable and sound for corrupted
  shares.
- Random-oracle prior queries: S5 to S6 must quantify all losses from
  adversarial prior queries to `H_mu`, `H_w`, `H_c`, `H_vss`, and `H_contrib`
  across concurrent sessions and retries.
- Rejection-sampling distribution: S6 to S7 must prove that accepted threshold
  aggregate signatures are distributed as standard ML-DSA-65 signatures, with a
  concrete rejection-sampling bound.
- Selective aborts: S6 to S7 must separate denial-of-service from
  distributional bias and prove that retry, timing, evidence, and release
  leakage are simulatable.
- Unauthorized output extraction: S7 to S8 must give a complete classifier that
  turns every unauthorized accepting output into an ML-DSA EUF-CMA forgery or a
  precise threshold-assumption violation.
- Evidence noninterference: S1 to S2 and S6 to S7 must prove that public
  evidence neither leaks honest secrets nor creates new signing capability or
  framing attacks.

## SHR-6. Checklist for Later Proof Completion

Before this worksheet can become a completed proof, later work must replace
each placeholder with:

- a formally stated game or experiment;
- the exact reduction algorithm;
- the reduction's success probability and runtime loss;
- a bound in `lambda` and in concrete protocol counters;
- the bad-event probability and where it is charged;
- the exact production protocol relation, encoding, and oracle inputs used by
  the reduction;
- a statement of which repository implementation tests are conformance checks
  and which are not cryptographic evidence.

Until then, this document remains a reduction worksheet, not a completed proof.
