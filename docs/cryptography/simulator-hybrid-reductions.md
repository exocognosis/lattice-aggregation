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
For the setup phase it may cite the ideal setup assumption `F_VSS_DKG` from
[vss-idealization-and-selection.md](vss-idealization-and-selection.md), but only
as an explicit proof-decomposition placeholder.

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

## SHR-1A. Worksheet Advantage Terms

The following symbols name the losses used below. They are theorem obligations,
not established bounds.

```text
eps_sched(A,Z)      scheduling and authenticated-network trace loss
eps_evid(A,Z)       evidence soundness, anti-framing, and noninterference loss
eps_vss_ideal(A,Z)  loss from replacing DKG/VSS with ideal F_VSS_DKG setup
eps_commit(A,Z)     commitment binding, hiding, equivocation, and H_w loss
eps_contrib(A,Z)    contribution-proof simulation, soundness, and extraction loss
eps_ro_prior(A,Z)   prior-query and programming loss for H_mu,H_w,H_c,H_vss,H_contrib
eps_ro_sep(A,Z)     random-oracle domain separation and transcript-injectivity loss
eps_reject(A,Z)     accepted-signature distribution loss from rejection sampling
eps_abort(A,Z)      selective-abort, retry, withholding, and abort-label loss
eps_release(A,Z)    release-policy, idempotence, timing, and public-leakage mismatch
eps_collect(A,Z)    canonical collection validation and rogue-signer loss
eps_threshold(A,Z)  subthreshold-share signing or share-secrecy violation
eps_mldsa(B)        base ML-DSA-65 SUF/EUF-CMA forgery advantage
eps_classify(A,Z)   residual extraction-classifier gap not assigned elsewhere
```

The intended dependencies are:

- `eps_vss_ideal` depends on the ideal VSS/DKG guarantees of `F_VSS_DKG`:
  binding and extractability, hiding below threshold, output agreement,
  complaint soundness, anti-framing, key-bias resistance, and transcript
  binding.
- `eps_ro_prior` depends on the prior-query events required by
  [random-oracle-game.md](random-oracle-game.md), especially accepted
  `H_c` inputs queried before commitment finalization.
- `eps_reject` expands through
  [rejection-sampling-bounds.md](rejection-sampling-bounds.md) as
  `eps_rs_mask + eps_rs_commit + eps_rs_rej + eps_rs_withhold + eps_rs_ro
  + eps_rs_verify`, corresponding to that worksheet's `eps_mask`,
  `eps_commit`, `eps_rej`, `eps_withhold`, `eps_ro`, and `eps_verify` terms.
- `eps_contrib` depends on a production contribution relation that is
  simulatable for honest shares, sound and extractable for corrupted shares,
  and bound to `H_contrib`.
- `eps_evid` depends on the evidence leakage profile of `F_TMLDSA` and the
  active-adversary evidence model.
- `eps_mldsa` is the base ML-DSA-65 forgery term for any unauthorized
  accepting standard signature not explained by a threshold-side violation.

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

Worksheet transition bound:

```text
Delta_01 = |Pr[Exec_0=1] - Pr[Exec_1=1]|
Delta_01 <= eps_sched(A,Z)
          <= Adv_sched(A,Z)
           + Pr[BadSchedAuth or BadSchedFairness or BadSchedOrder]
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

Worksheet transition bound:

```text
Delta_12 <= eps_evid(A,Z)
eps_evid(A,Z) <= Adv_evidence_noninterference(A,Z)
               + Adv_evidence_soundness(A,Z)
               + Adv_evidence_antiframe(A,Z)
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

Reduction target or assumption: the ideal VSS/DKG setup functionality
`F_VSS_DKG`, or a later concrete backend proving VSS binding, VSS hiding, VSS
extractability, DKG output agreement, DKG key-bias resistance, complaint
soundness, anti-framing, transcript binding, and threshold-share secrecy as
described in [vss-dkg-security-plan.md](vss-dkg-security-plan.md) and
[vss-idealization-and-selection.md](vss-idealization-and-selection.md).

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

Worksheet transition bound:

```text
Delta_23 <= eps_vss_ideal(A,Z)
eps_vss_ideal(A,Z)
  <= Adv_F_VSS_DKG_realization(B_vss)
   + Adv_vss_bind(B_vss)
   + Adv_vss_hide(B_vss)
   + Adv_vss_extract(B_vss)
   + Adv_dkg_agreement(B_vss)
   + Adv_dkg_key_bias(B_vss)
   + Adv_complaint_soundness(B_vss)
   + Adv_vss_antiframe(B_vss)
```

If the proof remains inside the ideal setup model, the
`Adv_F_VSS_DKG_realization` term is not claimed negligible; it is an explicit
assumption boundary.

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

Worksheet transition bound:

```text
Delta_34 <= eps_commit(A,Z) + eps_ro_prior(A,Z)
eps_commit(A,Z) <= Adv_commit_hide(B_commit)
                 + Adv_commit_bind(B_commit)
                 + Adv_commit_equiv(B_commit)
eps_ro_prior(A,Z) includes Pr[BadHwPrior]
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

Worksheet transition bound:

```text
Delta_45 <= eps_contrib(A,Z) + eps_vss_ideal(A,Z) + eps_ro_prior(A,Z)
eps_contrib(A,Z)
  <= Adv_contrib_zk_or_hiding(B_contrib)
   + Adv_contrib_sound(B_contrib)
   + Adv_contrib_extract(B_contrib)
   + Adv_contrib_context_bind(B_contrib)
eps_ro_prior(A,Z) includes Pr[BadHcontribPrior]
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

Worksheet transition bound:

```text
Delta_56 <= eps_ro_prior(A,Z) + eps_ro_sep(A,Z)
eps_ro_prior(A,Z)
  <= Adv_ro_program(B_ro)
   + Pr[BadHmuPrior or BadHwPrior or BadHcPrior
        or BadHvssPrior or BadHcontribPrior or BadCrossSession]
eps_ro_sep(A,Z)
  <= Adv_domain_sep(B_ro) + Adv_transcript_injective(B_ro)
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

Transition dependencies:

- S6 must already provide global lazy tables for every oracle domain and a
  canonical `H_c(sid, t, V, pk, m or mu, Com)` value for the accepted
  commitment set.
- Any prior-query conflict for `H_c` must have been charged to `eps_ro_prior`
  in `Delta_56`; S7 does not silently reprogram `H_c`.
- Contribution frames counted in the aggregate must already be bound to one
  validator, one session, one commitment, one challenge, one public key, and
  one DKG digest, or the loss is charged to `eps_contrib`.
- Ordinary rejection-sampling failures and unattributable timeouts must remain
  retry or abort leakage, not slashable evidence, or the loss is charged to
  `eps_evid`.

Define the authorized-release distinguisher `D_67` from `(A,Z)` as the
distinguisher that receives the accepted real threshold transcript in S6 or the
`F_TMLDSA` released signature in S7 and outputs `Z`'s bit. The worksheet target
is:

```text
eps_reject(A,Z)
  := Adv_rej_sampling(D_67)
eps_reject(A,Z)
  <= eps_rs_mask + eps_rs_commit + eps_rs_rej
   + eps_rs_withhold + eps_rs_ro + eps_rs_verify
```

where the six `eps_rs_*` terms correspond to the rejection-sampling worksheet's
`eps_mask`, `eps_commit`, `eps_rej`, `eps_withhold`, `eps_ro`, and
`eps_verify`.

Worksheet transition bound:

```text
Delta_67 <= eps_reject(A,Z)
          + eps_abort(A,Z)
          + eps_release(A,Z)
          + eps_evid(A,Z)
          + eps_collect(A,Z)

eps_abort(A,Z)
  <= Adv_abort_bias(B_abort)
   + Pr[retry transcript reuses mask or challenge material]
   + Delta(View_with_abort_labels, SimulatedView)

eps_collect(A,Z)
  <= Adv_aggregation_correctness(B_agg)
   + Adv_collection_validation(B_coll)
   + Adv_challenge_binding(B_ro)
```

### Lemma SHR-L8, S7 to S8 Unauthorized Output Extraction

Claim target: in the final ideal execution, every accepting aggregate signature
for an unauthorized message yields either an ML-DSA EUF-CMA forgery or a
violation of a listed threshold, VSS, commitment, contribution-proof,
random-oracle, or evidence assumption.

Reduction target or assumption: base ML-DSA EUF-CMA or strong unforgeability,
threshold-share soundness, ideal-VSS or concrete VSS binding/hiding/
extractability, commitment binding/hiding, contribution-proof soundness/
extractability, random-oracle challenge binding, canonical collection
validation, and evidence noninterference.

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

Transition dependencies:

- S7 has already replaced every authorized accepting output with a
  `ReleaseSignature` result from `F_TMLDSA`, so a remaining accepting
  `(m*, sigma*)` with unauthorized `m*` is either a base ML-DSA forgery or a
  threshold-side assumption violation.
- If `(m*, sigma*)` is byte-identical to a previously released authorized
  signature for the same message, it is not a forgery; if it verifies for a
  different message or context, it is charged to ML-DSA strong unforgeability
  or transcript binding.
- If the accepting aggregate uses fewer than `t` valid, unique, in-set,
  contribution-proof-bound shares, the loss is charged to `eps_threshold`,
  `eps_collect`, `eps_contrib`, or `eps_ro_sep`.
- If the extractor cannot classify the output into one of the named cases, the
  residual is `eps_classify`; a completed proof must remove this term.

#### unauthorized-output-classifier

The S7 to S8 classifier is still a proof obligation, not a completed
reduction. Its intended input is an accepting aggregate output
`(m*, sigma*, trace*)` for an unauthorized `m*`, including the aggregate
verification transcript, selected contributors, VSS/DKG references,
commitments, contribution proofs, random-oracle inputs, collection metadata,
and evidence frames available to the simulator. The classifier must assign the
output to exactly one reduction case or leave it in `eps_classify`.
The dedicated closure route is tracked in
[unauthorized-output-classifier-closure.md](unauthorized-output-classifier-closure.md).

#### eps-classify-decomposition

The residual classifier term should be decomposed into the following named
cases:

```text
eps_classify(A,Z)
 <= eps_cls_mldsa(A,Z)
  + eps_cls_threshold(A,Z)
  + eps_cls_vss_dkg(A,Z)
  + eps_cls_commit(A,Z)
  + eps_cls_contrib(A,Z)
  + eps_cls_ro_transcript(A,Z)
  + eps_cls_collect(A,Z)
  + eps_cls_evid(A,Z)
  + eps_cls_unmapped(A,Z)
```

- `eps_cls_mldsa`: the aggregate verifies as a valid ML-DSA signature for
  unauthorized `m*`, is not byte-identical to an authorized release for the
  same message and context, and all threshold-side transcript checks needed to
  treat `sigma*` as a standalone signature are present. This maps to base
  ML-DSA EUF-CMA or strong unforgeability.
- `eps_cls_threshold`: the output needs honest-consistent signing material from
  fewer than `t` valid in-set contributors, or from shares not authorized by
  `F_TMLDSA`. This maps to threshold-share soundness.
- `eps_cls_vss_dkg`: a counted contributor is accepted with a share or public
  verification key that is not extractable from, or not consistent with, the
  accepted VSS/DKG transcript. This maps to VSS/DKG binding, agreement,
  extractability, or key-bias violations.
- `eps_cls_commit`: an accepted contribution depends on a commitment that is
  opened inconsistently, rebound across sessions, or otherwise used outside the
  committed statement. This maps to commitment binding or hiding violations.
- `eps_cls_contrib`: an accepted partial contribution lacks a valid proof tying
  the signer, share, message, context, and commitment transcript together. This
  maps to contribution-proof soundness or extractability violations.
- `eps_cls_ro_transcript`: verification succeeds only because a challenge,
  domain separator, context string, or transcript hash is reused, rebound, or
  programmed inconsistently across `H_mu`, `H_w`, `H_c`, `H_vss`, or
  `H_contrib`. This maps to random-oracle or transcript-binding violations.
- `eps_cls_collect`: the aggregate counts an unknown, duplicate, out-of-set,
  stale, malformed, or incorrectly weighted contribution, or accepts collection
  metadata that should be rejected. This maps to canonical collection and
  aggregation-validation violations.
- `eps_cls_evid`: evidence omission, reordering, replay, or rebinding changes
  authorization, contributor identity, or acceptance without producing one of
  the preceding failures. This maps to evidence noninterference or anti-framing
  violations.
- `eps_cls_unmapped`: the classifier cannot assign an accepting unauthorized
  output to any listed reduction case. A completed proof must prove this event
  has probability zero, then remove `eps_cls_unmapped` and hence remove
  `eps_classify` from the final theorem.

Closure checklist for eliminating `eps_classify`:

- Define the classifier input tuple, including exact encodings for `m*`,
  `sigma*`, contributor identities, VSS/DKG references, commitments,
  contribution proofs, oracle inputs, collection records, and evidence frames.
- Prove `classifier-totality-obligation`: every accepting unauthorized output
  either maps to ML-DSA forgery, threshold-share violation, VSS/DKG violation,
  commitment violation, contribution-proof violation, random-oracle/transcript
  violation, collection violation, evidence violation, or the explicitly named
  `eps_cls_unmapped` gap.
- Prove `classifier-disjointness-obligation`: the case predicates are ordered
  or made syntactically disjoint so the reduction does not double-charge a
  single accepting output, especially where collection, contribution-proof,
  transcript, and evidence failures overlap.
- For each non-gap case, specify the reduction algorithm, success probability,
  runtime loss, oracle programming constraints, and which transcript fields are
  forwarded to the underlying assumption game.
- Prove that the authorized-release replacement from S6 to S7 gives the
  classifier a reliable exclusion test for byte-identical authorized outputs
  and for outputs replayed under a different message, context, or transcript.
- Prove `eps_cls_unmapped = 0` from the production verification relation and
  transcript grammar before setting `eps_classify` to zero. Until that proof is
  supplied, the gap remains open.
The classifier input tuple, ordered case grammar, reduction map, and
acceptance criteria are separated in
[unauthorized-output-classifier-closure.md](unauthorized-output-classifier-closure.md)
so this worksheet can keep the global S7 -> S8 equation readable.

For `q_out` adversarial aggregate verification attempts in the final game, the
classifier target is:

```text
Pr[BadUnauthorizedAccept]
 <= q_out * eps_mldsa(B_mldsa)
  + eps_threshold(A,Z)
  + eps_vss_ideal(A,Z)
  + eps_commit(A,Z)
  + eps_contrib(A,Z)
  + eps_ro_sep(A,Z)
  + eps_collect(A,Z)
  + eps_evid(A,Z)
  + eps_classify(A,Z)
```

Worksheet transition bound:

```text
Delta_78 <= q_out * eps_mldsa(B_mldsa)
          + eps_threshold(A,Z)
          + eps_vss_ideal(A,Z)
          + eps_commit(A,Z)
          + eps_contrib(A,Z)
          + eps_ro_sep(A,Z)
          + eps_collect(A,Z)
          + eps_evid(A,Z)
          + eps_classify(A,Z)
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

## SHR-4. Consolidated Real/Ideal Bound

Let `Exec_i` denote the environment's output bit in hybrid `Si`. The intended
real/ideal distinguishing advantage is bounded by a telescoping sum:

```text
Adv_real_ideal(A,Z) =
    |Pr[Exec_0 = 1] - Pr[Exec_8 = 1]|
 <= Delta_01 + Delta_12 + Delta_23 + Delta_34
  + Delta_45 + Delta_56 + Delta_67 + Delta_78.
```

Theorem-style worksheet target SHR-T1. For every PPT real-world adversary `A`
and environment `Z` in the static active corruption model with `|C| < t`, if
the simulator satisfies the transition dependencies in SHR-L1 through SHR-L8,
then a completed proof should instantiate reductions such that:

```text
Adv_real_ideal(A,Z)
 <= eps_sched(A,Z)
  + eps_evid(A,Z)
  + eps_vss_ideal(A,Z)
  + eps_commit(A,Z)
  + eps_contrib(A,Z)
  + eps_ro_prior(A,Z)
  + eps_ro_sep(A,Z)
  + eps_reject(A,Z)
  + eps_abort(A,Z)
  + eps_release(A,Z)
  + eps_collect(A,Z)
  + eps_threshold(A,Z)
  + q_out * eps_mldsa(B_mldsa)
  + eps_classify(A,Z)
  + negl(lambda).
```

with the main expansion:

```text
eps_reject(A,Z)
 <= eps_rs_mask + eps_rs_commit + eps_rs_rej
  + eps_rs_withhold + eps_rs_ro + eps_rs_verify
```

This is still a worksheet equation. In particular:

- `eps_vss_ideal` is an explicit ideal setup dependency unless a later DKG/VSS
  realization theorem replaces `F_VSS_DKG`.
- `eps_ro_prior` must include every prior-query failure for `H_mu`, `H_w`,
  `H_c`, `H_vss`, and `H_contrib`; S6 to S7 may rely only on already charged
  prior-query events.
- `eps_contrib` must be closed before S6 to S7 can claim that all counted
  shares are context-bound and simulatable.
- `eps_reject`, `eps_abort`, and `eps_release` are the core S6 to S7
  dependencies; they must prove both standard ML-DSA distributional
  equivalence and no extra release or evidence leakage.
- `q_out * eps_mldsa(B_mldsa)` is only available for unauthorized accepting
  outputs not already explained by threshold, collection, oracle, or evidence
  failures.
- `eps_classify` must be eliminated, not merely bounded, before the worksheet
  can become a completed proof.

Every term must be parameterized by the number of sessions, oracle queries,
validators, corruptions, retries, evidence records, and aggregate verification
attempts allowed by the final theorem.

For the consolidated review status of the publication-facing theorem-loss
terms, see [proof-closure-ledger.md](proof-closure-ledger.md). The ledger maps
this worksheet's `eps_reject(A,Z)` expansion to `eps_mask`, `eps_commit`,
`eps_rej`, `eps_withhold`, `eps_ro`, and `eps_verify`; other worksheet terms
remain governed by the detailed reductions in this file.

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
