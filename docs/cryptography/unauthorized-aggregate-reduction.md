# Unauthorized Aggregate Reduction Manifest

Status: reduction-case manifest with required proof slots.

Date: 2026-06-20

## Scope and Claim Boundary

This manifest records the case split needed for blocker 5: every unauthorized
accepting aggregate output must reduce to either a base ML-DSA-65 forgery or a
named threshold-side assumption violation.

This manifest names the FST-T1 and FST-T2 reduction proof slots. The reduction package requires protocol evidence, base-theorem citations, threshold-side assumption bounds, conformance traces, and external review before threshold EUF-CMA security is promoted.

This closure package records the proof/citation slots, bound terms, classifier rows, and signoff slots required for an accepted reduction.

The current repository still lacks the production protocol, partial-verification
equations, simulator construction, standard-verifier bridge, and concrete bounds
needed to turn this manifest into a proof.

## Closure Package Framework

The closure package framework for this reduction is the combination of the
protocol event grammar, deterministic UAR classifier, base ML-DSA theorem
citation slot, threshold-side assumption proof slots, simulator obligations,
hybrid bound table, and external review signoff below. Completing this framework
requires replacing every pending slot with a reviewed proof artifact; the
framework itself is only a scaffold.

## Reduction Target

An unauthorized accepting aggregate output is a real execution event containing

```text
(key_id, sid, t, V, pk, m*, Com*, Partials*, sigma*)
```

such that `MLDSA65.Verify(pk, m*, sigma*) = accept`, while `m*` was not
authorized through `F_TMLDSA` for the target key epoch, validator set, and
message. In the base corruption model, the adversary controls at most `t - 1`
validators for the epoch.

The intended reduction is a classifier over such events:

1. If the event can be mapped to a standard-valid signature for an unauthorized
   message and every threshold-side precondition below is satisfied, the event
   is a base ML-DSA-65 forgery against FST-A1.
2. If any threshold-side precondition fails, the event is assigned to the first
   applicable named violation case in UAR-C1 through UAR-C8.
3. If no case applies, blocker 5 remains open because the manifest is missing a
   case or the proof model is underspecified.

## Assumptions Named by Case

| Name | Role in this manifest |
| --- | --- |
| FST-A1, ML-DSA-65 unforgeability | Base case for a standard-valid signature on an unauthorized message when all threshold-side checks hold. |
| FST-A2, threshold sharing soundness | Rules out useful signing capability from fewer than `t` valid shares. |
| FST-A3, verifiable share binding | Binds each validator identity to one epoch share and rejects invalid DKG share material or yields evidence. |
| FST-A4, commitment binding and hiding | Binds each signing commitment before challenge derivation and preserves the masking assumptions used by ML-DSA. |
| FST-A5, abort and noise-bound preservation | Rules out abort, rejection, norm, hint, and challenge-consistency behavior that changes the accepted-signature distribution beyond the final proof bound. |
| FST-A6, partial signature correctness and extractability | Requires each counted partial to verify against its signer metadata, commitment, transcript, and public key or yield attributable evidence. |
| FST-A7, transcript collision resistance and domain separation | Rules out rebinding one challenge, commitment set, partial, or aggregate to two distinct typed sessions. |
| FST-A8, canonical collection validation | Rejects duplicate, unknown, insufficient, threshold-mismatched, and validator-set-mismatched collections before aggregation. |
| IF-S1, threshold authorization | Ideal release invariant requiring at least `t` valid partial signers unless the epoch is threshold-compromised. |
| IF-S2, message authorization | Ideal release invariant forbidding signatures on messages not authorized by `IF-I3` unless the epoch is threshold-compromised. |
| IF-R6, aggregate mapping | Real-to-ideal mapping that must explain every accepting real aggregate as an ideal release, a base forgery, or a threshold-side violation. |

## Reduction Cases

Apply cases in order. UAR-C0 is reached only after the threshold-side cases have
been ruled out for the event.

| Case | Event shape | Reduction output | Required proof hook |
| --- | --- | --- | --- |
| UAR-C0 | Base ML-DSA forgery: `MLDSA65.Verify(pk, m*, sigma*) = accept`, `m* was not authorized`, all counted partials are valid for one typed transcript, collection validation holds, and the accepted output has the ML-DSA distribution required by the proof. | Output `(pk, m*, sigma*)` as a base-signature forgery. | FST-A1 plus the absence of UAR-C1 through UAR-C8. |
| UAR-C1 | Subthreshold share reconstruction: fewer than t valid validator contributions are enough to produce the accepting aggregate. | Threshold-side violation of sharing soundness or no-subthreshold signing. | FST-A2, FST-L6. |
| UAR-C2 | Rogue or unbound share admission: a validator outside `V`, a duplicated identity, or a share not bound to `(key_id, V, pk)` contributes to the aggregate. | Threshold-side violation of share binding, epoch binding, or rogue-share resistance. | FST-A3, FST-A8, FST-G4. |
| UAR-C3 | Invalid partial accepted: a counted partial cannot verify against `(sid, t, V, pk, m, commitment, id_i)` but is still used for aggregation. | Threshold-side violation of partial correctness, extractability, or evidence mapping. | FST-A6, FST-L4, IF-E3. |
| UAR-C4 | Transcript or random-oracle rebinding: one commitment, partial, challenge, or aggregate is valid for two distinct typed tuples. | Threshold-side violation of transcript injectivity, challenge binding, or domain separation. | FST-A7, FST-L1, FST-L2. |
| UAR-C5 | Canonical collection bypass: duplicate, unknown, insufficient, threshold-mismatched, or validator-set-mismatched collections reach transcript or aggregation use. | Threshold-side violation of canonical collection validation and validator-set soundness. | FST-A8, FST-L3. |
| UAR-C6 | Abort or distribution preservation failure: selective aborts, malformed commitments, omitted partials, rejection behavior, hints, or norm gates make accepted aggregates diverge from the ML-DSA distribution assumed by UAR-C0. | Threshold-side violation of abort compatibility or accepted-signature distribution preservation. | FST-A5, FST-L7, Noise Lemma H. |
| UAR-C7 | Ideal-functionality release mismatch: the real aggregate maps to `ReleaseSignature` even though the ideal functionality lacks `t` valid partial signers or `IF-I3` message authorization. | Threshold-side violation of the simulator, release invariants, or aggregate mapping. | IF-S1, IF-S2, IF-R6, FST-L8. |
| UAR-C8 | Commitment binding or hiding failure: a commitment is not fixed before challenge derivation, can be opened to two local masks, or leaks enough mask information to invalidate the ML-DSA signing distribution used by UAR-C0. | Threshold-side violation of commitment binding, commitment hiding, or local mask commitment before challenge. | FST-A4, Noise Lemma A. |

## Protocol Event Grammar

The future proof must replace this sketch with a typed grammar tied to the
production protocol. For now, the grammar fixes the event fields that the
classifier must inspect and keeps public evidence separate from secret share or
mask material.

```text
UnauthorizedAggregateEvent ::= EventEnvelope PublicObjects CommitmentSet PartialSet AggregateOutput VerifierResult EvidenceSet
EventEnvelope ::= key_id sid epoch_id threshold validator_set corruption_bound
PublicObjects ::= pk validator_public_keys authorization_policy domain_separation_tag
CommitmentSet ::= CommitmentRecord*
CommitmentRecord ::= signer_id commitment commitment_opening_status transcript_binding
PartialSet ::= PartialRecord*
PartialRecord ::= signer_id partial_signature partial_verification_result signer_evidence
AggregateOutput ::= pk message sigma aggregate_metadata
VerifierResult ::= MLDSA65.Verify(pk, message, sigma)
EvidenceSet ::= public transcript-bound evidence only
AbortRecord ::= signer_id abort_reason round transcript_prefix
```

Grammar closure requires an explicit parse failure rule. A malformed or
ambiguous event must not fall through to UAR-C0; it is either rejected before the
reduction input exists or classified as the earliest applicable threshold-side
case.

## Deterministic UAR Classifier

The classifier must be total, deterministic, and single-valued. First matching case wins; no event may be assigned to more than one case. Unclassified events keep blocker 5 open.

The order below checks threshold-side faults before the base-forgery case. The
base case is deliberately last: UAR-C0 is only available when all
threshold-side predicates are false and every pending proof/citation slot has
been discharged.

| Classifier row | Case | Predicate checked against `UnauthorizedAggregateEvent` | Reduction obligation |
| --- | --- | --- | --- |
| UAR-CLASS-C1 | UAR-C1 | The event has fewer than `t` valid contributions after parsing and partial verification. | Reduce to FST-A2 sharing soundness or cite a completed no-subthreshold-signing theorem. |
| UAR-CLASS-C2 | UAR-C2 | A signer is outside `V`, duplicated, epoch-mismatched, or unbound to `(key_id, V, pk)`. | Reduce to FST-A3/FST-A8 share and collection binding. |
| UAR-CLASS-C3 | UAR-C3 | A counted partial verification fails against the typed transcript, commitment, signer identity, and public key. | Reduce to FST-A6 partial correctness, extractability, or evidence mapping. |
| UAR-CLASS-C4 | UAR-C4 | One commitment, partial, challenge, or aggregate validates for two distinct typed tuples. | Reduce to FST-A7 transcript injectivity and random-oracle domain separation. |
| UAR-CLASS-C5 | UAR-C5 | The collection is duplicate, unknown, insufficient, threshold-mismatched, or validator-set-mismatched. | Reduce to FST-A8 canonical collection validation. |
| UAR-CLASS-C6 | UAR-C6 | Abort behavior, rejection behavior, hints, norm gates, or malformed commitments change the accepted-signature distribution. | Reduce to FST-A5 abort compatibility and distribution preservation. |
| UAR-CLASS-C7 | UAR-C7 | The real aggregate maps to an ideal release without IF-S1 threshold authorization, IF-S2 message authorization, or IF-R6 aggregate mapping. | Reduce to the simulator and ideal-functionality invariant slots. |
| UAR-CLASS-C8 | UAR-C8 | A commitment binding or hiding condition fails before challenge derivation or leaks local mask information. | Reduce to FST-A4 commitment binding/hiding or Noise Lemma A. |
| UAR-CLASS-C0 | UAR-C0 | `MLDSA65.Verify(pk, m*, sigma*) = accept`, `m*` is unauthorized, all threshold-side predicates are false, and the event has the ML-DSA distribution required by the cited base theorem. | Output `(pk, m*, sigma*)` against FST-A1. |

## Base ML-DSA Theorem Citation Placeholder

Base theorem citation status: PLACEHOLDER - no theorem imported yet.

- Theorem identifier slot: `PENDING-FST-A1-ML-DSA-65-EUF-CMA`
- Source citation slot: `PENDING`
- Model compatibility slot: `PENDING`
- Base ML-DSA theorem digest: `sha256:<pending>`
- Digest algorithm: SHA-256 over the final cited theorem artifact.

Reviewer must replace this placeholder before FST-A1 can close. The final
artifact must state the ML-DSA parameter set, adversary model, oracle access,
message authorization relation, random-oracle assumptions, and any loss terms
that UAR-C0 imports.

## Threshold-Side Assumption Proof and Citation Slots

Each nonbase case needs either a proof in this repository or a citation to an
audited theorem artifact. A pending slot is not evidence and does not close the
case.

| Slot row | Case | Assumptions and hooks | Required closure artifact |
| --- | --- | --- | --- |
| SLOT-UAR-C1 | UAR-C1 | FST-A2, FST-L6 | Proof/citation slot: PENDING |
| SLOT-UAR-C2 | UAR-C2 | FST-A3, FST-A8, FST-G4 | Proof/citation slot: PENDING |
| SLOT-UAR-C3 | UAR-C3 | FST-A6, FST-L4, IF-E3 | Proof/citation slot: PENDING |
| SLOT-UAR-C4 | UAR-C4 | FST-A7, FST-L1, FST-L2 | Proof/citation slot: PENDING |
| SLOT-UAR-C5 | UAR-C5 | FST-A8, FST-L3 | Proof/citation slot: PENDING |
| SLOT-UAR-C6 | UAR-C6 | FST-A5, FST-L7, Noise Lemma H | Proof/citation slot: PENDING |
| SLOT-UAR-C7 | UAR-C7 | IF-S1, IF-S2, IF-R6, FST-L8 | Proof/citation slot: PENDING |
| SLOT-UAR-C8 | UAR-C8 | FST-A4, Noise Lemma A | Proof/citation slot: PENDING |

## Simulator Obligations

The static-corruption simulator must be specified before any closure claim. The
minimum obligations are:

- SIM-O1 Static corruption schedule: sample, expose, and track corruptions
  consistently with the real/ideal games and the `t - 1` base corruption model.
- SIM-O2 Ideal release extraction: extract every accepting aggregate into an
  ideal `ReleaseSignature`, UAR-C0 forgery, or named threshold-side violation.
- SIM-O3 Evidence translation: convert real public evidence into ideal evidence
  without using honest secret shares or one-time mask openings.
- SIM-O4 Abort scheduling and distribution accounting: schedule aborts and
  rejection events while preserving the accepted-signature distribution used by
  UAR-C0.
- SIM-O5 Random-oracle programming and accounting: account for programmed and
  observed transcript queries with typed domain separation.
- SIM-O6 Standard-verifier bridge: connect the aggregate output to
  `MLDSA65.Verify(pk, message, sigma)` without changing the message,
  verification key, or signature encoding.
- SIM-O7 Failure-to-case audit log: record why every simulator failure maps to
  exactly one UAR-C case or leaves blocker 5 open.

## Hybrid Bound Table

Every bound term is pending and must be replaced with a concrete advantage expression.

| Hybrid | Game transition | Bad event or loss term | Required bound artifact |
| --- | --- | --- | --- |
| HYB-0 | Real unauthorized aggregate event | Starting event probability `Pr[UAR]` | PENDING |
| HYB-1 | Grammar parse and canonicalization | malformed grammar, duplicate/unknown signer, or canonicalization failure mapped to UAR-C5 | PENDING |
| HYB-2 | Transcript binding and random-oracle programming | collision, rebinding, or programming loss mapped to UAR-C4 | PENDING |
| HYB-3 | Partial validation and extraction | invalid counted partial or extractor failure mapped to UAR-C3 | PENDING |
| HYB-4 | Commitment and distribution preservation | commitment failure, abort bias, or distribution gap mapped to UAR-C8/UAR-C6 | PENDING |
| HYB-5 | Ideal release mapping | simulator release mismatch mapped to UAR-C7 | PENDING |
| HYB-6 | Base ML-DSA forgery extraction | residual event extracted as `(pk, m*, sigma*)` for UAR-C0/FST-A1 | PENDING |

## External Review Signoff

No external review signoff has been recorded in this repository.

| Review item | Required before closure | Current status |
| --- | --- | --- |
| Cryptographer reduction review | reviewer identity, date, scope, verdict | PENDING |
| Base theorem artifact review | cited theorem digest and model match | PENDING |
| Threshold assumption review | proof/citation slots for UAR-C1 through UAR-C8 | PENDING |
| Implementation-binding review | conformance/KAT trace to final interfaces | PENDING |

Blocker 5 remains open until these signoff rows are replaced by reviewed
artifacts and the hybrid bound table contains concrete, checked loss terms.

## Manifest Checklist

The future proof should discharge this manifest by producing evidence for each
item below.

- A precise real protocol event grammar for `Com*`, `Partials*`, aggregate
  output, public evidence, aborts, and verifier results.
- A deterministic classifier from every unauthorized accepting aggregate output
  to exactly one UAR-C case, with explicit precedence for overlapping faults.
- For UAR-C0, a reduction that extracts `(pk, m*, sigma*)` and shows the ML-DSA
  signing oracle did not authorize `m*` for that key, backed by a cited theorem
  artifact and digest.
- For UAR-C1 through UAR-C8, a proof that the event contradicts the named
  assumption, invariant, or lemma, rather than silently becoming another
  unmodeled adversarial capability.
- Simulator obligations covering corruption scheduling, ideal release
  extraction, evidence translation, abort scheduling, random-oracle accounting,
  and the standard-verifier bridge.
- Concrete bounds for each hybrid transition that turns the real event into
  either the UAR-C0 forgery or a named threshold-side violation.
- A check that implementation evidence records are public, transcript-bound,
  and noninterfering with honest secret shares and one-time masks.
- External review signoff with reviewer scope, artifact digests, and explicit
  disposition for the base theorem, threshold assumptions, simulator, hybrid
  bounds, and implementation binding.

## What Remains to Close Blocker 5

This file makes the reduction case split reviewable, but blocker 5 is not fully
closed. Remaining work:

- Select and specify the production threshold ML-DSA protocol, including DKG,
  commitments, partial signing, partial verification, aggregation, rejection
  sampling, hints, and standard verification.
- Prove or cite the external ML-DSA-65 base unforgeability theorem used for
  FST-A1 in the selected model.
- Prove the threshold-side assumptions referenced by UAR-C1 through UAR-C8 or
  explicitly cite audited external theorem dependencies for them.
- Build the static-corruption simulator for `F_TMLDSA`, including aggregate
  extraction, evidence translation, abort scheduling, and random-oracle
  accounting.
- Add implementation conformance tests and known-answer tests that connect the
  Rust production backend to the final formal interfaces without treating those
  tests as proof.
