# Unauthorized Aggregate Reduction Manifest

Status: reduction-case manifest, not a completed proof.

Date: 2026-06-20

## Scope and Claim Boundary

This manifest records the case split needed for blocker 5: every unauthorized
accepting aggregate output must reduce to either a base ML-DSA-65 forgery or a
named threshold-side assumption violation.

This manifest does not prove FST-T1 or FST-T2. It is a checklist for a future reduction, not a theorem statement. The deterministic simulation backend is not evidence for this reduction. Conformance tests are necessary traceability gates, not cryptographic proof. Do not claim threshold EUF-CMA security from this manifest.

The current repository still lacks the production protocol, partial-verification
equations, simulator construction, standard-verifier bridge, and concrete bounds
needed to turn this manifest into a proof.

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

## Manifest Checklist

The future proof should discharge this manifest by producing evidence for each
item below.

- A precise real protocol event grammar for `Com*`, `Partials*`, aggregate
  output, public evidence, aborts, and verifier results.
- A deterministic classifier from every unauthorized accepting aggregate output
  to exactly one UAR-C case, with explicit precedence for overlapping faults.
- For UAR-C0, a reduction that extracts `(pk, m*, sigma*)` and shows the ML-DSA
  signing oracle did not authorize `m*` for that key.
- For UAR-C1 through UAR-C8, a proof that the event contradicts the named
  assumption, invariant, or lemma, rather than silently becoming another
  unmodeled adversarial capability.
- Concrete bounds for each hybrid transition that turns the real event into
  either the UAR-C0 forgery or a named threshold-side violation.
- A check that implementation evidence records are public, transcript-bound,
  and noninterfering with honest secret shares and one-time masks.

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
