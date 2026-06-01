# VSS/DKG Backend Selection Framework
<a id="vss-backend-selection"></a>

Date: 2026-05-27

## Status

This document compares candidate backend families for the production VSS/DKG
relation described in [production-vss-backend.md](production-vss-backend.md)
and [vss-dkg-security-plan.md](vss-dkg-security-plan.md).

Batch C narrows the production realization route in
[eps-vss-production-route.md](eps-vss-production-route.md), which decomposes
`eps_vss` into backend-selection, binding, hiding, extraction, complaint,
key-bias, privacy, anti-framing, and public-key derivation obligations without
selecting a production backend.

No production VSS/DKG backend is selected in this repository yet. The current
implementation remains the deterministic transcript-hash scaffold in
`src/crypto/vss.rs`, plus fail-closed production policy gates. This document is
a selection framework and decision record, not a proof completion claim.

## Required Selection Properties
<a id="backend-selection-required-properties"></a>

A candidate backend cannot be selected for production unless its specification,
implementation plan, tests, proof, and review package cover all of the
following properties for the active-adversary model:

- Binding: accepted shares for a fixed dealer commitment and context are
  evaluations of one degree-`< tau` dealer polynomial.
- Hiding: unopened honest receiver shares and dealer secret coefficients remain
  hidden from any adversary corrupting fewer than `tau` validators.
- Extractability: every accepted dealer transcript has a unique extractable
  polynomial, or public evidence causes deterministic rejection.
- Complaint soundness: public complaint predicates distinguish dealer faults,
  invalid receiver complaints, malformed frames, and inconclusive cases.
- Anti-framing: corrupted receivers cannot transform valid honest-dealer
  traffic into public evidence that falsely attributes a cryptographic fault.
- Key-bias resistance: rushing, last-mover behavior, complaint scheduling, and
  dealer exclusion do not let corrupted validators bias the final DKG key
  outside the stated bound.
- Implementation risk: canonical encoding, parameter size, proof system
  complexity, side-channel scope, transport binding, and auditability are
  acceptable for the production target.

The selected backend must also compose with threshold ML-DSA assumptions in
[formal-security-theorem.md](formal-security-theorem.md), the complaint model in
[active-adversary-model.md](active-adversary-model.md), and the production
policy gate in `src/crypto/production_policy.rs`.

## Candidate Family A: Feldman/Pedersen-Style Commitments
<a id="candidate-feldman-pedersen"></a>

This family commits to dealer polynomial coefficients using Feldman-style
public commitments or Pedersen-style hiding commitments over an algebra that is
compatible with the share field and public-key derivation.

Expected strengths:

- Binding can be mature and compact when the commitment group and share field
  match exactly.
- Pedersen-style variants can hide coefficients if independent generators,
  randomness handling, and private share delivery are sound.
- Complaint checks are simple when a receiver can reveal a share and opening
  that third parties verify against coefficient commitments.
- DKG literature gives useful templates for commit, share, complaint, response,
  and finalize phases.

Open blockers for this repository:

- Ordinary elliptic-curve or finite-field Feldman/Pedersen commitments are not
  post-quantum assumptions and do not directly match ML-DSA's module-lattice
  secret domain.
- Feldman commitments alone are not hiding, so they cannot satisfy the hiding
  requirement for secret ML-DSA shares.
- A production proof would need a precise relation between committed scalar or
  vector shares and the ML-DSA public key contribution. An algebra mismatch
  would create a new unproved bridge assumption.
- Extractability normally requires a proof of knowledge or an independently
  justified binding-to-opening theorem.
- Anti-framing depends on authenticated private-share delivery and exact rules
  for revealed complaint openings.

Assessment:

This family is a useful baseline and may be appropriate only if the project
selects a post-quantum-compatible commitment analogue or explicitly accepts a
non-post-quantum auxiliary assumption. As written, conventional
Feldman/Pedersen over discrete-log groups is not the recommended production
path for a threshold ML-DSA proof.

## Candidate Family B: Lattice/Vector Commitments With Opening Proofs
<a id="candidate-lattice-vector-commitments"></a>

This family commits to ML-DSA secret polynomial or vector coefficients with a
lattice-based or vector-commitment scheme and proves receiver-specific
evaluation openings, range/norm predicates where required, and dealer public-key
contribution consistency.

Expected strengths:

- The algebra can be aligned with `R_q`, module vectors, and ML-DSA parameter
  constraints rather than bridged through an unrelated group.
- Post-quantum security assumptions can be chosen to match the rest of the
  construction.
- Opening proofs can be designed to cover binding, hiding, extractability,
  receiver index binding, encrypted-share binding, and public-key contribution
  consistency in one relation.
- The production statement already exposed by `ProductionVssRelationStatement`
  is shaped for this kind of backend: context digest, backend ID, dealer,
  receiver, dealer commitment digest, encrypted-share digest, opening digest,
  and public-key contribution digest.

Open blockers for this repository:

- Parameter selection is high risk. The proof must account for ML-DSA-65
  dimensions, modulus `q = 8380417`, degree bounds, proof sizes, rejection
  behavior, and concrete security loss.
- Efficient zero-knowledge or witness-hiding openings for receiver shares and
  public-key consistency need external review.
- Extractability and anti-framing must be proved for the exact proof system,
  serialization, and complaint evidence format.
- Implementation complexity is significant, including constant-time secret
  handling, canonical encodings, proof verification limits, and failure-mode
  discipline.

Assessment:

This is the recommended backend investigation path because it can keep the VSS
relation inside post-quantum assumptions and the ML-DSA algebra. It is not
selected yet. Selection requires a named commitment/proof construction,
parameter file, theorem instantiation, prototype verifier, negative tests, and
external cryptographic review.

## Candidate Family C: Ideal-Functionality Placeholder
<a id="candidate-ideal-functionality-placeholder"></a>

This family models VSS/DKG through an ideal functionality or oracle boundary.
It is useful for proof decomposition and protocol API design, but it does not
instantiate a production backend.

Expected strengths:

- It can state exactly what the signing proof needs from DKG: unique shares,
  hiding below threshold, extractable accepted dealers, complaint outcomes, and
  one agreed joint public key.
- It helps separate threshold ML-DSA signing reductions from the still-open VSS
  construction.
- It can drive manifest anchors, simulator obligations, and fail-closed policy
  checks without inventing unsupported implementation claims.

Open blockers for this repository:

- Binding, hiding, extractability, complaint soundness, anti-framing, and
  key-bias resistance are assumed by the functionality rather than implemented.
- It cannot pass `VssCommitmentSecurityProfile::ProductionBindingHiding`.
- It cannot produce production complaint evidence or a deployed DKG transcript.
- The main implementation risk is accidental wording or configuration that
  treats an ideal placeholder as a real backend.

Assessment:

This family should remain a proof placeholder and testing boundary only. It is
not eligible for production selection.

## Comparison Matrix
<a id="backend-selection-comparison-matrix"></a>

| Property | Feldman/Pedersen-style compatible algebra | Lattice/vector commitments with opening proofs | Ideal-functionality placeholder |
| --- | --- | --- | --- |
| Binding | Strong when algebra and assumptions match; otherwise unproved bridge | Target property of commitment/proof relation; must be parameterized | Assumed, not implemented |
| Hiding | Feldman no; Pedersen yes under randomness and generator assumptions | Target property via hiding commitments or zero-knowledge openings | Assumed, not implemented |
| Extractability | Needs proof of knowledge or extractable commitment theorem | Needs explicit extractor for accepted transcripts | Assumed by simulator interface |
| Complaint soundness | Mature share-reveal pattern if openings are public-verifiable | Must be designed with deterministic public verifier and failure codes | Specified ideally only |
| Anti-framing | Depends on authenticated delivery and unforgeable openings | Must be proved for ciphertext/opening/proof binding | Assumed ideally only |
| Key-bias resistance | Requires commit-before-share and deterministic exclusion; last-mover abort still needs proof | Same requirement, plus proof that openings and complaints leak no biasing information | Assumed ideally only |
| Implementation risk | Lower protocol complexity, but high assumption/algebra mismatch risk for ML-DSA | Highest implementation and proof complexity, best assumption alignment | Low engineering cost, unacceptable production security value |
| Production eligibility now | Not selected | Not selected | Not eligible |

## Selection Checklist
<a id="backend-selection-checklist"></a>

Before a backend can move from candidate to selected, the decision record must
identify:

1. Backend family, backend ID, version, domain separators, and parameter set.
2. Exact public relation `R_vss`, witness relation, commitment objects, opening
   objects, proof objects, and complaint evidence objects.
3. Security assumptions for binding, hiding, extractability, encryption, random
   oracle use, and side-channel scope.
4. Static active adversary theorem target, including network model, rushing
   behavior, complaint timing, and dealer exclusion policy.
5. Key-bias theorem or quantified residual bias bound.
6. Anti-framing proof for every public evidence path.
7. Mapping from proof predicates to Rust verifier predicates and canonical
   encodings.
8. Negative tests for malformed objects, duplicate dealers, wrong context,
   invalid openings, invalid complaints, equivocation, and replay.
9. Fail-closed production policy integration showing scaffold and candidate
   backends cannot satisfy production configuration.
10. External cryptographic review scope and review outcome.

## Decision Record
<a id="vss-backend-decision-record"></a>

Current decision: no backend selected.

Rationale:

- Conventional Feldman/Pedersen-style commitments are not currently justified
  for post-quantum threshold ML-DSA production claims in this repository.
- Lattice/vector commitments with opening proofs are the preferred investigation
  path, but no concrete construction, parameters, implementation, proof, or
  review has been completed.
- The ideal-functionality placeholder remains useful for proof scaffolding but
  is not a production backend.

Required next decision:

Select a concrete lattice/vector commitment and opening-proof construction, or
document why another family satisfies the required properties with acceptable
assumptions and implementation risk. Until that decision is recorded and the
selection checklist is closed, production documentation must continue to say
that VSS/DKG is unselected and unproved.
