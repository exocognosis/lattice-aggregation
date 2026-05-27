# Proof-Grade VSS/DKG Security Plan

Date: 2026-05-27

## Scope

This plan specifies the VSS/DKG properties and production replacements required
before the repository can support a full cryptographic proof. It intentionally
does not claim that the current VSS or DKG code is production proven.

Backend selection is tracked in
[vss-backend-selection.md](vss-backend-selection.md). No production backend is
selected yet; the current repository only defines the required properties,
candidate families, and fail-closed policy boundaries.

The available code reviewed for this plan has deterministic test machinery:

- `src/crypto/vss.rs` evaluates Shamir-style polynomial shares over scaffold
  polynomials and uses deterministic masks.
- `src/dkg.rs` derives simulated commitments and public keys by hashing
  validated commitment sets.
- `src/backend.rs` implements deterministic simulated signing and reports that
  standard ML-DSA verification is unavailable.
- `src/collections.rs`, `src/transcript.rs`, `src/adapter/wire.rs`, and
  `src/adapter/evidence.rs` provide useful canonicalization and evidence
  shapes, but not production VSS/DKG security.

## Required VSS Relation

A production VSS instance must define a relation `R_vss` over:

- Public parameters: ML-DSA parameter set, module/ring dimensions, modulus,
  validator set digest, threshold `tau`, session ID, dealer ID, and domain
  labels.
- Dealer statement: coefficient commitments, commitment randomizers or
  commitment openings where appropriate, encrypted per-receiver shares,
  per-share validity proofs, and dealer public key contribution.
- Witness: the dealer's secret polynomial coefficients, commitment
  randomizers, encryption randomness, and any proof witnesses required by the
  selected commitment and encryption schemes.

The relation must verify:

- The secret-sharing polynomial has degree `< tau`.
- Each encrypted receiver share decrypts to the polynomial evaluation for that
  receiver index.
- Each public key contribution is derived from the polynomial constant term
  using the exact threshold ML-DSA key relation.
- All commitments, encrypted shares, and proofs bind to the same context:
  protocol version, session ID, epoch, dealer, receiver, validator set digest,
  threshold, and message type.
- Encodings are canonical and reject duplicate, unknown, or out-of-context
  validators before they affect transcript state.

<a id="vss-security-properties"></a>

## Binding, Hiding, and Extractability

The production VSS proof must state and prove or cite the following assumptions.

### Binding

Given the public VSS statement, no probabilistic polynomial-time adversary can
produce two different degree-`< tau` dealer polynomials that both verify against
the same coefficient commitments and context, except with negligible
probability in `lambda`.

Binding must cover:

- Coefficient commitments.
- Per-receiver share proofs.
- Dealer public key contribution.
- Complaint responses and revealed openings.
- Any compressed digest used in wire or evidence records.

### Hiding

Before valid reconstruction, any adversary corrupting fewer than `tau`
validators learns no information about an honest dealer's constant term beyond
what is implied by public key material and accepted public outputs.

Hiding must cover:

- VSS commitments.
- Per-receiver encrypted shares.
- Complaint transcripts that reveal fewer than `tau` valid shares.
- Zero-knowledge or witness-hiding proof material.
- Side-channel-relevant rejection, retry, and malformed-message behavior.

### Extractability

For any accepted dealer transcript, an efficient extractor must be able to
recover a unique degree-`< tau` polynomial, or the transcript must be rejected
with public evidence. Extractability may be obtained from an extractable
commitment/proof system or from a knowledge-sound proof of correct share
generation.

The extracted polynomial must satisfy:

- All accepted honest receiver shares equal evaluations of that polynomial.
- The dealer public key contribution corresponds to the extracted constant
  term.
- Any `tau` accepted valid shares reconstruct the same value.
- Invalid or missing shares are attributable to a dealer or receiver under the
  complaint semantics in `active-adversary-model.md`.

## DKG Construction Requirements

The DKG must combine accepted VSS dealer contributions into one joint threshold
key.

For every completed DKG session:

- All honest validators agree on the accepted-dealer set.
- Each honest validator's final private key share is the sum of accepted dealer
  shares for its receiver index.
- The joint public key is the canonical aggregation of accepted dealer public
  key contributions.
- Public output binds to the ordered transcript digest, not to local network
  arrival order.
- No validator accepts a final key unless its local share verifies against the
  joint public key and transcript.

The proof must cover correctness, secrecy, robustness, output agreement, and
unforgeability handoff to the threshold ML-DSA signing proof.

<a id="dkg-key-bias-resistance"></a>

## Key-Bias Resistance

The DKG proof must include an explicit key-bias theorem.

For any rushing active adversary controlling at most `f` validators, conditioned
on DKG completion and at least one accepted honest dealer contribution with
unrevealed randomness, the joint secret and joint public key distribution must
be computationally indistinguishable from a distribution containing that honest
dealer's fresh contribution.

The adversary must not be able to:

- Choose corrupted dealer contributions after learning honest dealer secrets.
- Selectively abort after learning enough information to force the final key
  into a targeted small subset.
- Make different honest validators finalize different accepted-dealer sets.
- Use rogue public key contributions that are not backed by extractable VSS
  witnesses.
- Bias the signing challenge by changing DKG transcript order.

The construction must therefore include:

- A commit-before-share or equivalent binding phase for every dealer.
- A deterministic accepted-dealer rule based only on public transcript and
  complaint outcomes.
- A rule that excludes dealers with unresolved valid complaints before final
  key derivation.
- A proof that dealer exclusion cannot depend on hidden honest contribution
  values, except through publicly valid complaint predicates.
- A final transcript digest that fixes dealer order, commitments, complaints,
  responses, accepted set, threshold, and validator set.

If the selected protocol remains vulnerable to last-mover abort bias, the
production claim must weaken liveness, add a randomness beacon or commit-reveal
countermeasure, or explicitly quantify the residual bias and show it is
acceptable for threshold ML-DSA key generation.

## Complaint and Evidence Requirements

Production VSS/DKG evidence must be publicly checkable and anti-framing. The
adapter evidence types in the current code are not sufficient by themselves.

Required production evidence records:

- `InvalidDealerShare`: proves a dealer sent a malformed, undecryptable, or
  commitment-inconsistent share for a receiver.
- `DealerEquivocation`: proves a dealer signed two conflicting commitments,
  shares, or responses for the same canonical context.
- `InvalidComplaint`: proves a receiver complained about a share that verifies.
- `MissingComplaintResponse`: proves a dealer failed to answer a valid
  complaint by the adjudication deadline under the chosen network model.
- `MalformedDkgFrame`: proves a frame cannot decode or violates canonical
  context before entering VSS verification.

Every evidence verifier must be deterministic, side-effect-free, and usable by
the consensus layer without access to local private state. Evidence that cannot
be publicly verified may be used for local retry or exclusion policy, but not
for slashing.

<a id="production-replacement-obligations"></a>

## Production Replacement Checklist

The following replacements are required before production cryptographic claims.

1. Replace deterministic masks in `src/crypto/vss.rs` with CSPRNG-sampled
   degree-`< tau` secret-sharing polynomials over the exact algebra required by
   the selected threshold ML-DSA construction.
2. Replace scaffold VSS output with typed coefficient commitments, encrypted
   receiver shares, per-share validity proofs, dealer key contribution proofs,
   and canonical transcript digests.
3. Replace `SimulatedDkg::generate_share_commitment` and
   `SimulatedDkg::finalize_public_key` with an interactive DKG state machine
   implementing commit, share, complaint, response, adjudication, and finalize
   phases.
4. Replace `ValidatedDkgShares = CommitmentSet` with a typed DKG transcript
   containing dealer commitments, encrypted shares, complaints, responses,
   accepted-dealer set, and the final joint key statement.
5. Extend `PqcThresholdWireMsg` with production DKG frames for dealer
   commitments, encrypted shares, complaint submissions, complaint responses,
   transcript-finalization votes, and proof-carrying evidence.
6. Replace local adapter `SlashingEvidence` authority with consensus-verifiable
   evidence predicates and anti-framing checks.
7. Add a production policy gate that fails closed unless the real VSS/DKG
   backend, contribution proof backend, standard ML-DSA verification, and
   external proof/audit identifiers are enabled together.
8. Replace transcript-hash or placeholder contribution proofs with a sound and
   hiding production proof system, or with an audited MPC verification relation
   that proves valid threshold ML-DSA contributions directly.
9. Bind DKG output into signing transcripts so signatures cannot mix shares,
   public keys, validator sets, or DKG transcript digests across sessions.
10. Add negative tests and proof harnesses for malformed shares, malicious
    dealers, invalid complaints, equivocation, rushing order changes, adaptive
    state exposure where claimed, and key-bias attempts.

## Backend Selection Checklist
<a id="vss-dkg-backend-selection-checklist"></a>

Before this plan can name a production VSS/DKG backend, the decision record in
[vss-backend-selection.md](vss-backend-selection.md) must be updated with:

1. A concrete backend family, backend ID, version, domain separators, and
   parameter set.
2. A complete `R_vss` statement, witness relation, commitment format, opening
   format, proof format, and complaint evidence format.
3. Proof coverage for binding, hiding, extractability, complaint soundness,
   anti-framing, and key-bias resistance.
4. A mapping from each public verifier predicate to Rust canonical encodings
   and tests.
5. A fail-closed production policy result showing scaffold and candidate
   placeholders cannot satisfy production configuration.
6. External cryptographic review of the selected construction and its
   integration with threshold ML-DSA signing.

Current selection status: no backend is selected. Lattice/vector commitments
with opening proofs are the recommended investigation path, but they remain
unselected until a concrete construction, parameterization, proof, tests, and
review are recorded.

## Proof Obligations

A full proof package must include:

- VSS correctness, binding, hiding, and extractability.
- Complaint soundness, completeness, and anti-framing.
- DKG output agreement and robustness under the chosen network model.
- DKG secrecy for fewer than `tau` corrupt validators.
- DKG key-bias resistance against rushing adversaries.
- Threshold ML-DSA signing correctness and unforgeability using DKG-produced
  shares.
- Fiat-Shamir transcript binding, rejection-sampling distribution preservation,
  and abort leakage analysis for ML-DSA-65.
- Composition theorem showing the VSS/DKG output meets the signing proof's key
  share assumptions.
- Side-channel and implementation assumptions, including constant-time
  requirements and allowed declassification events.

## Current Non-Claims

Until every production replacement and proof obligation above is satisfied, the
repository must continue to state that:

- The VSS code is an algebraic scaffold with deterministic masks.
- The DKG code is simulated test machinery.
- Current evidence records are adapter diagnostics, not production slashing
  proofs.
- Passing tests demonstrates API and transcript behavior, not production
  cryptographic security.
- No VSS/DKG backend has been selected for production.
