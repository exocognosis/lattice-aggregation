# VSS Idealization and Backend Selection
<a id="vss-idealization-and-selection"></a>

Date: 2026-05-27

## Status

This note separates two decisions that must not be conflated:

1. an ideal VSS/DKG functionality that lets the threshold ML-DSA proof proceed
   temporarily under an explicit setup assumption, and
2. the later production backend selection that must instantiate the VSS/DKG
   relation with concrete commitments, openings, proofs, complaint evidence,
   implementation tests, and external cryptographic review.

The ideal route is a proof-decomposition device only. It is not a production
backend selection, does not satisfy
`VssCommitmentSecurityProfile::ProductionBindingHiding`, and does not change
the fail-closed production policy in `src/crypto/production_policy.rs`.

## Ideal Functionality `F_VSS_DKG`

`F_VSS_DKG` is an ideal DKG/VSS functionality for the setup phase of the
threshold ML-DSA proof. It supplies exactly the properties that the signing
proof needs from DKG while leaving the concrete VSS backend unselected.

Parameters:

```text
lambda
V = (id_1, ..., id_n)
tau
f
epoch_id
session_id
parameter_set = ML-DSA-65
```

The baseline use matches the static active model in
[active-adversary-model.md](active-adversary-model.md): the adversary chooses a
corruption set `C` before setup, `|C| = f < tau`, and may rush, equivocate,
withhold, duplicate, reorder, and submit malformed messages subject to the
chosen network abstraction.

### Interface

On `Initialize(epoch_id, session_id, V, tau, C)`, `F_VSS_DKG` verifies:

- `1 <= tau <= |V|`
- validator identifiers in `V` are unique
- `|C| < tau`
- the `(epoch_id, session_id)` pair is unused

If validation fails, setup is rejected. If validation succeeds, the
functionality creates an epoch state with an initially empty public transcript,
accepted-dealer set, complaint log, and extraction table.

On `DealerContribution(id_d, contribution_policy)`, `F_VSS_DKG` behaves as
follows:

- For an honest dealer, it samples an ideal degree-`< tau` dealer polynomial
  over the ML-DSA secret-share domain, records one receiver share per
  validator, and records an ideal public-key contribution derived from the
  dealer constant term.
- For a corrupted dealer, it accepts either one extractable degree-`< tau`
  polynomial supplied through the simulator or a public dealer-fault event that
  causes deterministic exclusion.
- It rejects equivocation, malformed dealer identity, duplicate dealer
  contributions, and out-of-context material by adding public transcript events
  with deterministic labels.

On `Complaint(event)`, `F_VSS_DKG` returns one of:

```text
ValidDealerFault
InvalidReceiverComplaint
Malformed
Inconclusive
```

The result is public, deterministic, bound to `(epoch_id, session_id, V, tau,
dealer, receiver)`, and anti-framing: except with negligible probability, a
corrupted receiver cannot turn an honest dealer's valid share delivery into an
attributable dealer fault.

On `Finalize`, `F_VSS_DKG` computes:

```text
AcceptedDealers
dkg_digest
pk_epoch
share_i for each id_i in V
```

The accepted-dealer set is a canonical function of the public transcript and
complaint outcomes, not network arrival order or local aggregator choice.
Every honest validator receives only its final share `share_i` and the public
outputs `(pk_epoch, dkg_digest, AcceptedDealers)`. The simulator receives
corrupted-validator state exactly as allowed by the corruption model.

### Guaranteed Properties

The main signing proof may treat `F_VSS_DKG` as providing:

- **Binding and extractability:** every accepted dealer contribution has one
  unique extractable degree-`< tau` polynomial and one corresponding public-key
  contribution.
- **Share consistency:** each accepted honest receiver share is the evaluation
  of the extracted dealer polynomial at that receiver index, and any `tau`
  valid final shares reconstruct the same epoch secret.
- **Hiding:** the adversary's view with fewer than `tau` corrupt validators
  reveals no unopened honest dealer share or honest dealer constant term beyond
  public outputs and allowed complaint leakage.
- **Output agreement:** all honest validators that finalize receive shares for
  the same `pk_epoch`, `AcceptedDealers`, and `dkg_digest`.
- **Complaint soundness and anti-framing:** public complaint outcomes attribute
  dealer faults, invalid receiver complaints, malformed frames, and
  inconclusive events without creating valid false evidence against honest
  validators.
- **Key-bias resistance:** conditioned on completion and at least one accepted
  honest dealer with unrevealed randomness, the final key distribution includes
  that honest contribution and is not biased by rushing, complaint scheduling,
  dealer exclusion, or transcript ordering beyond the bound stated by the DKG
  theorem assumption.
- **Transcript binding:** `dkg_digest` binds the epoch, session, validator set,
  threshold, accepted dealers, dealer public contributions, complaints,
  adjudication outcomes, and final key.

These guarantees are assumptions at the ideal boundary. They are not currently
implemented by `src/crypto/vss.rs`, whose default backend is a deterministic
transcript-hash scaffold.

## When the Main Proof May Cite Ideal VSS/DKG

The `F_TMLDSA` proof may cite `F_VSS_DKG` instead of a concrete backend only
when all of the following conditions hold:

1. The theorem or lemma explicitly labels DKG/VSS as an idealized setup
   assumption or hybrid step, such as the DKG simulation step in
   [real-ideal-simulator.md](real-ideal-simulator.md).
2. The claim is proof decomposition for threshold signing, not production
   deployment, production slashing, or backend readiness.
3. The proof consumes only the ideal outputs `pk_epoch`, `dkg_digest`,
   `AcceptedDealers`, validator shares, corruption leakage, and public
   complaint labels.
4. The proof does not rely on concrete VSS object sizes, commitment schemes,
   opening formats, zero-knowledge proof systems, ciphertext formats, or Rust
   verifier predicates.
5. Evidence used in the proof is ideal evidence only; it is not described as
   production slashing evidence or as evidence verified by the current
   scaffold code.
6. The adversary, corruption threshold, rushing behavior, network abstraction,
   and complaint semantics match the assumptions stated for `F_VSS_DKG`.
7. The production policy remains fail-closed unless both VSS/DKG and
   contribution-proof backends declare production profiles through the
   implementation gates.
8. The dependency is tracked as open in the proof obligations until a concrete
   backend closes binding, hiding, extractability, complaint soundness,
   anti-framing, key-bias resistance, and implementation fidelity.

If any proof step needs a concrete verifier predicate, complaint evidence
format, serialization theorem, parameter size, proof-system extractor, or
production-security claim, the proof must leave the ideal boundary and select
a concrete VSS/DKG backend.

## Decision Tree

Use this tree when deciding whether to keep the idealization or begin concrete
backend selection.

```text
1. Is the immediate goal to prove threshold signing assuming ideal setup?
   - Yes: keep `F_VSS_DKG`, cite it as an explicit ideal setup assumption, and
     mark the DKG realization theorem open.
   - No: go to 2.

2. Is the goal a production-security, deployment-readiness, or slashing claim?
   - Yes: idealization is insufficient; select and prove a concrete backend.
   - No: go to 3.

3. Does the argument need concrete VSS bytes, verifier predicates, complaint
   evidence, or implementation conformance?
   - Yes: select a concrete backend.
   - No: keep the ideal boundary and document the dependency.

4. If selecting a backend, can the construction stay in ML-DSA-compatible
   lattice/module algebra under post-quantum assumptions?
   - Yes: investigate lattice/vector commitments with opening proofs first.
   - No: go to 5.

5. Is a non-lattice Feldman/Pedersen-style assumption or algebra bridge
   explicitly acceptable for the claim?
   - Yes: document the extra assumption, the algebra bridge, and why it
     composes with ML-DSA before selection.
   - No: do not select Feldman/Pedersen-style commitments for production.

6. Before replacing the ideal boundary, has the candidate closed the selection
   checklist in [vss-backend-selection.md](vss-backend-selection.md)?
   - Yes: update the theorem, simulator, policy notes, and proof obligations
     to cite the concrete backend.
   - No: keep `F_VSS_DKG` as an assumption and keep backend selection open.
```

## Risk Table

| Path | Main benefit | Main risks | Current production status |
| --- | --- | --- | --- |
| Feldman/Pedersen-style commitments | Mature DKG templates and simple public share-opening checks when the algebra matches. | Conventional discrete-log assumptions are not post-quantum; Feldman is not hiding; Pedersen requires exact generator/randomness assumptions; ML-DSA algebra bridging and extractability remain unproved; anti-framing depends on concrete private-share delivery and opening rules. | Not selected. Not recommended unless a post-quantum-compatible analogue or explicitly accepted auxiliary assumption is documented and proved. |
| Lattice/vector commitments with opening proofs | Best alignment with `R_q`, ML-DSA-65 parameters, post-quantum assumptions, receiver-index binding, and public-key contribution consistency. | High parameter and implementation risk; proof sizes and verifier costs may be large; extractability, hiding, zero-knowledge, complaint evidence, and anti-framing must be proved for exact encodings; external cryptographic review is mandatory. | Recommended investigation path, but not selected. |
| Ideal functionality placeholder `F_VSS_DKG` | Lets the threshold signing proof isolate what it needs from setup: consistent shares, one public key, hiding below threshold, extractable accepted dealers, complaint labels, and key-bias resistance. | Assumes the hard VSS/DKG properties rather than implementing them; cannot satisfy production policy gates; can mislead readers if not labeled as an assumption; does not produce production complaint evidence or deployment parameters. | Allowed only as proof placeholder. Not eligible for production selection. |

## Recommendation

For the immediate proof path, keep `F_VSS_DKG` as an explicit ideal setup
assumption and use it to advance the `F_TMLDSA` threshold-signing proof
decomposition. This should unblock the signing-side hybrids while preserving a
clear open dependency for the DKG realization theorem.

This recommendation is not a production backend selection. It does not choose
Feldman/Pedersen, lattice/vector commitments, or any other concrete VSS/DKG
backend. It also does not change the current implementation status:
`src/crypto/vss.rs` remains a deterministic scaffold or production-shaped
candidate scaffold, and `src/crypto/production_policy.rs` must continue to
reject production-security claims unless real production VSS/DKG and
contribution-proof backends are both selected, implemented, proved, tested, and
reviewed.

Recommended next backend step: continue the concrete selection track with
lattice/vector commitments and opening proofs, because that path best matches
ML-DSA's post-quantum and module-lattice setting. Keep that work separate from
the ideal proof route until the selected construction closes the backend
selection checklist, the VSS/DKG security plan, and the proof obligation
tracker.
