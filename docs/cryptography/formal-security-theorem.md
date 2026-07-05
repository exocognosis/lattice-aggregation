# Formal Security Theorem for Threshold ML-DSA-65

Status: proof target, not a completed proof.

Date: 2026-05-27

## FST-0. Scope and Reading Notes

This document states the formal security theorem that the project must prove
before the threshold ML-DSA design can move from research scaffold to production
cryptography. It is intentionally stronger than the current implementation.

The current Rust backend is deterministic simulation machinery. It exercises API
shape, transcript binding, canonical collection validation, and aggregation
control flow. It does not instantiate ML-DSA signing, does not verify standard
ML-DSA signatures, and does not satisfy the theorem below.

This document depends on related proof artifacts in two states.

Present in this checkout:

- `docs/cryptography/formal-threshold-mldsa-transcript.md`
- `docs/cryptography/proof-obligations.md`

Still missing:

- `docs/cryptography/security-model.md`
- `docs/cryptography/threshold-mldsa-protocol-spec.md`

Until the missing model and protocol inputs are added and the listed proof
obligations are discharged, this document should be treated as a precise target
statement and dependency map, not as evidence that a proof has been completed.

## FST-1. Objects and Notation

Let `lambda` be the security parameter. Let `MLDSA65.KeyGen`,
`MLDSA65.Sign`, and `MLDSA65.Verify` denote the FIPS 204 ML-DSA-65 algorithms,
with public key `pk`, secret key `sk`, message `m`, and signature `sigma`.

Let `n` be the validator count, `t` the reconstruction threshold, and
`V = (id_1, ..., id_n)` the canonical ordered validator set. Threshold
parameters are valid when `1 <= t <= n` and every validator identifier is
unique. A threshold key-generation protocol outputs public key `pk`, local key
shares `sk_i`, and verification metadata `vk_i` for each validator.

The current operating-parameter contract for the selected production-candidate
direction is `native-threshold-mldsa65-aggregation-p1`, documented in
`docs/cryptography/thesis-operating-parameters.md` and
`docs/cryptography/thesis-operating-parameters.json`. That contract records
the Profile P1 notation and guardrails for review; it does not close this
theorem or claim production threshold ML-DSA security.

A signing session is identified by:

- session identifier `sid`
- threshold `t`
- canonical validator set `V`
- threshold public key `pk`
- message `m`
- ordered commitment map `Com`

The transcript function is written as:

```text
T = TMLDSA.Transcript(sid, t, V, pk, m, Com)
c = H_T(T)
```

where `H_T` is the domain-separated challenge derivation function. In the
current implementation, the transcript label is
`lattice-aggregation/threshold-mldsa65` with protocol version `1`, and the
challenge is derived with SHAKE256 over canonical encodings.

## FST-2. Adversary Model

Definition FST-D1, network adversary. The adversary `A` controls scheduling,
message delivery, message omission, duplication, and corruption of network
messages. The adversary may adaptively choose signing messages, session IDs,
validator subsets, and the order in which honest parties receive messages.

Definition FST-D2, corruption model. The base theorem targets static
corruption of at most `t - 1` validators before distributed key generation. An
adaptive-corruption extension may be proved later, but it requires erasures for
one-time signing masks and a separate state-exposure model.

Definition FST-D3, Byzantine behavior. Corrupted validators may deviate from all
protocol steps, publish malformed commitments, equivocate across sessions,
submit invalid partial signatures, abort after commitment, or collude with an
aggregator.

Definition FST-D4, aggregator. The aggregator is untrusted. It may be corrupted,
may choose any subset of received commitments or partial shares, and may attempt
to output signatures without involving `t` honest-consistent shares. The
aggregator receives only public transcript material and submitted partial
shares.

Definition FST-D5, signing oracle access. `A` may request threshold signatures
on messages of its choice for sessions that satisfy the protocol admission
rules. A session must bind `sid`, `t`, `V`, `pk`, `m`, and ordered commitments
before any challenge-dependent partial signature is produced.

Definition FST-D6, target forgery. A forgery is a pair `(m*, sigma*)` such that
`MLDSA65.Verify(pk, m*, sigma*) = accept`, while `m*` was not authorized through
the threshold signing functionality for the target key and validator set.

## FST-3. Security Assumptions

Assumption FST-A1, ML-DSA-65 unforgeability. ML-DSA-65 is strongly
existentially unforgeable under chosen-message attack in the relevant quantum
random-oracle model or standard-model interpretation accepted for FIPS 204
analysis.

Assumption FST-A2, threshold sharing soundness. The DKG or dealer-based sharing
procedure produces shares whose interpolation reconstructs the ML-DSA secret
material only from authorized sets of size at least `t`, and any set of fewer
than `t` shares leaks no computationally useful information about `sk`.

Assumption FST-A3, verifiable share binding. Public verification metadata binds
each validator identifier to exactly one share for the target epoch and public
key. Invalid DKG shares are rejected or produce publicly attributable evidence.

Assumption FST-A4, commitment binding and hiding. Each signing commitment binds
a validator to a unique local masking contribution before the Fiat-Shamir
challenge is derived, while hiding the contribution well enough to preserve the
ML-DSA signing distribution.

Assumption FST-A5, abort and noise-bound preservation. The threshold signing
protocol preserves the distribution of ML-DSA masking and response values,
including all rejection-sampling, norm, hint-vector, and challenge-consistency
checks required for ML-DSA-65.

Assumption FST-A6, partial signature correctness and extractability. A valid
partial signature verifies against the signer metadata, transcript, commitment,
and public key. Invalid partial signatures are rejected before aggregation or
yield attributable evidence.

Assumption FST-A7, transcript collision resistance and domain separation.
Canonical transcript encoding is injective over all typed fields that affect
the challenge, and `H_T` is modeled as a domain-separated random oracle or a
collision-resistant XOF derivation sufficient for the selected ML-DSA proof.

Assumption FST-A8, canonical collection validation. Commitment and partial-share
sets reject duplicate validators, unknown validators, threshold mismatch, and
validator-set mismatch. Iteration order is canonical and independent of network
arrival order.

Assumption FST-A9, implementation constant-time discipline. Production
implementations of share generation, partial verification, aggregation, and
secret erasure do not leak enough timing, memory-access, logging, or error-path
information to invalidate the cryptographic proof.

## FST-4. Games

Game FST-G1, threshold EUF-CMA. The challenger runs threshold key generation for
`(t, n, V)`, gives `pk` and corrupted-party state to `A`, answers signing
queries by executing honest threshold signing sessions, and finally receives
`(m*, sigma*)`. `A` wins if FST-D6 holds.

Game FST-G2, ideal functionality indistinguishability. The real protocol
execution is compared against the ideal execution with `F_TMLDSA` from
`ideal-functionality.md`. `A` wins if an environment distinguishes real from
ideal execution with non-negligible advantage.

Game FST-G3, transcript-binding attack. `A` wins if it obtains one valid
partial signature or aggregate signature whose challenge can be interpreted as
binding to two distinct typed transcript tuples.

Game FST-G4, rogue-share attack. `A` wins if a validator outside `V`, a
duplicate identifier, or an unverified key share contributes to an accepting
aggregate signature for `pk`.

Game FST-G5, abort-bias attack. `A` wins if selective aborts, malformed
commitments, or partial-share omission cause the distribution of accepted
aggregate signatures to deviate from ML-DSA-65 by more than the bound allowed by
the ML-DSA proof.

## FST-5. Lemma Targets

Lemma FST-L1, canonical transcript injectivity. For all valid sessions, two
distinct typed transcript tuples produce distinct canonical encodings except
with negligible encoding collision probability. This lemma must be proved over
the exact byte encoding used by the production transcript implementation.

Lemma FST-L2, challenge binding. Under FST-A7 and FST-L1, an adversary cannot
reuse a commitment set or partial signature across different values of `sid`,
`t`, `V`, `pk`, `m`, or `Com` except with negligible probability.

Lemma FST-L3, validator-set soundness. Under FST-A8, accepted commitment and
partial-share collections contain only unique validators from `V` and contain at
least `t` entries.

Lemma FST-L4, partial-share validity. Under FST-A3, FST-A4, and FST-A6, every
partial share accepted for aggregation is attributable to one validator and one
bound transcript.

Lemma FST-L5, aggregation correctness. If at least `t` valid partial shares are
accepted for the same transcript, aggregation outputs `sigma` such that
`MLDSA65.Verify(pk, m, sigma) = accept`.

Lemma FST-L6, no subthreshold signing. Under FST-A2 and FST-A6, any adversary
corrupting fewer than `t` validators cannot produce accepting aggregate
signatures for unauthorized messages except by breaking ML-DSA-65 or a listed
threshold assumption.

Lemma FST-L7, abort compatibility. Under FST-A5, the distribution of accepted
threshold signatures is computationally indistinguishable from the distribution
of ordinary ML-DSA-65 signatures for the same key and message.

Lemma FST-L8, ideal extraction. For every real adversary corrupting fewer than
`t` validators, there exists a simulator that can translate real signing
requests, aborts, invalid shares, and aggregate outputs into calls to
`F_TMLDSA` without changing the environment view except negligibly.

Lemma FST-L9, evidence noninterference. Evidence generation for malformed
messages, duplicate messages, missing partials, and invalid partials does not
expose honest secret share material and does not create additional signing
capability.

## FST-6. Theorem Statements

Theorem FST-T1, threshold unforgeability target. Assuming FST-A1 through
FST-A8, for any probabilistic polynomial-time adversary corrupting at most
`t - 1` validators, the advantage in Game FST-G1 is negligible in `lambda`.

Proof status: not proved in this repository. Required lemmas include FST-L1
through FST-L7.

Theorem FST-T2, real/ideal threshold-signing realization target. Assuming
FST-A1 through FST-A9 and the ideal functionality `F_TMLDSA`, the production
threshold protocol UC-realizes `F_TMLDSA` against static Byzantine corruption of
at most `t - 1` validators in the random-oracle model selected for ML-DSA-65.

Proof status: not proved in this repository. Required lemmas include FST-L1
through FST-L9 plus a complete simulator construction.

Theorem FST-T3, transcript non-malleability target. Assuming FST-A7 and
FST-A8, the advantage of any adversary in Game FST-G3 is negligible.

Proof status: partially supported by current implementation tests for canonical
ordering and deterministic challenge derivation, but no formal encoding proof is
present.

Theorem FST-T4, implementation conformance target. If a production backend
implements the protocol specification, partial-share verification, aggregation,
standard ML-DSA verification, constant-time secret handling, and transcript
encoding exactly as modeled, then passing the implementation conformance suite
is necessary but not sufficient evidence for FST-T1 or FST-T2.

Proof status: engineering gate only. This theorem is a traceability statement,
not a cryptographic reduction.

## FST-7. Real-to-Ideal Proof Shape

The intended proof of FST-T2 should proceed through hybrids:

Hybrid FST-H0. Real production protocol with real DKG, commitments, partial
shares, aggregation, and network scheduling.

Hybrid FST-H1. Replace network delivery with ideal scheduling while preserving
the adversary-visible message trace.

Hybrid FST-H2. Replace rejected malformed, duplicate, or invalid messages with
ideal evidence events.

Hybrid FST-H3. Replace honest partial-share generation with simulated shares
whose only accepting aggregate output is obtained through the ideal signing
interface.

Hybrid FST-H4. Replace aggregate signatures with signatures returned by
`F_TMLDSA.Sign`.

Hybrid FST-H5. Ideal execution. All authorized signing occurs through
`F_TMLDSA`; unauthorized aggregate output would imply a forgery against
ML-DSA-65 or a violation of a threshold assumption.

Each hybrid transition needs an explicit distinguishing bound. No such bounds
are currently supplied.

## FST-8. Current Implementation Traceability

The current code has engineering hooks that correspond to proof obligations:

- `src/transcript.rs` binds protocol label, version, session ID, threshold,
  validator set, public key, message, and ordered commitments.
- `src/collections.rs` rejects duplicate validators, unknown validators,
  invalid thresholds, insufficient commitments, and insufficient partial shares.
- `src/protocol.rs` enforces a commitment-before-challenge signing flow through
  type-state transitions.
- `src/aggregation.rs` requires partial-share threshold and validator-set
  agreement with the transcript before aggregation.
- `src/backend.rs` defines the production backend boundary, but the current
  `SimulatedBackend` is not a cryptographic instantiation.
- `src/adapter/evidence.rs` records local evidence categories, but it is not a
  proof of slashability or a chain-specific fraud proof.

These hooks are useful for conformance and review, but they do not prove any
cryptographic theorem.

## FST-9. Explicit Limitations

Limitation FST-X1. The selected P1 threshold ML-DSA route is a review
direction only; the production security model, full protocol specification,
and proof remain open.

Limitation FST-X2. No formal DKG, dealer, or share-verification proof is
present.

Limitation FST-X3. No ML-DSA-65 Fiat-Shamir-with-aborts preservation proof is
present for the threshold setting.

Limitation FST-X4. No partial-signature verification algorithm is specified at
the mathematical level.

Limitation FST-X5. No simulator for adaptive corruption is specified. Adaptive
security requires erasure semantics and state-exposure rules.

Limitation FST-X6. No side-channel model or constant-time audit is complete.

Limitation FST-X7. The deterministic simulation backend must not be used as
evidence for FST-T1 or FST-T2.

Limitation FST-X8. The ideal functionality currently models signing authority,
availability, and evidence events, but it does not by itself prove that a real
protocol realizes them.

## FST-10. Proof Dependencies for Later Workers

To complete this theorem package, later work must provide:

- A full protocol specification with exact algorithms for DKG, commitment,
  partial signing, partial verification, aggregation, rejection sampling, and
  standard verification.
- Complete the transcript-encoding proof in
  `formal-threshold-mldsa-transcript.md`, including machine-checkable
  injectivity tests or proof.
- A noise-bound and abort-preservation proof specialized to ML-DSA-65.
- A reduction from threshold forgery to ML-DSA-65 forgery plus threshold-share
  assumption violations.
- A simulator for `F_TMLDSA` with explicit corruption, abort, evidence, and
  scheduling behavior.
- A production backend conformance suite with known-answer tests against
  standard ML-DSA-65 verification.
- An implementation security review covering side channels, zeroization,
  panic/error behavior, serialization, and transcript compatibility.
