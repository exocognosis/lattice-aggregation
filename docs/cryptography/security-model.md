# Strong Threshold ML-DSA-65 Security Model

Status: normative proof input for the no-single-holder research target. This is
not a security proof, implementation claim, audit result, or theorem closure.

Date: 2026-07-18

## SM-0. Scope and Claim Boundary

This document instantiates the base security model required by
[`formal-security-theorem.md`](formal-security-theorem.md). It governs the
strong threshold target specified in
[`threshold-mldsa-protocol-spec.md`](threshold-mldsa-protocol-spec.md): an
ordinary ML-DSA-65 signature is produced without any coordinator, aggregator,
validator, service, enclave, or other single process reconstructing the ML-DSA
secret key, its seed, the per-signature nonce seed, or the one-time mask.

The model is intentionally different from the coordinator-assisted Profile P1
path described in [`threshold-stack-architecture.md`](threshold-stack-architecture.md).
TEE/HSM confinement may be useful defense in depth, but it is not a trusted
assumption in this model and does not turn centralized seed reconstruction into
a realization of the strong theorem.

This model fixes the first proof target to **static active corruption**. It does
not claim adaptive security, guaranteed liveness, side-channel resistance,
implementation conformance, FIPS validation, or completed external review.

## SM-1. Parties and Parameters

For one key epoch, let:

- `V = (P_1, ..., P_n)` be the canonical ordered validator set;
- `t` be the authorization and secret-sharing threshold, with `1 <= t <= n`;
- `A` be the active network adversary;
- `Agg` be an untrusted public-message coordinator and output collector;
- `Z` be the environment that submits authorized signing requests;
- `f_sec` be the number of statically corrupted validators; and
- `f_live` be the number of validators unavailable or Byzantine in an
  execution for which completion is requested.

The confidentiality and unforgeability target requires `f_sec < t`. Completion
is conditional on at least `t` protocol-capable validators, so
`f_live <= n - t`. These are distinct bounds: the theorem may preserve safety
and secrecy in an execution for which it makes no progress claim.

For the planned production-shaped evidence campaign, `n = 10000` and
`t = 6667`. Thus completion evidence is conditioned on at most `3333`
unavailable validators; the unforgeability game still considers any static
corrupt set of size at most `6666` and permits abort.

## SM-2. Corruption Model

Before DKG starts, `A` chooses a static corrupt set `C subset V` with
`|C| = f_sec < t`. A corrupted validator may:

- expose all of its local state to `A`;
- deviate arbitrarily from DKG, MPC, signing, retry, and erasure rules;
- equivocate, send malformed frames, omit messages, or replay old frames;
- collude with `Agg` and every other corrupted validator;
- choose its randomness maliciously and rush after seeing honest round
  messages; and
- selectively abort before or after observing any value exposed by the
  protocol.

Honest validators follow the protocol and erase attempt-local state at the
normative points in the protocol specification. Erasure is hygiene in the base
static model, not a basis for an adaptive-security claim. An adaptive extension
requires a separate state-exposure theorem, forward-secure or non-committing
channels where needed, explicit erasure timing, and a simulator that handles
post-message corruption.

## SM-3. Network and Scheduling

The safety proof uses authenticated point-to-point channels and an
authenticated reliable-broadcast abstraction. Each delivered broadcast frame
has one sender, epoch, session, attempt, round, sequence number, and canonical
payload; all honest recipients deliver the same value or no value.

Private DKG shares use mutually authenticated, confidential channels with
replay protection. The channel construction and its assumptions must be named
in the implementation proof package. Channel confidentiality is not a
substitute for VSS hiding or share-validation proofs.

`A` controls delivery order, delay, omission, duplication, and corrupted-party
contents. It is rushing within every logical round. Liveness is claimed only
after the synchrony condition selected by the deployment profile holds. Before
that point, timeout records may drive retry or exclusion but are not by
themselves slashable evidence.

If reliable broadcast is instantiated through a Byzantine consensus layer,
that layer's own resilience bound applies in addition to `f_sec < t`. The proof
package must not infer `n >= 3f + 1` merely from the signing threshold; it must
state the actual broadcast assumption and reconcile its fault bound with the
deployment profile.

## SM-4. Aggregator and Coordinator Boundary

`Agg` is fully untrusted. It may choose subsets, reorder public frames, propose
malformed transcripts, suppress valid contributions, and publish arbitrary
candidate signatures. Honest validators accept only canonical, quorum-bound
protocol state, and public consumers accept only signatures that pass the
unmodified ML-DSA-65 verifier.

The following is a normative invariant:

> No coordinator or aggregator interface accepts, reconstructs, returns, logs,
> serializes, or retains the full ML-DSA secret key, the FIPS key-generation
> seed, the secret `K` value, the per-signature `rho_prime_prime` value, or the
> full one-time mask `y`.

Secret values remain in the selected actively secure MPC sharing throughout
key generation and signing. The only signature-path declassifications are the
public key, permitted public transcript fields, one accepted standard ML-DSA
signature, a session-level completion or abort result, and public fault evidence
proved noninterfering. A debugger, crash report, trace collector, enclave API,
or test harness that materializes a prohibited value violates this model.

The DKG public-output step may additionally declassify the ephemeral full
public relation `t = A*s1+s2` and its `Power2Round` low part `t0`. FIPS 204 does
not require the low bits of `t` to remain secret. A conforming implementation
may therefore combine public `t` contributions before rounding. It must still
retain exact `t0` signing state (publicly or in authenticated shares), and this
declassification does not permit disclosure of `s1`, `s2`, `K`, the
key-generation seed, or any reconstructable equivalent.

## SM-5. Authorization and Signing Queries

`Z` may authorize a signing request only by producing a canonical authorization
certificate bound to:

```text
(epoch_digest, pk, message_mode, context, message_digest, signer_set, policy)
```

The certificate must contain at least `t` unique valid validator approvals or a
consensus certificate whose proof is explicitly reduced to that threshold.
Session identifiers, signer sets, and messages are adversarially chosen subject
to uniqueness and authorization checks.

An accepting signature for a message/context pair without a valid certificate
is an unauthorized output even if it passes `MLDSA65.Verify`. Replay of a valid
certificate under another epoch, public key, message, context, signer set, or
policy is rejected.

## SM-6. Security Goals

The strong theorem proof package must establish all of the following under the
same parameters and assumptions:

1. **Key privacy and no reconstruction.** Any view containing fewer than `t`
   validator states, all public messages, and all allowed leakage is simulatable
   without the full secret key or seeds.
2. **Threshold unforgeability.** An unauthorized accepting signature reduces to
   ML-DSA-65 EUF-CMA or to a named DKG, VSS, MPC, commitment, or authorization
   assumption violation.
3. **Correctness and standard compatibility.** Every completed session emits
   the ordinary 3309-byte ML-DSA-65 encoding accepted by an unmodified verifier
   for the same public key, message mode, context, and message.
4. **Transcript and contribution soundness.** DKG, authorization, MPC,
   commitment, partial-opening, retry, and evidence records cannot be replayed
   or transplanted across typed contexts.
5. **Distribution compatibility.** Conditioned on completion, accepted outputs
   have the standard ML-DSA-65 signing distribution, or a precisely stated
   reviewed distance bound. The exact-MPC construction targets distance zero at
   the algorithmic level, subject to the pseudorandomness and implementation
   assumptions used by FIPS 204.
6. **Abort noninterference.** Public abort and retry behavior leaks no more than
   the declared leakage profile and does not give `A` a selective-abort bias
   exceeding the proved bound.
7. **Evidence noninterference.** Public fault evidence neither reveals honest
   shares or masks nor creates additional signing capability.

## SM-7. Allowed Leakage

The base model permits disclosure of:

- protocol identifiers and versions;
- epoch identifier, `n`, `t`, canonical validator-set digest, public key, and
  DKG transcript digest;
- the DKG public-output intermediate `t = A*s1+s2` and derived `t0`, when bound
  to the finalized epoch and erased where it is not retained as signing state;
- authorized message/context or their application-approved digest;
- requested signer set and authorization certificate;
- public MPC frame metadata and authenticated transcript digests;
- the final accepted ML-DSA signature;
- one session-level completion, timeout, or abort result; and
- public, anti-framing evidence records.

The base model does not permit disclosure of:

- honest key shares, VSS openings, or MPC authentication keys;
- the joint key-generation seed or any reconstructable equivalent;
- honest `K`, `rho_prime_prime`, mask, response, low-bit, or hint state before
  the protocol's explicit aggregate declassification;
- per-attempt secret rejection predicates or a data-dependent attempt trace;
- private complaint material not proved safe for public release; or
- logs, timings, error strings, or memory artifacts that distinguish honest
  secret-dependent branches beyond the proved leakage profile.

## SM-8. MPC Assumption Boundary

The protocol requires a concrete actively secure MPC construction with:

- privacy and correctness against the declared static corrupt bound;
- authenticated secret sharing or an equivalent integrity mechanism;
- malicious-input validation;
- identifiable abort or an explicitly modeled non-attributable abort;
- secure generation of joint random inputs;
- a proof for the concrete arithmetic and Boolean circuit compilation; and
- a transcript and implementation binding suitable for independent review.

Naming “MPC” or invoking MPC completeness is not sufficient. The selected
protocol, field/ring embeddings, corruption threshold, setup assumptions,
preprocessing, output-delivery semantics, and concrete security loss must all be
recorded and proved.

The `k = 64` committee described in
[`distributed-mask-mpc-feasibility.md`](distributed-mask-mpc-feasibility.md) is
a prototype scope, not part of this base theorem. A committee construction may
replace full signer-set MPC only after an additional theorem proves the
authorization bridge, share conversion, committee corruption bound, key
privacy, and inability of the committee to sign without `t` validator
authorizations. Committee selection alone does not preserve the `t`-of-`n`
theorem.

## SM-9. Explicit Non-Goals

This base model does not claim:

- adaptive corruption security;
- guaranteed output delivery against arbitrary aborts;
- security from a centralized signer confined in a TEE or HSM;
- CAVP/ACVTS or FIPS module validation;
- side-channel closure without implementation review;
- production readiness; or
- theorem closure merely because a large aggregation campaign succeeds.

The status `internally_closed_pending_independent_review` is defined separately
in
[`internal-theorem-closure-candidate.md`](internal-theorem-closure-candidate.md).
It is a digest-bound internal review state, not an external validation or public
security claim.

## SM-10. Traceability

This model instantiates FST-D1 through FST-D5 and the static branch of FST-D2 in
[`formal-security-theorem.md`](formal-security-theorem.md). It refines the
options in [`active-adversary-model.md`](active-adversary-model.md) by selecting
static active corruption and by separating secrecy, completion, and broadcast
fault bounds. It supplies the adversary and leakage inputs needed by
[`ideal-functionality.md`](ideal-functionality.md), while leaving the simulator
and reduction obligations open.
