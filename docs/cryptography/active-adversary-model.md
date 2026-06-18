# Active Adversary Model for Proof-Grade VSS/DKG
<a id="active-adversary-model"></a>

Date: 2026-05-27

## Scope

This document defines the adversary and network options that a full
cryptographic proof must choose before production VSS/DKG can be claimed. It is
not a proof that the current repository implements these properties.

The current code reviewed for this note includes deterministic simulation
surfaces in `src/dkg.rs`, `src/crypto/vss.rs`, `src/backend.rs`,
`src/transcript.rs`, `src/collections.rs`, `src/adapter/evidence.rs`, and
`src/adapter/wire.rs`. The deterministic VSS and simulated DKG code are test
fixtures only.

## Parameters

Let:

- `n` be the number of validators in the epoch.
- `C` be the adversarially controlled validator set.
- `f = |C|` be the active corruption bound.
- `tau` be the signing, reconstruction, and VSS polynomial threshold unless a
  proof explicitly separates those thresholds.
- `lambda` be the cryptographic security parameter.

The baseline production proof target must satisfy:

- `0 <= f < tau <= n - f` for secrecy against corrupt validators, unforgeability
  of threshold signing shares, and honest-party availability.
- If complaint agreement relies on a partially synchronous Byzantine broadcast
  or consensus layer, `n >= 3f + 1` is required for that layer unless the proof
  instantiates a stronger authenticated broadcast abstraction with its own
  assumptions.
- If the consensus protocol requires quorum certificates of size `q`, the DKG
  proof must state whether `tau = q`, `tau = f + 1`, or a distinct threshold is
  used, and must prove that the chosen value is compatible with consensus
  safety and signing unforgeability.

## Corruption Options

The proof must choose exactly one corruption model for the first production
claim. A later stronger model must be proved as a separate theorem.

### Option A: Static Active Corruptions

The adversary chooses `C` before DKG setup and before seeing honest
commitments, encrypted shares, complaints, or signing transcripts. Corrupted
validators may deviate arbitrarily, equivocate where the network permits it,
withhold messages, submit malformed messages, and coordinate all private state.

Required theorem shape:

- Privacy: for any `f < tau`, the adversary's view before reconstruction is
  computationally indistinguishable for any two honest joint secrets that induce
  the same public key distribution.
- Correctness and agreement: all honest validators that complete DKG output
  shares for the same joint public key and accepted-dealer set.
- Robustness: if enough honest validators remain online, malicious dealers or
  receivers are either accepted with a well-defined contribution or excluded by
  publicly checkable evidence.

### Option B: Adaptive Active Corruptions With Erasures

The adversary may choose whom to corrupt during the protocol, after observing
public messages and scheduled delivery. Upon corruption, it obtains the
validator's unerased local state.

This option requires all of the static guarantees plus:

- Explicit erasure points after sending encrypted shares, proofs, complaint
  responses, signing masks, and any randomness whose later disclosure would
  break hiding or simulation.
- A proof that erased randomness is not needed for later honest behavior.
- Private-channel encryption that remains secure under adaptive exposure of
  long-term validator keys, or a non-committing or forward-secure channel model
  that the proof states precisely.
- A state-exposure theorem showing that corrupting fewer than `tau` validators
  over time does not reveal the joint secret before a valid reconstruction or
  signature-combining event.

Without these erasure and channel assumptions, the implementation must not
claim adaptive security.

### Option C: Adaptive Active Corruptions Without Erasures

This is not an acceptable first production target for this repository unless a
new protocol is selected that is specifically proved under full state exposure.
The current simulation and VSS scaffold provide no basis for such a claim.

## Rushing Behavior

The active adversary is rushing within each broadcast round:

- It sees all honest messages scheduled for the round before choosing corrupted
  validators' messages for that same round.
- It may send different messages to different recipients unless the protocol
  uses reliable broadcast or consensus to enforce a single canonical value.
- It may delay, drop, or reorder corrupted-party messages subject to the chosen
  synchrony model.
- It may selectively abort corrupted validators after seeing honest
  commitments, complaint responses, or signing commitments.

The proof must show that rushing does not let the adversary bias the DKG public
key, create inconsistent honest outputs, frame honest validators, or influence
the Fiat-Shamir challenge outside the protocol's stated abort probability.

## Network Model

Production proofs must bind to one network abstraction:

- Synchronous rounds: all honest-to-honest messages sent in round `r` arrive by
  the end of round `r`, and timeout evidence is defined against that round
  clock.
- Partial synchrony: messages may be delayed before GST; after GST,
  honest-to-honest messages arrive within a known bound. Liveness claims must
  be conditioned on post-GST execution.
- Authenticated broadcast abstraction: every broadcast value has one canonical
  sender, session, epoch, and round value, and all honest validators either
  deliver the same value or no value.

All messages must be signed or otherwise authenticated, domain-separated by
protocol label, version, epoch, session ID, dealer, receiver when applicable,
round number, validator set digest, threshold, and message type.

## Current Proof-Closure Route Selection
<a id="eps-withhold-production-route-selection"></a>

The immediate `eps_withhold` proof route is scoped to Option A, static active
corruptions, with rushing behavior inside each protocol round. This selection
is a theorem-planning boundary only; it is not a claim that the current
implementation proves static active security.

For the H5 -> H6 selective-abort route in
[withholding-abort-bound.md](withholding-abort-bound.md), the proof must use:

- static corruptions fixed before DKG and before signing commitments;
- authenticated, context-bound broadcast or an explicitly modeled
  partially-synchronous transport;
- a concrete retry cap `R_max`;
- deterministic timeout and signer-exclusion rules;
- an explicit abort-observable set `O_abort`;
- a separate availability statement for denial of service.

Adaptive corruptions, erasure-dependent claims, and production slashing
soundness remain outside this first route.

## Complaint and Evidence Semantics

Complaint evidence must be precise enough to support anti-framing. The current
`SlashingEvidence` and `SlashingEvidencePayload` types are local adapter
containers, not production slashing authority.

A production complaint record must include:

- The complete canonical transcript prefix needed to verify context: protocol
  version, epoch, session ID, validator set digest, threshold, dealer,
  receiver, round, message type, and relevant public commitments.
- The signed or authenticated wire frame being challenged.
- A public verification predicate that returns `Valid`, `InvalidDealer`,
  `InvalidReceiverComplaint`, `Malformed`, or `Inconclusive`.
- A replay and equivocation rule: duplicate frames are ignored unless they
  prove equivocation under the same context.
- A privacy rule stating which complaint paths reveal an individual share, and
  a proof that revealed complaint material does not reveal the joint secret
  when fewer than `tau` valid shares are exposed.

Dealer-fault evidence is valid only if a public verifier can confirm at least
one of:

- The encrypted share fails to decrypt under the receiver's authenticated
  channel transcript and the receiver supplies a decryption-failure proof
  accepted by the selected encryption model.
- The decrypted share is not consistent with the dealer's VSS commitment and
  proof, and the receiver supplies the signed share frame plus a public opening
  or zero-knowledge failure witness required by the VSS.
- The dealer equivocated by signing two conflicting commitments, shares, or
  complaint responses for the same canonical context.
- The dealer failed to answer a valid complaint before the adjudication
  deadline defined by the network model.

Receiver-fault evidence is valid only if the dealer or another verifier can
show the complaint contradicts a valid, authenticated, commitment-consistent
share for that receiver and context.

Timeout or liveness evidence must not be slashable by itself unless the
consensus layer proves delivery assumptions strong enough to distinguish
withholding from network delay. Under partial synchrony before GST, timeout
records are retry or exclusion inputs, not final slashing evidence.

## Output Agreement and Finality

Every honest validator that completes DKG must output:

- The same validator set digest.
- The same accepted-dealer set.
- The same ordered VSS commitment transcript.
- A private share that verifies against the joint public key.
- The same joint public key.

If an honest validator cannot derive these exact values, it must halt,
complain, or request transcript repair. It must not silently finalize a
different key.

## Non-Goals for the Current Scaffold

The current deterministic simulation code does not provide:

- Malicious-secure VSS.
- Adaptive corruption security.
- Production complaint soundness or anti-framing.
- Bias-resistant DKG.
- Production slashing predicates.
- A proof that simulated aggregate signatures are standard ML-DSA signatures.
