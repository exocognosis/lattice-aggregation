# Ideal Functionality F_TMLDSA
<a id="ideal-functionality-ftmldsa"></a>

Status: ideal functionality draft, not a realization proof.

Date: 2026-05-27

## IF-0. Purpose and Scope

This document defines the ideal threshold ML-DSA-65 signing functionality
`F_TMLDSA` that the production protocol should realize. It is intended to pair
with `formal-security-theorem.md`.

`F_TMLDSA` specifies the target behavior for key registration, threshold signing,
abort handling, signature release, and evidence notification. It does not define
the concrete distributed protocol, does not prove that the current repository
realizes the functionality, and does not apply to the deterministic simulation
backend as production cryptography.

## IF-1. Parties, Roles, and Parameters

Definition IF-D1, parties. The functionality interacts with:

- validators `P_i`, each identified by `ValidatorId id_i`
- an untrusted aggregator `Agg`
- an environment `Z`
- an adversary or simulator `S`
- an optional evidence consumer `E`

Definition IF-D2, session parameters. A key epoch is identified by:

```text
epoch = (key_id, t, V, pk)
```

where `key_id` is a unique key-epoch identifier, `t` is the threshold,
`V = (id_1, ..., id_n)` is the canonical validator set, and `pk` is an
ML-DSA-65 public key.

Definition IF-D3, signing session. A signing session is identified by:

```text
sid = (key_id, session_nonce)
ctx = (sid, t, V, pk, m)
```

The real protocol may encode `sid` as 32 bytes, but the ideal functionality
treats it as a typed value bound to one key epoch and one message.

Definition IF-D4, corruption threshold. The base functionality permits the
adversary to corrupt at most `t - 1` validators for unforgeability claims. If
`t` or more validators are corrupted, `F_TMLDSA` may allow the adversary to
authorize signatures because the threshold key is considered compromised.

## IF-2. Internal State

For each `epoch`, `F_TMLDSA` stores:

- `params[epoch] = (key_id, t, V, pk)`
- `corrupt[epoch]`, the set of corrupted validators
- `authorized[epoch]`, a set of messages authorized for signing
- `sessions[sid]`, a signing-session record
- `released[epoch]`, a set of released `(m, sigma)` pairs
- `evidence[epoch]`, a log of attributable faults

Each signing-session record contains:

```text
record sid:
    key_id
    message m
    status in {open, aborted, signed}
    requested_signers set
    committed_signers set
    partial_signers set
    invalid_events list
    release_policy in {release_to_requester, release_to_all, adversary_scheduled}
```

## IF-3. Interfaces

Interface IF-I1, register key epoch.

On input:

```text
(RegisterKey, key_id, t, V, pk)
```

from the environment or trusted setup, `F_TMLDSA` verifies:

- `1 <= t <= |V|`
- all validator identifiers in `V` are unique
- `pk` has the ML-DSA-65 public-key encoding length
- `key_id` is unused

If validation succeeds, it stores the epoch and returns:

```text
(KeyRegistered, key_id, t, V, pk)
```

If validation fails, it returns:

```text
(KeyRegistrationRejected, key_id, reason)
```

Interface IF-I2, corrupt validator.

On input:

```text
(Corrupt, key_id, id_i)
```

from `S`, `F_TMLDSA` records `id_i` as corrupted for the epoch and returns the
ideal leakage allowed by the corruption model. In the static-corruption base
model, this interface is only available before signing begins for the epoch.
Adaptive corruption requires an extension that defines erasures and exposure of
in-progress signing masks.

Interface IF-I3, request signing.

On input:

```text
(SignRequest, key_id, sid, m, requested_signers, release_policy)
```

from the environment, a validator, or an authorized client, `F_TMLDSA` verifies:

- `key_id` is registered
- `sid` is unused
- `requested_signers` is a subset of `V`
- `|requested_signers| >= t`

If validation succeeds, it creates an open session and leaks to `S`:

```text
(SignRequestLeak, key_id, sid, t, V, pk, m, requested_signers)
```

The message `m` is recorded as authorized for the epoch. If validation fails,
it returns:

```text
(SignRequestRejected, key_id, sid, reason)
```

Interface IF-I4, observe commitment.

On input:

```text
(CommitObserved, key_id, sid, id_i)
```

from a validator or `S`, `F_TMLDSA` verifies that the session is open and
`id_i` is in `requested_signers`. If valid, `id_i` is added to
`committed_signers`.

If `id_i` is unknown, duplicated in a way the real protocol would attribute, or
outside the requested signer set, `F_TMLDSA` appends an evidence event
`IF-E1` or `IF-E2`.

Interface IF-I5, observe partial signature.

On input:

```text
(PartialObserved, key_id, sid, id_i, validity)
```

from a validator or `S`, `F_TMLDSA` verifies that the session is open, `id_i` is
in `V`, and `id_i` committed for this session. If `validity = valid`, `id_i` is
added to `partial_signers`.

If `validity = invalid`, or if the partial is not associated with a valid
commitment, `F_TMLDSA` appends evidence event `IF-E3`.

Interface IF-I6, abort session.

On input:

```text
(Abort, key_id, sid, reason)
```

from `S` or from timeout policy, `F_TMLDSA` marks the session aborted if it is
open. If a validator committed but did not provide a partial before timeout, it
appends evidence event `IF-E4` for each attributable missing partial.

The functionality leaks:

```text
(SessionAborted, key_id, sid, reason)
```

to the parties allowed by the release policy.

Interface IF-I7, release signature.

On input:

```text
(ReleaseSignature, key_id, sid)
```

from `S`, `Agg`, or policy, `F_TMLDSA` checks that:

- the session is open
- `|partial_signers| >= t`
- `m` was authorized by `IF-I3`

If the checks pass, `F_TMLDSA` obtains:

```text
sigma <- MLDSA65.Sign(sk_ideal[key_id], m)
```

or, in a formulation without ideal secret-key storage, asks the external
signature oracle to return a valid ML-DSA-65 signature for `(pk, m)`.

It stores `(m, sigma)`, marks the session signed, and releases:

```text
(Signature, key_id, sid, m, sigma)
```

according to the session release policy.

If the checks fail, it returns:

```text
(ReleaseRejected, key_id, sid, reason)
```

Interface IF-I8, verify public signature.

On input:

```text
(Verify, key_id, m, sigma)
```

`F_TMLDSA` returns:

```text
(VerifyResult, key_id, m, sigma, MLDSA65.Verify(pk, m, sigma))
```

This interface models public ML-DSA verification and does not grant signing
capability.

## IF-4. Evidence Events

Evidence event IF-E1, unknown validator. A message is attributed to an
identifier not in `V`.

Evidence event IF-E2, duplicate or equivocated message. A validator sends two
distinct commitments or partials for the same typed session context.

Evidence event IF-E3, invalid partial signature. A submitted partial fails
verification against `(sid, t, V, pk, m, commitment, id_i)`.

Evidence event IF-E4, commitment without partial. A validator committed for an
open session but did not provide a valid partial before timeout.

Evidence event IF-E5, malformed wire message. A message cannot be decoded into
the canonical protocol grammar.

Evidence event IF-E6, session timeout. A session fails to collect enough valid
commitments or partials before its deadline.

Evidence events are ideal notifications. They are not by themselves slashing
transactions, consensus state transitions, or proof that an external chain can
verify the fault.

## IF-5. Security Invariants

Invariant IF-S1, threshold authorization. No signature is released for a session
unless at least `t` valid partial signers were observed for that session, unless
the adversary has corrupted at least `t` validators for the epoch.

Invariant IF-S2, message authorization. No signature is released for a message
that was not authorized by `IF-I3`, unless the epoch is threshold-compromised.

Invariant IF-S3, transcript uniqueness. A partial contribution is credited only
to one typed signing context `(sid, t, V, pk, m)`.

Invariant IF-S4, validator uniqueness. At most one valid contribution per
validator counts toward the threshold for a session.

Invariant IF-S5, public verifiability. Every released signature verifies under
`MLDSA65.Verify(pk, m, sigma)`.

Invariant IF-S6, abort visibility. If an open session aborts, parties permitted
by the release policy receive an abort notification, and attributable faults are
logged as evidence events when the model permits attribution.

Invariant IF-S7, no evidence leakage. Evidence events reveal only public
session fields, attributed validator identifiers, malformed public bytes, and
proof artifacts needed to verify the fault. They do not reveal honest secret
shares or honest one-time masks.

## IF-6. Leakage Profile

The ideal functionality leaks to the adversary:

- registered epoch parameters `(key_id, t, V, pk)`
- signing requests `(sid, m, requested_signers)`
- which validators are asked to participate
- scheduling, abort, timeout, and release events
- public evidence records
- corrupted-validator state allowed by the corruption model

The ideal functionality does not leak:

- honest secret shares
- honest one-time signing masks before they are safely hidden by commitments
- rejection-sampling internals beyond public accept or abort behavior
- partial-signature randomness not already exposed by the final ML-DSA
  signature distribution

Any production proof must show that the real protocol leaks no more than this
profile except for negligible leakage covered by the side-channel model.

## IF-7. Real/Ideal Relation

Definition IF-R1, real protocol trace. A real trace contains network messages,
commitments, partial shares, aggregate outputs, evidence records, aborts, and
public verification results produced by the concrete protocol.

Definition IF-R2, ideal trace. An ideal trace contains calls to `F_TMLDSA`,
leakage messages to `S`, evidence events, abort notifications, and released
standard ML-DSA signatures.

Definition IF-R3, realization target. A real protocol realizes `F_TMLDSA` if
for every real-world adversary `A` there exists an ideal-world simulator `S`
such that no probabilistic polynomial-time environment can distinguish IF-R1
from IF-R2 except with negligible advantage.

Relation IF-R4, commitment mapping. Each accepted real commitment maps to one
`CommitObserved` event for the same `(key_id, sid, id_i)`.

Relation IF-R5, partial-share mapping. Each accepted real partial share maps to
one `PartialObserved(..., valid)` event. Each rejected attributable partial maps
to `PartialObserved(..., invalid)` and evidence IF-E3.

Relation IF-R6, aggregate mapping. Each accepting real aggregate signature maps
to one `ReleaseSignature` event and one released `(m, sigma)` pair. If a real
aggregate verifies for an unauthorized message, the simulator must convert that
event into a forgery against ML-DSA-65 or a violation of a threshold assumption.

Relation IF-R7, abort mapping. Each real timeout or adversarial abort maps to
`Abort`, plus IF-E4 or IF-E6 when the real trace provides attribution.

Relation IF-R8, evidence mapping. Real adapter evidence is admissible in the
ideal trace only if its public fields are bound to the same typed session and
validator identity.

## IF-8. Simulator Obligations

A simulator for `F_TMLDSA` must:

- simulate honest commitments without access to honest secret shares in the
  ideal world
- simulate honest partial-share messages consistently with released signatures
- preserve adversarial scheduling and abort choices
- extract or explain every accepting aggregate output
- translate malformed, duplicate, invalid, and missing messages into evidence
  events without leaking honest secrets
- program or account for the transcript random oracle if the proof uses a
  random-oracle model
- maintain consistency across concurrent sessions for the same key epoch

No simulator construction is currently present in the repository.

## IF-9. Concurrency and Replay Rules

Rule IF-C1, unique session identifiers. `sid` must be unique within a key epoch.
Reusing `sid` with a different message is rejected and may produce evidence if
attributable.

Rule IF-C2, concurrent sessions. Concurrent sessions are permitted when their
typed contexts differ and transcript encodings are domain separated.

Rule IF-C3, replay rejection. A commitment, partial share, or aggregate output
from one typed session does not count in another session.

Rule IF-C4, release idempotence. Repeating `ReleaseSignature` for a signed
session returns the previously released signature or an idempotent release
notice, not a fresh signature sample, unless the protocol specification
explicitly models rerandomized signatures.

## IF-10. Explicit Limitations

Limitation IF-X1. This functionality abstracts away the concrete DKG. A
separate ideal key-generation functionality or trusted setup relation is needed
for an end-to-end proof.

Limitation IF-X2. This functionality assumes an ideal source of valid ML-DSA-65
signatures for authorized messages. The real protocol still needs a reduction
showing its aggregate output has the same verification and distribution
properties.

Limitation IF-X3. Adaptive corruption is not fully modeled. Adding it requires
state-erasure rules for local masks, commitment secrets, and partial-signing
state.

Limitation IF-X4. Availability is only partially captured. Byzantine validators
can always prevent liveness by withholding enough commitments or partial shares.
The functionality records aborts and evidence but does not guarantee progress
under fewer than `t` live honest participants.

Limitation IF-X5. Slashing is out of scope. Evidence events are inputs to
policy or chain-specific fraud proof systems, not an ideal slashing mechanism.

Limitation IF-X6. Side-channel leakage is out of scope for this ideal
functionality and must be handled by the implementation theorem and audit
process.

Limitation IF-X7. The current deterministic simulation backend is only a test
scaffold. It does not realize this functionality.

## IF-11. Open Proof Dependencies

Later proof work must instantiate or reference:

- an ideal DKG or trusted dealer functionality linked to `F_TMLDSA`
- exact admission rules for authorized signing requests
- mathematical partial-signature verification equations
- transcript encoding injectivity proof
- ML-DSA-65 abort and noise-bound preservation proof
- simulator for static corruption
- optional simulator extension for adaptive corruption with erasures
- evidence soundness and noninterference proof
- implementation conformance tests tying the Rust API to the formal interfaces
