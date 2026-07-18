# Strong Threshold ML-DSA-65 Protocol Specification

Status: normative protocol target for the no-single-holder research path. No
implementation is asserted to conform, and no theorem or audit is claimed
complete.

Date: 2026-07-18

## PS-0. Purpose and Normative Language

This document supplies the protocol specification requested by
[`formal-security-theorem.md`](formal-security-theorem.md). The keywords MUST,
MUST NOT, SHOULD, SHOULD NOT, and MAY are normative requirements on a future
conforming implementation and proof package.

The protocol target emits an ordinary ML-DSA-65 signature under the strong
model in [`security-model.md`](security-model.md). It does not use the
coordinator seed-reconstruction path. The present Stack A and Stack B code paths
described in [`threshold-stack-architecture.md`](threshold-stack-architecture.md)
do not yet implement this specification.

## PS-1. Parameters, Roles, and Values

The base instance uses:

```text
parameter_set = ML-DSA-65
V             = canonical ordered validators (P_1, ..., P_n)
t             = authorization and sharing threshold
Agg           = untrusted public coordinator
sid           = unique 32-byte signing-session identifier
retry         = unsigned 64-bit internal attempt counter
```

The implementation MUST use the exact ML-DSA-65 constants, encodings,
`KeyGen_internal`, `Sign_internal`, and verification predicates selected by the
referenced FIPS 204 edition. The proof manifest MUST pin that edition and all
errata. An output signature MUST be the ordinary 3309-byte encoding and MUST be
accepted by an unmodified verifier for the same `(pk, message mode, ctx, m)`.

The following values are secret throughout their lifetime: the FIPS
key-generation seed, `K`, secret vectors `s1` and `s2`, the per-signature
`rho_prime_prime`, every rejected or unreleased `y`, intermediate signing low
bits and rejection predicates, and every validator's persistent secret share.
Secret values MUST exist only as authenticated MPC shares or as approved
ephemeral local shares. No code path may reconstruct them at `Agg` or any other
single party.

The full DKG public relation `t = A*s1+s2` and its `Power2Round` low part `t0`
are a declared exception: FIPS 204 does not require the low bits of `t` to be
secret. The DKG may declassify ephemeral `t` to derive exact `t1` and `t0`.
Validators MUST nevertheless retain exact `t0` signing state, either publicly
bound to the epoch or as authenticated shares. Public `t0` does not relax the
secrecy requirements for `s1`, `s2`, `K`, or the key-generation seed.

## PS-2. Canonical Encoding and Domain Separation

All non-FIPS protocol records MUST use the following canonical encoding:

```text
Record := domain_len:u16be || domain:bytes
       || version:u16be
       || field_count:u16be
       || Field[0] || ... || Field[field_count-1]
Field  := type:u16be || length:u32be || value:bytes
```

Integers use the smallest fixed width specified by the record grammar and are
big-endian. Byte strings are length-delimited. Lists encode a `u32be` element
count followed by elements. Validator identifiers are unsigned 64-bit integers
in strictly increasing order. Duplicate, unsorted, unknown, trailing,
overlong, or non-minimal values MUST be rejected before hashing or state
transition. Decoders MUST round-trip to exactly the received bytes.

SHAKE256-based protocol digests use the full canonical `Record` and 32 output
bytes. These v1 domains are disjoint:

| Record | Domain |
| --- | --- |
| epoch and DKG context | `lattice-aggregation/strong-tmldsa65/dkg/v1` |
| authorization certificate | `lattice-aggregation/strong-tmldsa65/auth/v1` |
| signing control transcript | `lattice-aggregation/strong-tmldsa65/sign/v1` |
| MPC round frame | `lattice-aggregation/strong-tmldsa65/mpc-frame/v1` |
| partial opening/proof | `lattice-aggregation/strong-tmldsa65/partial/v1` |
| abort/retry state | `lattice-aggregation/strong-tmldsa65/retry/v1` |
| public fault evidence | `lattice-aggregation/strong-tmldsa65/evidence/v1` |

Changing a domain or grammar requires a protocol-version change. A digest from
one domain MUST NOT be accepted in a field typed for another domain.

The epoch context is:

```text
E = (parameter_set, key_id, epoch, n, t, V, security_profile)
```

The finalized epoch statement is:

```text
E_final = (E, pk, accepted_dealers, dkg_transcript_digest,
           mpc_protocol_digest, proof_parameter_digest)
```

The signing control context is:

```text
S = (digest(E_final), sid, message_mode, ctx, digest(m),
     signer_set, authorization_certificate_digest)
```

An attempt is typed by `(digest(S), retry)`. Every DKG, authorization, MPC,
partial, retry, and evidence frame MUST additionally bind its sender, optional
recipient, logical round, monotonically increasing per-sender sequence number,
and payload type.

## PS-3. FIPS Challenge Versus Control Transcript

The protocol MUST keep two hash surfaces distinct:

1. The control-transcript digests above bind threshold-protocol authorization,
   session, participant, retry, and MPC state.
2. The final ML-DSA challenge MUST be computed exactly as required by FIPS 204
   from the standard message representative `mu` and reconstructed public
   `w1`. Protocol-only fields MUST NOT be silently appended to that FIPS hash
   input.

If the application requires `sid`, epoch, validator set, or authorization
policy to be covered by the public signature, those values MUST be placed in a
canonical application message envelope or a standard-supported ML-DSA context
given identically to the unmodified verifier. The verifier-visible message
contract MUST be fixed before authorization.

Every MPC contribution and opening proof MUST bind both the signing control
digest and the exact FIPS values `mu`, `w1`, `c_tilde`, and `c` used for that
attempt. This construction reconciles protocol replay protection with standard
verifier compatibility. The existing challenge in `src/transcript.rs` is a
scaffold control challenge; it MUST NOT be substituted for the FIPS 204 signing
challenge in a conforming backend.

## PS-4. Distributed Key Generation and VSS

### PS-4.1 Joint key-generation relation

The DKG MUST jointly instantiate the exact distribution of FIPS
`KeyGen_internal` without revealing or reconstructing its seed or secret-key
state. A conforming construction MAY evaluate exact key generation inside the
selected active-secure MPC, or use a proved distribution-equivalent DKG. In
both cases it MUST output:

- the ordinary ML-DSA-65 public key `pk` publicly;
- authenticated persistent shares of every secret value needed by exact
  `Sign_internal`, including `K`, `s1`, and `s2`, plus exact retained `t0`
  signing state or a proved equivalent;
- validator verification metadata bound to `E_final`; and
- no reconstructable full `sk`, seed, or equivalent at any single party.

The proof MUST establish that the public `(rho, t1)` and shared secret state
satisfy the exact ML-DSA key relation and the required key distribution.

Deriving byte-exact `pk = (rho, t1)` from caller-supplied shares is only one
sub-capability of this relation. It does not establish exact joint `ExpandS`
sampling, private receiver custody, secret-shared `K`, retained `t0` signing
state, or a malicious-secure DKG proof. The current implementation boundary and
its non-promotion rule are recorded in
[`distributed-keygen-capability-boundary.md`](distributed-keygen-capability-boundary.md).

### PS-4.2 VSS state machine

For every dealer contribution, the state machine is:

```text
Commit -> Distribute -> Verify -> Complain -> Respond -> Adjudicate -> Finalize
```

The VSS relation MUST bind `E`, dealer, receiver where applicable, polynomial
degree `< t`, coefficient commitments, encrypted receiver shares, dealer key
contribution, and proof parameters. It MUST provide or reduce to binding,
hiding, knowledge soundness or extractability, and receiver-share correctness.

Dealers commit before seeing other dealers' openings. Receivers validate their
authenticated encrypted shares and associated proofs. Complaints and responses
use deterministic public predicates with anti-framing and privacy rules.
Finalization derives one canonical accepted-dealer set from the public
adjudication transcript. Every honest validator that finalizes MUST obtain the
same `pk`, accepted-dealer set, transcript digest, and verification relation for
its private share; otherwise it halts.

A DKG session MUST NOT finalize when:

- fewer than the policy-required accepted dealers remain;
- an accepted dealer has an unresolved valid complaint;
- the joint public key or any honest local share fails the exact relation;
- transcript agreement fails; or
- key-bias countermeasures required by the proof do not complete.

The DKG construction and complaint predicates MUST satisfy the stronger
requirements in [`vss-dkg-security-plan.md`](vss-dkg-security-plan.md).

### PS-4.3 Persistent-state rule

After finalization, validators retain only their authenticated secret shares,
exact `t0` signing state, verification metadata, `E_final`, and state required
by the selected MPC. They
MUST erase dealer polynomial randomness, decrypted inbound shares after
combination, temporary openings, and superseded complaint secrets. There MUST
be no production reconstruction API.

## PS-5. Signing Admission and Live Distributed Nonces

Before signing, validators verify a canonical authorization certificate for
the exact `S` context and at least `t` unique eligible signers. A signer MUST
refuse an unknown epoch, stale key, reused `sid`, mismatched message/context,
uncanonical signer set, or insufficient authorization.

For every admitted session, nonce material MUST be generated live by the
authorized distributed execution. The exact FIPS `rho_prime_prime` derivation
MUST occur inside MPC from secret-shared `K`, exact `mu`, jointly generated
fresh randomness when the selected signing mode uses hedging, and the FIPS
domain/encoding rules. `rho_prime_prime` MUST remain secret-shared.

No external PRF-output oracle, deterministic fixture, coordinator-provided
nonce, previously generated capture, or single-party entropy source is
admissible closure evidence. Joint randomness MUST remain unpredictable if at
least one required honest contributor follows the protocol, and malicious
input handling or commit-reveal MUST prevent last-mover choice. A failed session
MUST never reuse its nonce state under another `sid`.

## PS-6. Exact Distributed Mask and Signing Attempt

The complete FIPS signing attempt, including its rejection loop, executes
inside the selected active-secure MPC. For internal retry counter `retry`, the
joint circuit MUST:

1. derive the exact FIPS mask-expansion input and counter;
2. compute `y = ExpandMask(rho_prime_prime, kappa)` byte-for-byte as FIPS 204;
3. compute `w = A * y` and the exact `Decompose`/`HighBits` representation;
4. reveal only the public `w1` value committed to the current attempt;
5. compute `c_tilde` and `c` using the exact FIPS challenge derivation;
6. compute authenticated secret shares of `z = y + c * s1`;
7. compute the low-bit relation, `c * t0`, and the exact `MakeHint` result
   inside MPC, using the retained public or shared `t0` state;
8. evaluate all FIPS rejection predicates, including the `z`, `r0`, `c*t0`,
   and hint-weight bounds; and
9. declassify `(c_tilde, z, h)` only for the first accepting attempt.

All samplers, NTTs, decompositions, rounding, coefficient representatives,
norm comparisons, hint calculations, packing, and counter behavior MUST be
byte- and branch-semantics-equivalent to the pinned FIPS implementation.
Replacing exact `ExpandMask` with sums of participant-local uniform masks is
nonconforming because it reintroduces `epsilon_mask`.

Before `w1` is used, participants commit to the attempt's MPC output-sharing
state under the control transcript. No party may choose a new participant set,
message, authorization certificate, or retry identifier after seeing `w1` or
the FIPS challenge.

## PS-7. Partial `z` and Hint Aggregation

Persistent key values and attempt values are represented by authenticated
secret sharing. For each accepted signer `P_i`, linear operations produce:

```text
[z]_i = [y]_i + c * [s1]_i
```

where brackets denote a share under the selected MPC and not a public local
partial signature. Nonlinear low-bit and hint operations run inside MPC and
produce authenticated shares `[h]_i` of the exact aggregate hint. The circuit
also holds secret-shared rejection bits.

Each party's partial-opening or MPC-authentication record MUST bind:

```text
(digest(S), retry, id_i, digest(E_final), mu, digest(w1),
 c_tilde, c, output_wire, MPC transcript digest)
```

Invalid, duplicated, unknown, or context-mismatched shares are rejected before
opening. The output protocol reconstructs only the accepted aggregate `z` and
`h`; it MUST NOT reveal individual `y_i`, `s1_i`, `z_i`, hint shares, rejection
shares, or enough openings to reconstruct a persistent secret. MPC MAC failure
or inconsistent opening aborts the session and produces only proof-approved
public evidence.

After opening, the output collector packs `(c_tilde, z, h)` using the exact
ML-DSA-65 wire encoding and runs an unmodified standard verifier. Verification
failure is a protocol failure, never an alternate success mode.

## PS-8. Rejection, Retry, Abort, and Erasure

FIPS rejection is an internal signing operation, not an external coordinator
decision. The selected circuit MUST hide per-attempt `y`, `w0`, `r0`, `z`,
hint candidates, predicate bits, and whether a specific internal attempt
failed. It SHOULD execute a fixed-size batch or another proved
data-oblivious schedule so that participants and observers learn no
secret-dependent per-attempt trace.

The internal `retry` counter starts at zero, increases monotonically, and is
bound to all attempt state. Counter overflow, reuse, rollback, or fork causes a
terminal session abort. Only the first accepting candidate may be opened. All
other candidate state is erased without opening.

A transport failure before authorization completion may be retried under the
same request but a fresh `sid`. A failure after nonce state is instantiated
consumes that `sid` and all associated nonce state permanently. A validator
MUST NOT resume a consumed attempt with a different signer set, transcript,
message, or authorization certificate.

The public protocol exposes only one of:

```text
Completed(sid, signature, transcript_digest)
Aborted(sid, public_reason, transcript_digest)
```

Public reasons use a fixed, proof-reviewed enumeration and MUST NOT encode
secret rejection predicates or internal attempt counts. Timing, frame counts,
padding, timeout policy, and malicious selective abort remain part of the
abort-distribution proof; hiding an error string alone is insufficient.

On completion or abort, validators erase all session-local masks, nonce seeds,
MPC preprocessing that cannot be safely reused, partial openings, and secret
predicate state. Crash recovery MUST fail closed using monotonic consumed-state
storage so snapshots cannot roll back nonce consumption.

## PS-9. Evidence and Fault Handling

Public evidence MAY cover authenticated equivocation, malformed canonical
frames, invalid public proofs, MPC authentication failure when safely
attributable, or failure to answer after the selected synchrony assumption
holds. Evidence MUST bind the full typed context and use deterministic public
verification predicates.

Evidence MUST NOT reveal honest secret shares, decrypted share contents,
one-time masks, individual response shares, internal rejection state, or MPC
authentication keys. Non-public diagnostic records may trigger local exclusion
or retry but cannot be labeled slashing evidence. Evidence noninterference and
anti-framing are proof obligations, not consequences of record formatting.

## PS-10. Committee Compilation Rule

The base protocol runs among a threshold-authorized signer set. A small MPC
committee MAY be used for feasibility experiments, but it is not a conforming
replacement unless a separately reviewed compiler proves all of the following:

- `t` validator authorizations are cryptographically necessary for each output;
- conversion from validator shares to committee state leaks no persistent key
  or reusable signing capability;
- the committee corruption threshold is explicit and composed with the
  validator corruption bound;
- no committee quorum can sign a new message from retained state;
- committee selection, resharing, proactive refresh, and erasure preserve DKG
  and VSS security; and
- the resulting signature and accepted-output distribution remain exact.

The `k = 64` prototype in
[`distributed-mask-mpc-feasibility.md`](distributed-mask-mpc-feasibility.md)
therefore measures the nonlinear circuit; it does not by itself close the
`10000`-validator, `6667`-threshold theorem.

## PS-11. Conformance and Proof Deliverables

A candidate implementation conforms only when one digest-bound bundle contains:

- exact DKG/VSS protocol, primitives, parameters, proofs, and negative tests;
- exact MPC protocol, circuit inventory, compiler, preprocessing, and
  corruption/output-delivery proof;
- canonical encoding test vectors and injectivity checks;
- live-nonce, rollback, retry, abort, and erasure tests;
- accepted and rejected FIPS signing-attempt vectors;
- ML-DSA known-answer and differential tests against an independent standard
  implementation;
- successful standard verification of every accepted campaign output;
- proof artifacts for FST-L1 through FST-L9 and the FST-T1/FST-T2 reductions;
- source, binary, toolchain, transcript, circuit, proof, and evidence digests;
  and
- explicit unresolved assumptions and security-loss bounds.

Passing tests or a 10,000-validator campaign is implementation evidence only.
It does not replace reductions, simulation, accepted-output distribution
analysis, side-channel review, or independent cryptographic review.

## PS-12. Current Implementation Boundary

No current backend is asserted to implement this specification. In particular:

- Stack B emits standard-verifier-compatible signatures but reconstructs seed
  material at a coordinator and is nonconforming with PS-1 and PS-4;
- Stack A supplies distributed research components but does not implement the
  exact FIPS mask/rejection circuit or a standard-valid wire signature; and
- hazmat captures, deterministic fixtures, evidence emitters, and centralized
  provider calls are inadmissible as strong-theorem conformance evidence.

An internally complete implementation may use the state defined in
[`internal-theorem-closure-candidate.md`](internal-theorem-closure-candidate.md)
while independent review is pending. That state does not alter the current
claim vocabulary in
[`hypothesis-outcome-taxonomy.md`](hypothesis-outcome-taxonomy.md).
