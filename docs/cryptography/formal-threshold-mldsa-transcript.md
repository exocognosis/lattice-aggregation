# Formal Threshold ML-DSA-65 Transcript Draft
<a id="ftmt-0-scope"></a>

Date: 2026-05-26

## Status
This document is a documentation-only transcript draft for the intended
threshold ML-DSA-65 protocol. It is a proof target and terminology lock for the
research scaffold, not a completed construction, security proof, production
specification, or deployment claim.

Adjacent scaffold documents:
[threshold-mldsa-protocol-spec.md](threshold-mldsa-protocol-spec.md),
[hazmat-real-mldsa-protocol.md](hazmat-real-mldsa-protocol.md),
[formal-proof-scaffold.md](formal-proof-scaffold.md),
[security-model.md](security-model.md),
[proof-bearing-contribution-boundary.md](proof-bearing-contribution-boundary.md),
[random-oracle-game.md](random-oracle-game.md),
[protocol-code-crosswalk.md](protocol-code-crosswalk.md),
[protocol-lock.md](protocol-lock.md), and
[claims-matrix.md](claims-matrix.md).

<a id="ftmt-1-notation"></a>

## Notation
```text
V              ordered validator set {1, ..., N}
N, t, f        validator count, signing threshold, static corruption bound f < t
i              validator index
epoch_id       DKG/public-key epoch identifier
pk_epoch       joint ML-DSA-65 public key
sid            signing session identifier
height         consensus block height
attempt        rejection/retry attempt number
M, mu          message and ML-DSA internal message digest
A              ML-DSA public matrix
y_i, w_i       masking vector and A * y_i
w1, c          HighBits(sum_i w_i) and Fiat-Shamir challenge
s1_i,s2_i,t0_i validator i secret share components
sigma          final standard ML-DSA-65 signature bytes
H              domain-separated hash / random oracle in the proof model
Com            binding commitment; hiding where the production proof requires it
```
All encodings are intended to be canonical and domain separated. Participant
ordering is by validator index, never by network arrival order.

<a id="ftmt-2-random-oracle-alignment"></a>

## Random Oracle Alignment

The proof model treats challenge derivation as the `H_c` domain defined in
[random-oracle-game.md](random-oracle-game.md). The current implementation in
`src/transcript.rs` binds the protocol label
`lattice-aggregation/threshold-mldsa65`, version `1`, session ID, threshold,
canonical validator set, threshold public key, message bytes, and ordered
commitment map before partial signature generation.

A production proof may introduce a separate message representative `mu` through
the `H_mu` domain, masking commitment digest through `H_w`, VSS relation
digest through `H_vss`, and contribution proof digest through `H_contrib`.
If it does, the production transcript must prove that those values are
canonically encoded and are not interchangeable with the scaffold's raw message
binding. Regression tests establish useful engineering guardrails, not a
complete random-oracle simulation proof.

## Participants And Adversary
Participants are validators `i in V`, an untrusted aggregator, a proposer or
consensus layer requesting signatures, and public verifiers that only run
standard ML-DSA-65 verification.

The initial proof target is static active security against a static active
adversary, as in
[security-model.md](security-model.md) and
[formal-proof-scaffold.md](formal-proof-scaffold.md). Before DKG, the adversary
chooses at most `f` corrupted validators. It may schedule, delay, drop,
duplicate, and reorder messages; act as aggregator or proposer; submit
malformed DKG material, commitments, openings, and proofs; equivocate where
identity/session binding is absent; withhold after observing `c`; and attempt
replay across epochs, sessions, heights, or attempts.

Anchor phrase for audits: static active adversary.

This target excludes adaptive corruptions, side-channel leakage, forged
authenticated transport identities, and direct cryptanalytic breaks of
ML-DSA-65. Adaptive security is a separate theorem requiring erasure semantics
for `y_i`, commitment randomness, and proof witness state.

## DKG Placeholder
The signing transcript assumes an epoch setup that outputs:
```text
(epoch_id, V, t, pk_epoch, dkg_digest, sk_i for each validator i)
```
`dkg_digest` is a canonical digest of accepted DKG public material: validator
universe, threshold, public commitments, complaint resolution, and public-key
derivation. Current VSS/interpolation support is scaffold-only. It fixes
algebraic and API boundaries, but does not provide malicious-secure production
DKG, production complaint soundness, or anti-framing analysis.

A production DKG must provide binding public commitments, private share
delivery, verified complaints, deterministic exclusion rules, and a proof that
all honest accepted subsets reconstruct the same epoch secret.

## Transcript Context
Every signing attempt binds:
```text
ctx = (
  protocol_version, epoch_id, sid, height, attempt,
  V, t, pk_epoch, dkg_digest, mu
)
```
The canonical transcript order is:
```text
(epoch_id, sid, height, attempt, validator_index, round)
```
No challenge, proof, finalization decision, or evidence object should depend on
message arrival order.

## Round 1a: Masking Precommitment
Validator `i` samples or derives attempt-local masking material:
```text
y_i
w_i = A * y_i
```
Before revealing a masking opening, it broadcasts:
```text
MaskPrecommit_i = (ctx, i, Cmask_i)
Cmask_i = Com("mask" || ctx || i || MaskOpen_i)
```
The current hazmat backend realizes this as a SHA3-256 digest over the later
payload, per [hazmat-real-mldsa-protocol.md](hazmat-real-mldsa-protocol.md).
That is an engineering binding check, not a full hiding commitment claim.

## Round 1b: Masking Opening
Validator `i` opens:
```text
MaskOpen_i = (ctx, i, y_i or production-hidden equivalent, w_i, mask_aux_i)
```
Receivers accept only if `i in V`, there is no prior accepted opening for `i`
in the same attempt, `Cmask_i` opens under `ctx` and `i`, parameters match
`V`, `t`, `epoch_id`, `sid`, `height`, and `attempt`, and either `w_i = A*y_i`
or the production proof relation verifies the equivalent fact.

The current hazmat transcript reveals experimental material only as a research
scaffold. A production transcript should avoid revealing `y_i` unless the final
proof justifies that disclosure.

## Round 2: Challenge Derivation
After at least `t` valid masking openings are accepted:
```text
Wset = canonical accepted set of (i, Cmask_i, MaskOpen_i)
w    = sum_{i in Wset} w_i
w1   = HighBits(w)
c    = H("challenge" || ctx || Wset || w1)
```
The challenge binds the accepted masking quorum and all context required to
prevent cross-session, cross-attempt, cross-epoch, or cross-message replay.
Open obligations are to prove precommitment binding before challenge
derivation, remove aggregator ordering influence, and bound selective-abort
advantage from retries after `c` is known.

Compatibility note: the current standard-verifying hazmat implementation must
respect the FIPS 204 ML-DSA-65 challenge path. In that profile, consensus
context that should affect the signature challenge must be encoded into `M` and
therefore into `mu`; `sid`, `height`, `attempt`, commitment digests, and DKG
digests are enforced by the wire envelope and proof-bound contribution
statement. A production proof must explicitly reconcile this formal `ctx`
binding with unmodified standard ML-DSA-65 verification.

## Round 3a: Secret Precommitment
After `c` is fixed, validator `i` computes the secret-dependent response
material required by the production relation. In current hazmat notation:
```text
cs1_i = c * s1_i
cs2_i = c * s2_i
ct0_i = c * t0_i
```
Before opening any secret contribution frame, it broadcasts:
```text
SecretPrecommit_i = (ctx, i, c, Csecret_i)
Csecret_i = Com("secret" || ctx || i || c || SecretOpen_i)
```
Receivers reject a secret precommitment whose `c` differs from the session
challenge.

## Round 3b: Secret Opening With Proof-Bound Frame
Validator `i` opens:
```text
SecretFrame_i = (
  ctx, i, c, Cmask_i, Csecret_i, dkg_digest,
  contribution_encoding_i, ContributionProof_i
)
```
This is the proof-bound secret contribution object for the attempt.
The production proof statement must bind at least protocol version, epoch,
session, height, attempt, validator index, challenge, `pk_epoch`, `dkg_digest`,
masking commitment digest, secret commitment digest, `mu`, the ML-DSA-65
parameter set, and the claimed contribution encoding.

Receivers accept only if `i in V`, no prior `SecretFrame_i` was accepted for
the attempt, `c` equals the session challenge, `Csecret_i` opens under `ctx`,
`i`, and `c`, the proof verifies under the bound public statement, and the
frame is not stale, cross-session, cross-attempt, or cross-epoch.

The current `ContributionProof` is only a transcript-hash scaffold binding a
public statement to a payload digest. It is not zero-knowledge,
knowledge-sound, or a production contribution proof. See
[proof-bearing-contribution-boundary.md](proof-bearing-contribution-boundary.md).

## Finalization And Verification
Once at least `t` valid secret frames are accepted, the aggregator combines the
accepted contributions, performs ML-DSA response and hint checks, and emits
`sigma`. The external verification target is exactly:
```text
Verify_MLDSA65(pk_epoch, M, sigma) = accept
```
This is the standard ML-DSA-65 verification path. Public verifiers do not need
threshold metadata. Threshold transcripts are for audit, evidence, and proof
reasoning only. The hazmat backend provides engineering evidence for
standard-sized artifacts and unmodified verification, but not a proof of
distributional compatibility with centralized ML-DSA-65.

## Formal Game-Hopping Skeleton
The formal proof target is a sequence of OPEN games. This transcript names the
objects each game must bind; it does not close any proof obligation.

| Game | OPEN obligation | Required assumptions | Repository evidence |
| --- | --- | --- | --- |
| G1 setup/DKG idealization | Replace accepted setup with one ideal `pk_epoch` and consistent shares. | Malicious-secure VSS, complaint soundness, private share delivery, deterministic exclusions. | `dkg_digest`, interpolation checks, and DKG placeholder text only. |
| G2 masking commitment binding | Prevent two valid openings for one masking precommitment in one attempt. | Binding commitment before `c`; hiding if production masking remains hidden. | `Cmask_i` and hazmat digest checks are engineering evidence only. |
| G3 challenge unbiasability | Show `c` cannot be biased except through bounded abort/retry choices. | Canonical `Wset`, domain separation, fixed retry/exclusion policy, random-oracle model. | Transcript order and determinism hooks; no bias bound. |
| G4 contribution proof soundness | Extract or validate each accepted secret frame against the ML-DSA relation. | Sound reviewed proof or MPC relation binding `ctx`, `i`, `c`, DKG material, commitments, bounds, and payload. | `ContributionProof` transcript-hash scaffold; not production soundness. |
| G5 rejection/selective abort | Bound conditioning introduced by rejection sampling, withholding, retries, and exclusions. | Fresh attempt masks, no commitment reuse, explicit retry limits, abort distribution bound. | Retry/evidence boundaries and telemetry only. |
| G6 aggregation correctness | Show accepted frames aggregate to values satisfying ML-DSA equations and bounds. | Correct recombination, noise bounds, hint bounds, and contribution proof soundness. | Standard-verifying hazmat artifacts; not a proof for all transcripts. |
| G7 standard verification compatibility | Show final `sigma` is exactly accepted by unmodified ML-DSA-65 verification. | FIPS 204-compatible encodings, challenge path, `mu`, public key, hints, and bounds. | Bridge/differential verification evidence; no EUF-CMA reduction. |

## Rejection, Retry, And Evidence Boundaries
ML-DSA rejection sampling, written in code paths as rejection-sampling failure,
is non-slashable. It triggers `attempt + 1`
under the same `sid` or an explicitly linked retry session, with fresh
attempt-bound masking material. Prior commitments remain audit material but
must not be reused as valid frames in the new attempt. Retry limits and
validator exclusion policy are deployment parameters that the proof must model
when bounding selective abort.

Slashing evidence is limited to potentially slashable or attributable
cryptographic transcript violations. Evidence is limited to
deterministically verifiable transcript violations: duplicate valid-looking
frames for the same `(epoch_id, sid, height, attempt, i, round)` with
inconsistent contents; opening failure for a prior commitment under the same
context; stale-challenge or cross-session secret frames; authenticated
malformed encodings; or proof-bound frames inconsistent with commitment,
challenge, DKG digest, or payload digest.

Non-slashable retry conditions include ordinary rejection-sampling failure,
timeout or non-delivery without consensus-layer attribution, local verifier
refusal where evidence is incomplete, and failures caused by ambiguous
aggregator transcripts.

Evidence soundness must include anti-framing analysis. An aggregator must not
be able to manufacture evidence against an honest validator by reordering,
omitting, or rebinding otherwise valid frames.

### Abort Transcript `O_abort`
<a id="abort-transcript-o-abort"></a>

The selective-abort proof must define the exact abort transcript `O_abort`
before invoking an accepted-distribution theorem. At minimum, `O_abort` must
classify retry identifiers, aggregate rejection labels, timeout and exclusion
records, malformed-frame evidence, proof-invalid evidence, participant indices
attached to attributable failures, and any timing or message-size buckets that
remain visible to the adversary.

Anything not included in `O_abort` must either be hidden from the adversary
until after the aggregate decision or excluded from the theorem as availability
or side-channel leakage. Ordinary rejection sampling and ambiguous network loss
remain non-slashable.

## Explicit Non-Claims
This draft does not claim production threshold ML-DSA-65 security,
malicious-secure DKG/VSS, zero-knowledge or knowledge-sound contribution
proofs, hiding of current hazmat raw payloads, adaptive security, reliable
erasures, side-channel resistance, FIPS validation, production network
liveness, production slashing soundness, a completed selective-abort bound, or
a completed reduction to ML-DSA-65 EUF-CMA security.

Before stronger claims are made, the open obligations in
[formal-proof-scaffold.md](formal-proof-scaffold.md),
[proof-bearing-contribution-boundary.md](proof-bearing-contribution-boundary.md),
and [claims-matrix.md](claims-matrix.md) must be closed and externally reviewed.
