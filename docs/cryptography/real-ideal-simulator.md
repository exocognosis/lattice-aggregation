# Real/Ideal Simulator Skeleton for Threshold ML-DSA-65
<a id="real-ideal-simulator-skeleton"></a>

Status: simulator skeleton, not a completed proof.

Date: 2026-05-27

## RIS-0. Scope and Non-Claim

This document sketches the simulator and hybrid proof structure needed for the
real/ideal realization theorem in
[formal-security-theorem.md](formal-security-theorem.md) against the ideal
functionality [F_TMLDSA](ideal-functionality.md). It is a simulator skeleton,
not a completed proof.

The skeleton targets the first proof setting named by the surrounding proof
documents:

- static active corruption of at most `t - 1` validators before DKG
- rushing, scheduling, omission, duplication, and malformed-message behavior
  as described in [active-adversary-model.md](active-adversary-model.md)
- random-oracle domains `H_mu`, `H_w`, `H_c`, `H_vss`, and `H_contrib` as
  described in [random-oracle-game.md](random-oracle-game.md)
- typed transcript binding from
  [formal-threshold-mldsa-transcript.md](formal-threshold-mldsa-transcript.md)
- implementation traceability boundaries from
  [proof-implementation-crosswalk.md](proof-implementation-crosswalk.md)

The current repository does not provide a production threshold ML-DSA protocol,
malicious-secure DKG, contribution proof relation, abort-bias bound, or final
distinguishing bounds. Those gaps remain proof blockers.

## RIS-1. Simulator Goal and Interfaces

For every real-world adversary `A`, the simulator `S` must interact with
`F_TMLDSA` and an environment `Z` so that `Z` cannot distinguish the ideal
execution from the real execution except with negligible advantage.

Simulator inputs:

- public epoch parameters `(key_id, t, V, pk)` registered with `F_TMLDSA`
- static corruption set `C` chosen by `A`, with `|C| < t`
- adversarial network schedule, wire frames, oracle queries, abort choices,
  malformed inputs, and aggregate-output attempts
- ideal leakage from `F_TMLDSA`, including signing requests, release decisions,
  abort notifications, and evidence notifications

Simulator outputs:

- adversary-visible DKG messages, signing commitments, partial-share frames,
  aggregate signatures, aborts, retries, and evidence records
- ideal calls `RegisterKey`, `Corrupt`, `SignRequest`, `CommitObserved`,
  `PartialObserved`, `Abort`, and `ReleaseSignature`
- extraction records or reduction events for accepting unauthorized aggregate
  signatures
- random-oracle answers consistent with all prior and programmed queries

`S` must preserve the real adversary's control over scheduling and corrupted
validators. It may not invent liveness or fairness beyond the real network
model.

## RIS-2. Simulator State

`S` maintains one global state table per proof execution.

Epoch state:

```text
EpochSim:
    key_id
    t
    V
    pk
    dkg_digest
    corrupt set C
    honest set H = V \ C
    dkg_public_transcript
    dkg_secret_handles for corrupted validators only
    registered bool
    threshold_compromised bool
```

Oracle state:

```text
OracleTables:
    H_mu[input] -> output
    H_w[input] -> output
    H_c[input] -> output
    H_vss[input] -> output
    H_contrib[input] -> output
    programmed[input] -> reason and session binding
```

Signing-session state:

```text
SessionSim:
    sid
    key_id
    message m
    requested_signers
    attempt
    ctx = (protocol_version, key_id, sid, attempt, t, V, pk, dkg_digest, m or mu)
    commitments map id_i -> simulated or adversarial commitment
    commitment_openings map id_i -> simulated or adversarial opening handle
    challenge c
    partials map id_i -> simulated or adversarial partial frame
    valid_partial_signers set
    invalid_events list
    release_policy
    status in {open, aborted, signed}
    final_signature optional sigma
```

Evidence state:

```text
EvidenceSim:
    event_id
    key_id
    sid optional
    validator optional id_i
    ideal_event in {IF-E1, IF-E2, IF-E3, IF-E4, IF-E5, IF-E6}
    public_transcript_prefix
    challenged_frame_or_timeout_record
    anti_framing_status in {attributable, inconclusive}
```

Reduction state:

```text
ReductionSim:
    unauthorized_accepting_outputs
    transcript_collision_events
    rogue_share_events
    abort_bias_events
    prior_oracle_query_conflicts
```

The state intentionally records only corrupted-validator secret material.
Honest shares, honest one-time masks, and honest rejection-sampling internals
are never materialized in the ideal execution except through abstract handles
whose public openings are sampled by the simulator.

## RIS-3. Real-to-Ideal Event Mapping

`S` maps real events to ideal functionality calls as follows.

| Real event | Ideal action | Simulator obligation |
| --- | --- | --- |
| epoch setup finalizes `(key_id, t, V, pk)` | `RegisterKey` | produce adversary-visible DKG transcript with the same public parameters |
| static corruption of `id_i` | `Corrupt` | reveal only corruption-model state and preserve corrupted-party behavior |
| admitted signing request | `SignRequest` | leak the same `(sid, m, requested_signers)` that the real protocol exposes |
| accepted honest or corrupted commitment | `CommitObserved` | bind one validator to one session context |
| accepted valid partial | `PartialObserved(..., valid)` | ensure contribution is bound to `ctx`, `c`, `Com`, and `id_i` |
| rejected invalid partial | `PartialObserved(..., invalid)` | emit evidence IF-E3 when attribution is public |
| timeout or adversarial abort | `Abort` | preserve schedule and log IF-E4 or IF-E6 only when attribution is justified |
| accepting aggregate for authorized `m` | `ReleaseSignature` | replace final aggregate with the ideal ML-DSA signature |
| accepting aggregate for unauthorized `m*` | reduction event | output a forgery or assumption violation instead of simulating success |

Malformed wire frames, unknown validators, duplicate frames, equivocations, and
cross-session replays map to the evidence events in
[ideal-functionality.md](ideal-functionality.md) only when the transcript
contains enough public context for anti-framing.

## RIS-4. Oracle Programming Points

`S` uses lazy random-oracle tables for every domain in
[random-oracle-game.md](random-oracle-game.md). All programming is conditional
on no inconsistent prior adversarial query.

Programming point RIS-OP1, `H_mu`.

- Program or answer `H_mu(key_id, t, V, pk, message_context, m)` when the
  signing request is admitted by `F_TMLDSA`.
- If the production protocol signs a prehash `mu`, bind `mu` to the same
  message used by `SignRequest`.
- If `A` queried the same input earlier, reuse the existing output and record
  the probability loss only if the proof requires a target value.

Programming point RIS-OP2, `H_w`.

- Sample honest masking commitments before `H_c` is exposed for the session.
- Program only unopened or proof-simulated commitment statements whose public
  transcript is not already fixed in an inconsistent way.
- Preserve corrupted validators' chosen commitments exactly.

Programming point RIS-OP3, `H_c`.

- Answer `H_c(sid, t, V, pk, m or mu, Com)` only for the exact accepted,
  canonical commitment set.
- If `A` queried the accepted challenge input before the simulator fixed
  `Com`, use the existing oracle value and continue; the proof must account for
  any lost ability to embed a reduction target.
- Never reuse a challenge across different `sid`, `attempt`, `V`, `pk`, `m`,
  `mu`, or `Com`.

Programming point RIS-OP4, `H_vss`.

- Simulate DKG and complaint proof challenges for public VSS statements.
- Corrupted dealers and receivers receive oracle answers matching their actual
  statements.
- Honest-dealer proofs may be simulated only under the zero-knowledge or
  witness-hiding theorem selected by the eventual production DKG.

Programming point RIS-OP5, `H_contrib`.

- Simulate honest contribution proofs for the bound context
  `(sid, t, V, pk, m or mu, Com, c, id_i, com_i, vk_i, partial_statement_i)`.
- Program proof challenges only before the corresponding proof transcript is
  fixed to `A`.
- If an accepted corrupted contribution proves under a different context,
  record a proof-portability or transcript-binding failure.

The simulator must never program one oracle domain to repair an inconsistency
in another domain. All tables are global across concurrent sessions.

## RIS-5. Corruption Handling

The base simulator handles static active corruptions.

Before DKG:

1. `A` chooses `C` with `|C| < t`.
2. `S` calls `Corrupt(key_id, id_i)` for every `id_i in C` after the epoch is
   registered or records the pending corruption for registration time.
3. `S` gives `A` the corrupted validators' DKG inputs, local shares, signing
   state, and randomness exactly as the real protocol would expose.

During signing:

- Corrupted validators choose their own commitments, openings, partials,
  omissions, equivocations, and abort behavior.
- Honest validators are simulated from ideal handles. Their secret shares and
  one-time masks are not exposed.
- If `A` corrupts adaptively, this skeleton rejects the event as outside the
  base theorem unless a later adaptive extension defines erasure and exposure
  rules.

Threshold compromise:

- If `|C| >= t`, the unforgeability and realization claim no longer applies in
  the base theorem. `S` records `threshold_compromised = true` and the ideal
  functionality may allow adversarial authorization as described in
  `ideal-functionality.md`.

Open gap: the final proof must specify exactly which corrupted-party state is
equivocable in the ideal execution and which state must be sampled from the
real distribution.

## RIS-6. DKG Simulation

The simulator's DKG task is to produce a public transcript that looks like the
real DKG while registering the same `(key_id, t, V, pk)` with `F_TMLDSA`.

Skeleton steps:

1. Receive or select public epoch parameters `(key_id, t, V, pk)` according to
   the theorem setup.
2. Simulate honest dealer commitments, encrypted shares, VSS proofs, complaint
   responses, and public-key contribution material using the selected DKG
   theorem.
3. Embed corrupted dealers' real messages unchanged.
4. Translate malformed, inconsistent, duplicate, missing, or equivocated DKG
   material to public evidence only when the selected DKG complaint model makes
   attribution sound.
5. Produce one canonical `dkg_digest` that binds `V`, `t`, accepted dealer
   material, complaint resolution, and `pk`.
6. Call `RegisterKey(key_id, t, V, pk)` once the simulated public DKG transcript
   reaches finality.

Required DKG assumptions:

- binding to one polynomial or key contribution per accepted dealer
- privacy of unopened honest shares
- deterministic complaint resolution and exclusion
- bias resistance for the joint public key or a precise trusted-setup
  replacement
- anti-framing for dealer and receiver fault evidence

Open gap: the repository currently has only deterministic VSS/DKG scaffolding,
so this DKG simulation is a placeholder until a production DKG relation and
proof are selected.

## RIS-7. Signing Simulation

For each admitted signing session, `S` simulates the adversary-visible signing
trace and uses `F_TMLDSA` for authorization and final signature release.

Admission:

1. On a real signing request `(key_id, sid, m, requested_signers,
   release_policy)`, call `SignRequest`.
2. Initialize `SessionSim` with `status = open` and attempt-local context.
3. Answer or program `H_mu` consistently with the message-binding rule.

Commitment phase:

1. For honest requested signers, sample simulated commitments and proof
   statements that are indistinguishable from real honest commitments.
2. For corrupted signers, forward adversarial commitments, preserving
   scheduling and equivocation.
3. For every accepted commitment, call `CommitObserved`.
4. For duplicates, unknown validators, stale attempts, and malformed frames,
   emit the matching evidence event only when the public transcript supports
   attribution.

Challenge phase:

1. Canonicalize `Com` by validator order, not arrival order.
2. Answer `H_c` on the exact accepted transcript tuple.
3. Record prior-query conflicts as distinguishing-loss terms or reduction
   events.

Partial-share phase:

1. For honest signers, simulate contribution frames and `H_contrib` proofs
   without using honest shares.
2. For corrupted signers, verify or reject submitted partials under the public
   contribution relation.
3. Call `PartialObserved(..., valid)` for accepted partials and
   `PartialObserved(..., invalid)` for rejected attributable partials.
4. Maintain `valid_partial_signers` with at most one signer contribution per
   validator.

Release phase:

1. If at least `t` valid partials are present for an authorized message, call
   `ReleaseSignature`.
2. Replace the real aggregate signature with the signature returned by
   `F_TMLDSA`, preserving release policy and idempotence.
3. If `A` outputs a valid aggregate signature for an unauthorized message,
   terminate the simulation with a reduction to ML-DSA unforgeability,
   threshold-share soundness, contribution-proof soundness, transcript
   collision resistance, or rogue-share resistance.

Open gap: the proof must still show that simulated honest partials are
indistinguishable from real partials and that replacing the final aggregate
with an ideal ML-DSA signature preserves the accepted-signature distribution.

## RIS-8. Abort and Evidence Simulation

`S` must preserve abort behavior because selective aborts are a central
distinguishing surface.

Abort handling:

- If `A` withholds enough commitments or partials to prevent threshold
  completion, call `Abort(key_id, sid, reason)` with the same public reason the
  real protocol would expose.
- If a committed validator fails to provide a valid partial before the modeled
  deadline, emit IF-E4 only when the network model supports attribution.
- If the session times out without attributable signer fault, emit IF-E6 or an
  inconclusive retry record, not slashable evidence.
- Ordinary ML-DSA rejection-sampling failure is not slashable evidence. It must
  advance to a fresh attempt with fresh masking material under the production
  retry policy.

Evidence handling:

- IF-E1: unknown validator messages are recorded only with authenticated
  identity and context.
- IF-E2: duplicate or equivocated messages require two conflicting frames bound
  to the same typed session and validator.
- IF-E3: invalid partial signatures require public verification failure under
  the exact `(sid, t, V, pk, m, Com, c, id_i)` context.
- IF-E4: missing partial evidence requires a prior accepted commitment plus a
  timeout model that makes omission attributable.
- IF-E5: malformed wire evidence includes only public bytes and decode
  context.
- IF-E6: session timeout is an availability event unless the model proves
  stronger attribution.

Evidence noninterference:

- Evidence records must not reveal honest secret shares, honest masking
  randomness, unopened complaint material, or rejection-sampling internals.
- An aggregator must not be able to frame an honest validator by omitting,
  reordering, or rebinding otherwise valid frames.

Open gap: the final proof must quantify the selective-abort advantage and
separate slashable cryptographic faults from network availability failures.

<a id="ris-9-hybrid-sequence-s0s8"></a>

## RIS-9. Hybrid Sequence S0..S8

The realization proof should refine the theorem-level hybrids into the
following simulator-oriented sequence. Every transition below needs an explicit
distinguishing bound before this skeleton can become a proof.

| Hybrid | Description | Required argument |
| --- | --- | --- |
| S0 | Real production protocol with real DKG, real commitments, real partials, real aggregation, and adversarial scheduling. | Starting game. |
| S1 | Replace network delivery with simulator-controlled scheduling that preserves the adversary-visible trace. | Scheduling abstraction equivalence under the active adversary model. |
| S2 | Replace malformed, duplicate, replayed, and invalid public messages with ideal evidence events. | Evidence soundness, anti-framing, and canonical transcript binding. |
| S3 | Replace DKG with simulated public DKG transcript and ideal registration of `(key_id, t, V, pk)`. | Malicious-secure DKG/VSS simulation, share privacy, complaint soundness, and key-bias resistance. |
| S4 | Replace honest masking commitments and openings with simulated commitments programmed through `H_w` as needed. | Commitment hiding, binding, and no detectable prior-query conflict. |
| S5 | Replace honest partial-share and contribution-proof generation with simulated proof-bound frames. | Contribution proof zero-knowledge or MPC privacy plus context binding under `H_contrib`. |
| S6 | Replace challenge derivation with the global `H_c` table and account for prior adversarial queries. | Random-oracle programmability, transcript injectivity, and challenge binding. |
| S7 | Replace accepting aggregate signatures for authorized messages with signatures released by `F_TMLDSA`. | Aggregation correctness, ML-DSA distributional equivalence, and abort compatibility. |
| S8 | Ideal execution with `F_TMLDSA`, simulated DKG/signing/evidence trace, and reductions for unauthorized accepting outputs. | Unauthorized outputs imply ML-DSA forgery or a listed threshold-assumption violation. |

Relation to theorem hybrids:

- S0 through S2 refine FST-H0 through FST-H2.
- S3 adds the DKG simulation missing from the theorem-level list.
- S4 through S6 refine FST-H3 and the random-oracle programming obligations.
- S7 refines FST-H4.
- S8 is FST-H5.

## RIS-10. Hard Gaps Before Completion

The hardest simulator gaps are:

- DKG equivocation and extraction: the simulator needs a selected
  malicious-secure DKG/VSS theorem with public-key bias resistance and
  anti-framing complaint semantics.
- Honest partial simulation: the proof needs a real contribution relation that
  is sound and simulatable while preserving ML-DSA witness privacy.
- Abort distribution: the proof must bound selective aborts, retries, and
  rejection sampling so accepted signatures remain ML-DSA-distributed.
- Oracle prior queries: the simulator must handle adversarial queries to
  `H_mu`, `H_w`, `H_c`, `H_vss`, and `H_contrib` before programming points.
- Final signature replacement: replacing threshold aggregates with
  `F_TMLDSA` signatures requires a distributional equivalence argument for
  standard ML-DSA-65 signatures.
- Adaptive corruption: this skeleton excludes adaptive security until erasure
  and state-exposure rules are specified.

## RIS-11. Stable Anchors

The documentation manifest treats the following anchors as stable:

- `# Real/Ideal Simulator Skeleton for Threshold ML-DSA-65`
- `real-ideal-simulator-skeleton`
- `## RIS-2. Simulator State`
- `## RIS-4. Oracle Programming Points`
- `## RIS-5. Corruption Handling`
- `## RIS-6. DKG Simulation`
- `## RIS-7. Signing Simulation`
- `## RIS-8. Abort and Evidence Simulation`
- `## RIS-9. Hybrid Sequence S0..S8`
- `simulator skeleton, not a completed proof`

Keep these anchors stable when reorganizing this document, or update
`tests/proof_documentation_manifest.rs` in the same change.
