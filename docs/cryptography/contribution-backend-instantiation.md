# Contribution Backend Instantiation Route
<a id="contribution-backend-instantiation"></a>

Date: 2026-05-28

Status: proof-route worksheet for instantiating `eps_contrib`, not a completed
production contribution proof backend.

This worksheet turns
[contribution-soundness-relation.md](contribution-soundness-relation.md) from a
relation target into an implementation-selection route. It defines what a
future backend must declare, prove, and expose before S4 -> S5 and S5 -> S6 in
[simulator-hybrid-reductions.md](simulator-hybrid-reductions.md) may treat
accepted contribution frames as sound, context-bound, and simulatable.

## CBI-0. Scope and Non-Claims
<a id="cbi-scope"></a>

The current transcript-hash contribution scaffold remains an API boundary and
test harness. It is not a production backend. It does not prove partial-share
validity, witness hiding, zero knowledge, MPC privacy, extractability, or
algebraic correctness for ML-DSA secret-dependent terms.

This route does not choose a concrete proof system. It records the exact
acceptance criteria that a selected zero-knowledge proof, MPC verification
relation, interactive proof, or reviewed equivalent must satisfy.

## CBI-1. Backend Declaration Target
<a id="cbi-backend-declaration"></a>

A production contribution backend must declare a canonical profile:

```text
ContributionBackendProfile = (
  backend_id,
  backend_version,
  relation_id,
  statement_schema_id,
  parameter_set_id,
  soundness_theorem_ref,
  hiding_theorem_ref,
  extractor_or_equivalent_ref,
  leakage_function_id,
  audit_status_ref
)
```

The declaration is an input to policy checks; it is not itself a proof. The
backend must be rejected for production-labeled configuration unless all of the
following are true:

- `relation_id` instantiates `R_contrib` or a versioned successor.
- `statement_schema_id` binds the canonical production statement fields.
- `soundness_theorem_ref` identifies a reviewed theorem strong enough for
  accepted corrupted contributions.
- `hiding_theorem_ref` identifies either zero knowledge, witness hiding, or a
  reviewed MPC leakage theorem for honest contributions.
- `extractor_or_equivalent_ref` identifies the extraction target or the exact
  replacement lemma used by the simulator.
- `leakage_function_id` is explicit and compatible with the theorem's
  side-channel and abort-observable boundary.

## CBI-2. Theorem Target
<a id="cbi-theorem-target"></a>
<a id="theorem-cbi-production-contribution"></a>

Theorem CBI-production-contribution. For every accepted contribution frame
`frame_i` with canonical statement `S_contrib_i`, proof or verification artifact
`pi_i`, and public transcript context `ctx`, the selected production backend
must establish:

```text
Accept_contrib(S_contrib_i, pi_i, ctx) = 1
  => R_contrib(S_contrib_i, W_i) = 1
```

except with probability:

```text
eps_contrib
  <= eps_contrib_sound
   + eps_contrib_extract
   + eps_contrib_hide
   + eps_contrib_context
   + eps_contrib_encoding
   + eps_contrib_leakage.
```

The theorem must also provide either an extractor for `W_i` or a
proof-system-native replacement lemma sufficient for the S4 -> S5 simulator.
If the backend is only verification-sound, the substitute target must be
spelled out and carried visibly into the real/ideal reduction.

The Batch B roadmap in
[eps-contrib-backend-proof-route.md](eps-contrib-backend-proof-route.md)
expands this target into visible `eps_contrib` subterms and keeps `F_CONTRIB`
as an idealized boundary until a backend is selected and proved.

## CBI-3. Backend Families
<a id="cbi-backend-families"></a>

| Family | Accepted artifact | Required theorem |
| --- | --- | --- |
| Non-interactive zero-knowledge proof | `pi_contrib` over canonical `S_contrib` | Knowledge soundness or simulation-extractability, plus zero knowledge or witness hiding in the random-oracle model used by the transcript. |
| MPC verification | Interactive or transcript-bound MPC result | Public verifiability, reviewed leakage function, robust abort handling, and composition with the threshold signing simulator. |
| Interactive proof | Challenge/response transcript | Soundness, special soundness or extractor substitute, honest-verifier or full zero knowledge as needed, and replay/domain separation. |
| Ideal proof functionality | `F_contrib` acceptance record | Explicit idealization theorem and later realization obligation; not a production implementation by itself. |

Changing backend families changes the proof. A manuscript must not cite tests
for one family as evidence for another family's theorem.

## CBI-4. Acceptance Criteria
<a id="cbi-acceptance-criteria"></a>

Before `eps_contrib` may be set to negligible or zero, all of the following
must be complete:

- The backend declaration, statement schema, and relation identifier are fixed.
- The verifier accepts only canonical statement encodings and rejects malformed,
  stale, cross-session, wrong-validator, wrong-challenge, wrong-DKG, and
  wrong-commitment inputs.
- The soundness theorem covers corrupted validators and accepted adversarial
  frames.
- The hiding or leakage theorem covers honest shares, masking material,
  `c*s1`, `c*s2`, `c*t0`, proof randomness, and rejected-attempt witness state.
- The extraction or replacement target is compatible with the classifier in
  [unauthorized-output-classifier-closure.md](unauthorized-output-classifier-closure.md).
- The backend theorem composes with `eps_mask`, `eps_rej`, `eps_withhold`,
  `eps_ro`, and the selected VSS/DKG route without double-counting bad events.

## CBI-5. Code and Artifact Crosswalk
<a id="cbi-code-crosswalk"></a>

Current repository evidence:

- `src/crypto/contribution_proof.rs` exposes scaffold and profile boundaries.
- `src/crypto/production_policy.rs` rejects scaffold backend families for
  production-labeled configurations.
- `src/adapter/wire.rs` and `src/adapter/actor.rs` carry proof-bound
  contribution frames and production statement digests.
- `tests/contribution_proof.rs`, `tests/production_policy.rs`, and
  `tests/hazmat_mldsa65_wire.rs` check statement digest binding, policy
  rejection, and malformed-frame behavior.
- [contribution-soundness-relation.md](contribution-soundness-relation.md)
  defines the target statement, witness relation, soundness game, extraction
  target, hiding target, context binding, and non-claims.

These artifacts are engineering scaffolding only. They do not prove the backend
theorem target above.

## CBI-6. Non-Claims
<a id="cbi-non-claims"></a>

This worksheet does not instantiate a production proof system, prove
zero-knowledge, prove extraction, prove MPC privacy, or validate a slashing
relation. It does not make transcript-hash proofs sound. It is the route for
selecting and verifying a future backend, not the backend itself.
