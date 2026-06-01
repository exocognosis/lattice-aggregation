# eps_contrib Backend Decision Record
<a id="eps-contrib-backend-decision-record"></a>

Stable anchor: `eps-contrib-backend-decision-record`

Status: decision record / roadmap for eps_contrib; not a backend selection
for production, not a completed contribution proof, and not evidence that any
current contribution backend is production secure.

This record evaluates plausible backend routes for `eps_contrib` and names the
immediate theorem route. It preserves the non-production boundary around the
current proof work: idealized theorem decomposition may continue, but concrete
production claims remain blocked until a proof, MPC, or interactive backend is
specified, reviewed, and proved.

## C2-0. Scope
<a id="c2-scope"></a>

`eps_contrib` accounts for the loss from treating accepted contribution frames
as valid, context-bound, hidden within declared leakage, and available to the
simulator through extraction or replacement. The current transcript-hash
scaffold and implementation gates are engineering evidence only. They are not
cryptographic proof and do not close contribution soundness.

The decision target is:

Decision C2-immediate-ideal-contrib-route. Immediate theorem work should
continue with ideal `F_CONTRIB` for proof isolation. Production remains blocked
pending a concrete proof-system, MPC, or interactive backend that satisfies the
decision criteria below. This is not a production security claim.

## C2-1. Decision Criteria
<a id="c2-decision-criteria"></a>

Candidate routes are evaluated against:

- relation coverage: whether the route covers share consistency, commitment
  openings, challenge binding, ML-DSA partial-contribution equations,
  contribution encoding, active set, validator identity, and context binding;
- witness hiding/leakage: whether honest shares, masks, openings, randomness,
  rejected attempts, and secret-dependent partial terms are hidden except for a
  declared leakage function;
- extraction or replacement: whether the simulator receives a context-bound
  witness, witness handle, or ideal replacement record for accepted adversarial
  frames;
- malleability: whether replay, fork, cross-session, cross-validator,
  cross-backend, aggregation, and transcript-malleability cases are rejected or
  charged;
- implementation maturity: whether the route has a concrete specification,
  parameter set, code boundary, test coverage, and fail-closed policy behavior;
- auditability: whether the relation, assumptions, domains, leakage, theorem,
  and implementation are independently reviewable; and
- composition with selective abort/classifier: whether leakage, abort labels,
  rejection reasons, evidence routing, and unauthorized-output classification
  compose without hiding residual terms or double-counting them.

## C2-2. Candidate Route: Ideal `F_CONTRIB`
<a id="c2-ideal-f-contrib-route"></a>

The ideal `F_CONTRIB` route gives theorem writers a clean contribution-validity
boundary. It can define accepted contribution outputs as relation-valid by
construction, expose only declared public outputs and leakage, and provide
simulator hooks needed for proof isolation.

Strengths:

- isolates signing-theorem work from an unselected concrete backend;
- keeps relation, leakage, extraction, and replacement obligations visible;
- avoids treating scaffold tests as cryptographic proof; and
- composes naturally with the current idealized proof route.

Limits:

- it is not an implementation backend;
- it does not prove that transcript-hash contribution frames are sound;
- it does not provide zero knowledge, MPC privacy, or production extraction;
  and
- it must remain paired with a future concrete realization obligation.

Decision impact: recommended for immediate theorem work only.

## C2-3. Candidate Route: Proof System / NIZK
<a id="c2-proof-system-nizk-route"></a>

A proof-system route would instantiate a NIZK, proof of knowledge, or
simulation-extractable proof over canonical contribution statements. It must
define the exact relation, statement schema, witness schema, parameter set,
domain separators, verifier, extractor or replacement lemma, and leakage.

Strengths:

- can give public, non-interactive verification for accepted contributions;
- may align well with transcript-bound statement encoding; and
- can be audited as a standalone cryptographic component if the relation is
  explicit.

Open blockers:

- no concrete proof system is selected here;
- relation coverage for ML-DSA partial-contribution equations is not proved;
- witness hiding and leakage are not established;
- extraction or simulation-extractability is not supplied; and
- malleability and random-oracle composition remain unclosed.

Decision impact: plausible future production route, but not selected.

## C2-4. Candidate Route: MPC / Interactive Proof
<a id="c2-mpc-interactive-proof-route"></a>

An MPC or interactive-proof route would verify contribution validity through
interactive messages, public transcripts, or a transcript-bound verifier. It
must specify scheduling assumptions, active corruption model, leakage,
selective-abort handling, transcript audit rules, and the simulator interface.

Strengths:

- may avoid forcing the whole contribution relation into one NIZK circuit;
- can use protocol-native interaction to validate contribution consistency;
  and
- can expose auditable transcripts if message schemas are canonical.

Open blockers:

- no MPC or interactive backend is selected or audited here;
- privacy under abort, timing, message counts, and malformed-frame
  classifications is not proved;
- extraction, ideal realization, or replacement is not supplied;
- scheduler, replay, fork, and transcript-malleability cases remain open; and
- composition with evidence routing and the classifier must be shown.

Decision impact: plausible future production route, but not selected.

## C2-5. Candidate Route: Transcript-Hash Scaffold
<a id="c2-transcript-hash-scaffold-route"></a>

The transcript-hash scaffold is useful for deterministic tests, schema
plumbing, production-policy gates, and integration evidence. It can help check
that context fields are carried through code and that scaffold backends are
rejected for production-labeled configurations.

Limits:

- it is not a proof of contribution soundness;
- it does not prove witness hiding, zero knowledge, MPC privacy, extraction, or
  replacement;
- it does not justify negligible or zero `eps_contrib`; and
- implementation evidence is not cryptographic proof.

Decision impact: keep as scaffold and evidence only. It is not a production
backend route.

## C2-6. Recommendation
<a id="c2-recommendation"></a>

Immediate theorem work should continue with ideal `F_CONTRIB` for proof
isolation. This keeps downstream signing reductions explicit about the
contribution-validity boundary while avoiding unsupported production claims.

Production remains blocked until a concrete proof-system, MPC, or interactive
backend provides the relation coverage, hiding/leakage theorem, extraction or
replacement target, malleability analysis, implementation maturity,
auditability, and selective-abort/classifier composition required by this
record and by the backend proof route.

This recommendation does not claim production security, select a production
backend, prove contribution soundness, prove zero knowledge, or make any
`eps_contrib` term negligible or zero.

## C2-7. Residual Accounting Impact
<a id="c2-residual-accounting-impact"></a>

For `eps_contrib_ideal`, the immediate route keeps an explicit ideal-boundary
term. The term accounts for the proof step that assumes ideal contribution
validity instead of a concrete backend theorem.

For `eps_contrib_backend_selection`, the decision preserves a visible residual
for treating an unselected, scaffold, unaudited, mismatched, or
policy-ineligible backend as if it satisfied the contribution theorem.

For concrete `eps_contrib`, no residual is closed by this record. A future
backend must still expand and discharge relation, binding, hiding, extraction
or replacement, simulation, malleability, leakage, and composition terms before
any negligible or zero claim is available.

## C2-8. Acceptance Criteria
<a id="c2-acceptance-criteria"></a>

This decision record is acceptable only if downstream documents:

- cite `Decision C2-immediate-ideal-contrib-route` when using the immediate
  ideal route;
- label `F_CONTRIB` as idealized theorem decomposition, not a production
  backend;
- keep `eps_contrib_ideal`, `eps_contrib_backend_selection`, and concrete
  `eps_contrib` residuals visible where they are relied on;
- preserve the future concrete realization obligation;
- reject transcript-hash scaffold evidence as a production proof; and
- require a concrete proof-system, MPC, or interactive backend before
  production contribution claims.

## C2-9. Non-Claims
<a id="c2-non-claims"></a>

This record makes these non-claims:

- no production backend is selected;
- no contribution soundness is proved;
- no zero or negligible `eps_contrib` claim is made;
- `F_CONTRIB` is not production-ready;
- the transcript-hash scaffold is not production-ready;
- implementation evidence is not cryptographic proof;
- no zero-knowledge, witness-hiding, MPC-privacy, leakage, extraction,
  replacement, or malleability theorem is proved; and
- no final composition with selective abort or the unauthorized-output
  classifier is closed.

## C2-10. Manifest Anchors
<a id="c2-manifest-anchors"></a>

- `# eps_contrib Backend Decision Record`
- `eps-contrib-backend-decision-record`
- `Status: decision record / roadmap for eps_contrib`
- `C2-0. Scope`
- `C2-1. Decision Criteria`
- `C2-2. Candidate Route: Ideal F_CONTRIB`
- `C2-3. Candidate Route: Proof System / NIZK`
- `C2-4. Candidate Route: MPC / Interactive Proof`
- `C2-5. Candidate Route: Transcript-Hash Scaffold`
- `C2-6. Recommendation`
- `C2-7. Residual Accounting Impact`
- `C2-8. Acceptance Criteria`
- `C2-9. Non-Claims`
- `C2-10. Manifest Anchors`
- `Decision C2-immediate-ideal-contrib-route`
- `F_CONTRIB`
- `proof system/NIZK`
- `MPC/interactive proof`
- `transcript-hash scaffold`
- `eps_contrib`
- `eps_contrib_ideal`
- `eps_contrib_backend_selection`
- `relation coverage`
- `witness hiding/leakage`
- `extraction or replacement`
- `malleability`
- `implementation maturity`
- `auditability`
- `composition with selective abort/classifier`
- `no production backend selected`
- `no contribution soundness proved`
- `no zero/negligible claim`
- `not production-ready`
- `implementation evidence is not cryptographic proof`
