# eps_contrib Backend Proof Route
<a id="eps-contrib-backend-proof-route"></a>

Status: backend-proof roadmap for eps_contrib; not a selected backend, not a
completed contribution proof, and not evidence that any current backend is
production sound.

This roadmap expands the contribution-validity, hiding, extraction, and
simulation obligations that must be discharged before the signing proof may
replace the idealized contribution boundary with a concrete backend theorem. It
tightens the `F_CONTRIB` idealization boundary so downstream theorem text can
name exactly what is assumed without claiming that a backend has been selected
or proved.

## C1-0. Scope
<a id="c1-scope"></a>

`eps_contrib` covers the loss from treating accepted contribution frames as
valid, context-bound, hidden within the declared leakage, and available to the
simulator through extraction or an ideal replacement lemma. The current
transcript-hash scaffold, production policy gate, and documentation manifest
are integration evidence only. They are not cryptographic proof.

This route is compatible with the immediate ideal `F_CONTRIB` theorem route and
with a future concrete proof, MPC, or interactive backend. It does not choose
among those families.

## C1-1. Contribution Statement
<a id="c1-contribution-statement"></a>

The public contribution statement `S_contrib_i` is the canonical, injectively
encoded public input for validator `i` in a single signing attempt. It must bind
at least:

- protocol and statement schema version;
- epoch, session, block height, attempt, and validator index;
- threshold parameters and active validator set digest;
- ML-DSA-65 parameter-set digest, public key digest, `mu`, and challenge;
- accepted DKG/VSS commitment digest for the epoch;
- masking, secret-contribution, and contribution-encoding commitment digests;
- contribution backend family, backend ID, version, domain separators, and
  relation identifier.

The statement is not allowed to depend on implicit local state. A verifier or
ideal functionality must be able to reject stale, cross-session,
wrong-validator, wrong-challenge, wrong-DKG, wrong-commitment, malformed, or
unsupported statements from the public encoding alone.

## C1-2. Witness
<a id="c1-witness"></a>

The private witness `W_contrib_i` is backend-specific, but the proof target must
define enough structure to audit the relation. It includes, or is replaced by a
backend-native handle for:

- validator share consistency with the accepted DKG/VSS relation;
- masking commitment openings and attempt-local randomness;
- secret-contribution commitment openings, if the backend uses them;
- ML-DSA partial-contribution terms needed to check the contribution equation;
- bound predicates or labeled deferrals to aggregation/rejection lemmas;
- proof, MPC, or interactive verification randomness; and
- the claimed contribution encoding before public digesting.

No theorem may rely on witness fields that are absent from the relation
statement. If a backend uses a replacement lemma instead of explicit
extraction, the replacement object must still be stated with the same public
context and contribution encoding.

## C1-3. Context Binding and Active Set
<a id="c1-context-active-set"></a>

Context binding means that acceptance for `(S_contrib_i, pi_i)` is valid only
for the exact transcript context used by aggregation:

```text
ctx_i = (
  protocol_version,
  epoch_id,
  session_id,
  block_height,
  attempt,
  validator_index,
  threshold,
  total_nodes,
  active_set_digest,
  public_key_digest,
  parameter_set_digest,
  mu,
  challenge,
  dkg_commitment_digest,
  masking_commitment_digest,
  secret_commitment_digest,
  contribution_commitment_digest,
  backend_id,
  backend_version,
  relation_id
)
```

The active set is the ordered set of validators eligible for the epoch and
attempt. The backend theorem must state whether it proves validity for every
accepted frame in the active set, only for accepted corrupted frames, or for
accepted frames after collection filtering. Any dependency on collection
soundness, evidence routing, or no-subthreshold authorization must be explicit
and charged outside `eps_contrib` unless the backend theorem includes it.

## C1-4. Relation Validity
<a id="c1-relation-validity"></a>

Relation validity is the claim that an accepted contribution corresponds to a
witness or replacement object satisfying the production relation:

```text
Accept_contrib(S_contrib_i, pi_i, ctx_i) = 1
  => R_contrib(S_contrib_i, W_contrib_i) = 1
```

The relation must cover share consistency, commitment openings, challenge
binding, ML-DSA partial-contribution equations, contribution-encoding binding,
and every bound predicate that aggregation later assumes. If a predicate is
proved elsewhere, the statement must name the exact predicate and residual
term.

## C1-5. Hiding and Leakage
<a id="c1-hiding-leakage"></a>

The backend must provide zero knowledge, witness hiding, MPC leakage security,
or an explicitly reviewed leakage theorem. The leakage function
`L_contrib(ctx_i)` must be stated before the theorem is used.

The hiding target must protect honest validator shares, masking secrets,
commitment openings, proof randomness, MPC local views, and rejected-attempt
witness state. In particular, it must not reveal `c*s1`, `c*s2`, `c*t0`, DKG
private shares, masking randomness, or secret-dependent partial terms except as
permitted by `L_contrib`.

If a backend leaks timing, abort labels, message counts, proof sizes, or
malformed-frame classifications, that leakage must be named and composed with
`eps_withhold`, `eps_rej`, `eps_evid`, and side-channel assumptions. Silence is
not a leakage theorem.

## C1-6. Extraction or Ideal Replacement
<a id="c1-extraction-ideal-replacement"></a>

The simulator needs one of two targets:

- an extractor that, for every accepted adversarial contribution, outputs a
  context-bound witness or witness handle satisfying `R_contrib`; or
- an ideal replacement lemma showing that the accepted contribution can be
  replaced by an ideal relation-valid contribution with the same public
  encoding and declared leakage.

The chosen target must be strong enough for the S4 -> S5 transition in the
real/ideal simulator. A verification-only theorem is insufficient unless it
states the replacement object and the exact bad event charged to
`eps_contrib_extract`.

## C1-7. Simulation Interface
<a id="c1-simulation-interface"></a>

The simulator-facing interface must expose only:

- public accept/reject decisions for canonical contribution statements;
- relation-valid contribution encodings or backend-native replacement handles;
- declared leakage `L_contrib(ctx_i)`;
- simulator-generated honest contribution frames;
- extractor outputs or ideal replacement records for adversarial accepted
  frames; and
- failure labels needed by the unauthorized-output classifier.

It must not expose honest witnesses, proof randomness, rejected-attempt
internals, or secret-dependent ML-DSA partial terms outside the declared
leakage. The interface must specify how simulator-generated honest frames are
indistinguishable from real honest frames under the chosen backend theorem.

## C1-8. Theorem Target
<a id="c1-theorem-target"></a>
<a id="theorem-c1-contribution-backend-soundness"></a>

Theorem C1-contribution-backend-soundness. For every PPT adversary `A`,
environment `Z`, static active corruption set of size less than the threshold,
accepted DKG/VSS epoch context, and contribution backend profile satisfying
this route's declaration requirements, the replacement of real contribution
checking by the selected backend theorem or ideal `F_CONTRIB` interface changes
the signing experiment by at most:

```text
eps_contrib(A,Z)
  <= eps_contrib_relation(A,Z)
   + eps_contrib_binding(A,Z)
   + eps_contrib_hiding(A,Z)
   + eps_contrib_extract(A,Z)
   + eps_contrib_sim(A,Z)
   + eps_contrib_malleability(A,Z)
   + eps_contrib_backend_selection(A,Z)
```

where:

- `eps_contrib_relation` covers accepted frames that do not satisfy
  `R_contrib` or its stated replacement relation.
- `eps_contrib_binding` covers context, active-set, commitment, challenge, and
  statement-encoding binding failures.
- `eps_contrib_hiding` covers witness hiding, zero knowledge, MPC privacy, and
  declared leakage mismatches.
- `eps_contrib_extract` covers extractor failure or replacement-lemma failure
  for accepted adversarial frames.
- `eps_contrib_sim` covers simulator indistinguishability for honest frames and
  ideal-interface behavior.
- `eps_contrib_malleability` covers proof, transcript, replay, aggregation,
  and cross-context malleability not already charged to binding.
- `eps_contrib_backend_selection` covers the event that an unselected,
  scaffold, unaudited, mismatched, or policy-ineligible backend is used as if
  it satisfied the theorem.

The theorem target is a roadmap. This document does not prove that the bound is
negligible, zero, or currently instantiated.

## C1-9. Candidate Backend Families
<a id="c1-candidate-backend-families"></a>

### Proof System

A proof-system backend may be a NIZK, proof of knowledge, or
simulation-extractable proof over canonical `S_contrib`. Acceptance requires:

- a precise relation, statement schema, witness schema, and parameter set;
- soundness or knowledge soundness for corrupted accepted contributions;
- zero knowledge or witness hiding for honest contributions;
- domain separation and random-oracle composition compatible with the
  transcript proof;
- extraction or a proof-system-native replacement lemma; and
- malleability, replay, and cross-context rejection arguments.

Non-claim: no such proof system is selected or proved here.

### MPC or Interactive Proof

An MPC or interactive backend may verify contribution validity through
interactive messages, public verification, or a transcript-bound verifier.
Acceptance requires:

- a declared leakage function and privacy theorem for honest parties;
- robust abort handling and composition with selective-abort accounting;
- public verifiability or auditable transcript acceptance;
- active-set and context binding for every message;
- extractor, ideal functionality realization, or replacement theorem; and
- replay, fork, scheduling, and malleability analysis.

Non-claim: no MPC or interactive backend is selected, audited, or proved here.

### Ideal Functionality `F_CONTRIB`

`F_CONTRIB` is an ideal contribution-validity boundary used for theorem
decomposition. Acceptance requires:

- exact public inputs, outputs, leakage, and failure labels;
- relation-valid acceptances by definition or explicit ideal replacement
  records;
- simulator hooks matching the S4 -> S5 transition;
- no production-implementation language; and
- a visible future realization obligation.

Non-claim: `F_CONTRIB` is not a production backend, not a zero-knowledge proof,
not MPC privacy, and not a completed contribution theorem.

## C1-10. Acceptance Criteria
<a id="c1-acceptance-criteria"></a>

This roadmap is acceptable only if downstream documents:

- keep `eps_contrib` expanded into the visible subterms in
  `Theorem C1-contribution-backend-soundness`;
- identify whether they use a proof system, MPC or interactive proof, or ideal
  `F_CONTRIB`;
- keep `F_CONTRIB` labeled as idealized theorem decomposition;
- preserve the future concrete realization obligation;
- reject scaffold, unaudited, mismatched, or undeclared backends for
  production-labeled claims;
- do not claim a backend is selected;
- do not claim contribution soundness is proved;
- do not claim any `eps_contrib` subterm is negligible or zero;
- do not claim production readiness; and
- state that implementation evidence is not cryptographic proof.

## C1-11. Non-Claims
<a id="c1-non-claims"></a>

This document selects no backend. It proves no contribution soundness,
zero-knowledge, witness-hiding, MPC privacy, extraction, ideal realization,
leakage bound, malleability bound, or negligible/zero residual. It does not
make the transcript-hash scaffold production eligible. It is not
production-ready, and implementation evidence is not cryptographic proof.

## C1-12. Manifest Anchors
<a id="c1-manifest-anchors"></a>

- `# eps_contrib Backend Proof Route`
- `eps-contrib-backend-proof-route`
- `Status: backend-proof roadmap for eps_contrib`
- `C1-0. Scope`
- `C1-1. Contribution Statement`
- `C1-2. Witness`
- `C1-3. Context Binding and Active Set`
- `C1-4. Relation Validity`
- `C1-5. Hiding and Leakage`
- `C1-6. Extraction or Ideal Replacement`
- `C1-7. Simulation Interface`
- `C1-8. Theorem Target`
- `C1-9. Candidate Backend Families`
- `C1-10. Acceptance Criteria`
- `C1-11. Non-Claims`
- `C1-12. Manifest Anchors`
- `Theorem C1-contribution-backend-soundness`
- `theorem-c1-contribution-backend-soundness`
- `F_CONTRIB`
- `eps_contrib`
- `eps_contrib_relation`
- `eps_contrib_binding`
- `eps_contrib_hiding`
- `eps_contrib_extract`
- `eps_contrib_sim`
- `eps_contrib_malleability`
- `eps_contrib_backend_selection`
- `R_contrib`
- `S_contrib`
- `W_contrib`
- `L_contrib`
- `no backend selected`
- `no contribution soundness proved`
- `no negligible or zero claim`
- `not production-ready`
- `implementation evidence is not cryptographic proof`
