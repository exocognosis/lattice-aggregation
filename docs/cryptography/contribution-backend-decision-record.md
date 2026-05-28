# Contribution Backend Decision Record
<a id="contribution-backend-decision-record"></a>

Date: 2026-05-28

Status: decision record for the immediate proof route, not a production backend selection.

## Status
<a id="cbdr-status"></a>

This record resolves the immediate theorem-writing fork described in
[contribution-backend-selection.md](contribution-backend-selection.md). It
selects the contribution backend assumption used for the next IdealVSS proof
worksheets. It does not select or implement a production NIZK, MPC,
interactive, or audited contribution backend.

This document does not close `eps_contrib`. It does not make the
`TranscriptHashScaffold` production eligible and does not prove
`ProductionProofRelation` security.

## Decision
<a id="cbdr-decision"></a>

Decision: adopt ideal `F_contrib` as the immediate proof-route placeholder for
accepted contribution validity. This is an idealization for theorem
decomposition only. It is not a production contribution backend, not a
zero-knowledge proof, not an MPC verification protocol, not extractable
implementation evidence, and not a claim that current transcript-hash
contribution proofs are sound.

The symbol `F_CONTRIB` is retained in theorem-route text as the uppercase
ideal-functionality name for `F_contrib`.

## Immediate Theorem Route
<a id="cbdr-immediate-theorem-route"></a>

The current repository has a production statement target, contribution
soundness relation scaffolding, production policy gates that reject scaffold
backends, proof-bearing boundaries and tests, and no reviewed concrete
proof/MPC/interactive backend theorem.

Selecting a concrete backend now would overclaim. Ideal contribution
functionality keeps the proof architecture honest: signing-side reductions can
be written against a crisp interface while `eps_contrib` and concrete
realization remain visible.

## Non-Production Idealization Boundary
<a id="cbdr-non-production-idealization-boundary"></a>

`F_CONTRIB` exposes only:

- public acceptance or rejection for `ContributionStatement_i`;
- relation-valid contribution encoding or a replacement handle sufficient for
  aggregation proofs;
- explicit leakage allowed by the selected theorem statement;
- simulator hooks for honest contribution frames;
- failure labels needed for classifier routing.

It must not reveal honest shares, masks, `c*s1`, `c*s2`, `c*t0`, proof
randomness, or rejected-attempt internals beyond the declared leakage function.

`ContributionProofSecurityProfile::ProductionProofRelation` is a policy marker,
not proof completion.

## Residual Terms
<a id="cbdr-residual-terms"></a>

The decision preserves:

```text
eps_contrib
  <= eps_contrib_sound
   + eps_contrib_extract
   + eps_contrib_hide
   + eps_contrib_context
   + eps_contrib_encoding
   + eps_contrib_leakage
```

For the immediate proof route, these are represented by an explicit
idealization term:

```text
eps_contrib_ideal
```

Cross-dependencies remain visible: `eps_vss_ideal`, `eps_ro_prior`,
`eps_ro_sep`, `eps_commit`, `eps_collect`, `eps_cls_contrib`, and
`eps_cls_unmapped = 0`. These terms are not closed by tests or scaffold
evidence.

## Non-Selected Candidates
<a id="cbdr-non-selected-candidates"></a>

The following remain candidate families:

- NIZK or proof-of-knowledge contribution backend.
- MPC verification backend.
- Interactive contribution proof backend.
- Concrete production proof relation.

The `TranscriptHashScaffold` and `ProductionCandidateScaffold` remain
scaffold-only and not production eligible.

## Production Realization Requirements
<a id="cbdr-production-realization-requirements"></a>

To replace `F_CONTRIB`, a future backend must provide:

- backend declaration with `backend_id`, family, statement and witness schemas,
  assumptions, leakage, extractor or replacement argument, simulator strategy,
  and audit status;
- a theorem matching `Theorem CBI-production-contribution`;
- canonical `ProductionContributionStatement` binding and manifest-tested
  schema;
- soundness for corrupted accepted frames;
- extraction or precise replacement lemma for S4 to S5;
- witness hiding, zero knowledge, or explicit leakage theorem covering `c*s1`,
  `c*s2`, `c*t0`, masks, proof randomness, and rejected attempts;
- composition notes avoiding double-counting with `eps_vss`, `eps_mask`,
  `eps_commit`, `eps_ro`, `eps_rej`, `eps_withhold`, and `eps_classify`;
- independent cryptographic review.

## Revisit Criteria
<a id="cbdr-revisit-criteria"></a>

Revisit this decision only when a concrete backend candidate provides the
production realization requirements above and updates
`csr-production-statement`, `csr-soundness-game`, `csr-extraction-target`, and
`csr-witness-hiding-target` with reviewed backend-specific details.

## Evidence And Tests
<a id="cbdr-evidence-tests"></a>

Implementation evidence includes `tests/contribution_proof.rs`,
`tests/production_policy.rs`, `tests/hazmat_mldsa65_wire.rs`,
`src/crypto/production_policy.rs`, and
[proof-implementation-crosswalk.md](proof-implementation-crosswalk.md).

Implementation evidence is not cryptographic proof.

## Safe Status Language
<a id="cbdr-safe-status-language"></a>

Safe:

- The immediate route assumes ideal contribution functionality.
- No production contribution backend is selected.
- Current transcript-hash proofs remain scaffold-only.
- `eps_contrib` remains open.

Unsafe:

- Contribution proofs are sound.
- The production relation is implemented.
- Scaffold tests close Game 4.
- `ProductionProofRelation` proves contribution security.

## Acceptance Criteria
<a id="cbdr-acceptance-criteria"></a>

This decision record is acceptable only if downstream documents:

- label `F_CONTRIB` as idealized;
- keep `eps_contrib` or `eps_contrib_ideal` visible;
- do not claim production contribution soundness;
- do not treat scaffold tests as proof;
- preserve the future concrete realization obligation.

## Non-Claims
<a id="cbdr-non-claims"></a>

This record does not select a production contribution backend. It does not
prove zero knowledge, MPC privacy, witness hiding, extraction, leakage bounds,
or production contribution soundness. It does not prove the project thesis.

## Manifest Anchors
<a id="cbdr-manifest-anchors"></a>

- `# Contribution Backend Decision Record`
- `contribution-backend-decision-record`
- `Status: decision record for the immediate proof route, not a production backend selection.`
- `cbdr-status`
- `cbdr-decision`
- `cbdr-immediate-theorem-route`
- `cbdr-non-production-idealization-boundary`
- `cbdr-residual-terms`
- `cbdr-revisit-criteria`
- `cbdr-evidence-tests`
- `cbdr-safe-status-language`
- `F_CONTRIB`
- `F_contrib`
- `ideal contribution functionality`
- `eps_contrib`
- `eps_contrib_ideal`
- `eps_contrib_sound`
- `eps_contrib_extract`
- `eps_contrib_hide`
- `eps_contrib_context`
- `eps_contrib_encoding`
- `eps_contrib_leakage`
- `Theorem CBI-production-contribution`
- `csr-production-statement`
- `csr-soundness-game`
- `csr-extraction-target`
- `csr-witness-hiding-target`
- `ProductionContributionStatement`
- `ProductionCandidateScaffold`
- `ProductionProofRelation`
- `TranscriptHashScaffold`
- `not production eligible`
- `not a production backend selection`
- `implementation evidence is not cryptographic proof`
