# Contribution Backend Selection Framework
<a id="contribution-backend-selection"></a>

Date: 2026-05-28

## Status
<a id="cbs-status"></a>

Selection framework and decision record only. No production contribution
backend is selected; `eps_contrib` remains open. Current transcript-hash
contribution proofs are scaffold-only.

## Scope
<a id="cbs-scope"></a>

This plan defines the decision record needed before the project can close the
`eps_contrib` term. It sits above
[contribution-soundness-relation.md](contribution-soundness-relation.md) and
[contribution-backend-instantiation.md](contribution-backend-instantiation.md):
those files define the relation and theorem route, while this file records the
candidate backend families and acceptance criteria.

No backend is selected by this document. The current transcript-hash payload
binding remains scaffold evidence only; it is not a zero-knowledge proof, an
MPC proof, an extractable proof, or a production contribution relation.

## Required Backend Declaration
<a id="cbs-required-backend-declaration"></a>

A production backend candidate must declare:

```text
backend_id
backend_family
statement_schema
witness_schema
public_parameters
soundness_assumption
hiding_or_leakage_statement
extractor_or_replacement_argument
simulation_strategy
audit_status
```

The declaration must bind `sid`, epoch, validator set, threshold, signer
identity, DKG digest, commitment set, challenge, contribution encoding, and
ML-DSA-65 parameter set.

## Backend Candidates
<a id="cbs-backend-candidates"></a>

| Candidate | Possible role | Required proof before selection |
| --- | --- | --- |
| NIZK / proof-of-knowledge backend <a id="candidate-nizk-contribution-proof"></a> | Non-interactive proof `pi_contrib` over canonical `ProductionContributionStatement`. | Knowledge soundness or simulation extractability, zero knowledge or witness hiding, ROM/domain-separation compatibility, extractor usable by S4 -> S5, concrete proof system and reviewed parameters. |
| MPC verification backend <a id="candidate-mpc-contribution-verification"></a> | Transcript-bound MPC verification result. | Public verifiability, explicit leakage function, robust abort handling, simulator composition, and witness privacy for `c*s1`, `c*s2`, `c*t0`, masking material, and rejected attempts. |
| Interactive proof backend <a id="candidate-interactive-contribution-proof"></a> | Challenge/response transcript. | Soundness plus special soundness or replacement lemma, HVZK/full ZK as needed, replay protection, transcript binding, and scheduling/rewinding analysis. |
| Ideal `F_contrib` placeholder <a id="candidate-ideal-contribution-functionality"></a> | Ideal acceptance record for proof decomposition. | Explicit idealization theorem, leakage statement, simulator replacement, and later realization obligation. It is not production eligible. |
| Transcript-hash scaffold <a id="candidate-transcript-hash-scaffold"></a> | Current payload digest/proof digest scaffolding. | Ineligible for production. It must remain rejected by production policy. |

## Decision Criteria
<a id="cbs-decision-criteria"></a>

The backend selection must satisfy:

- Soundness for malformed, stale, duplicated, rebound, or out-of-set
  contribution frames.
- Hiding for secret shares, masks, and any witness material outside the stated
  leakage function.
- Context binding to the exact transcript and contribution statement.
- Compatibility with aggregate rejection and standard ML-DSA-65 verification.
- Simulator support for honest contributions and extractor or replacement
  support for corrupted contributions.
- Clear runtime, proof-size, and bandwidth assumptions for the L1 setting.
- Integration with
  `ContributionProofSecurityProfile::ProductionProofRelation`.
- Independent cryptographic review status.

## Theorem Dependencies
<a id="cbs-theorem-dependencies"></a>

The selected backend must instantiate:

```text
eps_contrib
  <= eps_contrib_sound
   + eps_contrib_extract
   + eps_contrib_hide
   + eps_contrib_context
   + eps_contrib_encoding
   + eps_contrib_leakage
```

Every subterm must be either proved negligible under a named assumption or
carried visibly into the theorem statement. A production claim cannot treat
`eps_contrib` as closed while any subterm is only scaffold-tested.

The selection must cite `Theorem CBI-production-contribution`,
`csr-production-statement`, `csr-soundness-game`, `csr-extraction-target`, and
`csr-witness-hiding-target`. It must also avoid double-counting with
`eps_vss`, `eps_mask`, `eps_commit`, `eps_ro`, `eps_rej`, `eps_withhold`, and
`eps_classify`.

## Acceptance Criteria
<a id="cbs-acceptance-criteria"></a>

Before this decision record can select a backend:

- A backend declaration is added and reviewed.
- The relation statement is byte-level canonical and manifest-tested.
- The backend theorem states soundness, hiding or leakage, and extraction or
  replacement assumptions.
- The implementation rejects scaffold backend families for production labels.
- The proof crosswalk maps source modules and tests to each theorem
  precondition without claiming tests prove the backend.

## Decision Record
<a id="cbs-decision-record"></a>

Current decision: no production contribution backend selected. The next
logical choice is either a proof-carrying contribution backend or an ideal
contribution functionality that isolates signing proof work from backend
realization work.

NIZK, MPC verification, and interactive proof remain candidate families. Ideal
functionality remains a proof placeholder. Transcript-hash scaffold is not
production eligible.

## Safe Status Language
<a id="cbs-safe-status-language"></a>

Safe:

- The repository defines a contribution-backend selection framework.
- No production contribution backend is selected.
- Current transcript-hash contribution proofs are scaffold-only.
- `eps_contrib` remains open pending a reviewed backend theorem.

Unsafe:

- Contribution proofs are sound.
- The production relation is implemented.
- The scaffold closes Game 4.
- Passing the production gate proves contribution security.

## Production Policy Anchors
<a id="cbs-production-policy-anchors"></a>

The decision record must remain aligned with:

- `ContributionProofSecurityProfile::TranscriptHashScaffold`
- `ContributionProofSecurityProfile::ProductionCandidateScaffold`
- `ContributionProofSecurityProfile::ProductionProofRelation`
- `require_production_contribution_proof_backend`
- `require_production_threshold_backends`

## Manifest Anchors

- `# Contribution Backend Selection Framework`
- `contribution-backend-selection`
- `cbs-status`
- `cbs-scope`
- `cbs-required-backend-declaration`
- `cbs-backend-candidates`
- `candidate-nizk-contribution-proof`
- `candidate-mpc-contribution-verification`
- `candidate-interactive-contribution-proof`
- `candidate-ideal-contribution-functionality`
- `candidate-transcript-hash-scaffold`
- `cbs-decision-criteria`
- `cbs-theorem-dependencies`
- `eps_contrib_sound`
- `eps_contrib_extract`
- `eps_contrib_hide`
- `cbs-acceptance-criteria`
- `cbs-decision-record`
- `cbs-safe-status-language`
- `cbs-production-policy-anchors`
- `ProductionProofRelation`
- `not production eligible`
