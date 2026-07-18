# Internal Theorem-Closure Candidate Semantics

Status: internal evidence-state definition. This does not declare theorem
closure, production cryptographic security, FIPS validation, or independent
review.

Date: 2026-07-18

## ITCC-0. Purpose

`internally_closed_pending_independent_review` is the strongest status the
project may assign before external independent cryptographers review the same
digest-bound implementation, specification, proofs, and evidence.

The status means the project has completed its own implementation and proof
case and has found no remaining internal blocker under the strong model in
[`security-model.md`](security-model.md) and the protocol in
[`threshold-mldsa-protocol-spec.md`](threshold-mldsa-protocol-spec.md). It does
not mean those arguments are correct. Independent review exists to test that
conclusion.

## ITCC-1. State Machine

The allowed progression is:

```text
research_scaffold
  -> internal_closure_work_in_progress
  -> internally_closed_pending_independent_review
  -> independent_review_in_progress
  -> externally_reviewed_accepted | external_review_changes_required
```

`externally_reviewed_accepted` may feed the repository's existing promotion
process. It does not automatically imply production readiness, CAVP/ACVTS
validation, or FIPS module validation. `external_review_changes_required`
returns the package to `internal_closure_work_in_progress` after findings are
recorded and the bundle digest changes.

## ITCC-2. Required Gate

The internal-closure status is valid only when one machine-readable manifest
fails closed unless every requirement below is satisfied for one immutable
bundle digest:

1. The strong security model and protocol specification are approved
   internally without unresolved normative placeholders.
2. The implementation contains a real distributed DKG/VSS and exact active-
   secure MPC signing path with no key, seed, `K`, `rho_prime_prime`, or mask
   reconstruction at a coordinator.
3. Live distributed nonce generation, exact `ExpandMask`, partial `z`/hint
   aggregation, FIPS rejection, retry, abort, erasure, and rollback protection
   all execute in the captured backend.
4. Every accepted output is the ordinary 3309-byte ML-DSA-65 encoding and
   verifies under at least one independent unmodified implementation.
5. FST-L1 through FST-L9 have complete internal proof artifacts with explicit
   assumptions, reductions, simulator hybrids, and concrete loss bounds.
6. The five hypothesis criteria have complete internal evidence and no open
   internal proof or implementation blocker.
7. The production-shaped campaign includes `n = 10000`, `t = 6667`, live DKG,
   multiple authorized signer sets and messages, accepted and rejected signing
   attempts, abort/retry cases, malicious participants, replay/mutation cases,
   and standard-verifier results.
8. The campaign comes from a clean Git-tracked checkout with pinned toolchain,
   source, binary, circuit, protocol, proof, transcript, and evidence digests.
   `dirty`, simulation, fixture, hazmat, quarantined, imported, or
   external-capture sources are not admissible.
9. Unit, integration, conformance, differential, negative, fault-injection,
   serialization, rollback, and side-channel-oriented test gates pass for the
   same bundle.
10. Two named internal reviewers independently sign the manifest after checking
    the proof-to-code crosswalk and reproducing the evidence build. Neither
    signature is represented as independent external review.
11. All known limitations, assumptions, failed experiments, statistical sample
    targets, and residual risks are included in the handoff bundle.
12. `independent_review_status = not_started` or `pending` and every external,
    production, CAVP/ACVTS, and FIPS claim flag remains false.

The gate MUST derive its status from referenced artifacts and their digests. A
manually written status string, passing readiness preflight, or absence of
reported blockers is insufficient.

## ITCC-3. Minimum Manifest Semantics

The machine-readable record MUST include at least:

```json
{
  "schema": "lattice-aggregation:internal-theorem-closure-candidate:v1",
  "status": "internally_closed_pending_independent_review",
  "security_profile": "strong-no-single-holder-static-active-v1",
  "bundle_digest": "required",
  "source_commit": "required-clean-commit",
  "working_tree_clean": true,
  "real_distributed_threshold_core_verified": true,
  "coordinator_secret_reconstruction_observed": false,
  "all_five_criteria_internally_satisfied": true,
  "fst_l1_through_l9_internally_discharged": true,
  "internal_reviewers": ["required-reviewer-1", "required-reviewer-2"],
  "independent_review_status": "pending",
  "claims_theorem_closure": false,
  "claims_criterion_met": false,
  "claims_production_threshold_mldsa_security": false,
  "claims_cavp_acvts_validation": false,
  "claims_fips_validation": false
}
```

The manifest schema shown here is semantic, not evidence that a generator or
assessor currently enforces it. Any later implementation MUST validate digest
syntax, uniqueness, referential integrity, artifact schemas, signature
authenticity, and proof/evidence consistency rather than trusting booleans.

## ITCC-4. Allowed and Prohibited Language

Allowed internal statement:

> The digest-bound package is internally closed under the documented strong
> model and is pending independent cryptographic review.

Required qualification:

> Internal closure is the project's review conclusion, not independent
> validation or a production security claim.

Prohibited before accepted independent review:

- “the theorem is proved” or “the theorem is closed” without the internal and
  pending-review qualification;
- “cryptographically audited,” “independently verified,” or “peer reviewed”;
- promotion of any existing public criterion to `met` when its taxonomy
  requires external review;
- `completely_proven`, production-safe, deployment-ready, FIPS validated, or
  equivalent language; and
- claims based solely on validator count, signature size, standard-verifier
  acceptance, readiness status, or tests.

## ITCC-5. Relationship to Existing Assessors

The current
[`hypothesis-outcome-taxonomy.md`](hypothesis-outcome-taxonomy.md) defines
`met` and `completely_proven` as requiring external review. This document does
not weaken that rule. Until accepted independent review is digest-bound to the
package, the existing public assessment remains `partially_proven` with
criterion statuses no stronger than `partially_met`, even when the internal
candidate gate passes.

Similarly, `ready_for_theorem_closure_assessment` means that a review can be
performed; it is not this internal-closure state. The internal gate is stricter
because it requires the real protocol, completed internal proof artifacts, and
production-shaped execution evidence rather than review-package completeness.

## ITCC-6. Revocation

Internal closure MUST be revoked immediately if:

- any referenced artifact or source digest changes;
- a required test or reproduction gate fails;
- a prohibited reconstruction or leakage path is found;
- an internal or external reviewer identifies an unresolved proof,
  implementation, parameter, or evidence defect;
- the FIPS reference or pinned dependency changes in a way that affects the
  argument; or
- campaign provenance is shown to be dirty, simulated, imported, or otherwise
  outside the admissible source policy.

Revocation preserves the old bundle for audit history, records the reason, and
returns the active package to `internal_closure_work_in_progress`. It MUST NOT
rewrite or silently re-sign the old manifest.
