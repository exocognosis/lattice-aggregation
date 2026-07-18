# Internal Theorem-Closure Evidence Bundle

## Purpose

The internal closure bundle is a content-addressed handoff package for the five
Lattice Aggregation theorem criteria. It has exactly two statuses:

- `blocked_incomplete`
- `internally_closed_pending_independent_review`

The second status is an internal result. Independent cryptographic review is
still required and is always recorded as incomplete by this bundle version.
The bundle never claims production threshold security, FIPS validation,
CAVP/ACVTS validation, or externally validated theorem closure.

## Strong Profile

This bundle targets
`native-threshold-mldsa65-mpc-no-reconstruction-v1`. It binds ML-DSA-65,
10,000 validators, authorization threshold 6,667, committee sizes through 64,
ordinary 3,309-byte signatures, exact distributed key generation, private
per-receiver share custody, exact distributed `ExpandMask`, and explicit
committee authorization by the validator threshold. Secret or seed
reconstruction is forbidden.

Legacy P1 coordinator-assisted and TEE/HSM review artifacts remain useful as
historical or comparison evidence, but they cannot satisfy this profile.

## Criterion Inputs

Each criterion input lives at:

`artifacts/internal-theorem-closure-evidence/latest/<criterion-id>.json`

and conforms to
`lattice-aggregation:internal-theorem-closure-criterion-evidence:v1`.
Every input must contain:

- the criterion-specific substantive checks;
- four groups of local, digest-verified protocol, proof, implementation, and
  test artifacts;
- group digests matching those files byte for byte;
- recorded passing reproduction commands;
- a clean Git commit and source-tree digest;
- a completed internal review record; and
- an explicitly pending independent-review record.

The five IDs are:

1. `aggregate_mask_distribution`
2. `aggregate_rejection_equivalence`
3. `abort_retry_bias`
4. `partial_contribution_soundness`
5. `unauthorized_aggregate_reduction`

## Campaign Binding

The bundle also requires the campaign files at
`artifacts/internal-aggregation-campaign/latest/`:

- `request.json`
- `capture.json`
- `manifest.json`

The campaign must validate all 24 preregistered committee/case combinations,
bind the request, capture, and local evidence digests, prove threshold
authorization of the MPC committee, and preserve false theorem and validation
claims. Missing campaign files are blockers, not errors that can be waived.
The bundle builder deterministically re-runs the campaign validator and requires
byte-identical validator output, including the request-bound reviewed verifier
identity and implementation digest. Capture-supplied `verified` booleans have
no promotion authority.

## Build and Gate

Generate the current fail-closed criterion input manifests:

```sh
python3 scripts/build_internal_theorem_closure_criterion_inputs.py --root .
```

Build the current fail-closed package:

```sh
python3 scripts/build_internal_theorem_closure_bundle.py --root .
```

Require the internal closure status in automation:

```sh
python3 scripts/build_internal_theorem_closure_bundle.py \
  --root . \
  --require-internal-closure
```

The strict command exits with status 2 until every substantive criterion,
campaign, provenance, toolchain, and reproducibility check passes.
The final assessor independently recomputes the canonical bundle digest,
re-hashes each source and artifact inventory entry, and checks that bundle Git
provenance matches the current clean checkout.
