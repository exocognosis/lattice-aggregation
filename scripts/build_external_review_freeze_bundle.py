#!/usr/bin/env python3
"""Freeze a digest-bound evidence bundle for EXTERNAL independent reviewers.

This builder only *packages and digests* evidence. It performs no review and
promotes no claim. External equivalence, security, and theorem-linkage review
is explicitly out of this bundle's authority: `external_review_status` stays
`not_started`, `external_reviewers` stays empty, and every public
theorem/production/no-single-secret claim flag stays false.

The bundle content-addresses each evidence file (SHA-256) and binds the sorted
`path\tsha256` lines into a single `bundle_digest`, so an external reviewer can
verify they are reviewing exactly the frozen bytes. A missing expected file is
recorded as `present: false` rather than silently skipped, and forces a blocked
status so an incomplete freeze can never read as complete.
"""

import argparse
import hashlib
import json
import time
from pathlib import Path

BUNDLE_SCHEMA = "lattice-aggregation:external-review-freeze-bundle:v1"
NAME = "external-review-freeze-bundle-v1"
FROZEN_STATUS = "frozen_prepared_for_external_review_not_reviewed"
BLOCKED_STATUS = "blocked_incomplete_freeze"

CLAIM_BOUNDARY = (
    "Evidence frozen and digest-bound for external review only. No external "
    "equivalence, security, or theorem-linkage review has occurred. Internal "
    "AI-agent review is not external independent review. Every production, "
    "no-single-secret, N-party-execution, and theorem-closure claim remains "
    "unproven and fail-closed."
)

REVIEW_SCOPE = ("equivalence", "security", "theorem_linkage")

# Files frozen from the primary repository (paths relative to repo root).
PRIMARY_EVIDENCE = (
    ("signer_custody_module", "src/backend/custody.rs"),
    ("signer_fips_sign", "src/backend/fips_sign.rs"),
    ("signer_backend_mod", "src/backend/mod.rs"),
    ("crate_root", "src/lib.rs"),
    (
        "internal_expandmask_additive_review",
        "docs/reviews/2026-07-19-expandmask-additive-ml-dsa-internal-review.md",
    ),
    (
        "internal_six_gate_review",
        "docs/reviews/2026-07-19-six-gate-security-production-review.md",
    ),
    (
        "internal_expandmask_additive_gates",
        "artifacts/reviews/expandmask-additive-ml-dsa-internal-gates.json",
    ),
    (
        "internal_six_gate_gates",
        "artifacts/reviews/2026-07-19-six-gate-security-production-gate.json",
    ),
    (
        "campaign_manifest",
        "artifacts/real-6667-of-10000-mldsa-campaign/latest/manifest.json",
    ),
    (
        "campaign_blockers",
        "artifacts/real-6667-of-10000-mldsa-campaign/latest/blockers.json",
    ),
    (
        "mama_6667_scale_manifest",
        "artifacts/exact-distributed-expandmask-mpc/mama-6667-scale-latest/manifest.json",
    ),
    ("campaign_runner", "scripts/run_real_6667_of_10000_mldsa_campaign.py"),
    ("mama_scale_runner", "scripts/run_mama_6667_scale.py"),
    ("exact_expandmask_circuit", "mpc/Programs/Source/mldsa65_expandmask.mpc"),
)

# Files frozen from the sibling execution backend (absolute-root + relative).
BACKEND_EVIDENCE = (
    ("backend_dealerless_dkg", "src/dealerless_dkg.rs"),
    ("backend_private_share_custody", "src/private_share_custody.rs"),
    ("backend_cli", "src/main.rs"),
    ("backend_dkg_custody_doc", "docs/NO_DEALER_DKG_AND_CUSTODY.md"),
)

# What an external reviewer must independently establish. These mirror the
# open blockers; freezing evidence does not discharge any of them.
REVIEWER_CHECKLIST = (
    "Independently confirm the additive/Lagrange mixed-share equation "
    "z_i = y_i + c*(lambda_i*s1_i) and the plain-sum z aggregation.",
    "Confirm the custody-consumption seam is only a code seam: the test "
    "provisioner holds the whole secret, so no-single-secret is NOT proven.",
    "Confirm the signer still derives the full key from one seed in the "
    "shipped harness (single-secret signing path remains open).",
    "Confirm DKG K shares are not yet consumed by the MPC input path and that "
    "rhopp is coordinator-known in the custody harness (a test artifact).",
    "Confirm custody-held s1/s2 shares trace to a locally generated secret, "
    "not a real attested hardware/TEE vault.",
    "Confirm the end-to-end linkage digest only BINDS fields and does not "
    "prove the DKG/MPC transcripts came from real distributed executions.",
    "Confirm retry/abort accounting exists but formal erasure and "
    "selective-abort proofs are incomplete.",
    "Confirm ExpandA is byte-exact in the wire path but deferred in the "
    "module-form DKG, so wire-verifiable shares cannot yet be sourced from "
    "the module DKG (open reconciliation blocker).",
    "Confirm no 6,667-party MAMA execution exists (only a 2-party run).",
    "Confirm the real 6,667-of-10,000 campaign has not executed "
    "(blocked_prerequisites_unmet).",
    "Provide named, signed external equivalence, security, and "
    "theorem-linkage reviews; none exist yet.",
)

CLAIM_FLAGS = {
    "claims_external_independent_review_complete": False,
    "claims_no_single_secret_signing_path": False,
    "claims_production_private_share_custody": False,
    "claims_6667_party_mama_execution": False,
    "claims_real_6667_of_10000_mldsa_campaign": False,
    "claims_production_threshold_mldsa_security": False,
    "claims_theorem_closure": False,
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def freeze_entries(root: Path, entries, origin):
    frozen = []
    all_present = True
    for name, rel in entries:
        path = (root / rel).resolve()
        present = path.is_file()
        if not present:
            all_present = False
        frozen.append(
            {
                "name": name,
                "origin": origin,
                "relative_path": rel,
                "present": present,
                "sha256": sha256_file(path) if present else None,
                "size_bytes": path.stat().st_size if present else None,
            }
        )
    return frozen, all_present


def bundle_digest(frozen) -> str:
    lines = sorted(
        f"{entry['origin']}/{entry['relative_path']}\t{entry['sha256']}"
        for entry in frozen
        if entry["present"]
    )
    digest = hashlib.sha256()
    digest.update("\n".join(lines).encode("utf-8"))
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parent.parent),
        help="Primary repository root.",
    )
    parser.add_argument(
        "--backend-root",
        default="/Users/rickglenn/Documents/lattice-threshold-backend-p1",
        help="Sibling execution backend repository root.",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output directory (default: artifacts/reviews/external-review-freeze/latest).",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    backend_root = Path(args.backend_root).resolve()
    out_dir = (
        Path(args.out).resolve()
        if args.out
        else repo_root / "artifacts/reviews/external-review-freeze/latest"
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    primary_frozen, primary_ok = freeze_entries(repo_root, PRIMARY_EVIDENCE, "primary")
    backend_frozen, backend_ok = freeze_entries(backend_root, BACKEND_EVIDENCE, "backend")
    frozen = primary_frozen + backend_frozen
    all_present = primary_ok and backend_ok

    status = FROZEN_STATUS if all_present else BLOCKED_STATUS

    manifest = {
        "schema": BUNDLE_SCHEMA,
        "schema_version": 1,
        "name": NAME,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": status,
        "claim_boundary": CLAIM_BOUNDARY,
        "review_scope": list(REVIEW_SCOPE),
        "external_review_status": "not_started",
        "external_reviewers": [],
        "internal_ai_review_is_not_external_review": True,
        "all_expected_evidence_present": all_present,
        "bundle_digest": bundle_digest(frozen),
        "evidence": frozen,
        "reviewer_checklist": list(REVIEWER_CHECKLIST),
        "claim_flags": CLAIM_FLAGS,
    }

    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    sums_lines = [
        f"{entry['sha256']}  {entry['origin']}/{entry['relative_path']}"
        for entry in frozen
        if entry["present"]
    ]
    (out_dir / "SHA256SUMS").write_text("\n".join(sorted(sums_lines)) + "\n")

    present_count = sum(1 for entry in frozen if entry["present"])
    summary = [
        f"# External review freeze bundle ({status})",
        "",
        CLAIM_BOUNDARY,
        "",
        f"- bundle_digest: `{manifest['bundle_digest']}`",
        f"- evidence files frozen: {present_count} / {len(frozen)}",
        f"- external_review_status: {manifest['external_review_status']}",
        f"- external_reviewers: {len(manifest['external_reviewers'])}",
        "",
        "## Scope requested from external reviewers",
        *[f"- {scope}" for scope in REVIEW_SCOPE],
        "",
        "## Reviewer checklist (open items; freezing does not discharge these)",
        *[f"- {item}" for item in REVIEWER_CHECKLIST],
    ]
    (out_dir / "summary.md").write_text("\n".join(summary) + "\n")

    print(json.dumps({"status": status, "bundle_digest": manifest["bundle_digest"],
                      "evidence_present": present_count, "evidence_total": len(frozen),
                      "out": str(out_dir)}, indent=2))
    return 0 if all_present else 2


if __name__ == "__main__":
    raise SystemExit(main())
