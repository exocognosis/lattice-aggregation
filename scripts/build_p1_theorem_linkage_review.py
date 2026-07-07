#!/usr/bin/env python3
"""Build the P1 theorem-linkage review package from current evidence."""

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path


SCHEMA = "lattice-aggregation:p1-theorem-linkage-review:v1"
NAME = "p1-theorem-linkage-review"
READY_STATUS = "reviewed_theorem_linkage_ready"
BLOCKED_STATUS = "blocked_theorem_linkage_review"
CLAIM_BOUNDARY = "conformance/proof-review evidence"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
CRITERION2_SCHEMA = "lattice-aggregation.criterion-2-proof-substance.v1"
EXTERNAL_ATTEMPT_READY = "external_evidence_close_candidate_ready"
DKG_READY = "reviewed_production_dkg_no_single_secret_ready"
DISTRIBUTION_ABORT_READY = "reviewed_distribution_abort_ready"

REQUIRED_THEOREM_LINKS = (
    "Correctness Lemma 7",
    "Correctness Lemma 8",
    "Noise Lemma D",
    "Noise Lemma F",
    "Noise Lemma H",
    "FST-L5",
    "FST-L7",
)

CLAIM_FLAG_KEYS = (
    "claims_theorem_closure",
    "claims_criterion_met",
    "claims_selected_backend_proof_closure",
    "claims_rejection_distribution_preservation",
    "claims_standard_verifier_compatibility_complete",
    "claims_production_threshold_mldsa_security",
    "claims_cavp_acvts_validation",
    "claims_fips_validation",
)


def canonical_json(data):
    """Render stable pretty JSON with a trailing newline."""
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def sha256_text(text):
    """Return SHA-256 for UTF-8 text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_path(path):
    """Return SHA-256 for a file path, or None when absent."""
    path = Path(path)
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path):
    """Load JSON from a required path."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def read_text_if_present(path):
    """Read text from a path when present."""
    path = Path(path)
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def false_claim_flags():
    """Return all closure/security claim flags pinned false."""
    return {key: False for key in CLAIM_FLAG_KEYS}


def input_record(path):
    """Build a stable input path/checksum record."""
    path = Path(path)
    return {
        "path": str(path),
        "present": path.is_file(),
        "sha256": sha256_path(path),
    }


def digest_json(domain, data):
    """Return a domain-separated SHA-256 digest over JSON data."""
    return sha256_text(canonical_json({"domain": domain, "data": data}))


def default_criterion2(root):
    return Path(root) / "docs/cryptography/criterion-2-proof-substance.json"


def default_formal_theorem(root):
    return Path(root) / "docs/cryptography/formal-security-theorem.md"


def default_proof_obligations(root):
    return Path(root) / "docs/cryptography/proof-obligations.md"


def default_rejection_batch(root):
    return Path(root) / "artifacts/p1-rejection-equivalence-batch/latest/batch.json"


def default_closure_candidate(root):
    return (
        Path(root)
        / "artifacts/p1-external-backend-cryptographic-closure-candidate/latest/manifest.json"
    )


def default_external_attempt(root):
    return Path(root) / "artifacts/p1-external-backend-evidence-attempt/latest/manifest.json"


def default_dkg_review(root):
    return Path(root) / "artifacts/p1-production-dkg-no-single-secret-review/latest/manifest.json"


def default_distribution_abort(root):
    return Path(root) / "artifacts/p1-accepted-distribution-abort-review/latest/manifest.json"


def default_out(root):
    return Path(root) / "artifacts/p1-theorem-linkage-review/latest"


def claim_flags_preserved(*documents):
    """Return true only when all present claim flags are false."""
    for document in documents:
        flags = document.get("claim_flags") if isinstance(document, dict) else None
        if isinstance(flags, dict):
            if any(flags.get(key) is not False for key in flags):
                return False
        if isinstance(document, dict):
            for key, value in document.items():
                if key.startswith("claims_") and value is not False:
                    return False
    return True


def criterion2_checks(criterion2):
    """Validate Criterion 2 theorem-linkage material."""
    proof_payload = criterion2.get("proof_payload", {}) if isinstance(criterion2, dict) else {}
    theorem_links = proof_payload.get("theorem_links", [])
    artifact_refs = proof_payload.get("artifact_fixture_refs", [])
    slot_ids = {
        item.get("slot_id")
        for item in artifact_refs
        if isinstance(item, dict) and item.get("current_status") == "evidence_present_unclosed"
    }
    return {
        "criterion2_schema_valid": criterion2.get("schema") == CRITERION2_SCHEMA,
        "criterion2_claim_boundary_preserved": claim_flags_preserved(
            criterion2.get("claim_boundary", {})
        ),
        "required_theorem_links_present": all(
            link in theorem_links for link in REQUIRED_THEOREM_LINKS
        ),
        "threshold_output_slot_present": "threshold_output_certificate_digest" in slot_ids,
        "real_recomputation_slot_present": "real_recomputation_evidence_digest" in slot_ids,
        "standard_verifier_slot_present": (
            "standard_verifier_compatibility_artifact_digest" in slot_ids
        ),
        "rejection_distribution_slot_present": (
            "rejection_distribution_review_digest" in slot_ids
        ),
        "theorem_linkage_slot_present": "theorem_linkage_artifact_digest" in slot_ids,
    }


def theorem_doc_checks(formal_theorem_text, proof_obligations_text):
    """Validate that theorem documents contain the target lemma surfaces."""
    combined = formal_theorem_text + "\n" + proof_obligations_text
    return {
        "formal_theorem_document_present": bool(formal_theorem_text),
        "proof_obligations_document_present": bool(proof_obligations_text),
        "fst_l5_linked": "FST-L5" in combined,
        "fst_l7_linked": "FST-L7" in combined,
        "correctness_lemma_7_linked": "Correctness Lemma 7" in combined,
        "correctness_lemma_8_linked": "Correctness Lemma 8" in combined,
        "noise_lemma_h_linked": "Noise Lemma H" in combined,
    }


def evidence_checks(candidate, attempt, rejection_batch, dkg_review, distribution_abort):
    """Validate current evidence package linkage inputs."""
    result = rejection_batch.get("result", {}) if isinstance(rejection_batch, dict) else {}
    scope = (
        rejection_batch.get("equivalence_scope", {})
        if isinstance(rejection_batch, dict)
        else {}
    )
    attempt_checks = attempt.get("checks", {}) if isinstance(attempt, dict) else {}
    dkg_flags = dkg_review.get("claim_flags", {}) if isinstance(dkg_review, dict) else {}
    distribution_flags = (
        distribution_abort.get("claim_flags", {})
        if isinstance(distribution_abort, dict)
        else {}
    )
    return {
        "closure_candidate_ready": candidate.get("close_candidate") is True
        and candidate.get("blockers") == [],
        "external_attempt_ready": attempt.get("attempt_status") == EXTERNAL_ATTEMPT_READY
        and attempt.get("close_candidate") is True
        and attempt.get("blockers") == [],
        "external_attempt_source_exclusions_passed": (
            attempt_checks.get("source_exclusion_passed") is True
        ),
        "rejection_batch_predicate_shape_linked": (
            result.get("predicate_mismatch_count") == 0
            and result.get("accepted_or_rejected_matches") is True
            and result.get("standard_verifier_accepts_threshold_signature") is True
        ),
        "rejection_distribution_proof_still_open": (
            result.get("distribution_compatibility_proven") is not True
            and scope.get("accepted_aggregate_distribution_compatibility_proven")
            is not True
        ),
        "dkg_review_ready": dkg_review.get("review_status") == DKG_READY,
        "distribution_abort_review_ready": (
            distribution_abort.get("review_status") == DISTRIBUTION_ABORT_READY
        ),
        "review_claim_boundaries_preserved": claim_flags_preserved(
            candidate,
            attempt,
            rejection_batch,
            {"claim_flags": dkg_flags},
            {"claim_flags": distribution_flags},
        ),
    }


def build_report(
    root,
    criterion2_path=None,
    formal_theorem_path=None,
    proof_obligations_path=None,
    rejection_batch_path=None,
    closure_candidate_path=None,
    external_attempt_path=None,
    dkg_review_path=None,
    distribution_abort_path=None,
    generated_at=None,
):
    """Build the theorem-linkage review report."""
    root = Path(root)
    criterion2_path = Path(criterion2_path or default_criterion2(root))
    formal_theorem_path = Path(formal_theorem_path or default_formal_theorem(root))
    proof_obligations_path = Path(
        proof_obligations_path or default_proof_obligations(root)
    )
    rejection_batch_path = Path(rejection_batch_path or default_rejection_batch(root))
    closure_candidate_path = Path(closure_candidate_path or default_closure_candidate(root))
    external_attempt_path = Path(external_attempt_path or default_external_attempt(root))
    dkg_review_path = Path(dkg_review_path or default_dkg_review(root))
    distribution_abort_path = Path(distribution_abort_path or default_distribution_abort(root))
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    criterion2 = load_json(criterion2_path)
    rejection_batch = load_json(rejection_batch_path)
    candidate = load_json(closure_candidate_path)
    attempt = load_json(external_attempt_path)
    dkg_review = load_json(dkg_review_path)
    distribution_abort = load_json(distribution_abort_path)
    formal_theorem_text = read_text_if_present(formal_theorem_path)
    proof_obligations_text = read_text_if_present(proof_obligations_path)

    checks = {
        **criterion2_checks(criterion2),
        **theorem_doc_checks(formal_theorem_text, proof_obligations_text),
        **evidence_checks(
            candidate,
            attempt,
            rejection_batch,
            dkg_review,
            distribution_abort,
        ),
    }
    ready = all(checks.values())
    blockers = [name for name, value in checks.items() if value is not True]
    inputs = {
        "criterion2_manifest": input_record(criterion2_path),
        "formal_security_theorem": input_record(formal_theorem_path),
        "proof_obligations": input_record(proof_obligations_path),
        "rejection_batch": input_record(rejection_batch_path),
        "closure_candidate": input_record(closure_candidate_path),
        "external_attempt": input_record(external_attempt_path),
        "production_dkg_no_single_secret_review": input_record(dkg_review_path),
        "accepted_distribution_abort_review": input_record(distribution_abort_path),
    }
    digest_material = {
        "schema": SCHEMA,
        "name": NAME,
        "selected_profile": SELECTED_PROFILE,
        "checks": checks,
        "inputs": inputs,
        "claim_flags": false_claim_flags(),
    }
    manifest = {
        "schema": SCHEMA,
        "schema_version": 1,
        "name": NAME,
        "generated_at": generated_at,
        "selected_profile": SELECTED_PROFILE,
        "claim_boundary": CLAIM_BOUNDARY,
        "review_status": READY_STATUS if ready else BLOCKED_STATUS,
        "checks": checks,
        "blockers": blockers,
        "review_digests": {
            "theorem_linkage_review_digest_hex": digest_json(
                "theorem_linkage_review", digest_material
            ),
            "criterion2_theorem_links_digest_hex": digest_json(
                "criterion2_theorem_links",
                criterion2.get("proof_payload", {}).get("theorem_links", []),
            ),
            "source_inputs_digest_hex": digest_json("source_inputs", inputs),
        },
        "inputs": inputs,
        "claim_flags": false_claim_flags(),
        "assessment_boundary": (
            "This package links current Criterion 2 evidence to named theorem "
            "obligations for review. It does not claim theorem closure, "
            "rejection-distribution preservation, CAVP/ACVTS validation, FIPS "
            "validation, or production threshold ML-DSA security."
        ),
    }
    return {"manifest": manifest, "summary_md": render_summary(manifest)}


def render_summary(manifest):
    """Render a concise theorem-linkage review summary."""
    lines = [
        "# P1 Theorem-Linkage Review",
        "",
        "This artifact links the current P1 evidence package to the named theorem "
        "obligations used by Criterion 2 review. It does not claim theorem closure.",
        "",
        f"- Review status: `{manifest['review_status']}`",
        f"- Claim boundary: `{manifest['claim_boundary']}`",
        "- Theorem-linkage digest SHA-256: "
        f"`{manifest['review_digests']['theorem_linkage_review_digest_hex']}`",
        "",
        "Checks:",
    ]
    for name, passed in manifest["checks"].items():
        lines.append(f"- `{name}`: `{str(passed).lower()}`")
    lines.extend(["", "Blockers:"])
    if manifest["blockers"]:
        for blocker in manifest["blockers"]:
            lines.append(f"- `{blocker}`")
    else:
        lines.append("- none")
    lines.append("")
    return "\n".join(lines)


def artifact_contents(report):
    """Build final artifact file contents."""
    return {
        "manifest.json": canonical_json(report["manifest"]),
        "summary.md": report["summary_md"],
    }


def render_checksums(contents):
    """Render deterministic SHA-256 checksums for artifact files."""
    return "\n".join(
        f"{sha256_text(contents[name])}  {name}" for name in sorted(contents)
    ) + "\n"


def write_artifacts(report, out_dir):
    """Write theorem-linkage review artifacts and checksums."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = artifact_contents(report)
    contents["SHA256SUMS"] = render_checksums(contents)
    for name, content in contents.items():
        (out_dir / name).write_text(content, encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Build P1 theorem-linkage review")
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--criterion2", default=None)
    parser.add_argument("--formal-theorem", default=None)
    parser.add_argument("--proof-obligations", default=None)
    parser.add_argument("--rejection-batch", default=None)
    parser.add_argument("--closure-candidate", default=None)
    parser.add_argument("--external-attempt", default=None)
    parser.add_argument("--dkg-review", default=None)
    parser.add_argument("--distribution-abort", default=None)
    parser.add_argument("--out", default=None)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    root = Path(args.root)
    report = build_report(
        root,
        criterion2_path=args.criterion2,
        formal_theorem_path=args.formal_theorem,
        proof_obligations_path=args.proof_obligations,
        rejection_batch_path=args.rejection_batch,
        closure_candidate_path=args.closure_candidate,
        external_attempt_path=args.external_attempt,
        dkg_review_path=args.dkg_review,
        distribution_abort_path=args.distribution_abort,
    )
    out = Path(args.out) if args.out else default_out(root)
    write_artifacts(report, out)
    print(f"wrote P1 theorem-linkage review artifacts to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
