#!/usr/bin/env python3
"""Build the P1 full KAT/CAVP validation review package."""

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path


SCHEMA = "lattice-aggregation:p1-full-kat-cavp-validation-review:v1"
NAME = "p1-full-kat-cavp-validation-review"
READY_STATUS = "reviewed_full_kat_cavp_validation_ready"
BLOCKED_STATUS = "blocked_full_kat_cavp_validation_review"
CLAIM_BOUNDARY = "conformance/proof-review evidence"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
VALIDATION_EVIDENCE_SCHEMA = "external-review:p1-full-kat-cavp-validation:v1"

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

REQUIRED_CHECKS = (
    "provider_kat_vectors_passed",
    "fips204_mldsa65_kat_passed",
    "acvts_or_cavp_campaign_reviewed",
    "signing_verification_vectors_reviewed",
    "mutation_negative_vectors_reviewed",
    "public_key_signature_length_vectors_reviewed",
    "implementation_digest_bound",
    "binds_backend_capture_digest",
    "binds_backend_manifest_digest",
    "external_reviewer_digest_present",
)

REQUIRED_CAMPAIGN_MODES = ("keyGen", "sigGen", "sigVer")


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


def load_json_if_present(path):
    """Load JSON from a path when present."""
    path = Path(path)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def input_record(path):
    """Build a stable input path/checksum record."""
    path = Path(path)
    return {
        "path": str(path),
        "present": path.is_file(),
        "sha256": sha256_path(path),
    }


def false_claim_flags():
    """Return all theorem/security claim flags pinned false."""
    return {key: False for key in CLAIM_FLAG_KEYS}


def digest_json(domain, data):
    """Return a domain-separated SHA-256 digest over JSON data."""
    return sha256_text(canonical_json({"domain": domain, "data": data}))


def default_backend_manifest(root):
    return Path(root) / "artifacts/backend-emission-capture/latest/manifest.json"


def default_backend_capture(root):
    return Path(root) / "artifacts/backend-emission-capture/latest/capture.json"


def default_validation_evidence(root):
    return (
        Path(root)
        / "artifacts/p1-full-kat-cavp-validation-input/latest/evidence.json"
    )


def default_out(root):
    return Path(root) / "artifacts/p1-full-kat-cavp-validation-review/latest"


def is_digest(value):
    """Return true for nonzero 64-character hex digests."""
    if not isinstance(value, str) or len(value) != 64:
        return False
    if value == "0" * 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def validation_package_section(validation_evidence, section_key):
    """Return a structured validation package section, or an empty dict."""
    if not isinstance(validation_evidence, dict):
        return {}
    validation_package = validation_evidence.get("validation_package", {})
    if not isinstance(validation_package, dict):
        return {}
    section = validation_package.get(section_key, {})
    return section if isinstance(section, dict) else {}


def reviewed_passed_section(validation_evidence, section_key):
    """Return true when a validation package section is reviewed and passed."""
    section = validation_package_section(validation_evidence, section_key)
    return section.get("reviewed") is True and section.get("passed") is True


def campaign_modes_cover(campaign):
    """Return true when the campaign covers keyGen, sigGen, and sigVer."""
    modes = campaign.get("modes", []) if isinstance(campaign, dict) else []
    return all(mode in modes for mode in REQUIRED_CAMPAIGN_MODES)


def campaign_transcript_or_lab_equivalent(validation_evidence):
    """Return true when ACVTS/CAVP transcript evidence or lab equivalent exists."""
    if not isinstance(validation_evidence, dict):
        return False
    campaign = validation_evidence.get("campaign", {})
    section = validation_package_section(
        validation_evidence,
        "acvts_cavp_campaign_transcript",
    )
    return (
        section.get("reviewed") is True
        and (
            is_digest(section.get("transcript_digest_hex"))
            or is_digest(campaign.get("transcript_digest_hex"))
            or campaign.get("official_cavp_certificate_present") is True
            or campaign.get("lab_reviewed_equivalent") is True
        )
    )


def keygen_siggen_sigver_coverage_reviewed(validation_evidence):
    """Return true when keyGen, sigGen, and sigVer coverage is reviewed."""
    section = validation_package_section(
        validation_evidence,
        "keygen_siggen_sigver_coverage",
    )
    return (
        section.get("reviewed") is True
        and section.get("keyGen") is True
        and section.get("sigGen") is True
        and section.get("sigVer") is True
    )


def reviewer_signoff_section_matches(validation_evidence, reviewer_digest):
    """Return true when the validation package binds reviewer signoff digest."""
    section = validation_package_section(validation_evidence, "reviewer_signoff_digest")
    return (
        section.get("reviewed") is True
        and section.get("digest_hex") == reviewer_digest
        and is_digest(reviewer_digest)
    )


def hex_len(hex_value):
    """Return decoded hex length, or -1 for invalid hex."""
    if not isinstance(hex_value, str):
        return -1
    try:
        return len(bytes.fromhex(hex_value))
    except ValueError:
        return -1


def backend_vector_checks(backend_capture):
    """Extract positive and negative vector checks from backend capture."""
    capture = backend_capture.get("capture", {}) if isinstance(backend_capture, dict) else {}
    return {
        "standard_verifier_accepts": capture.get("standard_verifier_accepts") is True,
        "mutated_message_rejected": capture.get("mutated_message_rejected") is True,
        "mutated_public_key_rejected": capture.get("mutated_public_key_rejected") is True,
        "mutated_signature_rejected": capture.get("mutated_signature_rejected") is True,
        "public_key_len_1952": hex_len(capture.get("public_key_hex")) == 1952,
        "signature_len_3309": hex_len(capture.get("aggregate_signature_hex")) == 3309,
    }


def validation_checks(
    backend_manifest,
    backend_capture,
    validation_evidence,
    backend_manifest_sha256,
    backend_capture_sha256,
):
    """Build the full KAT/CAVP validation package checks."""
    evidence_checks = (
        validation_evidence.get("checks", {})
        if isinstance(validation_evidence, dict)
        else {}
    )
    vector_checks = backend_vector_checks(backend_capture)
    evidence_schema_valid = (
        isinstance(validation_evidence, dict)
        and validation_evidence.get("schema") == VALIDATION_EVIDENCE_SCHEMA
    )
    implementation_digest = (
        validation_evidence.get("implementation_digest_sha256")
        if isinstance(validation_evidence, dict)
        else None
    )
    reviewer_digest = (
        validation_evidence.get("external_reviewer_digest_hex")
        if isinstance(validation_evidence, dict)
        else None
    )
    campaign = (
        validation_evidence.get("campaign", {})
        if isinstance(validation_evidence, dict)
        else {}
    )
    return {
        "provider_kat_vectors_passed": (
            evidence_schema_valid
            and evidence_checks.get("provider_kat_vectors_passed") is True
            and reviewed_passed_section(validation_evidence, "provider_kat_vectors")
        ),
        "fips204_mldsa65_kat_passed": (
            evidence_schema_valid
            and evidence_checks.get("fips204_mldsa65_kat_passed") is True
            and reviewed_passed_section(
                validation_evidence,
                "fips204_mldsa65_kat_vectors",
            )
            and campaign.get("parameter_set") == "ML-DSA-65"
            and campaign.get("revision") == "FIPS204"
        ),
        "acvts_or_cavp_campaign_reviewed": (
            evidence_schema_valid
            and evidence_checks.get("acvts_or_cavp_campaign_reviewed") is True
            and campaign_modes_cover(campaign)
            and campaign_transcript_or_lab_equivalent(validation_evidence)
        ),
        "signing_verification_vectors_reviewed": (
            evidence_schema_valid
            and evidence_checks.get("signing_verification_vectors_reviewed") is True
            and keygen_siggen_sigver_coverage_reviewed(validation_evidence)
            and vector_checks["standard_verifier_accepts"]
        ),
        "mutation_negative_vectors_reviewed": (
            evidence_schema_valid
            and evidence_checks.get("mutation_negative_vectors_reviewed") is True
            and vector_checks["mutated_message_rejected"]
            and vector_checks["mutated_public_key_rejected"]
            and vector_checks["mutated_signature_rejected"]
        ),
        "public_key_signature_length_vectors_reviewed": (
            vector_checks["public_key_len_1952"]
            and vector_checks["signature_len_3309"]
            and (
                not isinstance(validation_evidence, dict)
                or evidence_checks.get("public_key_signature_length_vectors_reviewed")
                is True
            )
        ),
        "implementation_digest_bound": is_digest(implementation_digest),
        "binds_backend_capture_digest": (
            isinstance(validation_evidence, dict)
            and validation_evidence.get("backend_capture_sha256")
            == backend_capture_sha256
        )
        or validation_evidence is None,
        "binds_backend_manifest_digest": (
            isinstance(validation_evidence, dict)
            and validation_evidence.get("backend_manifest_sha256")
            == backend_manifest_sha256
        )
        or validation_evidence is None,
        "external_reviewer_digest_present": reviewer_signoff_section_matches(
            validation_evidence,
            reviewer_digest,
        ),
    }


def build_report(
    root,
    backend_manifest_path=None,
    backend_capture_path=None,
    validation_evidence_path=None,
    generated_at=None,
):
    """Build the full KAT/CAVP validation review report."""
    root = Path(root)
    backend_manifest_path = Path(backend_manifest_path or default_backend_manifest(root))
    backend_capture_path = Path(backend_capture_path or default_backend_capture(root))
    validation_evidence_path = Path(
        validation_evidence_path or default_validation_evidence(root)
    )
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    backend_manifest = load_json(backend_manifest_path)
    backend_capture = load_json(backend_capture_path)
    validation_evidence = load_json_if_present(validation_evidence_path)
    backend_manifest_sha256 = sha256_path(backend_manifest_path)
    backend_capture_sha256 = sha256_path(backend_capture_path)

    checks = validation_checks(
        backend_manifest,
        backend_capture,
        validation_evidence,
        backend_manifest_sha256,
        backend_capture_sha256,
    )
    ready = all(checks.values())
    blockers = [name for name, passed in checks.items() if not passed]
    source_inputs = {
        "backend_capture_sha256": backend_capture_sha256,
        "backend_manifest_sha256": backend_manifest_sha256,
        "validation_evidence_sha256": sha256_path(validation_evidence_path),
    }
    review_material = {
        "backend_manifest_capture_sha256": backend_manifest.get("capture_sha256"),
        "backend_capture_expected": backend_capture.get("expected", {}),
        "validation_evidence": validation_evidence,
        "checks": checks,
    }
    validation_package = (
        validation_evidence.get("validation_package", {})
        if isinstance(validation_evidence, dict)
        else {}
    )
    manifest = {
        "schema": SCHEMA,
        "schema_version": 1,
        "name": NAME,
        "generated_at": generated_at,
        "selected_profile": SELECTED_PROFILE,
        "package_class": "full_kat_cavp_validation_review",
        "claim_boundary": CLAIM_BOUNDARY,
        "review_status": READY_STATUS if ready else BLOCKED_STATUS,
        "checks": checks,
        "blockers": blockers,
        "source_inputs": source_inputs,
        "validation_package": validation_package,
        "review_digests": {
            "provider_kat_review_digest_hex": digest_json(
                "provider_kat_review",
                review_material,
            ),
            "acvts_cavp_campaign_digest_hex": digest_json(
                "acvts_cavp_campaign",
                validation_evidence.get("campaign", {})
                if isinstance(validation_evidence, dict)
                else {},
            ),
            "validation_package_digest_hex": digest_json(
                "validation_package",
                validation_package,
            ),
            "implementation_digest_hex": (
                validation_evidence.get("implementation_digest_sha256")
                if isinstance(validation_evidence, dict)
                else None
            ),
            "backend_capture_digest_hex": backend_capture_sha256,
            "backend_manifest_digest_hex": backend_manifest_sha256,
            "reviewer_identity_digest_hex": (
                validation_evidence.get("external_reviewer_digest_hex")
                if isinstance(validation_evidence, dict)
                else None
            ),
        },
        "claim_flags": false_claim_flags(),
        "package_boundary": (
            "This package records reviewed KAT/CAVP/ACVTS validation evidence "
            "for the selected ML-DSA-65 provider. It does not assert theorem "
            "closure or FIPS validation by itself."
        ),
    }
    return {"manifest": manifest, "summary_md": render_summary(manifest)}


def render_summary(manifest):
    """Render a concise package summary."""
    validation_package = manifest.get("validation_package", {})
    lines = [
        "# P1 Full KAT/CAVP Validation Review",
        "",
        "This package records whether reviewed ML-DSA-65 KAT/CAVP validation "
        "evidence is bound to the current backend capture.",
        "",
        f"- Review status: `{manifest['review_status']}`",
        f"- Claim boundary: `{manifest['claim_boundary']}`",
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
    lines.extend(["", "Validation package:"])
    if isinstance(validation_package, dict) and validation_package:
        for name in sorted(validation_package):
            section = validation_package[name]
            reviewed = (
                section.get("reviewed")
                if isinstance(section, dict)
                else False
            )
            if name == "reviewer_signoff_digest" and isinstance(section, dict):
                lines.append(
                    f"- `{name}`: `reviewed={str(reviewed).lower()}`, "
                    f"digest `{section.get('digest_hex')}`"
                )
            else:
                lines.append(f"- `{name}`: `reviewed={str(reviewed).lower()}`")
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
    """Write package artifacts and checksums."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = artifact_contents(report)
    contents["SHA256SUMS"] = render_checksums(contents)
    for name, content in contents.items():
        (out_dir / name).write_text(content, encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Build P1 full KAT/CAVP validation review package"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--backend-manifest", default=None)
    parser.add_argument("--backend-capture", default=None)
    parser.add_argument("--validation-evidence", default=None)
    parser.add_argument(
        "--out",
        default=None,
        help="validation review artifact output directory",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    root = Path(args.root)
    report = build_report(
        root,
        backend_manifest_path=args.backend_manifest,
        backend_capture_path=args.backend_capture,
        validation_evidence_path=args.validation_evidence,
    )
    write_artifacts(report, Path(args.out or default_out(root)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
