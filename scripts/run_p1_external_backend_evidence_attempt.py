#!/usr/bin/env python3
"""Run the Batch 8 external-backend evidence closure-candidate attempt."""

import argparse
import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path


SCHEMA = "lattice-aggregation:p1-external-backend-evidence-attempt:v1"
NAME = "p1-external-backend-evidence-attempt-v1"
CLAIM_BOUNDARY = "conformance/proof-review evidence only"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
STATUS_READY = "external_evidence_close_candidate_ready"
STATUS_BLOCKED = "blocked_external_evidence_missing"
FORBIDDEN_SOURCE_MARKERS = (
    "hazmat",
    "simulation",
    "simulated",
    "deterministic",
    "localnet",
    "fixture",
    "test-vector",
    "test_vector",
    "single-key",
    "single_key",
    "standardprovidersinglekey",
    "standard_provider_single_key",
    "repo_reference_cli_capture",
    "quarantined_local_schema_replay",
    "centralized-oracle",
    "centralized oracle",
)
REQUIRED_CANDIDATE_CHECK_KEYS = (
    "strict_external_nonce_capture_ready",
    "real_threshold_emission_present",
    "standard_verifier_acceptance_present",
    "mutation_rejection_complete",
    "rejection_distribution_comparison_present",
    "comparison_close_candidate",
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


def load_json_if_present(path):
    """Load JSON from a path if present."""
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


def default_nonce_gate(root):
    return (
        Path(root)
        / "artifacts"
        / "nonce-producer-actual-external-gate"
        / "latest"
        / "manifest.json"
    )


def default_backend_manifest(root):
    return Path(root) / "artifacts" / "backend-emission-capture" / "latest" / "manifest.json"


def default_backend_capture(root):
    return Path(root) / "artifacts" / "backend-emission-capture" / "latest" / "capture.json"


def default_rejection_batch(root):
    return Path(root) / "artifacts" / "p1-rejection-equivalence-batch" / "latest" / "batch.json"


def default_candidate_out(root):
    return (
        Path(root)
        / "artifacts"
        / "p1-external-backend-cryptographic-closure-candidate"
        / "latest"
    )


def load_closure_candidate_builder():
    """Load the Batch 7 closure-candidate builder beside this script."""
    script = Path(__file__).resolve().parent / (
        "build_p1_external_backend_cryptographic_closure_candidate.py"
    )
    spec = importlib.util.spec_from_file_location(
        "build_p1_external_backend_cryptographic_closure_candidate",
        script,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_marker_blockers(*documents):
    """Return blockers for hazmat/simulation/local fixture source markers."""
    blockers = []
    for label, document in documents:
        if document is None:
            continue
        for value in string_values(document):
            lowered = value.lower()
            for marker in FORBIDDEN_SOURCE_MARKERS:
                if marker in lowered:
                    blockers.append(
                        f"forbidden external-evidence source marker in {label}: {marker}"
                    )
    return blockers


def string_values(value):
    """Yield only JSON string values, not field names, for source-marker checks."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from string_values(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from string_values(item)


def build_report(
    root,
    nonce_gate_path=None,
    backend_manifest_path=None,
    backend_capture_path=None,
    rejection_batch_path=None,
    candidate_out=None,
    generated_at=None,
):
    """Build the Batch 8 external evidence attempt report."""
    root = Path(root)
    nonce_gate_path = Path(nonce_gate_path or default_nonce_gate(root))
    backend_manifest_path = Path(backend_manifest_path or default_backend_manifest(root))
    backend_capture_path = Path(backend_capture_path or default_backend_capture(root))
    rejection_batch_path = Path(rejection_batch_path or default_rejection_batch(root))
    candidate_out = Path(candidate_out or default_candidate_out(root))
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    nonce_gate = load_json_if_present(nonce_gate_path)
    backend_manifest = load_json_if_present(backend_manifest_path)
    backend_capture = load_json_if_present(backend_capture_path)
    rejection_batch = load_json_if_present(rejection_batch_path)

    candidate_builder = load_closure_candidate_builder()
    candidate_report = candidate_builder.build_report(
        root,
        nonce_gate_path=nonce_gate_path,
        backend_manifest_path=backend_manifest_path,
        backend_capture_path=backend_capture_path,
        rejection_batch_path=rejection_batch_path,
        generated_at=generated_at,
    )
    candidate_builder.write_artifacts(candidate_report, candidate_out)
    candidate_manifest = candidate_report["manifest"]

    source_blockers = source_marker_blockers(
        ("actual external nonce gate", nonce_gate),
        ("real-threshold backend manifest", backend_manifest),
        ("real-threshold backend capture", backend_capture),
        ("rejection-distribution batch", rejection_batch),
    )
    missing_check_blockers = [
        f"closure candidate missing required check: {key}"
        for key in REQUIRED_CANDIDATE_CHECK_KEYS
        if key not in candidate_manifest["checks"]
    ]
    checks = {
        **{key: False for key in REQUIRED_CANDIDATE_CHECK_KEYS},
        **candidate_manifest["checks"],
        "source_exclusion_passed": not source_blockers,
    }
    blockers = list(
        dict.fromkeys(
            candidate_manifest["blockers"] + source_blockers + missing_check_blockers
        )
    )
    close_candidate = (
        bool(candidate_manifest["close_candidate"])
        and not source_blockers
        and not missing_check_blockers
    )
    claim_flags = {
        "claims_theorem_closure": False,
        "claims_rejection_distribution_preservation": False,
        "claims_selected_backend_proof_closure": False,
        "claims_standard_verifier_compatibility": False,
        "claims_production_threshold_mldsa_security": False,
        "claims_cavp_acvts_validation": False,
        "claims_fips_validation": False,
    }
    candidate_manifest_path = candidate_out / "manifest.json"
    digest_material = {
        "schema": SCHEMA,
        "name": NAME,
        "checks": checks,
        "close_candidate": close_candidate,
        "claim_flags": claim_flags,
        "inputs": {
            "actual_external_nonce_gate_manifest": input_record(nonce_gate_path),
            "real_threshold_backend_capture_manifest": input_record(backend_manifest_path),
            "real_threshold_backend_capture_json": input_record(backend_capture_path),
            "rejection_equivalence_batch_json": input_record(rejection_batch_path),
            "closure_candidate_manifest": input_record(candidate_manifest_path),
        },
    }
    manifest = {
        "schema": SCHEMA,
        "schema_version": 1,
        "name": NAME,
        "generated_at": generated_at,
        "claim_boundary": CLAIM_BOUNDARY,
        "selected_profile": SELECTED_PROFILE,
        "attempt_status": STATUS_READY if close_candidate else STATUS_BLOCKED,
        "close_candidate": close_candidate,
        "checks": checks,
        "blockers": blockers,
        "inputs": digest_material["inputs"],
        "candidate_manifest_path": str(candidate_manifest_path),
        "candidate_manifest_sha256": sha256_path(candidate_manifest_path),
        "candidate_digest_sha256": candidate_manifest.get("candidate_digest_sha256"),
        "attempt_digest_sha256": sha256_text(canonical_json(digest_material)),
        **claim_flags,
        "closure_boundary": (
            "Batch 8 external evidence attempt only; not theorem closure, not "
            "rejection-distribution preservation, and not selected-backend proof closure."
        ),
    }
    return {
        "manifest": manifest,
        "summary_md": render_summary(manifest),
    }


def render_summary(manifest):
    """Render a concise Batch 8 attempt summary."""
    lines = [
        "# P1 External Backend Evidence Attempt",
        "",
        "This artifact groups the actual external nonce gate, real-threshold backend "
        "emission capture, standard-verifier acceptance evidence, mutation rejection "
        "evidence, and rejection-distribution comparison into the Batch 7 "
        "closure-candidate gate.",
        "",
        f"- Status: `{manifest['attempt_status']}`",
        f"- Close candidate: `{str(manifest['close_candidate']).lower()}`",
        f"- Claim boundary: `{manifest['claim_boundary']}`",
        f"- Candidate manifest SHA-256: `{manifest['candidate_manifest_sha256']}`",
        f"- Attempt digest SHA-256: `{manifest['attempt_digest_sha256']}`",
        "",
        "Checks:",
    ]
    for name, passed in manifest["checks"].items():
        lines.append(f"- `{name}`: `{str(passed).lower()}`")
    if manifest["blockers"]:
        lines.extend(["", "Blockers:"])
        for blocker in manifest["blockers"]:
            lines.append(f"- {blocker}")
    lines.extend(
        [
            "",
            "This is not theorem closure. It does not prove Criterion 2, "
            "rejection-distribution preservation, selected-backend proof "
            "closure, production threshold ML-DSA security, CAVP/ACVTS "
            "validation, FIPS validation, or completed cryptographic proof.",
            "",
        ]
    )
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
    """Write Batch 8 attempt artifacts and checksums."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = artifact_contents(report)
    contents["SHA256SUMS"] = render_checksums(contents)
    for name, content in contents.items():
        (out_dir / name).write_text(content, encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Run the P1 external-backend evidence closure-candidate attempt"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--nonce-gate", default=None, help="actual external nonce gate")
    parser.add_argument(
        "--backend-manifest",
        default=None,
        help="real-threshold backend capture manifest",
    )
    parser.add_argument(
        "--backend-capture",
        default=None,
        help="real-threshold backend capture JSON",
    )
    parser.add_argument(
        "--rejection-batch",
        default=None,
        help="rejection-equivalence batch JSON",
    )
    parser.add_argument(
        "--candidate-out",
        default=None,
        help="Batch 7 closure-candidate output directory",
    )
    parser.add_argument(
        "--out",
        default="artifacts/p1-external-backend-evidence-attempt/latest",
        help="Batch 8 attempt output directory",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit nonzero until the grouped external evidence attempt is a close candidate",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    report = build_report(
        Path(args.root),
        nonce_gate_path=args.nonce_gate,
        backend_manifest_path=args.backend_manifest,
        backend_capture_path=args.backend_capture,
        rejection_batch_path=args.rejection_batch,
        candidate_out=args.candidate_out,
    )
    write_artifacts(report, Path(args.out))
    print(f"wrote P1 external backend evidence attempt artifacts to {args.out}")
    if args.strict and not report["manifest"]["close_candidate"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
