#!/usr/bin/env python3
"""Gate a promoted nonce-producer capture as actual external backend evidence."""

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path


GATE_SCHEMA = "lattice-aggregation:p1-actual-external-nonce-producer-gate:v1"
ATTEMPT_SCHEMA = "lattice-aggregation:p1-admissible-nonce-producer-capture-attempt:v1"
HANDOFF_SCHEMA = "lattice-aggregation:p1-nonce-producer-executable-handoff-replay:v1"
CLAIM_BOUNDARY = "conformance/proof-review evidence only"
EXPECTED_SOURCE_PROFILE = "admissible_external_backend_capture"
STATUS_READY = "actual_external_capture_ready"
STATUS_MISSING = "actual_external_capture_missing"


def canonical_json(data):
    """Render stable pretty JSON with a trailing newline."""
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def sha256_text(text):
    """Return SHA-256 for UTF-8 text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_path(path):
    """Return SHA-256 for a file path."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_json(path):
    """Load JSON from a path."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def resolve_handoff_path(attempt_path, attempt):
    """Resolve the handoff manifest path named by an attempt manifest."""
    handoff_manifest_path = attempt.get("handoff_manifest_path")
    if not isinstance(handoff_manifest_path, str) or not handoff_manifest_path:
        return None
    return Path(attempt_path).parent / handoff_manifest_path


def source_profile_blockers(label, source_profile, quarantine):
    """Return blockers for one manifest source profile/quarantine pair."""
    blockers = []
    if source_profile != EXPECTED_SOURCE_PROFILE:
        blockers.append(
            f"{label} source profile is {source_profile}, not {EXPECTED_SOURCE_PROFILE}"
        )
    if not isinstance(quarantine, dict):
        blockers.append(f"{label} quarantine record is missing")
    elif quarantine.get("quarantined") is not False:
        allowed_use = quarantine.get("allowed_use", "unknown")
        blockers.append(
            f"{label} is quarantined as {allowed_use}; actual external backend evidence is required"
        )
    return blockers


def build_report(root, attempt_path, generated_at=None):
    """Build an actual-external nonce-producer capture gate report."""
    root = Path(root)
    attempt_path = Path(attempt_path)
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    attempt = load_json(attempt_path)
    blockers = []

    if attempt.get("schema") != ATTEMPT_SCHEMA:
        blockers.append("attempt manifest schema mismatch")
    if attempt.get("claim_boundary") not in (CLAIM_BOUNDARY, None):
        blockers.append("attempt manifest claim boundary mismatch")
    if attempt.get("attempt_status") != "capture_promoted":
        blockers.append("attempt status is not capture_promoted")
    if attempt.get("backend_command_executed") is not True:
        blockers.append("backend command was not executed")

    attempt_source_profile = attempt.get("handoff_source_profile")
    attempt_quarantine = attempt.get("handoff_quarantine")
    blockers.extend(
        source_profile_blockers(
            "attempt handoff",
            attempt_source_profile,
            attempt_quarantine,
        )
    )

    handoff_path = resolve_handoff_path(attempt_path, attempt)
    handoff = None
    if handoff_path is None:
        blockers.append("attempt manifest does not name a handoff manifest")
    elif not handoff_path.is_file():
        blockers.append("handoff manifest is missing")
    else:
        handoff = load_json(handoff_path)
        if handoff.get("schema") != HANDOFF_SCHEMA:
            blockers.append("handoff manifest schema mismatch")
        blockers.extend(
            source_profile_blockers(
                "handoff manifest",
                handoff.get("handoff_source_profile"),
                handoff.get("quarantine"),
            )
        )

    ready = not blockers
    manifest = {
        "schema": GATE_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "claim_boundary": CLAIM_BOUNDARY,
        "gate_status": STATUS_READY if ready else STATUS_MISSING,
        "actual_external_capture_ready": ready,
        "expected_source_profile": EXPECTED_SOURCE_PROFILE,
        "attempt_manifest_path": str(attempt_path),
        "attempt_manifest_sha256": sha256_path(attempt_path),
        "attempt_status": attempt.get("attempt_status"),
        "attempt_source_profile": attempt_source_profile,
        "attempt_quarantine": attempt_quarantine,
        "handoff_manifest_path": str(handoff_path) if handoff_path else None,
        "handoff_manifest_sha256": sha256_path(handoff_path)
        if handoff_path and handoff_path.is_file()
        else None,
        "handoff_source_profile": handoff.get("handoff_source_profile")
        if handoff
        else None,
        "handoff_quarantine": handoff.get("quarantine") if handoff else None,
        "blockers": blockers,
        "closure_boundary": (
            "Actual external nonce-producer capture gate only; even a ready "
            "capture remains proof-review evidence until rejection-distribution "
            "and theorem obligations are discharged."
        ),
        "root": str(root),
    }
    return {
        "manifest": manifest,
        "summary_md": render_summary(manifest),
    }


def render_summary(manifest):
    """Render a concise actual-external capture gate summary."""
    lines = [
        "# P1 Actual External Nonce-Producer Capture Gate",
        "",
        "This artifact gates the promoted nonce-producer handoff before it can "
        "occupy the actual external backend slot. It is conformance/proof-review "
        "evidence only.",
        "",
        f"- Status: `{manifest['gate_status']}`",
        f"- Actual external capture ready: `{str(manifest['actual_external_capture_ready']).lower()}`",
        f"- Expected source profile: `{manifest['expected_source_profile']}`",
        f"- Attempt source profile: `{manifest['attempt_source_profile']}`",
    ]
    if manifest.get("handoff_source_profile"):
        lines.append(f"- Handoff source profile: `{manifest['handoff_source_profile']}`")
    if manifest["blockers"]:
        lines.append("- Blockers:")
        for blocker in manifest["blockers"]:
            lines.append(f"  - {blocker}")
    lines.extend(
        [
            "",
            "This gate does not prove Criterion 2, rejection-distribution "
            "preservation, production threshold ML-DSA security, CAVP/ACVTS "
            "validation, FIPS validation, or theorem closure.",
            "",
        ]
    )
    return "\n".join(lines)


def artifact_contents(report):
    """Build output artifact contents."""
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
    """Write gate artifacts and checksums."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = artifact_contents(report)
    contents["SHA256SUMS"] = render_checksums(contents)
    for name, content in contents.items():
        (out_dir / name).write_text(content, encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Gate a promoted P1 nonce-producer capture as actual external evidence"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument(
        "--attempt",
        default="artifacts/nonce-producer-capture-attempt/latest/manifest.json",
        help="capture-attempt manifest to verify",
    )
    parser.add_argument(
        "--out",
        default="artifacts/nonce-producer-actual-external-gate/latest",
        help="output directory",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit nonzero when the actual external capture slot is not ready",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    report = build_report(Path(args.root), Path(args.attempt))
    write_artifacts(report, Path(args.out))
    print(f"wrote actual external nonce-producer gate artifacts to {args.out}")
    if args.strict and not report["manifest"]["actual_external_capture_ready"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
