#!/usr/bin/env python3
"""Inspect a candidate P1 nonce-producer backend before capture promotion."""

import argparse
import hashlib
import json
import os
import sys
import time
import tomllib
from pathlib import Path


READINESS_SCHEMA = "lattice-aggregation:p1-nonce-producer-backend-readiness:v1"
REQUEST_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-request:v1"
CAPTURE_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-capture:v1"
CLAIM_BOUNDARY = "conformance/proof-review evidence only"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
ENV_BACKEND_CRATE = "LATTICE_NONCE_PRODUCER_BACKEND_CRATE"


def canonical_json(data):
    """Render stable pretty JSON with a trailing newline."""
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def sha256_text(text):
    """Return the SHA-256 digest for UTF-8 text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_path(path):
    """Return the SHA-256 digest for a file path."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_json(path):
    """Load JSON from a path."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_request(request_path):
    """Load and validate the P1 nonce-producer request being answered."""
    request = load_json(request_path)
    if request.get("schema") != REQUEST_SCHEMA:
        raise ValueError("nonce-producer readiness request schema mismatch")
    if request.get("claim_boundary") != CLAIM_BOUNDARY:
        raise ValueError("nonce-producer readiness request claim boundary mismatch")
    if request.get("selected_profile") != SELECTED_PROFILE:
        raise ValueError("nonce-producer readiness selected profile mismatch")
    required_capture = request.get("required_capture")
    if not isinstance(required_capture, dict):
        raise ValueError("nonce-producer readiness requires capture contract")
    if required_capture.get("schema") != CAPTURE_SCHEMA:
        raise ValueError("nonce-producer readiness capture schema mismatch")
    if required_capture.get("reviewed") is not True:
        raise ValueError("nonce-producer readiness requires reviewed capture")
    return request


def load_cargo_manifest(backend_crate):
    """Load Cargo.toml from a candidate backend crate."""
    cargo_toml = Path(backend_crate) / "Cargo.toml"
    if not cargo_toml.is_file():
        raise ValueError("nonce-producer readiness requires backend crate Cargo.toml")
    with cargo_toml.open("rb") as handle:
        manifest = tomllib.load(handle)
    return manifest


def source_inventory(backend_crate):
    """Return source-file inventory and stable source-tree digest."""
    backend_crate = Path(backend_crate)
    candidates = [backend_crate / "Cargo.toml"]
    cargo_lock = backend_crate / "Cargo.lock"
    if cargo_lock.is_file():
        candidates.append(cargo_lock)
    src_dir = backend_crate / "src"
    if src_dir.is_dir():
        candidates.extend(sorted(src_dir.rglob("*.rs")))

    inventory = []
    for path in sorted({p.resolve() for p in candidates}):
        if not path.is_file():
            continue
        relative = path.relative_to(backend_crate.resolve()).as_posix()
        inventory.append(
            {
                "path": relative,
                "sha256": sha256_path(path),
                "size_bytes": path.stat().st_size,
            }
        )
    tree_digest = sha256_text(canonical_json(inventory))
    return inventory, tree_digest


def read_source_blob(backend_crate):
    """Read the backend source files used for marker-based readiness checks."""
    src_dir = Path(backend_crate) / "src"
    if not src_dir.is_dir():
        return ""
    parts = []
    for path in sorted(src_dir.rglob("*.rs")):
        try:
            parts.append(path.read_text(encoding="utf-8"))
        except UnicodeDecodeError:
            parts.append(path.read_text(encoding="utf-8", errors="ignore"))
    return "\n".join(parts)


def feature_names(cargo):
    """Return declared Cargo feature names."""
    features = cargo.get("features", {})
    if not isinstance(features, dict):
        return []
    return sorted(features)


def default_features(cargo):
    """Return the Cargo default feature list."""
    features = cargo.get("features", {})
    if not isinstance(features, dict):
        return []
    default = features.get("default", [])
    if not isinstance(default, list):
        return []
    return sorted(str(item) for item in default)


def package_value(cargo, key, default="unknown"):
    """Return a Cargo package field as a string."""
    package = cargo.get("package", {})
    if not isinstance(package, dict):
        return default
    value = package.get(key, default)
    return str(value) if value is not None else default


def package_list(cargo, key):
    """Return a Cargo package array field as strings."""
    package = cargo.get("package", {})
    if not isinstance(package, dict):
        return []
    value = package.get(key, [])
    if not isinstance(value, list):
        return []
    return sorted(str(item) for item in value)


def detect_capabilities(cargo, source_blob):
    """Detect nonce-producer-relevant backend capabilities and hazards."""
    lowered = source_blob.lower()
    features = feature_names(cargo)
    defaults = default_features(cargo)
    categories = package_list(cargo, "categories")
    description = package_value(cargo, "description", default="")
    description_lower = description.lower()
    return {
        "distributed_nonce_prf_output_share_interface": (
            "Mldsa65DistributedNoncePrfOutputShare" in source_blob
        ),
        "distributed_nonce_prf_output_splitter": (
            "split_mldsa65_distributed_nonce_prf_output" in source_blob
        ),
        "distributed_nonce_masking_contribution": (
            "derive_mldsa65_distributed_nonce_prf_masking_contribution_from_share"
            in source_blob
        ),
        "reviewed_external_capture_contract": (
            "p1_shamir_nonce_dkg_tee_external_capture" in source_blob
            and "abort_accountability" in lowered
        ),
        "centralized_nonce_prf_oracle": (
            "derive_mldsa65_centralized_nonce_prf_output_from_expanded_secret_key"
            in source_blob
        ),
        "hazmat_feature": any("hazmat" in feature.lower() for feature in features),
        "simulated_default_feature": any(
            feature.lower() == "simulated" for feature in defaults
        ),
        "simulation_category": any(
            category.lower() == "simulation" for category in categories
        ),
        "research_grade_simulation_description": (
            "research-grade" in description_lower and "simulation" in description_lower
        ),
        "deterministic_test_vector_plumbing": (
            "deterministic test-vector" in lowered
            or "test-vector plumbing" in lowered
        ),
    }


def detected_blockers(capabilities):
    """Return blockers that prevent artifact-ready external handoff promotion."""
    blockers = []
    if not capabilities["distributed_nonce_prf_output_share_interface"]:
        blockers.append("missing distributed nonce PRF output share interface")
    if not capabilities["distributed_nonce_prf_output_splitter"]:
        blockers.append("missing distributed nonce PRF output splitter")
    if not capabilities["distributed_nonce_masking_contribution"]:
        blockers.append("missing distributed nonce masking contribution converter")
    if not capabilities["reviewed_external_capture_contract"]:
        blockers.append("missing reviewed external capture contract marker")
    if capabilities["hazmat_feature"]:
        blockers.append("hazmat feature present")
    if capabilities["simulated_default_feature"]:
        blockers.append("simulated default feature present")
    if capabilities["simulation_category"] or capabilities["research_grade_simulation_description"]:
        blockers.append("research-grade simulation backend marker present")
    if capabilities["centralized_nonce_prf_oracle"]:
        blockers.append("centralized nonce PRF oracle present")
    if capabilities["deterministic_test_vector_plumbing"]:
        blockers.append("deterministic test-vector plumbing present")
    return blockers


def render_summary(manifest):
    """Render a concise backend readiness summary."""
    admissible = manifest["admissibility"]["admissible_for_p1_nonce_handoff"]
    return "\n".join(
        [
            "# P1 Nonce-Producer Backend Readiness",
            "",
            "This artifact inspects a candidate backend before the executable "
            "nonce-producer capture handoff. It is conformance/proof-review "
            "evidence only.",
            "",
            f"- Status: `{manifest['readiness_status']}`",
            f"- Backend package: `{manifest['backend']['package_name']}`",
            f"- Request SHA-256: `{manifest['request']['request_sha256']}`",
            f"- Source tree SHA-256: `{manifest['backend']['source_tree_sha256']}`",
            f"- Admissible for P1 handoff: `{str(admissible).lower()}`",
            "",
            "This artifact does not prove Criterion 2, rejection-distribution "
            "preservation, production threshold ML-DSA security, CAVP/ACVTS "
            "validation, FIPS validation, or theorem closure.",
            "",
        ]
    )


def build_report(request_path, backend_crate, generated_at=None, backend_label=None):
    """Build a backend readiness report for a candidate nonce producer."""
    request_path = Path(request_path)
    backend_crate = Path(backend_crate)
    request = load_request(request_path)
    request_sha256 = sha256_text(canonical_json(request))
    cargo = load_cargo_manifest(backend_crate)
    inventory, tree_digest = source_inventory(backend_crate)
    source_blob = read_source_blob(backend_crate)
    capabilities = detect_capabilities(cargo, source_blob)
    blockers = detected_blockers(capabilities)
    admissible = not blockers
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    manifest = {
        "schema": READINESS_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "claim_boundary": CLAIM_BOUNDARY,
        "readiness_status": (
            "backend_candidate_admissible_pending_capture"
            if admissible
            else "backend_detected_not_admissible"
        ),
        "selected_profile": SELECTED_PROFILE,
        "request": {
            "schema": request["schema"],
            "name": request["name"],
            "request_sha256": request_sha256,
            "request_path": str(request_path),
            "capture_schema": request["required_capture"]["schema"],
            "required_producer_evidence": request["required_capture"][
                "producer_evidence"
            ],
        },
        "backend": {
            "crate_path": backend_label or str(backend_crate),
            "package_name": package_value(cargo, "name"),
            "version": package_value(cargo, "version"),
            "description": package_value(cargo, "description"),
            "repository": package_value(cargo, "repository"),
            "features": feature_names(cargo),
            "default_features": default_features(cargo),
            "categories": package_list(cargo, "categories"),
            "cargo_toml_sha256": sha256_path(backend_crate / "Cargo.toml"),
            "source_tree_sha256": tree_digest,
            "source_file_count": len(inventory),
            "source_inventory": inventory,
        },
        "capabilities": capabilities,
        "admissibility": {
            "admissible_for_p1_nonce_handoff": admissible,
            "detected_blockers": blockers,
            "blocked_reason": (
                "candidate backend is not admissible for the P1 external "
                "nonce-producer handoff until blockers are removed"
                if blockers
                else None
            ),
            "requirements_to_become_admissible": [
                "external command emits canonical P1 distributed nonce-producer capture JSON",
                "capture binds the exact request schema, request name, and request SHA-256",
                "capture source is not hazmat, localnet, simulation, fixture, centralized, or single-key material",
                "capture carries reviewed Shamir nonce-DKG/TEE transcript, coordinator attestation, nonce-share commitments, abort accountability, and external review evidence",
            ],
        },
        "next_external_cli_contract": {
            "contract_document": "docs/cryptography/p1-nonce-producer-backend-cli-contract.md",
            "backend_command_shape": [
                "/opt/p1-nonce-producer",
                "emit",
                "--request",
                str(request_path),
            ],
            "stdout_schema": CAPTURE_SCHEMA,
            "runner": "scripts/run_nonce_producer_capture.py",
        },
        "next_capture_command": [
            "python3",
            "scripts/run_nonce_producer_handoff_replay.py",
            "--root",
            ".",
            "--out",
            "artifacts/nonce-producer-handoff/latest",
            "--backend-command",
            "/opt/p1-nonce-producer",
            "emit",
            "--request",
            "artifacts/nonce-producer-handoff/latest/request/request.json",
        ],
        "closure_boundary": (
            "Backend readiness and source capability detection only; an actual "
            "reviewed capture and proof review remain required."
        ),
    }
    return {
        "manifest": manifest,
        "summary_md": render_summary(manifest),
    }


def artifact_contents(report):
    """Build final artifact file contents."""
    return {
        "manifest.json": canonical_json(report["manifest"]),
        "summary.md": report["summary_md"],
    }


def render_checksums(contents):
    """Render deterministic SHA-256 checksums for artifact files."""
    lines = []
    for name in sorted(contents):
        lines.append(f"{sha256_text(contents[name])}  {name}")
    return "\n".join(lines) + "\n"


def write_artifacts(report, out_dir):
    """Write readiness artifacts and checksums."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = artifact_contents(report)
    contents["SHA256SUMS"] = render_checksums(contents)
    for name, content in contents.items():
        (out_dir / name).write_text(content, encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Inspect candidate P1 nonce-producer backend readiness"
    )
    parser.add_argument("--request", required=True, help="repo-generated request JSON")
    parser.add_argument(
        "--backend-crate",
        default=os.environ.get(ENV_BACKEND_CRATE),
        help=f"candidate backend crate path, or ${ENV_BACKEND_CRATE}",
    )
    parser.add_argument(
        "--out",
        default="artifacts/nonce-producer-backend-readiness/latest",
        help="output directory",
    )
    parser.add_argument(
        "--backend-label",
        help="stable label to record instead of a local absolute backend path",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    if not args.backend_crate:
        raise SystemExit(f"--backend-crate or ${ENV_BACKEND_CRATE} is required")
    report = build_report(
        request_path=Path(args.request),
        backend_crate=Path(args.backend_crate),
        backend_label=args.backend_label,
    )
    write_artifacts(report, Path(args.out))
    print(f"wrote nonce-producer backend readiness artifacts to {args.out}")


if __name__ == "__main__":
    main()
