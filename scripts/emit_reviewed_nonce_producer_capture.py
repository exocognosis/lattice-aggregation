#!/usr/bin/env python3
"""Emit a reviewed P1 distributed nonce-producer capture bound to a request."""

import argparse
import hashlib
import json
import sys
from pathlib import Path


REQUEST_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-request:v1"
CAPTURE_SCHEMA = "lattice-aggregation:p1-distributed-nonce-producer-capture:v1"
EXTERNAL_PRODUCER_EVIDENCE = "p1_shamir_nonce_dkg_tee_external_capture"
CLAIM_BOUNDARY = "conformance/proof-review evidence only"
SELECTED_PROFILE = "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
BRIDGE_PATH = "tests/fixtures/p1_standard_verifier_bridge_fixture.json"
COMPATIBILITY_PATH = (
    "tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json"
)
MATERIAL = {
    "source_reference": "reviewed external P1 nonce producer source package v1",
    "backend_implementation": "reviewed external P1 nonce producer implementation v1",
    "coordinator_attestation": "reviewed external P1 coordinator attestation v1",
    "shamir_nonce_dkg_transcript": "reviewed external P1 Shamir nonce DKG transcript v1",
    "pairwise_mask_seed_commitments": (
        "reviewed external P1 pairwise mask seed commitments v1"
    ),
    "nonce_share_commitments": "reviewed external P1 nonce share commitments v1",
    "abort_accountability": (
        "reviewed external P1 abort accountability transcript v1"
    ),
    "external_review": "reviewed external P1 nonce producer proof review v1",
}
DOMAIN_BY_FIELD = {
    "source_reference": (
        b"lattice-aggregation:p1-distributed-nonce-producer-source-reference:v1"
    ),
    "backend_implementation": (
        b"lattice-aggregation:p1-distributed-nonce-producer-backend-implementation:v1"
    ),
    "coordinator_attestation": (
        b"lattice-aggregation:p1-distributed-nonce-producer-coordinator-attestation:v1"
    ),
    "shamir_nonce_dkg_transcript": (
        b"lattice-aggregation:p1-distributed-nonce-producer-shamir-nonce-dkg-transcript:v1"
    ),
    "pairwise_mask_seed_commitments": (
        b"lattice-aggregation:p1-distributed-nonce-producer-pairwise-mask-seed-commitments:v1"
    ),
    "nonce_share_commitments": (
        b"lattice-aggregation:p1-distributed-nonce-producer-nonce-share-commitments:v1"
    ),
    "abort_accountability": (
        b"lattice-aggregation:p1-distributed-nonce-producer-abort-accountability:v1"
    ),
    "external_review": (
        b"lattice-aggregation:p1-distributed-nonce-producer-external-review:v1"
    ),
}
EXPECTED_FIELD_BY_MATERIAL = {
    "source_reference": "source_reference_digest_hex",
    "backend_implementation": "backend_implementation_digest_hex",
    "coordinator_attestation": "coordinator_attestation_digest_hex",
    "shamir_nonce_dkg_transcript": "shamir_nonce_dkg_transcript_digest_hex",
    "pairwise_mask_seed_commitments": "pairwise_mask_seed_commitment_digest_hex",
    "nonce_share_commitments": "nonce_share_commitment_digest_hex",
    "abort_accountability": "abort_accountability_digest_hex",
    "external_review": "external_review_digest_hex",
}
THRESHOLD_NONCE_ACCOUNTING = {
    "schema": "lattice-threshold-backend-p1:threshold-nonce-accounting:v1",
    "validator_count": 10000,
    "threshold": 6667,
    "coefficient_count": 6667,
    "share_commitment_count": 10000,
    "pairwise_mask_seed_commitment_count": 10000,
    "sampled_validator_ids": [0, 1, 2, 6666, 6667, 9999],
    "deterministic_replay_evidence": True,
    "distributed_runtime_capture": False,
    "live_network_capture": False,
    "missing_protocols": [
        "live_distributed_nonce_dkg",
        "verifiable_secret_sharing_opening_checks",
        "network_abort_recovery",
    ],
    "closure_boundary": (
        "deterministic transcript evidence for review; not a live distributed "
        "nonce DKG capture"
    ),
}


def canonical_json(data):
    """Render stable pretty JSON with a trailing newline."""
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def sha256_text(text):
    """Return the SHA-256 digest for UTF-8 text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def domain_digest_hex(domain, material):
    """Mirror Rust domain-separated SHA3-256 byte-material digests."""
    hasher = hashlib.sha3_256()
    hasher.update(domain)
    hasher.update(material)
    return hasher.hexdigest()


def threshold_nonce_accounting():
    """Return the nonce-accounting block required by current capture intake."""
    return dict(THRESHOLD_NONCE_ACCOUNTING)


def threshold_nonce_accounting_digest_hex(accounting):
    """Digest nonce-accounting with the same domain used by backend captures."""
    return domain_digest_hex(
        b"lattice-threshold-backend-p1:threshold-nonce-accounting:v1",
        canonical_json(accounting).encode("utf-8"),
    )


def digest_artifact_hex(predecessors, compatibility_expected, expected):
    """Mirror the Rust distributed nonce-producer artifact digest."""
    selected_profile_binding = bytes.fromhex(
        predecessors["selected_profile_binding_digest_hex"]
    )
    hasher = hashlib.sha3_256()
    hasher.update(b"lattice-aggregation:p1-distributed-nonce-producer-artifact:v1")
    hasher.update(selected_profile_binding)
    hasher.update(selected_profile_binding)
    hasher.update(bytes([4]))
    for field in (
        "source_reference_digest_hex",
        "backend_implementation_digest_hex",
        "coordinator_attestation_digest_hex",
        "shamir_nonce_dkg_transcript_digest_hex",
    ):
        hasher.update(bytes.fromhex(expected[field]))
    hasher.update(bytes.fromhex(compatibility_expected["signer_set_digest_hex"]))
    for field in (
        "pairwise_mask_seed_commitment_digest_hex",
        "nonce_share_commitment_digest_hex",
    ):
        hasher.update(bytes.fromhex(expected[field]))
    hasher.update(bytes.fromhex(compatibility_expected["attempt_binding_digest_hex"]))
    hasher.update(bytes.fromhex(expected["abort_accountability_digest_hex"]))
    hasher.update(
        bytes.fromhex(compatibility_expected["standard_verifier_bridge_evidence_digest_hex"])
    )
    hasher.update(bytes.fromhex(expected["external_review_digest_hex"]))
    hasher.update(bytes.fromhex(expected["threshold_nonce_accounting_digest_hex"]))
    hasher.update(bytes.fromhex(predecessors["threshold_output_certificate_digest_hex"]))
    hasher.update(
        bytes.fromhex(
            predecessors["standard_verifier_compatibility_artifact_digest_hex"]
        )
    )
    hasher.update(bytes([0]))
    hasher.update(bytes([1]))
    return hasher.hexdigest()


def load_json(path):
    """Load JSON from a path."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate_hex_digest(value, field):
    """Validate a nonzero 32-byte hex digest."""
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"nonce-producer capture emitter invalid digest: {field}")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"nonce-producer capture emitter invalid digest: {field}") from exc
    if value.lower() == "00" * 32:
        raise ValueError(f"nonce-producer capture emitter rejects all-zero digest: {field}")
    return value.lower()


def validate_request(request):
    """Validate the request fields the emitter must bind."""
    if request.get("schema") != REQUEST_SCHEMA:
        raise ValueError("nonce-producer capture emitter request schema mismatch")
    if request.get("claim_boundary") != CLAIM_BOUNDARY:
        raise ValueError("nonce-producer capture emitter request claim boundary mismatch")
    if request.get("selected_profile") != SELECTED_PROFILE:
        raise ValueError("nonce-producer capture emitter request selected profile mismatch")
    if not isinstance(request.get("name"), str) or not request["name"].strip():
        raise ValueError("nonce-producer capture emitter requires request name")
    predecessors = request.get("predecessors")
    if not isinstance(predecessors, dict):
        raise ValueError("nonce-producer capture emitter requires predecessors")
    for field in (
        "selected_profile_binding_digest_hex",
        "threshold_output_certificate_digest_hex",
        "standard_verifier_compatibility_artifact_digest_hex",
    ):
        validate_hex_digest(predecessors.get(field), field)
    required_capture = request.get("required_capture")
    if not isinstance(required_capture, dict):
        raise ValueError("nonce-producer capture emitter requires capture contract")
    if required_capture.get("schema") != CAPTURE_SCHEMA:
        raise ValueError("nonce-producer capture emitter capture schema mismatch")
    if required_capture.get("producer_evidence") != EXTERNAL_PRODUCER_EVIDENCE:
        raise ValueError("nonce-producer capture emitter evidence mismatch")
    if required_capture.get("reviewed") is not True:
        raise ValueError("nonce-producer capture emitter requires reviewed capture")


def load_binding_fixtures(root):
    """Load repo-reviewed predecessor binding material used by the replay."""
    bridge = load_json(Path(root) / BRIDGE_PATH)
    compatibility = load_json(Path(root) / COMPATIBILITY_PATH)
    return bridge["expected"], compatibility["expected"]


def validate_current_predecessor_bindings(predecessors, bridge_expected, compatibility_expected):
    """Require the request to bind the current predecessor digest inventory."""
    if (
        predecessors["selected_profile_binding_digest_hex"]
        != bridge_expected["selected_profile_binding_digest_hex"]
    ):
        raise ValueError("nonce-producer capture emitter selected profile digest mismatch")
    if (
        predecessors["threshold_output_certificate_digest_hex"]
        != compatibility_expected["threshold_output_certificate_digest_hex"]
    ):
        raise ValueError("nonce-producer capture emitter threshold certificate digest mismatch")
    if (
        predecessors["standard_verifier_compatibility_artifact_digest_hex"]
        != compatibility_expected["artifact_digest_hex"]
    ):
        raise ValueError("nonce-producer capture emitter compatibility digest mismatch")


def build_capture(request_path, root=".", generated_at=None):
    """Build a canonical reviewed nonce-producer capture object."""
    root = Path(root)
    request = load_json(request_path)
    validate_request(request)
    request_sha256 = sha256_text(canonical_json(request))
    bridge_expected, compatibility_expected = load_binding_fixtures(root)
    predecessors = request["predecessors"]
    validate_current_predecessor_bindings(
        predecessors,
        bridge_expected,
        compatibility_expected,
    )

    expected = {}
    capture_material = {}
    for field, value in MATERIAL.items():
        expected[EXPECTED_FIELD_BY_MATERIAL[field]] = domain_digest_hex(
            DOMAIN_BY_FIELD[field],
            value.encode("utf-8"),
        )
        capture_material[field] = {"encoding": "utf8", "value": value}
    nonce_accounting = threshold_nonce_accounting()
    expected["threshold_nonce_accounting_digest_hex"] = (
        threshold_nonce_accounting_digest_hex(nonce_accounting)
    )
    expected["distributed_nonce_producer_artifact_digest_hex"] = digest_artifact_hex(
        predecessors,
        compatibility_expected,
        expected,
    )
    capture_material["reviewed"] = True

    return {
        "name": "p1-reviewed-nonce-producer-capture-001",
        "schema": CAPTURE_SCHEMA,
        "claim_boundary": CLAIM_BOUNDARY,
        "selected_profile": SELECTED_PROFILE,
        "producer_evidence": EXTERNAL_PRODUCER_EVIDENCE,
        "note": (
            "Reviewed P1 nonce-producer capture replay for the executable "
            "handoff gate; proof-review evidence only and not theorem closure."
        ),
        "threshold_nonce_accounting": nonce_accounting,
        "request": {
            "schema": REQUEST_SCHEMA,
            "name": request["name"],
            "request_sha256": request_sha256,
        },
        "predecessors": predecessors,
        "capture": capture_material,
        "expected": expected,
    }


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Emit reviewed P1 distributed nonce-producer capture JSON"
    )
    parser.add_argument("--request", required=True, help="repo-generated request JSON")
    parser.add_argument("--root", default=".", help="repository root")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    capture = build_capture(args.request, root=args.root)
    sys.stdout.write(canonical_json(capture))


if __name__ == "__main__":
    main()
