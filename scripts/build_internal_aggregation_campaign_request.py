#!/usr/bin/env python3
"""Build a deterministic internal threshold-aggregation campaign request."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


REQUEST_SCHEMA = "lattice-aggregation:internal-aggregation-campaign-request:v1"
CAPTURE_SCHEMA = "lattice-aggregation:internal-aggregation-campaign-capture:v1"
CLAIM_BOUNDARY = "internal aggregation evidence; theorem unclosed pending proof review"
CAMPAIGN_STATUS = "preregistered_fail_closed"
VALIDATOR_COUNT = 10_000
THRESHOLD = 6_667
COMMITTEE_SIZES = (8, 16, 32, 64)
CASE_KINDS = (
    "accepted",
    "rejected",
    "retry",
    "abort",
    "malicious_share",
    "transcript_mutation",
)
MLDSA_PARAMETER_SET = "ML-DSA-65"
PUBLIC_KEY_BYTES = 1952
SIGNATURE_BYTES = 3309
SEED_DOMAIN = "lattice-aggregation:internal-campaign-seed:v1"
SEED_COUNT = 8
REQUIRED_EVIDENCE_ROLES = (
    "backend_source_archive",
    "backend_implementation_manifest",
    "backend_binary",
    "backend_test_results",
    "proof_artifact_bundle",
    "dkg_custody_capability_evidence",
    "authorization_certificate",
    "toolchain_lock",
    "environment_manifest",
    "transcript_bundle",
    "standard_verifier_binary",
    "kat_results",
)
ARTIFACT_ROOT = "artifacts/internal-aggregation-campaign/latest"
DEFAULT_REQUEST_OUT = ARTIFACT_ROOT
DEFAULT_REQUEST_PATH = f"{DEFAULT_REQUEST_OUT}/request.json"
DEFAULT_REQUEST_MANIFEST_PATH = f"{DEFAULT_REQUEST_OUT}/request-manifest.json"
DEFAULT_CAPTURE_PATH = f"{ARTIFACT_ROOT}/capture.json"
DEFAULT_VALIDATION_MANIFEST_PATH = f"{ARTIFACT_ROOT}/manifest.json"
CLAIM_FLAGS = (
    "claims_theorem_closure",
    "claims_production_threshold_mldsa_security",
    "claims_distribution_compatibility_proven",
    "claims_cavp_acvts_validation",
    "claims_fips_validation",
)


def canonical_json(value):
    """Render stable pretty JSON with a trailing newline."""
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def sha256_bytes(value):
    """Return a lowercase SHA-256 digest."""
    return hashlib.sha256(value).hexdigest()


def sha256_text(value):
    """Return a lowercase SHA-256 digest for UTF-8 text."""
    return sha256_bytes(value.encode("utf-8"))


def validate_campaign_id(value):
    """Validate an operator-selected stable campaign identifier."""
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,63}", value):
        raise ValueError(
            "campaign id must be 3-64 lowercase letters, digits, dots, dashes, or underscores"
        )
    return value


def pinned_seed_corpus():
    """Return the versioned deterministic seed corpus for campaign replay."""
    seeds = []
    for index in range(SEED_COUNT):
        seed = hashlib.sha256(f"{SEED_DOMAIN}:{index:02d}".encode("utf-8")).digest()
        seeds.append(
            {
                "seed_id": f"seed-{index:02d}",
                "seed_hex": seed.hex(),
                "seed_sha256": sha256_bytes(seed),
            }
        )
    return seeds


def expected_observations(case_kind):
    """Return case-specific minimum observations for the backend capture."""
    observations = {
        "protocol_outcome": "rejected",
        "aggregate_emitted": False,
        "standard_verifier_invoked": False,
        "standard_verifier_accepted": False,
        "retry_count_min": 0,
        "rejection_predicate_recorded": False,
        "abort_recorded": False,
        "malicious_share_rejected": False,
        "transcript_mutation_rejected": False,
    }
    if case_kind == "accepted":
        observations.update(
            {
                "protocol_outcome": "accepted",
                "aggregate_emitted": True,
                "standard_verifier_invoked": True,
                "standard_verifier_accepted": True,
            }
        )
    elif case_kind == "rejected":
        observations["rejection_predicate_recorded"] = True
    elif case_kind == "retry":
        observations.update(
            {
                "protocol_outcome": "accepted",
                "aggregate_emitted": True,
                "standard_verifier_invoked": True,
                "standard_verifier_accepted": True,
                "retry_count_min": 1,
                "rejection_predicate_recorded": True,
            }
        )
    elif case_kind == "abort":
        observations.update(
            {
                "protocol_outcome": "aborted",
                "abort_recorded": True,
            }
        )
    elif case_kind == "malicious_share":
        observations["malicious_share_rejected"] = True
    elif case_kind == "transcript_mutation":
        observations["transcript_mutation_rejected"] = True
    else:
        raise ValueError(f"unsupported campaign case kind: {case_kind}")
    return observations


def build_cases(campaign_id, seeds):
    """Build the complete preregistered committee/case matrix."""
    cases = []
    index = 0
    for committee_size in COMMITTEE_SIZES:
        for case_kind in CASE_KINDS:
            seed = seeds[index % len(seeds)]
            case_id = f"k{committee_size:02d}-{case_kind.replace('_', '-')}-001"
            message = hashlib.sha256(
                f"{REQUEST_SCHEMA}:{campaign_id}:{case_id}".encode("utf-8")
            ).digest()
            cases.append(
                {
                    "case_id": case_id,
                    "case_kind": case_kind,
                    "validator_count": VALIDATOR_COUNT,
                    "threshold": THRESHOLD,
                    "committee_size": committee_size,
                    "seed_id": seed["seed_id"],
                    "seed_sha256": seed["seed_sha256"],
                    "message": {
                        "encoding": "hex",
                        "value": message.hex(),
                        "sha256": sha256_bytes(message),
                    },
                    "required_observations": expected_observations(case_kind),
                }
            )
            index += 1
    return cases


def build_request(campaign_id, authorization_verifier_profile=None):
    """Build a deterministic campaign request and its manifest."""
    campaign_id = validate_campaign_id(campaign_id)
    authorization_verifier_profile = authorization_verifier_profile or {}
    verifier_id = authorization_verifier_profile.get("verifier_id")
    verifier_implementation_sha256 = authorization_verifier_profile.get(
        "verifier_implementation_sha256"
    )
    verifier_ready = (
        isinstance(verifier_id, str)
        and bool(verifier_id)
        and isinstance(verifier_implementation_sha256, str)
        and len(verifier_implementation_sha256) == 64
        and verifier_implementation_sha256 != "0" * 64
        and all(character in "0123456789abcdef" for character in verifier_implementation_sha256)
    )
    if authorization_verifier_profile and not verifier_ready:
        raise ValueError(
            "authorization_verifier_profile must bind a non-empty verifier_id "
            "and nonzero lowercase SHA-256 implementation digest"
        )
    seeds = pinned_seed_corpus()
    request = {
        "schema": REQUEST_SCHEMA,
        "campaign_id": campaign_id,
        "campaign_status": CAMPAIGN_STATUS,
        "claim_boundary": CLAIM_BOUNDARY,
        "topology": {
            "validator_count": VALIDATOR_COUNT,
            "threshold": THRESHOLD,
            "committee_size_ladder": list(COMMITTEE_SIZES),
        },
        "mldsa_profile": {
            "parameter_set": MLDSA_PARAMETER_SET,
            "public_key_bytes": PUBLIC_KEY_BYTES,
            "aggregate_signature_bytes": SIGNATURE_BYTES,
        },
        "seed_corpus": {
            "domain": SEED_DOMAIN,
            "seeds": seeds,
        },
        "cases": build_cases(campaign_id, seeds),
        "capture_requirements": {
            "schema": CAPTURE_SCHEMA,
            "evidence_class": "actual_distributed_threshold_mldsa_campaign",
            "execution_mode": "actual_distributed_threshold_backend",
            "required_evidence_file_roles": list(REQUIRED_EVIDENCE_ROLES),
            "clean_git_provenance": True,
            "self_contained_relative_evidence_paths": True,
            "dkg_custody_capability_evidence": {
                "schema": "lattice-threshold-backend-p1:dkg-custody-capability-evidence:v1",
                "evidence_file_role": "dkg_custody_capability_evidence",
                "claim_values_must_be_digest_bound": True,
                "capability_fields": [
                    "distributed_dkg_vss",
                    "fips204_exact_distributed_key_generation",
                    "exact_distributed_keygen",
                    "private_per_receiver_share_custody",
                    "per_receiver_private_share_custody",
                ],
            },
            "live_distributed_nonce_generation": True,
            "exact_distributed_expand_mask": True,
            "exact_expand_mask_mpc": True,
            "partial_signing_over_secret_shares": True,
            "partial_z_i_hint_aggregation": True,
            "fips204_rejection_loop_over_threshold_partials": True,
            "no_secret_or_seed_reconstruction": True,
            "standard_wire_output": True,
            "authorization_layer_validator_count": VALIDATOR_COUNT,
            "authorization_layer_threshold": THRESHOLD,
            "committee_authorization_bound": True,
            "authorization_certificate": {
                "schema": "lattice-aggregation:threshold-authorization-certificate:v1",
                "validator_count": VALIDATOR_COUNT,
                "threshold": THRESHOLD,
                "minimum_distinct_authorizers": THRESHOLD,
                "bind_each_execution": True,
                "parse_authorizer_records": True,
                "cryptographic_signature_verification_required": True,
                "cryptographic_verifier_status": (
                    "reviewed_ready" if verifier_ready else "not_implemented_fail_closed"
                ),
                "verifier_id": verifier_id if verifier_ready else None,
                "verifier_implementation_sha256": (
                    verifier_implementation_sha256 if verifier_ready else None
                ),
            },
            "standard_verifier_mutation_rejection": [
                "message",
                "public_key",
                "signature",
            ],
        },
        "kat_requirements": {
            "parameter_set": MLDSA_PARAMETER_SET,
            "source": "NIST ACVP/ACVTS ML-DSA vectors",
            "required_vector_types": ["keyGen", "sigGen", "sigVer"],
            "minimum_vector_count": 1,
            "failed_vector_count": 0,
        },
        "forbidden_backend_sources": [
            "simulation",
            "fixture harness",
            "localnet telemetry",
            "single-key standard-provider output",
            "threshold seed reconstruction",
            "centralized signing oracle",
        ],
        "artifact_contract": {
            "artifact_root": ARTIFACT_ROOT,
            "request_path": DEFAULT_REQUEST_PATH,
            "request_manifest_path": DEFAULT_REQUEST_MANIFEST_PATH,
            "capture_path": DEFAULT_CAPTURE_PATH,
            "validation_manifest_path": DEFAULT_VALIDATION_MANIFEST_PATH,
            "request_schema": REQUEST_SCHEMA,
            "capture_schema": CAPTURE_SCHEMA,
        },
        "claim_flags": {flag: False for flag in CLAIM_FLAGS},
    }
    request_json = canonical_json(request)
    manifest = {
        "schema_version": 1,
        "request_schema": REQUEST_SCHEMA,
        "capture_schema": CAPTURE_SCHEMA,
        "campaign_id": campaign_id,
        "campaign_status": CAMPAIGN_STATUS,
        "case_count": len(request["cases"]),
        "request_sha256": sha256_text(request_json),
        "claim_boundary": CLAIM_BOUNDARY,
        "artifact_contract": request["artifact_contract"],
    }
    return {
        "request": request,
        "request_json": request_json,
        "manifest": manifest,
        "summary_md": render_summary(request, manifest),
    }


def render_summary(request, manifest):
    """Render a human-readable campaign preregistration summary."""
    return "\n".join(
        [
            "# Internal Aggregation Campaign Preregistration",
            "",
            f"- Campaign: `{request['campaign_id']}`",
            f"- Status: `{CAMPAIGN_STATUS}`",
            f"- Validators / threshold: `{VALIDATOR_COUNT}` / `{THRESHOLD}`",
            f"- Committee ladder: `{list(COMMITTEE_SIZES)}`",
            f"- Preregistered cases: `{manifest['case_count']}`",
            f"- Request SHA-256: `{manifest['request_sha256']}`",
            "",
            "The capture gate accepts only a clean, digest-bound, actual distributed",
            "threshold backend campaign. Simulation, fixtures, single-key output, and",
            "secret/seed reconstruction fail closed. A passing campaign remains internal",
            "aggregation evidence and does not itself claim theorem closure or FIPS validation.",
            "",
        ]
    )


def render_checksums(contents):
    """Render stable checksums for generated artifact files."""
    return "".join(
        f"{sha256_text(contents[name])}  {name}\n" for name in sorted(contents)
    )


def write_artifacts(report, out_dir):
    """Write campaign request artifacts."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = {
        "request.json": report["request_json"],
        "request-manifest.json": canonical_json(report["manifest"]),
        "request-summary.md": report["summary_md"],
    }
    contents["request-SHA256SUMS"] = render_checksums(contents)
    for name, content in contents.items():
        (out_dir / name).write_text(content, encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Build a deterministic internal aggregation campaign request"
    )
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument(
        "--authorization-verifier-id",
        default=None,
        help="reviewed threshold-authorization verifier id to bind into the request",
    )
    parser.add_argument(
        "--authorization-verifier-implementation-sha256",
        default=None,
        help="lowercase SHA-256 digest of the reviewed authorization verifier implementation",
    )
    parser.add_argument("--out", default=DEFAULT_REQUEST_OUT)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    verifier_profile = {}
    if (
        args.authorization_verifier_id is not None
        or args.authorization_verifier_implementation_sha256 is not None
    ):
        verifier_profile = {
            "verifier_id": args.authorization_verifier_id,
            "verifier_implementation_sha256": (
                args.authorization_verifier_implementation_sha256
            ),
        }
    report = build_request(
        args.campaign_id,
        authorization_verifier_profile=verifier_profile,
    )
    write_artifacts(report, args.out)
    print(f"wrote internal aggregation campaign request to {args.out}")


if __name__ == "__main__":
    main()
