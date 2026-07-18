#!/usr/bin/env python3
"""Fail-closed validation for an actual internal aggregation campaign capture."""

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path, PurePosixPath


REQUEST_SCHEMA = "lattice-aggregation:internal-aggregation-campaign-request:v1"
CAPTURE_SCHEMA = "lattice-aggregation:internal-aggregation-campaign-capture:v1"
REPORT_SCHEMA = "lattice-aggregation:internal-aggregation-campaign-validation:v1"
READY_STATUS = "internal_campaign_evidence_ready"
BLOCKED_STATUS = "blocked_fail_closed"
THEOREM_STATUS = "unclosed_pending_proof_and_independent_review"
EXPECTED_EVIDENCE_CLASS = "actual_distributed_threshold_mldsa_campaign"
EXPECTED_EXECUTION_MODE = "actual_distributed_threshold_backend"
EXPECTED_CORE_MODE = "distributed_threshold_mldsa65_partial_aggregation"
EXPECTED_SIGNATURE_ORIGIN = "threshold_partial_aggregation"
EVIDENCE_BOUND_CORE_CHECKS = (
    "distributed_dkg_vss",
    "fips204_exact_distributed_key_generation",
    "exact_distributed_keygen",
    "private_per_receiver_share_custody",
    "per_receiver_private_share_custody",
)
REQUIRED_TRUE_CORE_CHECKS = (
    "live_distributed_nonce_generation",
    "exact_distributed_expand_mask",
    "exact_expand_mask_mpc",
    "partial_signing_over_secret_shares",
    "partial_z_i_hint_aggregation",
    "fips204_rejection_loop_over_threshold_partials",
    "no_secret_or_seed_reconstruction",
    "standard_wire_output",
    "committee_authorization_bound",
)
REQUIRED_CORE_CHECKS = EVIDENCE_BOUND_CORE_CHECKS + REQUIRED_TRUE_CORE_CHECKS
REQUIRED_CLEAN_CHECKS = (
    "repo_clean",
    "git_diff_empty",
    "untracked_files_empty",
    "capture_generated_from_clean_checkout",
)
REQUIRED_DIGEST_FIELDS = (
    "backend_source_digest_hex",
    "backend_implementation_digest_hex",
    "backend_binary_digest_hex",
    "backend_test_results_digest_hex",
    "proof_artifact_bundle_digest_hex",
    "authorization_certificate_digest_hex",
    "toolchain_lock_digest_hex",
    "environment_digest_hex",
    "capture_command_digest_hex",
    "transcript_bundle_digest_hex",
)
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
CAPABILITY_EVIDENCE_SCHEMA = "lattice-threshold-backend-p1:dkg-custody-capability-evidence:v1"
CAPABILITY_EVIDENCE_BINDING_SCHEMA = (
    "lattice-threshold-backend-p1:dkg-custody-capability-evidence-binding:v1"
)
CAPABILITY_EVIDENCE_ROLE = "dkg_custody_capability_evidence"
ARTIFACT_ROOT = "artifacts/internal-aggregation-campaign/latest"
DEFAULT_REQUEST_PATH = f"{ARTIFACT_ROOT}/request.json"
DEFAULT_CAPTURE_PATH = f"{ARTIFACT_ROOT}/capture.json"
DEFAULT_VALIDATION_OUT = ARTIFACT_ROOT
CLAIM_FLAGS = (
    "claims_theorem_closure",
    "claims_production_threshold_mldsa_security",
    "claims_distribution_compatibility_proven",
    "claims_cavp_acvts_validation",
    "claims_fips_validation",
)
FORBIDDEN_BACKEND_MARKERS = (
    "simulation",
    "simulated",
    "fixture",
    "localnet",
    "single-key",
    "single_key",
    "single seed",
    "single_seed",
    "seed reconstruction",
    "seed_reconstruction",
    "centralized signing",
    "centralized_mldsa",
    "hazmat threshold",
)


def canonical_json(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_text(value):
    return sha256_bytes(value.encode("utf-8"))


def sha256_path(path):
    return sha256_bytes(Path(path).read_bytes())


def is_digest(value):
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
        and value != "00" * 32
    )


def check_equal(blockers, actual, expected, label):
    if actual != expected:
        blockers.append(f"{label} mismatch: expected {expected!r}")


def require_true(blockers, mapping, field, label):
    if not isinstance(mapping, dict) or mapping.get(field) is not True:
        blockers.append(f"{label} must be true: {field}")


def require_false(blockers, mapping, field, label):
    if not isinstance(mapping, dict) or mapping.get(field) is not False:
        blockers.append(f"{label} must be false: {field}")


def validate_request(request):
    """Return blockers if the input request is not the expected preregistration."""
    blockers = []
    check_equal(blockers, request.get("schema"), REQUEST_SCHEMA, "request schema")
    topology = request.get("topology")
    if not isinstance(topology, dict):
        blockers.append("request topology missing")
    else:
        check_equal(blockers, topology.get("validator_count"), 10_000, "validator count")
        check_equal(blockers, topology.get("threshold"), 6_667, "threshold")
        check_equal(
            blockers,
            topology.get("committee_size_ladder"),
            [8, 16, 32, 64],
            "committee ladder",
        )
    seed_corpus = request.get("seed_corpus")
    seeds = seed_corpus.get("seeds", []) if isinstance(seed_corpus, dict) else []
    if not isinstance(seeds, list):
        seeds = []
    seed_ids = [seed.get("seed_id") for seed in seeds if isinstance(seed, dict)]
    if len(seeds) != 8 or len(seed_ids) != 8 or len(set(seed_ids)) != 8:
        blockers.append("request must contain eight unique pinned seeds")
    for seed in seeds:
        if not isinstance(seed, dict):
            blockers.append("request pinned seed must be an object")
            continue
        try:
            raw = bytes.fromhex(seed.get("seed_hex", ""))
        except ValueError:
            raw = b""
        if len(raw) != 32 or sha256_bytes(raw) != seed.get("seed_sha256"):
            blockers.append(f"request pinned seed invalid: {seed.get('seed_id')}")
    cases = request.get("cases")
    if not isinstance(cases, list) or len(cases) != 24:
        blockers.append("request must contain the 24-case committee matrix")
    else:
        valid_cases = [case for case in cases if isinstance(case, dict)]
        matrix = {
            (case.get("committee_size"), case.get("case_kind"))
            for case in valid_cases
            if isinstance(case.get("committee_size"), int)
            and isinstance(case.get("case_kind"), str)
        }
        expected = {
            (size, kind)
            for size in (8, 16, 32, 64)
            for kind in (
                "accepted",
                "rejected",
                "retry",
                "abort",
                "malicious_share",
                "transcript_mutation",
            )
        }
        if matrix != expected:
            blockers.append("request case matrix is incomplete or duplicated")
        case_ids = [case.get("case_id") for case in valid_cases]
        if len(valid_cases) != len(cases) or len(set(case_ids)) != len(cases):
            blockers.append("request case ids must be unique")
    for flag in CLAIM_FLAGS:
        require_false(blockers, request.get("claim_flags"), flag, "request claim flag")
    return blockers


def validate_evidence_files(capture, evidence_base, blockers):
    """Verify self-contained evidence paths and byte-for-byte SHA-256 bindings."""
    records = capture.get("evidence_files")
    if not isinstance(records, list):
        blockers.append("evidence_files must be a list")
        return {}
    by_role = {}
    for record in records:
        if not isinstance(record, dict):
            blockers.append("evidence file record must be an object")
            continue
        role = record.get("role")
        path_value = record.get("path")
        if not isinstance(role, str):
            blockers.append("evidence file role must be a string")
            continue
        if role in by_role:
            blockers.append(f"duplicate evidence file role: {role}")
            continue
        by_role[role] = record
        if not isinstance(path_value, str):
            blockers.append(f"evidence path missing for role: {role}")
            continue
        pure_path = PurePosixPath(path_value)
        if pure_path.is_absolute() or ".." in pure_path.parts:
            blockers.append(f"evidence path must be relative and contained: {role}")
            continue
        full_path = evidence_base / Path(*pure_path.parts)
        if not full_path.is_file():
            blockers.append(f"evidence file missing: {role}")
            continue
        if full_path.stat().st_size == 0:
            blockers.append(f"evidence file empty: {role}")
            continue
        actual_digest = sha256_path(full_path)
        if record.get("sha256") != actual_digest:
            blockers.append(f"evidence file digest mismatch: {role}")
    for role in REQUIRED_EVIDENCE_ROLES:
        if role not in by_role:
            blockers.append(f"required evidence file role missing: {role}")
    return by_role


def validate_provenance(capture, evidence_roles, blockers):
    provenance = capture.get("provenance")
    if not isinstance(provenance, dict):
        blockers.append("capture provenance missing")
        return
    check_equal(
        blockers,
        provenance.get("source_class"),
        "git_tracked_actual_backend",
        "provenance source class",
    )
    for field in REQUIRED_CLEAN_CHECKS:
        require_true(blockers, provenance, field, "clean provenance check")
    source_commit = provenance.get("source_commit")
    if not isinstance(source_commit, str) or re.fullmatch(r"[0-9a-f]{40,64}", source_commit) is None:
        blockers.append("provenance source_commit must be a full lowercase git object id")
    for field in REQUIRED_DIGEST_FIELDS:
        if not is_digest(provenance.get(field)):
            blockers.append(f"provenance digest invalid: {field}")

    bindings = {
        "backend_source_digest_hex": "backend_source_archive",
        "backend_implementation_digest_hex": "backend_implementation_manifest",
        "backend_binary_digest_hex": "backend_binary",
        "backend_test_results_digest_hex": "backend_test_results",
        "proof_artifact_bundle_digest_hex": "proof_artifact_bundle",
        "authorization_certificate_digest_hex": "authorization_certificate",
        "toolchain_lock_digest_hex": "toolchain_lock",
        "environment_digest_hex": "environment_manifest",
        "transcript_bundle_digest_hex": "transcript_bundle",
    }
    for digest_field, role in bindings.items():
        record = evidence_roles.get(role)
        if isinstance(record, dict) and provenance.get(digest_field) != record.get("sha256"):
            blockers.append(f"provenance/evidence digest binding mismatch: {digest_field}")

    backend_values = [
        provenance.get("backend_name", ""),
        provenance.get("backend_command", ""),
        provenance.get("source_class", ""),
    ]
    core = capture.get("cryptographic_core")
    if isinstance(core, dict):
        backend_values.extend(
            [core.get("core_mode", ""), core.get("signature_origin", "")]
        )
    lowered = " ".join(value for value in backend_values if isinstance(value, str)).lower()
    for marker in FORBIDDEN_BACKEND_MARKERS:
        if marker in lowered:
            blockers.append(f"forbidden backend source marker: {marker}")


def validate_core(capture, evidence_roles, evidence_base, blockers):
    check_equal(
        blockers,
        capture.get("evidence_class"),
        EXPECTED_EVIDENCE_CLASS,
        "capture evidence class",
    )
    check_equal(
        blockers,
        capture.get("execution_mode"),
        EXPECTED_EXECUTION_MODE,
        "capture execution mode",
    )
    core = capture.get("cryptographic_core")
    if not isinstance(core, dict):
        blockers.append("cryptographic_core missing")
        return
    check_equal(blockers, core.get("core_mode"), EXPECTED_CORE_MODE, "core mode")
    check_equal(
        blockers,
        core.get("signature_origin"),
        EXPECTED_SIGNATURE_ORIGIN,
        "signature origin",
    )
    for field in REQUIRED_TRUE_CORE_CHECKS:
        require_true(blockers, core, field, "cryptographic core check")
    for field in EVIDENCE_BOUND_CORE_CHECKS:
        if not isinstance(core.get(field), bool):
            blockers.append(f"cryptographic core evidence-bound field must be boolean: {field}")
    validate_capability_evidence(core, evidence_roles, evidence_base, blockers)
    check_equal(
        blockers,
        core.get("authorization_layer_validator_count"),
        10_000,
        "cryptographic core authorization validator count",
    )
    check_equal(
        blockers,
        core.get("authorization_layer_threshold"),
        6_667,
        "cryptographic core authorization threshold",
    )
    for field in (
        "simulation_used",
        "fixture_harness_used",
        "single_key_provider_used",
        "secret_or_seed_reconstruction_used",
        "centralized_signing_oracle_used",
    ):
        require_false(blockers, core, field, "cryptographic core exclusion")


def validate_capability_evidence(core, evidence_roles, evidence_base, blockers):
    binding = core.get("digest_bound_capability_evidence")
    if not isinstance(binding, dict):
        blockers.append("digest-bound DKG/custody capability evidence missing")
        return
    check_equal(
        blockers,
        binding.get("schema"),
        CAPABILITY_EVIDENCE_BINDING_SCHEMA,
        "DKG/custody capability evidence binding schema",
    )
    check_equal(
        blockers,
        binding.get("evidence_file_role"),
        CAPABILITY_EVIDENCE_ROLE,
        "DKG/custody capability evidence role",
    )
    fields = binding.get("capability_fields")
    if fields != list(EVIDENCE_BOUND_CORE_CHECKS):
        blockers.append("DKG/custody capability evidence fields mismatch")
    for field in ("evidence_file_digest_hex", "aggregate_evidence_digest_hex"):
        if not is_digest(binding.get(field)):
            blockers.append(f"DKG/custody capability evidence digest invalid: {field}")

    record = evidence_roles.get(CAPABILITY_EVIDENCE_ROLE)
    if not isinstance(record, dict):
        blockers.append("DKG/custody capability evidence file role missing")
        return
    if binding.get("evidence_file_digest_hex") != record.get("sha256"):
        blockers.append("DKG/custody capability evidence file digest binding mismatch")
    path_value = record.get("path")
    if not isinstance(path_value, str):
        blockers.append("DKG/custody capability evidence path missing")
        return
    pure_path = PurePosixPath(path_value)
    if pure_path.is_absolute() or ".." in pure_path.parts:
        blockers.append("DKG/custody capability evidence path is not safely contained")
        return
    evidence_path = Path(evidence_base) / Path(*pure_path.parts)
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        blockers.append("DKG/custody capability evidence is not valid UTF-8 JSON")
        return

    check_equal(
        blockers,
        evidence.get("schema"),
        CAPABILITY_EVIDENCE_SCHEMA,
        "DKG/custody capability evidence schema",
    )
    if evidence.get("capability_fields") != list(EVIDENCE_BOUND_CORE_CHECKS):
        blockers.append("DKG/custody capability evidence file fields mismatch")
    check_equal(
        blockers,
        evidence.get("aggregate_evidence_digest_hex"),
        binding.get("aggregate_evidence_digest_hex"),
        "DKG/custody aggregate evidence binding",
    )
    if not is_digest(evidence.get("aggregate_evidence_digest_hex")):
        blockers.append("DKG/custody aggregate evidence digest invalid")

    source_digests = evidence.get("source_digests")
    if not isinstance(source_digests, list) or not source_digests:
        blockers.append("DKG/custody capability source digests missing")
        source_digests = []
    for source in source_digests:
        if not isinstance(source, dict):
            blockers.append("DKG/custody capability source digest record must be an object")
            continue
        path = source.get("path")
        digest = source.get("sha256")
        if not isinstance(path, str) or not path:
            blockers.append("DKG/custody capability source path missing")
            continue
        if not is_digest(digest):
            blockers.append("DKG/custody capability source digest invalid")
            continue
        source_path = Path(path)
        if not source_path.is_file():
            blockers.append(f"DKG/custody capability source file missing: {path}")
            continue
        if sha256_path(source_path) != digest:
            blockers.append(f"DKG/custody capability source digest mismatch: {path}")

    statuses = evidence.get("capability_statuses")
    if not isinstance(statuses, dict):
        blockers.append("DKG/custody capability statuses missing")
        return
    if sorted(statuses) != sorted(EVIDENCE_BOUND_CORE_CHECKS):
        blockers.append("DKG/custody capability statuses do not match required fields")
    for field in EVIDENCE_BOUND_CORE_CHECKS:
        status = statuses.get(field)
        if not isinstance(status, dict):
            blockers.append(f"DKG/custody capability status missing: {field}")
            continue
        check_equal(blockers, status.get("field"), field, f"DKG/custody capability status field {field}")
        check_equal(
            blockers,
            status.get("claim_value"),
            core.get(field),
            f"DKG/custody capability claim binding {field}",
        )
        if not isinstance(status.get("status"), str) or not status.get("status"):
            blockers.append(f"DKG/custody capability status label missing: {field}")
        if not is_digest(status.get("evidence_digest_hex")):
            blockers.append(f"DKG/custody capability evidence digest invalid: {field}")
        status_sources = status.get("source_digests")
        if not isinstance(status_sources, list) or not status_sources:
            blockers.append(f"DKG/custody capability status source digests missing: {field}")
        elif any(
            not isinstance(item, dict) or not is_digest(item.get("sha256"))
            for item in status_sources
        ):
            blockers.append(f"DKG/custody capability status source digest invalid: {field}")
        if core.get(field) is False:
            counter = status.get("counter_evidence")
            if not isinstance(counter, list) or not counter:
                blockers.append(f"DKG/custody false capability lacks counter-evidence: {field}")
        status_without_digest = dict(status)
        status_without_digest.pop("evidence_digest_hex", None)
        if is_digest(status.get("evidence_digest_hex")) and sha256_text(
            canonical_json(status_without_digest)
        ) != status.get("evidence_digest_hex"):
            blockers.append(f"DKG/custody capability status digest mismatch: {field}")

    aggregate_input = {
        "schema": CAPABILITY_EVIDENCE_SCHEMA,
        "source_digests": source_digests,
        "capability_statuses": statuses,
    }
    if is_digest(evidence.get("aggregate_evidence_digest_hex")) and sha256_text(
        canonical_json(aggregate_input)
    ) != evidence.get("aggregate_evidence_digest_hex"):
        blockers.append("DKG/custody aggregate evidence digest mismatch")


def validate_authorization(
    request,
    capture,
    evidence_roles,
    evidence_base,
    blockers,
    authorization_verifier=None,
):
    """Parse threshold authorization records and verify them through a reviewed callback."""
    authorization = capture.get("authorization")
    verification = {
        "required": True,
        "verified": False,
        "verifier_id": None,
        "verifier_implementation_sha256": None,
    }
    if not isinstance(authorization, dict):
        blockers.append("threshold authorization record missing")
        return None, verification
    check_equal(
        blockers,
        authorization.get("schema"),
        "lattice-aggregation:threshold-authorization-certificate:v1",
        "authorization certificate schema",
    )
    check_equal(blockers, authorization.get("validator_count"), 10_000, "authorization validator count")
    check_equal(blockers, authorization.get("threshold"), 6_667, "authorization threshold")
    for field in (
        "authorized_validator_set_digest_hex",
        "committee_authorization_bundle_digest_hex",
        "authorization_transcript_digest_hex",
        "certificate_digest_hex",
    ):
        if not is_digest(authorization.get(field)):
            blockers.append(f"authorization digest invalid: {field}")
    record = evidence_roles.get("authorization_certificate")
    if isinstance(record, dict) and authorization.get("certificate_digest_hex") != record.get("sha256"):
        blockers.append("authorization certificate evidence digest mismatch")
    if not isinstance(record, dict) or not isinstance(record.get("path"), str):
        blockers.append("authorization certificate evidence record unavailable for parsing")
        blockers.append(
            "cryptographic authorization signature verification unavailable; campaign remains fail closed"
        )
        return authorization.get("certificate_digest_hex"), verification

    certificate_relative_path = PurePosixPath(record["path"])
    if certificate_relative_path.is_absolute() or ".." in certificate_relative_path.parts:
        blockers.append("authorization certificate path is not safely contained")
        blockers.append(
            "cryptographic authorization signature verification unavailable; campaign remains fail closed"
        )
        return authorization.get("certificate_digest_hex"), verification
    certificate_path = evidence_base / Path(*certificate_relative_path.parts)
    try:
        certificate = json.loads(certificate_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        blockers.append("authorization certificate is not valid UTF-8 JSON")
        blockers.append(
            "cryptographic authorization signature verification unavailable; campaign remains fail closed"
        )
        return authorization.get("certificate_digest_hex"), verification

    check_equal(
        blockers,
        certificate.get("schema"),
        "lattice-aggregation:threshold-authorization-certificate:v1",
        "parsed authorization certificate schema",
    )
    check_equal(
        blockers,
        certificate.get("campaign_id"),
        request.get("campaign_id"),
        "authorization campaign binding",
    )
    check_equal(
        blockers,
        certificate.get("request_sha256"),
        sha256_text(canonical_json(request)),
        "authorization request binding",
    )
    check_equal(blockers, certificate.get("validator_count"), 10_000, "certificate validator count")
    check_equal(blockers, certificate.get("threshold"), 6_667, "certificate threshold")

    validator_ids = certificate.get("validator_ids")
    expected_validator_ids = list(range(1, 10_001))
    if validator_ids != expected_validator_ids:
        blockers.append("authorization certificate validator_ids must be canonical 1..10000")
        validator_set = set()
    else:
        validator_set = set(validator_ids)
    validator_set_digest = sha256_text(canonical_json(validator_ids))
    check_equal(
        blockers,
        certificate.get("validator_set_digest_hex"),
        validator_set_digest,
        "certificate validator set digest",
    )
    check_equal(
        blockers,
        authorization.get("authorized_validator_set_digest_hex"),
        validator_set_digest,
        "capture/certificate validator set digest binding",
    )

    committee_records = certificate.get("committee_authorizations")
    if not isinstance(committee_records, list):
        blockers.append("authorization certificate committee_authorizations must be a list")
        committee_records = []
    by_size = {}
    for committee in committee_records:
        if not isinstance(committee, dict):
            blockers.append("authorization committee record must be an object")
            continue
        size = committee.get("committee_size")
        if not isinstance(size, int) or isinstance(size, bool):
            blockers.append("authorization committee size must be an integer")
            continue
        if size in by_size:
            blockers.append(f"duplicate authorization committee size: {size}")
        by_size[size] = committee

    request_digest = sha256_text(canonical_json(request))
    for size in (8, 16, 32, 64):
        committee = by_size.get(size)
        if not isinstance(committee, dict):
            blockers.append(f"authorization committee record missing: {size}")
            continue
        committee_ids = committee.get("committee_validator_ids")
        if (
            not isinstance(committee_ids, list)
            or len(committee_ids) != size
            or any(not isinstance(validator_id, int) or isinstance(validator_id, bool) for validator_id in committee_ids)
            or len(set(committee_ids)) != size
            or any(validator_id not in validator_set for validator_id in committee_ids)
        ):
            blockers.append(f"authorization committee membership invalid: {size}")
            committee_ids = []
        committee_digest = sha256_text(canonical_json(committee_ids))
        check_equal(
            blockers,
            committee.get("committee_digest_hex"),
            committee_digest,
            f"authorization committee digest {size}",
        )
        expected_session_binding = sha256_text(
            canonical_json(
                {
                    "campaign_id": request.get("campaign_id"),
                    "request_sha256": request_digest,
                    "committee_size": size,
                    "committee_digest_hex": committee_digest,
                }
            )
        )
        check_equal(
            blockers,
            committee.get("session_binding_digest_hex"),
            expected_session_binding,
            f"authorization session binding {size}",
        )
        authorizers = committee.get("authorizer_records")
        if not isinstance(authorizers, list):
            blockers.append(f"authorization authorizer records missing: {size}")
            continue
        authorizer_ids = []
        for authorizer in authorizers:
            if not isinstance(authorizer, dict):
                blockers.append(f"authorization record must be an object: {size}")
                continue
            validator_id = authorizer.get("validator_id")
            if not isinstance(validator_id, int) or isinstance(validator_id, bool):
                blockers.append(f"authorization validator id invalid: {size}")
            else:
                authorizer_ids.append(validator_id)
            if validator_id not in validator_set:
                blockers.append(f"authorization record outside validator set: {size}")
            for field in ("public_key_digest_hex", "signature_digest_hex"):
                if not is_digest(authorizer.get(field)):
                    blockers.append(f"authorization record digest invalid ({field}): {size}")
            try:
                signature = bytes.fromhex(authorizer.get("signature_hex", ""))
            except (TypeError, ValueError):
                signature = b""
            if not signature:
                blockers.append(f"authorization signature bytes missing: {size}")
            elif sha256_bytes(signature) != authorizer.get("signature_digest_hex"):
                blockers.append(f"authorization signature digest mismatch: {size}")
        if len(authorizer_ids) < 6_667 or len(set(authorizer_ids)) != len(authorizer_ids):
            blockers.append(f"authorization requires 6667 unique in-set records: {size}")

    if set(by_size) != {8, 16, 32, 64}:
        blockers.append("authorization committee ladder must be exactly 8,16,32,64")
    committee_bundle_digest = sha256_text(canonical_json(committee_records))
    check_equal(
        blockers,
        authorization.get("committee_authorization_bundle_digest_hex"),
        committee_bundle_digest,
        "capture/certificate committee bundle digest binding",
    )
    check_equal(
        blockers,
        authorization.get("authorization_transcript_digest_hex"),
        certificate.get("authorization_transcript_digest_hex"),
        "capture/certificate authorization transcript binding",
    )

    # A byte/digest check is not cryptographic signature verification. Promotion
    # requires a reviewed verifier whose identity and implementation digest were
    # bound into the preregistered request.  Tests may inject the same interface;
    # the production CLI deliberately supplies no callback and therefore remains
    # fail closed until the reviewed implementation lands.
    requested = request.get("capture_requirements", {}).get(
        "authorization_certificate", {}
    )
    if authorization_verifier is None:
        blockers.append(
            "cryptographic authorization signature verification unavailable; campaign remains fail closed"
        )
    else:
        verifier_id = getattr(authorization_verifier, "verifier_id", None)
        implementation_sha256 = getattr(
            authorization_verifier, "implementation_sha256", None
        )
        if (
            not isinstance(requested, dict)
            or requested.get("cryptographic_verifier_status") != "reviewed_ready"
            or requested.get("verifier_id") != verifier_id
            or requested.get("verifier_implementation_sha256")
            != implementation_sha256
            or not isinstance(verifier_id, str)
            or not verifier_id
            or not is_digest(implementation_sha256)
        ):
            blockers.append(
                "authorization verifier is not exactly bound into the preregistered request"
            )
        else:
            try:
                verified = authorization_verifier(certificate, request)
            except Exception as error:  # fail closed at the external verifier boundary
                blockers.append(
                    "cryptographic authorization verifier failed: "
                    f"{type(error).__name__}"
                )
                verified = False
            if verified is not True:
                blockers.append(
                    "cryptographic authorization signature verification failed"
                )
            else:
                verification = {
                    "required": True,
                    "verified": True,
                    "verifier_id": verifier_id,
                    "verifier_implementation_sha256": implementation_sha256,
                }
    return authorization.get("certificate_digest_hex"), verification


def load_authorization_verifier(name):
    if name is None:
        return None
    if name not in {
        "ed25519-v1",
        "reviewed-ed25519-threshold-authorization-v1",
    }:
        raise ValueError(f"unsupported authorization verifier: {name}")
    path = Path(__file__).with_name("threshold_authorization_verifier.py")
    spec = importlib.util.spec_from_file_location(
        "threshold_authorization_verifier_for_campaign_validator", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("threshold authorization verifier module is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Ed25519ThresholdAuthorizationVerifier()


def validate_kat(capture, evidence_roles, blockers):
    verifier = capture.get("standard_verifier")
    if not isinstance(verifier, dict):
        blockers.append("standard_verifier record missing")
    else:
        check_equal(
            blockers,
            verifier.get("implementation_kind"),
            "unmodified_mldsa65_standard_verifier",
            "standard verifier implementation kind",
        )
        check_equal(blockers, verifier.get("parameter_set"), "ML-DSA-65", "verifier parameter set")
        if not is_digest(verifier.get("implementation_digest_hex")):
            blockers.append("standard verifier implementation digest invalid")
        record = evidence_roles.get("standard_verifier_binary")
        if isinstance(record, dict) and verifier.get("implementation_digest_hex") != record.get("sha256"):
            blockers.append("standard verifier binary digest binding mismatch")

    kat = capture.get("kat_validation")
    if not isinstance(kat, dict):
        blockers.append("kat_validation record missing")
        return
    check_equal(blockers, kat.get("parameter_set"), "ML-DSA-65", "KAT parameter set")
    vector_types = kat.get("vector_types")
    if not isinstance(vector_types, list) or any(not isinstance(value, str) for value in vector_types):
        blockers.append("KAT vector types must be a string list")
    else:
        check_equal(
            blockers,
            sorted(vector_types),
            ["keyGen", "sigGen", "sigVer"],
            "KAT vector types",
        )
    vector_count = kat.get("vector_count")
    if not isinstance(vector_count, int) or isinstance(vector_count, bool) or vector_count < 1:
        blockers.append("KAT vector_count must be at least one")
    if kat.get("failed_vector_count") != 0:
        blockers.append("KAT failed_vector_count must be zero")
    if kat.get("passed_vector_count") != vector_count:
        blockers.append("KAT passed_vector_count must equal vector_count")
    if not is_digest(kat.get("vector_source_digest_hex")):
        blockers.append("KAT vector source digest invalid")
    record = evidence_roles.get("kat_results")
    if isinstance(record, dict) and kat.get("results_digest_hex") != record.get("sha256"):
        blockers.append("KAT results digest binding mismatch")


def validate_execution(case, execution, authorization_digest, blockers):
    label = f"case {case.get('case_id')}"
    for field in (
        "case_id",
        "case_kind",
        "validator_count",
        "threshold",
        "committee_size",
        "seed_id",
        "seed_sha256",
    ):
        check_equal(blockers, execution.get(field), case.get(field), f"{label} {field}")
    check_equal(
        blockers,
        execution.get("message_sha256"),
        case.get("message", {}).get("sha256"),
        f"{label} message digest",
    )
    if not is_digest(execution.get("transcript_digest_hex")):
        blockers.append(f"{label} transcript digest invalid")
    check_equal(
        blockers,
        execution.get("authorization_certificate_digest_hex"),
        authorization_digest,
        f"{label} authorization certificate binding",
    )

    required = case.get("required_observations", {})
    check_equal(
        blockers,
        execution.get("protocol_outcome"),
        required.get("protocol_outcome"),
        f"{label} protocol outcome",
    )
    check_equal(
        blockers,
        execution.get("aggregate_emitted"),
        required.get("aggregate_emitted"),
        f"{label} aggregate emission",
    )
    retry_count = execution.get("retry_count")
    if not isinstance(retry_count, int) or isinstance(retry_count, bool) or retry_count < required.get("retry_count_min", 0):
        blockers.append(f"{label} retry count below preregistered minimum")
    for field in (
        "rejection_predicate_recorded",
        "abort_recorded",
        "malicious_share_rejected",
        "transcript_mutation_rejected",
    ):
        check_equal(
            blockers,
            execution.get(field),
            required.get(field),
            f"{label} {field}",
        )

    verifier = execution.get("standard_verifier")
    if not isinstance(verifier, dict):
        blockers.append(f"{label} standard verifier observation missing")
        return
    check_equal(
        blockers,
        verifier.get("invoked"),
        required.get("standard_verifier_invoked"),
        f"{label} standard verifier invocation",
    )
    check_equal(
        blockers,
        verifier.get("accepted"),
        required.get("standard_verifier_accepted"),
        f"{label} standard verifier result",
    )
    if required.get("aggregate_emitted"):
        check_equal(blockers, execution.get("aggregate_signature_len"), 3309, f"{label} signature length")
        if not is_digest(execution.get("aggregate_signature_digest_hex")):
            blockers.append(f"{label} aggregate signature digest invalid")
        mutations = verifier.get("mutation_rejection")
        for mutation in ("message", "public_key", "signature"):
            require_true(blockers, mutations, mutation, f"{label} verifier mutation rejection")
    else:
        if execution.get("aggregate_signature_len") is not None:
            blockers.append(f"{label} must not report aggregate signature length")
        if execution.get("aggregate_signature_digest_hex") is not None:
            blockers.append(f"{label} must not report aggregate signature digest")


def validate_campaign(request, capture, evidence_base, authorization_verifier=None):
    """Validate a capture and return a non-promotional fail-closed report."""
    blockers = validate_request(request)
    check_equal(blockers, capture.get("schema"), CAPTURE_SCHEMA, "capture schema")
    check_equal(blockers, capture.get("campaign_id"), request.get("campaign_id"), "campaign id")
    binding = capture.get("request_binding")
    if not isinstance(binding, dict):
        blockers.append("capture request binding missing")
    else:
        check_equal(blockers, binding.get("schema"), REQUEST_SCHEMA, "request binding schema")
        check_equal(
            blockers,
            binding.get("request_sha256"),
            sha256_text(canonical_json(request)),
            "request binding digest",
        )
    for flag in CLAIM_FLAGS:
        require_false(blockers, capture.get("claim_flags"), flag, "capture claim flag")

    evidence_roles = validate_evidence_files(capture, Path(evidence_base), blockers)
    validate_core(capture, evidence_roles, Path(evidence_base), blockers)
    validate_provenance(capture, evidence_roles, blockers)
    authorization_digest, authorization_verification = validate_authorization(
        request,
        capture,
        evidence_roles,
        Path(evidence_base),
        blockers,
        authorization_verifier=authorization_verifier,
    )
    validate_kat(capture, evidence_roles, blockers)

    executions = capture.get("executions")
    if not isinstance(executions, list):
        blockers.append("capture executions must be a list")
        executions = []
    by_id = {}
    for execution in executions:
        if not isinstance(execution, dict):
            blockers.append("capture execution must be an object")
            continue
        case_id = execution.get("case_id")
        if not isinstance(case_id, str):
            blockers.append("capture execution case_id must be a string")
            continue
        if case_id in by_id:
            blockers.append(f"duplicate capture execution: {case_id}")
        by_id[case_id] = execution
    request_cases = request.get("cases")
    if not isinstance(request_cases, list):
        request_cases = []
    expected_ids = {
        case.get("case_id") for case in request_cases if isinstance(case, dict)
    }
    if set(by_id) != expected_ids:
        blockers.append("capture executions do not exactly match preregistered cases")
    for case in request_cases:
        if not isinstance(case, dict):
            continue
        execution = by_id.get(case.get("case_id"))
        if execution is not None:
            validate_execution(case, execution, authorization_digest, blockers)

    blockers = sorted(set(blockers))
    ready = len(blockers) == 0
    evidence_bindings = {
        role: record.get("sha256")
        for role, record in sorted(evidence_roles.items())
        if isinstance(record, dict)
    }
    capture_sha256 = sha256_text(canonical_json(capture))
    bundle_binding = {
        "request_sha256": sha256_text(canonical_json(request)),
        "capture_sha256": capture_sha256,
        "evidence_bindings": evidence_bindings,
    }
    report = {
        "schema": REPORT_SCHEMA,
        "request_schema": REQUEST_SCHEMA,
        "capture_schema": CAPTURE_SCHEMA,
        "campaign_id": request.get("campaign_id"),
        "campaign_status": READY_STATUS if ready else BLOCKED_STATUS,
        "internal_campaign_evidence_ready": ready,
        "theorem_status": THEOREM_STATUS,
        "claims_theorem_closure": False,
        "claims_fips_validation": False,
        "request_sha256": sha256_text(canonical_json(request)),
        "capture_sha256": capture_sha256,
        "evidence_bundle_binding_sha256": sha256_text(canonical_json(bundle_binding)),
        "evidence_bindings": evidence_bindings,
        "artifact_contract": request.get("artifact_contract"),
        "preregistered_case_count": len(request_cases),
        "validated_execution_count": len(executions),
        "authorization_verification": authorization_verification,
        "blockers": blockers,
    }
    authenticated_material = dict(report)
    report["validator_authentication"] = {
        "method": "deterministic_revalidation",
        "validator_implementation_sha256": sha256_path(Path(__file__)),
        "report_sha256": sha256_text(canonical_json(authenticated_material)),
    }
    return report


def render_summary(report):
    lines = [
        "# Internal Aggregation Campaign Validation",
        "",
        f"- Campaign: `{report['campaign_id']}`",
        f"- Campaign status: `{report['campaign_status']}`",
        f"- Theorem status: `{report['theorem_status']}`",
        f"- Validated executions: `{report['validated_execution_count']}` / `{report['preregistered_case_count']}`",
        "- Claims theorem closure: `false`",
        "- Claims FIPS validation: `false`",
        "",
    ]
    if report["blockers"]:
        lines.extend(["## Blockers", ""])
        lines.extend(f"- {blocker}" for blocker in report["blockers"])
        lines.append("")
    else:
        lines.extend(
            [
                "All preregistered campaign evidence gates passed. This promotes only",
                "the internal campaign evidence package; theorem and certification claims",
                "remain closed pending proof review and independent validation.",
                "",
            ]
        )
    return "\n".join(lines)


def write_report(report, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = {
        "manifest.json": canonical_json(report),
        "validation-summary.md": render_summary(report),
    }
    contents["validation-SHA256SUMS"] = "".join(
        f"{sha256_text(contents[name])}  {name}\n" for name in sorted(contents)
    )
    for name, content in contents.items():
        (out_dir / name).write_text(content, encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Validate an actual internal aggregation campaign capture"
    )
    parser.add_argument("--root", default=".", help="repository root for relative paths")
    parser.add_argument("--request", default=DEFAULT_REQUEST_PATH)
    parser.add_argument("--capture", default=DEFAULT_CAPTURE_PATH)
    parser.add_argument(
        "--evidence-base",
        default=None,
        help="directory containing capture-relative evidence files; defaults to capture directory",
    )
    parser.add_argument(
        "--authorization-verifier",
        default=None,
        help="reviewed verifier adapter to use for threshold authorization signatures",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit nonzero unless the capture is campaign-evidence ready",
    )
    parser.add_argument("--out", default=DEFAULT_VALIDATION_OUT)
    return parser.parse_args(argv)


def resolve_path(root, value):
    path = Path(value)
    return path if path.is_absolute() else Path(root) / path


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    root = Path(args.root)
    request_path = resolve_path(root, args.request)
    try:
        request = json.loads(request_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        report = {
            "schema": REPORT_SCHEMA,
            "request_schema": REQUEST_SCHEMA,
            "capture_schema": CAPTURE_SCHEMA,
            "campaign_id": None,
            "campaign_status": BLOCKED_STATUS,
            "internal_campaign_evidence_ready": False,
            "theorem_status": THEOREM_STATUS,
            "claims_theorem_closure": False,
            "claims_fips_validation": False,
            "request_sha256": None,
            "capture_sha256": None,
            "evidence_bundle_binding_sha256": None,
            "evidence_bindings": {},
            "artifact_contract": None,
            "preregistered_case_count": 0,
            "validated_execution_count": 0,
            "blockers": [f"campaign request unavailable or invalid: {type(exc).__name__}"],
        }
        write_report(report, resolve_path(root, args.out))
        print(f"campaign_status={report['campaign_status']}")
        print(f"blockers={len(report['blockers'])}")
        return 2
    if not isinstance(request, dict):
        request = {}
    capture_path = resolve_path(root, args.capture)
    try:
        capture = json.loads(capture_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        report = {
            "schema": REPORT_SCHEMA,
            "request_schema": REQUEST_SCHEMA,
            "capture_schema": CAPTURE_SCHEMA,
            "campaign_id": request.get("campaign_id"),
            "campaign_status": BLOCKED_STATUS,
            "internal_campaign_evidence_ready": False,
            "theorem_status": THEOREM_STATUS,
            "claims_theorem_closure": False,
            "claims_fips_validation": False,
            "request_sha256": sha256_text(canonical_json(request)),
            "capture_sha256": None,
            "evidence_bundle_binding_sha256": None,
            "evidence_bindings": {},
            "artifact_contract": request.get("artifact_contract"),
            "preregistered_case_count": len(request.get("cases", [])),
            "validated_execution_count": 0,
            "blockers": [f"campaign capture unavailable or invalid: {type(exc).__name__}"],
        }
        write_report(report, resolve_path(root, args.out))
        print(f"campaign_status={report['campaign_status']}")
        print(f"blockers={len(report['blockers'])}")
        return 2
    if not isinstance(capture, dict):
        capture = {}
    evidence_base = (
        resolve_path(root, args.evidence_base)
        if args.evidence_base is not None
        else capture_path.parent
    )
    try:
        authorization_verifier = load_authorization_verifier(args.authorization_verifier)
    except (RuntimeError, ValueError) as exc:
        report = {
            "schema": REPORT_SCHEMA,
            "request_schema": REQUEST_SCHEMA,
            "capture_schema": CAPTURE_SCHEMA,
            "campaign_id": request.get("campaign_id"),
            "campaign_status": BLOCKED_STATUS,
            "internal_campaign_evidence_ready": False,
            "theorem_status": THEOREM_STATUS,
            "claims_theorem_closure": False,
            "claims_fips_validation": False,
            "request_sha256": sha256_text(canonical_json(request)),
            "capture_sha256": sha256_text(canonical_json(capture)),
            "evidence_bundle_binding_sha256": None,
            "evidence_bindings": {},
            "artifact_contract": request.get("artifact_contract"),
            "preregistered_case_count": len(request.get("cases", [])),
            "validated_execution_count": 0,
            "authorization_verification": {
                "required": True,
                "verified": False,
                "verifier_id": args.authorization_verifier,
                "verifier_implementation_sha256": None,
            },
            "blockers": [
                "authorization verifier unavailable: " + type(exc).__name__
            ],
        }
    else:
        report = validate_campaign(
            request,
            capture,
            evidence_base,
            authorization_verifier=authorization_verifier,
        )
    write_report(report, resolve_path(root, args.out))
    print(f"campaign_status={report['campaign_status']}")
    print(f"blockers={len(report['blockers'])}")
    return 0 if report["internal_campaign_evidence_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
