#!/usr/bin/env python3
"""Run the fail-closed real 6,667-of-10,000 ML-DSA campaign.

The runner never manufactures enrollment, custody, signer, verifier, or
adversarial evidence. It launches the configured backend only after every
prerequisite is present, digest-bound, and structurally valid.
"""

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


SCHEMA = "lattice-aggregation:real-6667-of-10000-mldsa-campaign-evidence:v1"
PREREQUISITE_SCHEMA = "lattice-aggregation:real-6667-of-10000-mldsa-campaign-prerequisites:v1"
ENROLLMENT_SCHEMA = "lattice-aggregation:production-enrollment-registry:v1"
CUSTODY_SCHEMA = "lattice-aggregation:production-custody-registry:v1"
CAPTURE_SCHEMA = "lattice-aggregation:real-6667-of-10000-mldsa-campaign-capture:v1"
CAPABILITY_SCHEMA = "lattice-aggregation:real-6667-of-10000-mldsa-capability-evidence:v1"
VALIDATOR_COUNT = 10_000
THRESHOLD = 6_667
PARAMETER_SET = "ML-DSA-65"
PUBLIC_KEY_BYTES = 1_952
SIGNATURE_BYTES = 3_309
DEFAULT_PREREQUISITES = "artifacts/real-6667-of-10000-mldsa-campaign/prerequisites.json"
DEFAULT_OUT = "artifacts/real-6667-of-10000-mldsa-campaign/latest"
DEFAULT_SIBLING_BACKEND_ROOT = "/Users/rickglenn/Documents/lattice-threshold-backend-p1"
KNOWN_DKG_CUSTODY_CAPTURE = "artifacts/p1-dkg-custody-capture/latest/capture.json"
KNOWN_MAMA_CAPTURE = "artifacts/exact-distributed-expandmask-mpc/mama-equivalence-latest/manifest.json"
KNOWN_REJECTED_CAMPAIGN = "artifacts/internal-aggregation-campaign-run/latest/rejected-validation.json"
CLAIM_BOUNDARY = (
    "real campaign orchestration evidence only; production security and theorem "
    "closure require the separate DKG, custody, malicious-MPC, equivalence, "
    "security, and theorem-linkage review gates"
)
FORBIDDEN_COMMAND_TOKENS = (
    "fixture",
    "simulation",
    "simulated",
    "single-key",
    "single_key",
    "smoke",
    "seed-reconstruction",
    "seed_reconstruction",
)
FORBIDDEN_CAPABILITY_EVIDENCE_TOKENS = (
    "simulation",
    "simulated",
    "fixture",
    "count-only",
    "count_only",
    "count only",
    "smoke",
    "single-key",
    "single_key",
)
PROTOCOL_NEGATIVE_CHECKS = (
    "malicious_partial",
    "duplicate_signer",
    "below_threshold",
    "transcript_replay",
)
CAPABILITY_GATES = (
    "real_mldsa_partial_signing",
    "no_secret_reconstruction",
    "standards_verifier",
    "negative_adversarial_checks",
)


def canonical_json(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_path(path):
    path = Path(path)
    return sha256_bytes(path.read_bytes()) if path.is_file() else None


def is_sha256(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and value != "0" * 64
        and all(character in "0123456789abcdef" for character in value)
    )


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def blocker(code, field, expected, observed, evidence_path, message):
    return {
        "code": code,
        "field": field,
        "expected": expected,
        "observed": observed,
        "evidence_path": str(evidence_path) if evidence_path is not None else None,
        "message": message,
    }


def find_values(value, wanted_key, prefix=""):
    matches = []
    if isinstance(value, dict):
        for key, child in value.items():
            location = f"{prefix}.{key}" if prefix else key
            if key == wanted_key:
                matches.append((location, child))
            matches.extend(find_values(child, wanted_key, location))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            matches.extend(find_values(child, wanted_key, f"{prefix}[{index}]"))
    return matches


def first_value(document, key, default=None):
    matches = find_values(document, key)
    return matches[0][1] if matches else default


def detect_engineering_interfaces(repository_root, sibling_backend_root):
    """Recognize source-level integration seams without promoting runtime gates."""
    specifications = {
        "additive_mask_signing_seam": {
            "source": repository_root / "src/backend/fips_sign.rs",
            "markers": {
                "exact_mpc_mask_input_type": "pub struct AdditiveMaskAttempt65",
                "exact_mpc_signing_entrypoint": (
                    "pub fn strict_distributed_sign_from_additive_mask_outputs"
                ),
                "signing_set_lagrange_weights": "pub fn signing_set_lagrange_weights",
                "signer_partial_emission": "pub fn emit_additive_mask_partial",
                "plain_sum_partial_aggregation": "pub fn aggregate_additive_mask_partials",
                "standard_wire_mode": (
                    "exact_mpc_additive_y_partials_to_fips204_wire_signature"
                ),
            },
            "remaining_requirements": [
                "bind supplied mask shares to a live 6,667-party malicious MAMA execution",
                "consume dealerless-DKG K/s1/s2 shares through attested custody handles",
                "capture 6,667 distinct real custodial partials and independently verify the aggregate",
            ],
        },
        "dealerless_dkg": {
            "source": sibling_backend_root / "src/dealerless_dkg.rs",
            "markers": {
                "participant_limit_10000": "pub const MAX_DKG_PARTICIPANTS: usize = 10_000",
                "commitment_transcript_builder": "pub fn build_commitment_transcript",
                "dealerless_finalization": "pub fn finalize_dealerless_dkg",
                "k_s1_s2_commitment_binding": (
                    "signer_specific_k_s1_s2_share_commitments_bound"
                ),
                "no_trusted_dealer_record": '"trusted_dealer_present": false',
                "live_execution_claim_false": (
                    '"claims_live_multi_host_dkg_completed": false'
                ),
            },
            "remaining_requirements": [
                "execute the 10,000-participant, 6,667-threshold ceremony across real hosts",
                "use production VSS verification and production custody trust roots",
                "bind finalized shares to the real partial-signing execution",
            ],
        },
        "private_share_custody": {
            "source": sibling_backend_root / "src/private_share_custody.rs",
            "markers": {
                "opaque_share_handle": "pub struct OpaqueShareHandle",
                "no_export_provider_interface": "pub trait PrivateShareCustodyProvider",
                "attestation_verifier_interface": "pub trait CustodyAttestationVerifier",
                "receipt_validation": "pub fn validate_custody_receipt",
                "production_policy_predicate": "pub fn production_eligible(self) -> bool",
                "k_share_commitment": "expand_mask_k_share",
            },
            "remaining_requirements": [
                "deploy production custody providers backed by configured trust roots",
                "collect 6,667 valid non-exportable custody attestations",
                "prove the signing path consumes only custody-held shares",
            ],
        },
    }
    detected = {}
    for interface_id, specification in specifications.items():
        source = Path(specification["source"]).resolve(strict=False)
        try:
            source_text = source.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            source_text = ""
        marker_checks = {
            marker_id: marker in source_text
            for marker_id, marker in specification["markers"].items()
        }
        implemented = source.is_file() and all(marker_checks.values())
        detected[interface_id] = {
            "status": (
                "implemented_engineering_interface_not_production_complete"
                if implemented
                else "engineering_interface_not_detected"
            ),
            "implemented": implemented,
            "recognition_basis": "source_interface_markers_and_digest_only",
            "source": {
                "path": str(source),
                "sha256": sha256_path(source),
            },
            "marker_checks": marker_checks,
            "runtime_execution_evidence_present": False,
            "production_complete": False,
            "claims_production_complete": False,
            "remaining_requirements": specification["remaining_requirements"],
        }
    return detected


def known_repository_blockers(repository_root):
    """Translate current reduced-scale evidence into explicit preflight failures."""
    blockers = []
    dkg_path = repository_root / KNOWN_DKG_CUSTODY_CAPTURE
    if dkg_path.is_file():
        try:
            dkg = load_json(dkg_path)
        except (OSError, ValueError) as error:
            blockers.append(
                blocker(
                    "dkg_custody.capture_unreadable",
                    None,
                    "parseable JSON evidence",
                    str(error),
                    dkg_path,
                    "DKG/custody capture could not be parsed",
                )
            )
        else:
            executed_validators = first_value(dkg, "executed_validator_count", 8)
            executed_threshold = first_value(dkg, "executed_threshold", 6)
            blockers.extend(
                [
                    blocker(
                        "dkg_custody.execution_scale_insufficient",
                        "executed_validator_count/executed_threshold",
                        {"validator_count": VALIDATOR_COUNT, "threshold": THRESHOLD},
                        {
                            "validator_count": executed_validators,
                            "threshold": executed_threshold,
                        },
                        dkg_path,
                        "DKG/custody evidence was executed only at reduced scale",
                    ),
                    blocker(
                        "dkg_custody.production_profile_not_executed",
                        "production_profile_executed",
                        True,
                        first_value(dkg, "production_profile_executed", False),
                        dkg_path,
                        "Production DKG/custody profile has not been executed",
                    ),
                    blocker(
                        "dkg_custody.process_isolation_absent",
                        "process_isolated_receiver_custody",
                        True,
                        first_value(dkg, "process_isolated_receiver_custody", False),
                        dkg_path,
                        "Receiver custody is not process isolated",
                    ),
                    blocker(
                        "dkg_custody.private_share_custody_absent",
                        "per_receiver_private_share_custody",
                        True,
                        first_value(dkg, "per_receiver_private_share_custody", False),
                        dkg_path,
                        "Per-receiver private-share custody is absent",
                    ),
                    blocker(
                        "dkg_custody.signer_binding_absent",
                        "signer_consumes_custody_output",
                        True,
                        first_value(dkg, "signer_consumes_custody_output", False),
                        dkg_path,
                        "The real partial signer does not consume custody output",
                    ),
                ]
            )
    mama_path = repository_root / KNOWN_MAMA_CAPTURE
    if mama_path.is_file():
        try:
            mama = load_json(mama_path)
        except (OSError, ValueError) as error:
            blockers.append(
                blocker(
                    "mama.capture_unreadable",
                    None,
                    "parseable JSON evidence",
                    str(error),
                    mama_path,
                    "Malicious-MPC capture could not be parsed",
                )
            )
        else:
            mama_signers = first_value(mama, "signers", 2)
            blockers.extend(
                [
                    blocker(
                        "mama.execution_scale_insufficient",
                        "execution.signers",
                        THRESHOLD,
                        mama_signers,
                        mama_path,
                        "Malicious MAMA execution has not run with 6,667 distinct signers",
                    ),
                    blocker(
                        "mama.k_share_dkg_binding_absent",
                        "K_share_dkg_binding",
                        True,
                        False,
                        mama_path,
                        "MAMA mask inputs are not bound to no-dealer K-share DKG output",
                    ),
                    blocker(
                        "mama.production_custody_absent",
                        "production_private_share_custody",
                        True,
                        False,
                        mama_path,
                        "MAMA parties are not backed by production private-share custody",
                    ),
                ]
            )
    rejected_path = repository_root / KNOWN_REJECTED_CAMPAIGN
    if rejected_path.is_file():
        try:
            rejected = load_json(rejected_path)
        except (OSError, ValueError) as error:
            blockers.append(
                blocker(
                    "prior_campaign.capture_unreadable",
                    None,
                    "parseable JSON evidence",
                    str(error),
                    rejected_path,
                    "Prior rejected campaign capture could not be parsed",
                )
            )
        else:
            validated_count = first_value(rejected, "validated_execution_count", 24)
            blockers.extend(
                [
                    blocker(
                        "prior_campaign.count_evidence_only",
                        "validated_execution_count",
                        f"{THRESHOLD} distinct real ML-DSA partial contributions",
                        validated_count,
                        rejected_path,
                        "Prior campaign records validated executions, not 6,667 real partial contributions",
                    ),
                    blocker(
                        "prior_campaign.exact_distributed_mask_gate_failed",
                        "exact_distributed_expand_mask",
                        True,
                        first_value(rejected, "exact_distributed_expand_mask", False),
                        rejected_path,
                        "Prior campaign was rejected with the exact distributed mask gate unresolved",
                    ),
                    blocker(
                        "prior_campaign.real_partial_contribution_gate_failed",
                        "real_mldsa_partial_contributions",
                        THRESHOLD,
                        0,
                        rejected_path,
                        "Prior campaign does not evidence one real ML-DSA partial per custodial signer",
                    ),
                ]
            )
    return blockers


def resolve_bound_file(base, record, role, blockers):
    if not isinstance(record, dict):
        blockers.append(f"{role}: missing path and sha256 binding")
        return None
    raw_path = record.get("path")
    expected = record.get("sha256")
    if not isinstance(raw_path, str) or not raw_path:
        blockers.append(f"{role}: path is missing")
        return None
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = base / path
    path = path.resolve(strict=False)
    actual = sha256_path(path)
    if actual is None:
        blockers.append(f"{role}: file is absent: {path}")
        return None
    if not is_sha256(expected) or actual != expected:
        blockers.append(f"{role}: sha256 binding does not match {path}")
        return None
    return path


def records(value, key):
    if isinstance(value, dict):
        value = value.get(key)
    return value if isinstance(value, list) else []


def validate_enrollment(document, blockers):
    if not isinstance(document, dict) or document.get("schema") != ENROLLMENT_SCHEMA:
        blockers.append(f"enrollment_registry: schema must be {ENROLLMENT_SCHEMA}")
        return {}
    identities = records(document, "identities")
    by_id = {}
    for index, item in enumerate(identities):
        if not isinstance(item, dict):
            blockers.append(f"enrollment_registry: identity {index} is not an object")
            continue
        identity_id = item.get("identity_id")
        if not isinstance(identity_id, str) or not identity_id:
            blockers.append(f"enrollment_registry: identity {index} has no identity_id")
            continue
        if identity_id in by_id:
            blockers.append(f"enrollment_registry: duplicate identity_id {identity_id}")
            continue
        if item.get("enrolled") is not True or item.get("eligible") is not True:
            blockers.append(f"enrollment_registry: {identity_id} is not enrolled and eligible")
        for field in ("mldsa_identity_public_key_sha256", "enrollment_attestation_sha256"):
            if not is_sha256(item.get(field)):
                blockers.append(f"enrollment_registry: {identity_id} has invalid {field}")
        by_id[identity_id] = item
    if len(by_id) != VALIDATOR_COUNT:
        blockers.append(
            f"enrollment_registry: requires exactly {VALIDATOR_COUNT} distinct identities; "
            f"observed {len(by_id)}"
        )
    return by_id


def validate_custody(document, enrolled, blockers):
    if not isinstance(document, dict) or document.get("schema") != CUSTODY_SCHEMA:
        blockers.append(f"custody_registry: schema must be {CUSTODY_SCHEMA}")
        return {}
    custodians = records(document, "custodians")
    by_id = {}
    share_ids = set()
    backend_ids = set()
    for index, item in enumerate(custodians):
        if not isinstance(item, dict):
            blockers.append(f"custody_registry: custodian {index} is not an object")
            continue
        identity_id = item.get("identity_id")
        share_id = item.get("share_id")
        backend_id = item.get("custody_backend_id")
        if not isinstance(identity_id, str) or identity_id not in enrolled:
            blockers.append(f"custody_registry: custodian {index} is not an enrolled identity")
            continue
        if identity_id in by_id:
            blockers.append(f"custody_registry: duplicate identity_id {identity_id}")
            continue
        if not isinstance(share_id, str) or not share_id or share_id in share_ids:
            blockers.append(f"custody_registry: {identity_id} has missing or duplicate share_id")
        else:
            share_ids.add(share_id)
        if not isinstance(backend_id, str) or not backend_id:
            blockers.append(f"custody_registry: {identity_id} has no custody_backend_id")
        else:
            backend_ids.add(backend_id)
        if item.get("active") is not True or item.get("eligible") is not True:
            blockers.append(f"custody_registry: {identity_id} is not active and eligible")
        if item.get("private_share_exportable") is not False:
            blockers.append(f"custody_registry: {identity_id} must be non-exportable")
        if not is_sha256(item.get("custody_attestation_sha256")):
            blockers.append(f"custody_registry: {identity_id} has invalid custody attestation")
        by_id[identity_id] = item
    if len(by_id) < THRESHOLD:
        blockers.append(
            f"custody_registry: requires at least {THRESHOLD} distinct eligible custodians; "
            f"observed {len(by_id)}"
        )
    if len(backend_ids) < 2:
        blockers.append("custody_registry: requires at least two distinct custody backends")
    return by_id


def validate_capabilities(prerequisites, base, blockers):
    capabilities = prerequisites.get("capabilities")
    if not isinstance(capabilities, dict):
        blockers.append("capabilities: missing capability evidence map")
        return {}
    resolved = {}
    for gate in CAPABILITY_GATES:
        value = capabilities.get(gate)
        if not isinstance(value, dict) or value.get("ready") is not True:
            blockers.append(f"capabilities.{gate}: ready must be true")
            continue
        path = resolve_bound_file(base, value.get("evidence"), f"capabilities.{gate}", blockers)
        if path is None:
            continue
        try:
            document = load_json(path)
        except (OSError, ValueError) as error:
            blockers.append(
                blocker(
                    "capability.document_unreadable",
                    f"capabilities.{gate}",
                    "parseable capability evidence JSON",
                    str(error),
                    path,
                    f"Capability evidence for {gate} could not be parsed",
                )
            )
            continue
        requirements = {
            "schema": CAPABILITY_SCHEMA,
            "capability_id": gate,
            "ready": True,
            "production_profile": True,
            "validator_count": VALIDATOR_COUNT,
            "threshold": THRESHOLD,
            "parameter_set": PARAMETER_SET,
            "evidence_class": "production_implementation_and_execution_evidence",
        }
        valid = True
        for field, expected in requirements.items():
            observed = document.get(field) if isinstance(document, dict) else None
            if observed != expected:
                valid = False
                blockers.append(
                    blocker(
                        "capability.field_mismatch",
                        f"capabilities.{gate}.{field}",
                        expected,
                        observed,
                        path,
                        f"Capability {gate} does not satisfy production field {field}",
                    )
                )
        for field in ("implementation_sha256", "evidence_sha256"):
            observed = document.get(field) if isinstance(document, dict) else None
            if not is_sha256(observed):
                valid = False
                blockers.append(
                    blocker(
                        "capability.digest_binding_invalid",
                        f"capabilities.{gate}.{field}",
                        "nonzero lowercase SHA-256 digest",
                        observed,
                        path,
                        f"Capability {gate} lacks a nonzero {field} binding",
                    )
                )
        serialized = canonical_json(document).lower() if isinstance(document, dict) else ""
        forbidden = [
            token for token in FORBIDDEN_CAPABILITY_EVIDENCE_TOKENS if token in serialized
        ]
        if forbidden:
            valid = False
            blockers.append(
                blocker(
                    "capability.nonproduction_evidence_forbidden",
                    f"capabilities.{gate}.evidence_class",
                    "production implementation and execution evidence only",
                    forbidden,
                    path,
                    f"Capability {gate} contains simulation, fixture, smoke, or count-only evidence",
                )
            )
        if valid:
            resolved[gate] = {
                "path": str(path),
                "sha256": sha256_path(path),
                "schema": document["schema"],
                "capability_id": document["capability_id"],
                "production_profile": document["production_profile"],
                "implementation_sha256": document["implementation_sha256"],
                "evidence_sha256": document["evidence_sha256"],
            }
    return resolved


def validate_command(record, base, role, placeholders, blockers):
    if not isinstance(record, dict):
        blockers.append(f"{role}: command record is missing")
        return None
    argv = record.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(v, str) and v for v in argv):
        blockers.append(f"{role}: argv must be a non-empty string array")
        return None
    joined = " ".join(argv).lower()
    for token in FORBIDDEN_COMMAND_TOKENS:
        if token in joined:
            blockers.append(f"{role}: forbidden non-real command token: {token}")
    for placeholder in placeholders:
        if not any(placeholder in argument for argument in argv):
            blockers.append(f"{role}: argv is missing placeholder {placeholder}")
    executable = Path(argv[0]).expanduser()
    if not executable.is_absolute():
        executable = (base / executable).resolve(strict=False)
    actual = sha256_path(executable)
    expected = record.get("executable_sha256")
    if actual is None:
        blockers.append(f"{role}: executable is absent: {executable}")
    elif not is_sha256(expected) or actual != expected:
        blockers.append(f"{role}: executable sha256 binding does not match")
    normalized = [str(executable), *argv[1:]]
    return normalized


def prepare_prerequisites(path, sibling_backend_root):
    blockers = []
    path = Path(path).expanduser().resolve(strict=False)
    repository_root = Path(__file__).resolve().parent.parent
    engineering_interfaces = detect_engineering_interfaces(
        repository_root,
        Path(sibling_backend_root).expanduser().resolve(strict=False),
    )
    if not path.is_file():
        blockers.extend(known_repository_blockers(repository_root))
        blockers.append(
            blocker(
                "campaign.prerequisites_absent",
                "prerequisites",
                "digest-bound real campaign prerequisite manifest",
                None,
                path,
                "Real campaign prerequisites are absent; backend launch is forbidden",
            )
        )
        return {
            "engineering_interfaces": engineering_interfaces,
        }, None, None, None, blockers
    try:
        prerequisite = load_json(path)
    except (OSError, ValueError) as error:
        return None, None, None, None, [f"prerequisites: cannot parse JSON: {error}"]
    if not isinstance(prerequisite, dict) or prerequisite.get("schema") != PREREQUISITE_SCHEMA:
        blockers.append(f"prerequisites: schema must be {PREREQUISITE_SCHEMA}")
    if prerequisite.get("validator_count") != VALIDATOR_COUNT:
        blockers.append(f"prerequisites: validator_count must be {VALIDATOR_COUNT}")
    if prerequisite.get("threshold") != THRESHOLD:
        blockers.append(f"prerequisites: threshold must be {THRESHOLD}")
    if prerequisite.get("parameter_set") != PARAMETER_SET:
        blockers.append(f"prerequisites: parameter_set must be {PARAMETER_SET}")
    base = path.parent
    enrollment_path = resolve_bound_file(
        base, prerequisite.get("enrollment_registry"), "enrollment_registry", blockers
    )
    custody_path = resolve_bound_file(
        base, prerequisite.get("custody_registry"), "custody_registry", blockers
    )
    enrolled = validate_enrollment(load_json(enrollment_path), blockers) if enrollment_path else {}
    custodians = validate_custody(load_json(custody_path), enrolled, blockers) if custody_path else {}
    capability_evidence = validate_capabilities(prerequisite, base, blockers)
    campaign_command = validate_command(
        prerequisite.get("campaign_command"), base, "campaign_command", (), blockers
    )
    verifier_command = validate_command(
        prerequisite.get("standard_verifier_command"),
        base,
        "standard_verifier_command",
        ("{public_key}", "{message}", "{signature}"),
        blockers,
    )
    evidence = {
        "engineering_interfaces": engineering_interfaces,
        "prerequisites_path": str(path),
        "prerequisites_sha256": sha256_path(path),
        "enrollment_registry": {
            "path": str(enrollment_path) if enrollment_path else None,
            "sha256": sha256_path(enrollment_path) if enrollment_path else None,
            "distinct_eligible_identities": len(enrolled),
        },
        "custody_registry": {
            "path": str(custody_path) if custody_path else None,
            "sha256": sha256_path(custody_path) if custody_path else None,
            "distinct_eligible_custodians": len(custodians),
        },
        "capability_evidence": capability_evidence,
    }
    return evidence, enrolled, custodians, (campaign_command, verifier_command), blockers


def validate_hex(value, byte_length=None):
    if not isinstance(value, str) or len(value) % 2:
        return False
    if byte_length is not None and len(value) != byte_length * 2:
        return False
    return all(character in "0123456789abcdef" for character in value)


def find_forbidden_secret_fields(value, prefix="capture"):
    findings = []
    forbidden = {
        "secret_key",
        "secret_key_hex",
        "private_share",
        "private_share_hex",
        "signing_seed",
        "signing_seed_hex",
        "reconstructed_secret",
        "reconstructed_seed",
        "reconstructed_k",
    }
    if isinstance(value, dict):
        for key, child in value.items():
            location = f"{prefix}.{key}"
            if key.lower() in forbidden and child not in (None, False, "", []):
                findings.append(location)
            findings.extend(find_forbidden_secret_fields(child, location))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(find_forbidden_secret_fields(child, f"{prefix}[{index}]"))
    return findings


def validate_capture(capture, campaign_id, enrolled, custodians):
    blockers = []
    if not isinstance(capture, dict) or capture.get("schema") != CAPTURE_SCHEMA:
        blockers.append(f"capture: schema must be {CAPTURE_SCHEMA}")
        return blockers, {}
    exact = {
        "campaign_id": campaign_id,
        "execution_mode": "actual_distributed_threshold_mldsa",
        "parameter_set": PARAMETER_SET,
        "validator_count": VALIDATOR_COUNT,
        "threshold": THRESHOLD,
        "protocol_outcome": "accepted",
        "aggregate_emitted": True,
        "no_secret_reconstruction": True,
        "reconstructed_secret_material": False,
        "reconstructed_k": False,
        "centralized_signing_oracle": False,
    }
    for field, expected in exact.items():
        if capture.get(field) != expected:
            blockers.append(f"capture.{field}: expected {expected!r}")
    session_id = capture.get("session_id")
    session_binding = capture.get("session_binding_sha256")
    transcript_binding = capture.get("transcript_sha256")
    if not isinstance(session_id, str) or not session_id:
        blockers.append("capture.session_id: requires a nonempty campaign session identifier")
    if not is_sha256(session_binding):
        blockers.append("capture.session_binding_sha256: requires a nonzero digest")
    if not is_sha256(transcript_binding):
        blockers.append("capture.transcript_sha256: requires a nonzero digest")
    forbidden = find_forbidden_secret_fields(capture)
    if forbidden:
        blockers.append("capture: forbidden secret material fields are populated: " + ", ".join(forbidden))
    signing_set = capture.get("signing_set")
    if not isinstance(signing_set, list):
        signing_set = []
    if len(signing_set) != THRESHOLD or len(set(signing_set)) != THRESHOLD:
        blockers.append(f"capture.signing_set: requires exactly {THRESHOLD} distinct identities")
    unknown = sorted(set(signing_set) - set(custodians))
    if unknown:
        blockers.append(f"capture.signing_set: {len(unknown)} identities lack eligible custody")
    contributions = capture.get("partial_contributions")
    if not isinstance(contributions, list):
        contributions = []
    contribution_ids = []
    for index, contribution in enumerate(contributions):
        if not isinstance(contribution, dict):
            blockers.append(f"capture.partial_contributions[{index}]: not an object")
            continue
        identity_id = contribution.get("identity_id")
        contribution_ids.append(identity_id)
        enrolled_identity = enrolled.get(identity_id, {})
        custody_identity = custodians.get(identity_id, {})
        if contribution.get("contribution_kind") != "mldsa_partial_signature":
            blockers.append(f"capture.partial_contributions[{index}]: wrong contribution_kind")
        if contribution.get("accepted") is not True or contribution.get("custodial_signer") is not True:
            blockers.append(f"capture.partial_contributions[{index}]: not accepted custodial output")
        if not is_sha256(contribution.get("contribution_sha256")):
            blockers.append(f"capture.partial_contributions[{index}]: invalid contribution_sha256")
        identity_bindings = {
            "mldsa_identity_public_key_sha256": enrolled_identity.get(
                "mldsa_identity_public_key_sha256"
            ),
            "enrollment_attestation_sha256": enrolled_identity.get(
                "enrollment_attestation_sha256"
            ),
            "custody_attestation_sha256": custody_identity.get(
                "custody_attestation_sha256"
            ),
            "share_id": custody_identity.get("share_id"),
            "campaign_id": campaign_id,
            "session_id": session_id,
            "session_binding_sha256": session_binding,
            "transcript_sha256": transcript_binding,
        }
        for field, expected in identity_bindings.items():
            observed = contribution.get(field)
            if expected in (None, "") or observed != expected:
                blockers.append(
                    f"capture.partial_contributions[{index}].{field}: does not match "
                    "the enrolled identity, custody record, campaign, session, or transcript"
                )
    if (
        len(contributions) != THRESHOLD
        or len(set(contribution_ids)) != THRESHOLD
        or set(contribution_ids) != set(signing_set)
    ):
        blockers.append("capture.partial_contributions: must map one-to-one to the signing_set")
    message = capture.get("message_hex")
    public_key = capture.get("public_key_hex")
    signature = capture.get("aggregate_signature_hex")
    if not validate_hex(message) or not message:
        blockers.append("capture.message_hex: invalid or empty lowercase hex")
    if not validate_hex(public_key, PUBLIC_KEY_BYTES):
        blockers.append(f"capture.public_key_hex: must be {PUBLIC_KEY_BYTES} bytes")
    if not validate_hex(signature, SIGNATURE_BYTES):
        blockers.append(f"capture.aggregate_signature_hex: must be {SIGNATURE_BYTES} bytes")
    negatives = capture.get("negative_checks")
    if not isinstance(negatives, dict):
        negatives = {}
    for name in PROTOCOL_NEGATIVE_CHECKS:
        result = negatives.get(name)
        if not isinstance(result, dict) or result.get("rejected") is not True or result.get("aggregate_emitted") is not False:
            blockers.append(f"capture.negative_checks.{name}: must reject without aggregate output")
    normalized = {
        "signing_set": signing_set,
        "partial_contribution_count": len(contributions),
        "message_hex": message,
        "public_key_hex": public_key,
        "aggregate_signature_hex": signature,
        "protocol_negative_checks": negatives,
        "partial_binding_validation": {
            "mode": "structural_digest_and_registry_binding_only",
            "cryptographic_attestation_verified": False,
        },
    }
    return blockers, normalized


def substitute_command(argv, paths):
    return [
        argument.replace("{public_key}", str(paths["public_key"]))
        .replace("{message}", str(paths["message"]))
        .replace("{signature}", str(paths["signature"]))
        for argument in argv
    ]


def run_verifier(argv, public_key, message, signature, timeout):
    with tempfile.TemporaryDirectory(prefix="real-mldsa-verify-") as directory:
        root = Path(directory)
        paths = {
            "public_key": root / "public-key.bin",
            "message": root / "message.bin",
            "signature": root / "signature.bin",
        }
        paths["public_key"].write_bytes(public_key)
        paths["message"].write_bytes(message)
        paths["signature"].write_bytes(signature)
        completed = subprocess.run(
            substitute_command(argv, paths),
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        return {
            "accepted": completed.returncode == 0,
            "exit_code": completed.returncode,
            "stdout_sha256": sha256_bytes(completed.stdout),
            "stderr_sha256": sha256_bytes(completed.stderr),
        }


def independently_verify(verifier_command, normalized, timeout):
    public_key = bytes.fromhex(normalized["public_key_hex"])
    message = bytes.fromhex(normalized["message_hex"])
    signature = bytes.fromhex(normalized["aggregate_signature_hex"])
    original = run_verifier(verifier_command, public_key, message, signature, timeout)
    mutated_message = bytes([message[0] ^ 1]) + message[1:]
    mutated_public_key = bytes([public_key[0] ^ 1]) + public_key[1:]
    mutated_signature = bytes([signature[0] ^ 1]) + signature[1:]
    mutations = {
        "message_mutation": run_verifier(
            verifier_command, public_key, mutated_message, signature, timeout
        ),
        "public_key_mutation": run_verifier(
            verifier_command, mutated_public_key, message, signature, timeout
        ),
        "signature_mutation": run_verifier(
            verifier_command, public_key, message, mutated_signature, timeout
        ),
    }
    blockers = []
    if not original["accepted"]:
        blockers.append("standard_verifier: aggregate signature was not accepted")
    for name, result in mutations.items():
        result["rejected"] = not result.pop("accepted")
        if not result["rejected"]:
            blockers.append(f"standard_verifier: {name} was accepted")
    return blockers, {"original": original, "mutations": mutations}


def claim_flags(campaign_complete=False):
    return {
        "claims_campaign_complete": campaign_complete,
        "claims_production_threshold_mldsa_security": False,
        "claims_theorem_closure": False,
        "claims_independent_review_complete": False,
        "claims_fips_validation": False,
        "claims_cryptographic_attestation_validation": False,
    }


def write_evidence(out, manifest, blockers, capture=None, logs=None):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    normalized_blockers = [
        value
        if isinstance(value, dict)
        else blocker(
            "campaign.preflight_requirement_failed",
            None,
            None,
            None,
            None,
            str(value),
        )
        for value in blockers
    ]
    files = {
        "manifest.json": canonical_json(manifest),
        "blockers.json": canonical_json(
            {
                "schema": SCHEMA,
                "campaign_id": manifest["campaign_id"],
                "status": manifest["status"],
                "blockers": normalized_blockers,
                "claim_flags": manifest["claim_flags"],
                "engineering_interfaces": manifest["engineering_interfaces"],
            }
        ),
    }
    if capture is not None:
        files["capture.json"] = canonical_json(capture)
    if logs is not None:
        files["backend.stdout.log"] = logs["stdout"]
        files["backend.stderr.log"] = logs["stderr"]
    files["summary.md"] = "\n".join(
        [
            "# Real 6,667-of-10,000 ML-DSA Campaign",
            "",
            f"- Status: `{manifest['status']}`",
            f"- Campaign executed: `{str(manifest['campaign_executed']).lower()}`",
            f"- Distinct enrolled identities: `{manifest['observed_counts']['enrolled_identities']}`",
            f"- Distinct eligible custodians: `{manifest['observed_counts']['eligible_custodians']}`",
            f"- Distinct contributing signers: `{manifest['observed_counts']['contributing_signers']}`",
            f"- Aggregate standards-verifiable: `{str(manifest['aggregate_standards_verifiable']).lower()}`",
            f"- Blockers: `{len(blockers)}`",
            "",
            "## Engineering interfaces",
            "",
            *[
                f"- {interface_id}: `{record['status']}`"
                for interface_id, record in sorted(
                    manifest["engineering_interfaces"].items()
                )
            ],
            "",
            CLAIM_BOUNDARY + ".",
            "",
        ]
    )
    checksums = "".join(
        f"{sha256_bytes(content.encode('utf-8'))}  {name}\n"
        for name, content in sorted(files.items())
    )
    files["SHA256SUMS"] = checksums
    for name, content in files.items():
        (out / name).write_text(content, encoding="utf-8")


def base_manifest(campaign_id, status, executed, prerequisite_evidence=None):
    prerequisite_evidence = prerequisite_evidence or {}
    enrollment = prerequisite_evidence.get("enrollment_registry", {})
    custody = prerequisite_evidence.get("custody_registry", {})
    return {
        "schema": SCHEMA,
        "schema_version": 1,
        "campaign_id": campaign_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "claim_boundary": CLAIM_BOUNDARY,
        "campaign_executed": executed,
        "topology": {"validator_count": VALIDATOR_COUNT, "threshold": THRESHOLD},
        "parameter_set": PARAMETER_SET,
        "engineering_interfaces": prerequisite_evidence.get(
            "engineering_interfaces", {}
        ),
        "prerequisite_evidence": prerequisite_evidence,
        "observed_counts": {
            "enrolled_identities": enrollment.get("distinct_eligible_identities", 0),
            "eligible_custodians": custody.get("distinct_eligible_custodians", 0),
            "contributing_signers": 0,
            "partial_contributions": 0,
        },
        "aggregate_standards_verifiable": False,
        "standard_verifier_results": None,
        "negative_checks_passed": False,
        "partial_binding_validation": {
            "mode": "structural_digest_and_registry_binding_only",
            "cryptographic_attestation_verified": False,
        },
        "claim_flags": claim_flags(False),
    }


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-id", default="real-6667-of-10000-mldsa-001")
    parser.add_argument("--prerequisites", default=DEFAULT_PREREQUISITES)
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument(
        "--sibling-backend-root",
        default=DEFAULT_SIBLING_BACKEND_ROOT,
        help="sibling Rust backend root used only for engineering-interface detection",
    )
    parser.add_argument("--timeout-seconds", type=int, default=86_400)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    evidence, enrolled, custodians, commands, blockers = prepare_prerequisites(
        args.prerequisites, args.sibling_backend_root
    )
    if blockers:
        manifest = base_manifest(
            args.campaign_id, "blocked_prerequisites_unmet", False, evidence
        )
        write_evidence(args.out, manifest, blockers)
        print(canonical_json(manifest), end="")
        return 2

    campaign_command, verifier_command = commands
    try:
        completed = subprocess.run(
            campaign_command,
            capture_output=True,
            check=False,
            text=True,
            timeout=args.timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        blockers = [f"campaign_command: execution failed: {error}"]
        manifest = base_manifest(args.campaign_id, "blocked_backend_execution_failed", True, evidence)
        write_evidence(args.out, manifest, blockers)
        print(canonical_json(manifest), end="")
        return 3
    logs = {"stdout": completed.stdout, "stderr": completed.stderr}
    if completed.returncode != 0:
        blockers = [f"campaign_command: exited with status {completed.returncode}"]
        manifest = base_manifest(args.campaign_id, "blocked_backend_execution_failed", True, evidence)
        write_evidence(args.out, manifest, blockers, logs=logs)
        print(canonical_json(manifest), end="")
        return 3
    try:
        capture = json.loads(completed.stdout)
    except ValueError as error:
        blockers = [f"campaign_command: stdout is not one canonical JSON capture: {error}"]
        manifest = base_manifest(args.campaign_id, "blocked_capture_invalid", True, evidence)
        write_evidence(args.out, manifest, blockers, logs=logs)
        print(canonical_json(manifest), end="")
        return 4
    blockers, normalized = validate_capture(
        capture, args.campaign_id, enrolled, custodians
    )
    verifier_results = None
    if not blockers:
        try:
            verifier_blockers, verifier_results = independently_verify(
                verifier_command, normalized, args.timeout_seconds
            )
            blockers.extend(verifier_blockers)
        except (OSError, subprocess.TimeoutExpired, ValueError) as error:
            blockers.append(f"standard_verifier: execution failed: {error}")
    status = "campaign_evidence_ready" if not blockers else "blocked_capture_invalid"
    manifest = base_manifest(args.campaign_id, status, True, evidence)
    manifest["observed_counts"].update(
        {
            "contributing_signers": len(set(normalized.get("signing_set", []))),
            "partial_contributions": normalized.get("partial_contribution_count", 0),
        }
    )
    manifest["aggregate_standards_verifiable"] = not blockers
    manifest["standard_verifier_results"] = verifier_results
    manifest["negative_checks_passed"] = not blockers
    manifest["capture_sha256"] = sha256_bytes(canonical_json(capture).encode("utf-8"))
    manifest["claim_flags"] = claim_flags(not blockers)
    write_evidence(args.out, manifest, blockers, capture=capture, logs=logs)
    print(canonical_json(manifest), end="")
    return 0 if not blockers else 4


if __name__ == "__main__":
    raise SystemExit(main())
