#!/usr/bin/env python3
"""Preflight and run a fail-closed 6,667-party malicious-MAMA campaign.

Local subprocesses are always classified as a bounded simulation. A production
claim requires a signed 6,667-party roster, trusted custody attestations, a
runner-invoked external orchestrator, signed completion receipts, and an output
that matches an independent ExpandMask oracle.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import resource
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


SCHEMA = "lattice-aggregation:mama-6667-scale-run:v1"
INVENTORY_SCHEMA = "lattice-aggregation:mama-signer-inventory:v1"
ATTESTATION_SCHEMA = "lattice-aggregation:production-custody-attestation:v1"
COMPLETION_SCHEMA = "lattice-aggregation:mama-completion-bundle:v1"
RECEIPT_SCHEMA = "lattice-aggregation:mama-party-completion-receipt:v1"
TARGET_PARTIES = 6_667
FIELD_PRIME = 8_380_417
COMPONENTS = 5
COEFFICIENTS = 256
OUTPUT_COUNT = COMPONENTS * COEFFICIENTS
MIN_SECURITY = 40
DEFAULT_MEASURED = (
    "artifacts/exact-distributed-expandmask-mpc/"
    "mama-equivalence-latest/manifest.json"
)
DEFAULT_OUT = (
    "artifacts/exact-distributed-expandmask-mpc/"
    "mama-6667-scale-latest"
)
SIGNER_DOMAIN = b"lattice-mama-signer-v1\x00"
ZERO_DIGEST = "0" * 64
FORBIDDEN_LOG_PATTERNS = (
    "mac check failed",
    "sacrifice failed",
    "inconsistent preprocessing",
    "peer substitution",
    "protocol downgrade",
)


def canonical_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def pretty_json(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_path(path):
    path = Path(path)
    return sha256_bytes(path.read_bytes()) if path.is_file() else None


def is_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def contained_file(base, value):
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        return None
    base = Path(base).resolve()
    candidate = (base / value).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def parse_timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
            timezone.utc
        )
    except ValueError:
        return None


def canonical_endpoint(value):
    if not isinstance(value, str):
        return None
    parsed = urlsplit(value)
    if parsed.scheme not in {"tcp", "tls"} or not parsed.hostname or parsed.port is None:
        return None
    if parsed.username or parsed.password or parsed.path not in {"", "/"}:
        return None
    if parsed.query or parsed.fragment or parsed.port < 1 or parsed.port > 65535:
        return None
    host = parsed.hostname.rstrip(".").lower()
    try:
        address = ipaddress.ip_address(host)
        if address.is_loopback or address.is_unspecified or address.is_link_local:
            return None
        host = f"[{host}]" if address.version == 6 else host
    except ValueError:
        if host in {"localhost", "localhost.localdomain"}:
            return None
    return f"{parsed.scheme}://{host}:{parsed.port}"


def openssl_verify(public_key, signature, message):
    if shutil.which("openssl") is None:
        return False, "openssl is unavailable"
    with tempfile.NamedTemporaryFile() as handle:
        handle.write(message)
        handle.flush()
        completed = subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(public_key),
                "-signature",
                str(signature),
                handle.name,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
    return completed.returncode == 0, completed.stdout.strip()


def argument_value(arguments, flag):
    if not isinstance(arguments, list):
        return None
    try:
        return arguments[arguments.index(flag) + 1]
    except (ValueError, IndexError):
        return None


class Validation:
    def __init__(self):
        self.error_count = 0
        self.errors = []

    def require(self, condition, message):
        if not condition:
            self.error_count += 1
            if len(self.errors) < 100:
                self.errors.append(message)
        return bool(condition)

    def result(self):
        errors = list(self.errors)
        if self.error_count > len(errors):
            errors.append(
                f"{self.error_count - len(errors)} additional validation errors omitted"
            )
        return self.error_count == 0, errors


def validate_protocol(protocol, bundle_root, validation):
    protocol = protocol if isinstance(protocol, dict) else {}
    arguments = protocol.get("runtime_arguments")
    checks = {
        "framework_is_mp_spdz": protocol.get("framework") == "MP-SPDZ",
        "runtime_is_mama": protocol.get("runtime_name") == "mama-party.x",
        "malicious_multiple_mac_profile": protocol.get("execution_protocol")
        == "MAMA_multiple_MAC_malicious_dishonest_majority",
        "party_count_6667": argument_value(arguments, "-N") == str(TARGET_PARTIES),
        "security_at_least_40": (
            isinstance(argument_value(arguments, "-S"), str)
            and argument_value(arguments, "-S").isdigit()
            and int(argument_value(arguments, "-S")) >= MIN_SECURITY
            and protocol.get("statistical_security_parameter", 0) >= MIN_SECURITY
        ),
        "field_matches_mldsa_q": protocol.get("field_prime") == FIELD_PRIME,
        "full_mldsa65_dimensions": (
            protocol.get("components") == COMPONENTS
            and protocol.get("coefficients_per_component") == COEFFICIENTS
        ),
        "mp_spdz_commit_bound": isinstance(protocol.get("mp_spdz_commit"), str)
        and re.fullmatch(r"[0-9a-f]{40}", protocol["mp_spdz_commit"]) is not None,
    }
    artifact_fields = (
        ("runtime_path", "runtime_sha256"),
        ("source_path", "source_sha256"),
        ("schedule_path", "schedule_sha256"),
        ("bytecode_path", "bytecode_sha256"),
    )
    for path_field, digest_field in artifact_fields:
        path = contained_file(bundle_root, protocol.get(path_field))
        checks[f"{path_field}_digest_bound"] = (
            path is not None
            and is_digest(protocol.get(digest_field))
            and sha256_path(path) == protocol.get(digest_field)
        )
    for name, passed in checks.items():
        validation.require(passed, f"protocol check failed: {name}")
    return checks


def roster_binding(party):
    return {
        "authorization_id": party.get("authorization_id"),
        "custody_attestation_sha256": (
            party.get("custody_attestation", {}).get("document_sha256")
            if isinstance(party.get("custody_attestation"), dict)
            else None
        ),
        "dkg_receiver_id": party.get("dkg_receiver_id"),
        "endpoint": canonical_endpoint(party.get("endpoint")),
        "host_attestation_id": party.get("host_attestation_id"),
        "identity_public_key_sha256": party.get("identity_public_key_sha256"),
        "party_index": party.get("party_index"),
        "signer_id": party.get("signer_id"),
        "transport_public_key_sha256": party.get("transport_public_key_sha256"),
    }


def validate_inventory(path, trusted_roots):
    validation = Validation()
    if path is None or not Path(path).is_file():
        validation.require(False, "signed 6,667-party inventory is absent")
        valid, errors = validation.result()
        return valid, errors, {}, {}, None
    path = Path(path).resolve()
    bundle_root = path.parent
    try:
        inventory = load_json(path)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        validation.require(False, f"inventory is not valid UTF-8 JSON: {exc}")
        valid, errors = validation.result()
        return valid, errors, {}, {}, None

    validation.require(inventory.get("schema") == INVENTORY_SCHEMA, "inventory schema mismatch")
    campaign_id = inventory.get("campaign_id")
    validation.require(isinstance(campaign_id, str) and bool(campaign_id), "campaign_id missing")
    protocol_checks = validate_protocol(inventory.get("protocol"), bundle_root, validation)
    parties = inventory.get("parties")
    validation.require(isinstance(parties, list), "parties must be an array")
    parties = parties if isinstance(parties, list) else []
    validation.require(len(parties) == TARGET_PARTIES, "inventory must contain exactly 6,667 parties")

    bindings = [roster_binding(party) for party in parties if isinstance(party, dict)]
    computed_roster_digest = sha256_bytes(canonical_bytes(bindings))
    validation.require(
        inventory.get("roster_digest") == computed_roster_digest,
        "canonical roster digest mismatch",
    )
    indexes = [party.get("party_index") for party in parties if isinstance(party, dict)]
    signer_ids = [party.get("signer_id") for party in parties if isinstance(party, dict)]
    endpoints = [canonical_endpoint(party.get("endpoint")) for party in parties if isinstance(party, dict)]
    identity_digests = [party.get("identity_public_key_sha256") for party in parties if isinstance(party, dict)]
    transport_digests = [party.get("transport_public_key_sha256") for party in parties if isinstance(party, dict)]
    host_ids = [party.get("host_attestation_id") for party in parties if isinstance(party, dict)]
    dkg_ids = [party.get("dkg_receiver_id") for party in parties if isinstance(party, dict)]
    authorization_ids = [party.get("authorization_id") for party in parties if isinstance(party, dict)]

    cardinality_checks = {
        "party_indexes_exactly_0_through_6666": sorted(indexes) == list(range(TARGET_PARTIES)),
        "unique_signer_ids_6667": len(set(signer_ids)) == TARGET_PARTIES,
        "unique_identity_keys_6667": len(set(identity_digests)) == TARGET_PARTIES,
        "unique_transport_keys_6667": len(set(transport_digests)) == TARGET_PARTIES,
        "unique_canonical_endpoints_6667": None not in endpoints and len(set(endpoints)) == TARGET_PARTIES,
        "unique_host_attestation_ids_6667": len(set(host_ids)) == TARGET_PARTIES,
        "unique_dkg_receiver_ids_6667": len(set(dkg_ids)) == TARGET_PARTIES,
        "unique_authorization_ids_6667": len(set(authorization_ids)) == TARGET_PARTIES,
    }
    for name, passed in cardinality_checks.items():
        validation.require(passed, f"roster cardinality check failed: {name}")

    trusted_roots = {value.lower() for value in trusted_roots if is_digest(value.lower())}
    validation.require(bool(trusted_roots), "no external trusted custody-root digest was supplied")
    now = datetime.now(timezone.utc)
    party_context = {}
    for offset, party in enumerate(parties):
        if not isinstance(party, dict):
            validation.require(False, f"party record {offset} is not an object")
            continue
        index = party.get("party_index")
        label = f"party {index if isinstance(index, int) else offset}"
        public_key = contained_file(bundle_root, party.get("identity_public_key_path"))
        public_key_bytes = public_key.read_bytes() if public_key else b""
        identity_digest = sha256_bytes(public_key_bytes) if public_key_bytes else None
        validation.require(
            public_key is not None and identity_digest == party.get("identity_public_key_sha256"),
            f"{label}: identity public-key digest mismatch",
        )
        derived_signer_id = (
            sha256_bytes(SIGNER_DOMAIN + public_key_bytes) if public_key_bytes else None
        )
        validation.require(
            party.get("signer_id") == derived_signer_id,
            f"{label}: signer_id is not derived from the identity public key",
        )
        validation.require(
            party.get("dkg_receiver_id") == party.get("signer_id")
            and party.get("authorization_id") == party.get("signer_id"),
            f"{label}: signer, DKG receiver, and authorization identities are not one-to-one",
        )

        roster_signature = contained_file(bundle_root, party.get("roster_signature_path"))
        roster_statement = canonical_bytes(
            {
                "campaign_id": campaign_id,
                "party_index": index,
                "roster_digest": computed_roster_digest,
                "signer_id": party.get("signer_id"),
            }
        )
        roster_verified = False
        if public_key and roster_signature:
            roster_verified, _ = openssl_verify(public_key, roster_signature, roster_statement)
        validation.require(roster_verified, f"{label}: signed roster binding failed verification")

        custody = party.get("custody_attestation")
        custody = custody if isinstance(custody, dict) else {}
        document = contained_file(bundle_root, custody.get("document_path"))
        signature = contained_file(bundle_root, custody.get("signature_path"))
        root_key = contained_file(bundle_root, custody.get("root_public_key_path"))
        document_bytes = document.read_bytes() if document else b""
        root_key_bytes = root_key.read_bytes() if root_key else b""
        root_digest = sha256_bytes(root_key_bytes) if root_key_bytes else None
        validation.require(
            document is not None and sha256_bytes(document_bytes) == custody.get("document_sha256"),
            f"{label}: custody-attestation document digest mismatch",
        )
        validation.require(
            signature is not None and sha256_path(signature) == custody.get("signature_sha256"),
            f"{label}: custody-attestation signature digest mismatch",
        )
        validation.require(
            root_key is not None
            and root_digest == custody.get("root_public_key_sha256")
            and root_digest in trusted_roots,
            f"{label}: custody attestation does not terminate at an externally trusted root",
        )
        custody_signature_verified = False
        if document and signature and root_key:
            custody_signature_verified, _ = openssl_verify(root_key, signature, document_bytes)
        validation.require(
            custody_signature_verified,
            f"{label}: custody-attestation signature failed verification",
        )
        try:
            attestation = json.loads(document_bytes.decode("utf-8")) if document_bytes else {}
        except (UnicodeError, json.JSONDecodeError):
            attestation = {}
        required_bindings = {
            "authorization_id": party.get("authorization_id"),
            "campaign_id": campaign_id,
            "dkg_receiver_id": party.get("dkg_receiver_id"),
            "endpoint": canonical_endpoint(party.get("endpoint")),
            "host_attestation_id": party.get("host_attestation_id"),
            "identity_public_key_sha256": party.get("identity_public_key_sha256"),
            "party_index": index,
            "signer_id": party.get("signer_id"),
            "transport_public_key_sha256": party.get("transport_public_key_sha256"),
        }
        validation.require(attestation.get("schema") == ATTESTATION_SCHEMA, f"{label}: custody schema mismatch")
        for field, expected in required_bindings.items():
            actual = canonical_endpoint(attestation.get(field)) if field == "endpoint" else attestation.get(field)
            validation.require(actual == expected, f"{label}: custody binding mismatch for {field}")
        for field in (
            "dkg_transcript_sha256",
            "key_share_handle_sha256",
            "share_commitment_sha256",
            "signer_binary_sha256",
            "custody_policy_sha256",
        ):
            validation.require(is_digest(attestation.get(field)), f"{label}: invalid custody digest {field}")
        validation.require(attestation.get("production_custody") is True, f"{label}: production custody is not attested")
        validation.require(attestation.get("share_exportable") is False, f"{label}: share is exportable")
        validation.require(attestation.get("process_isolated") is True, f"{label}: custody is not process-isolated")
        validation.require(attestation.get("signer_consumes_share_directly") is True, f"{label}: signer does not consume the custody-held share")
        issued_at = parse_timestamp(attestation.get("issued_at"))
        expires_at = parse_timestamp(attestation.get("expires_at"))
        validation.require(
            issued_at is not None and expires_at is not None and issued_at <= now < expires_at,
            f"{label}: custody attestation is stale or has invalid timestamps",
        )
        if isinstance(index, int):
            party_context[index] = {
                "attestation": attestation,
                "custody_attestation_sha256": custody.get("document_sha256"),
                "endpoint": canonical_endpoint(party.get("endpoint")),
                "identity_public_key": public_key,
                "identity_public_key_sha256": party.get("identity_public_key_sha256"),
                "signer_id": party.get("signer_id"),
                "transport_public_key_sha256": party.get("transport_public_key_sha256"),
            }

    valid, errors = validation.result()
    checks = {**protocol_checks, **cardinality_checks}
    checks.update(
        inventory_schema_valid=inventory.get("schema") == INVENTORY_SCHEMA,
        roster_digest_valid=inventory.get("roster_digest") == computed_roster_digest,
        all_identity_roster_and_custody_bindings_valid=valid,
    )
    return valid, errors, checks, party_context, {
        "campaign_id": campaign_id,
        "inventory": inventory,
        "path": str(path),
        "roster_digest": computed_roster_digest,
    }


def read_u32_coefficients(path):
    raw = Path(path).read_bytes()
    if len(raw) != OUTPUT_COUNT * 4:
        return None, raw
    return list(struct.unpack("<" + "I" * OUTPUT_COUNT, raw)), raw


def validate_completion(path, inventory_context, party_context, run_nonce):
    validation = Validation()
    if path is None or not Path(path).is_file():
        validation.require(False, "post-run completion bundle is absent")
        valid, errors = validation.result()
        return valid, errors, {}
    path = Path(path).resolve()
    bundle_root = path.parent
    try:
        completion = load_json(path)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        validation.require(False, f"completion bundle is not valid UTF-8 JSON: {exc}")
        valid, errors = validation.result()
        return valid, errors, {}

    inventory = inventory_context["inventory"]
    protocol = inventory.get("protocol", {})
    validation.require(completion.get("schema") == COMPLETION_SCHEMA, "completion schema mismatch")
    validation.require(completion.get("campaign_id") == inventory_context["campaign_id"], "completion campaign_id mismatch")
    validation.require(completion.get("run_nonce") == run_nonce, "completion is not bound to this runner invocation")
    validation.require(completion.get("roster_digest") == inventory_context["roster_digest"], "completion roster digest mismatch")
    validation.require(completion.get("party_count") == TARGET_PARTIES, "completion party count is not 6,667")
    validation.require(completion.get("statistical_security_parameter", 0) >= MIN_SECURITY, "completion security parameter is below 40")

    transcript = contained_file(bundle_root, completion.get("global_transcript_path"))
    transcript_digest = sha256_path(transcript) if transcript else None
    validation.require(
        transcript is not None and transcript_digest == completion.get("global_transcript_sha256"),
        "global transcript digest mismatch",
    )
    actual_path = contained_file(bundle_root, completion.get("reconstructed_output_path"))
    oracle_path = contained_file(bundle_root, completion.get("oracle_output_path"))
    actual, actual_raw = read_u32_coefficients(actual_path) if actual_path else (None, b"")
    oracle, oracle_raw = read_u32_coefficients(oracle_path) if oracle_path else (None, b"")
    validation.require(actual is not None, "reconstructed output is not exactly 1,280 little-endian u32 coefficients")
    validation.require(oracle is not None, "oracle output is not exactly 1,280 little-endian u32 coefficients")
    validation.require(actual is not None and all(value < FIELD_PRIME for value in actual), "reconstructed output has non-canonical field coefficients")
    validation.require(oracle is not None and all(value < FIELD_PRIME for value in oracle), "oracle output has non-canonical field coefficients")
    validation.require(actual_raw == oracle_raw and bool(actual_raw), "reconstructed output does not match the independent oracle")

    receipts = completion.get("party_receipts")
    receipts = receipts if isinstance(receipts, list) else []
    validation.require(len(receipts) == TARGET_PARTIES, "completion must contain exactly 6,667 party receipts")
    indexes = [item.get("party_index") for item in receipts if isinstance(item, dict)]
    validation.require(sorted(indexes) == list(range(TARGET_PARTIES)), "completion receipt indexes are not exactly 0..6666")
    previous_digest = ZERO_DIGEST
    for offset, item in enumerate(receipts):
        if not isinstance(item, dict):
            validation.require(False, f"completion receipt record {offset} is not an object")
            continue
        index = item.get("party_index")
        label = f"party {index if isinstance(index, int) else offset}"
        expected_party = party_context.get(index, {})
        receipt_path = contained_file(bundle_root, item.get("receipt_path"))
        receipt_signature = contained_file(bundle_root, item.get("receipt_signature_path"))
        receipt_bytes = receipt_path.read_bytes() if receipt_path else b""
        receipt_digest = sha256_bytes(receipt_bytes) if receipt_bytes else None
        validation.require(receipt_digest == item.get("receipt_sha256"), f"{label}: receipt digest mismatch")
        verified = False
        identity_key = expected_party.get("identity_public_key")
        if identity_key and receipt_signature and receipt_bytes:
            verified, _ = openssl_verify(identity_key, receipt_signature, receipt_bytes)
        validation.require(verified, f"{label}: receipt signature failed verification")
        try:
            receipt = json.loads(receipt_bytes.decode("utf-8")) if receipt_bytes else {}
        except (UnicodeError, json.JSONDecodeError):
            receipt = {}
        expected_bindings = {
            "campaign_id": inventory_context["campaign_id"],
            "custody_attestation_sha256": expected_party.get("custody_attestation_sha256"),
            "endpoint": expected_party.get("endpoint"),
            "global_transcript_sha256": transcript_digest,
            "identity_public_key_sha256": expected_party.get("identity_public_key_sha256"),
            "party_index": index,
            "previous_receipt_sha256": previous_digest,
            "roster_digest": inventory_context["roster_digest"],
            "run_nonce": run_nonce,
            "signer_id": expected_party.get("signer_id"),
            "transport_public_key_sha256": expected_party.get("transport_public_key_sha256"),
        }
        validation.require(receipt.get("schema") == RECEIPT_SCHEMA, f"{label}: receipt schema mismatch")
        for field, expected in expected_bindings.items():
            actual_value = canonical_endpoint(receipt.get(field)) if field == "endpoint" else receipt.get(field)
            validation.require(actual_value == expected, f"{label}: receipt binding mismatch for {field}")
        validation.require(receipt.get("exit_code") == 0, f"{label}: nonzero process exit")
        validation.require(receipt.get("timed_out") is False, f"{label}: timed out")
        validation.require(receipt.get("restart_count") == 0, f"{label}: process restarted")
        validation.require(receipt.get("completion_marker") == "mldsa65_expandmask_complete", f"{label}: completion marker missing")
        validation.require(receipt.get("runtime_sha256") == protocol.get("runtime_sha256"), f"{label}: runtime digest mismatch")
        validation.require(receipt.get("source_sha256") == protocol.get("source_sha256"), f"{label}: source digest mismatch")
        validation.require(receipt.get("schedule_sha256") == protocol.get("schedule_sha256"), f"{label}: schedule digest mismatch")
        validation.require(receipt.get("bytecode_sha256") == protocol.get("bytecode_sha256"), f"{label}: bytecode digest mismatch")
        validation.require(receipt.get("statistical_security_parameter", 0) >= MIN_SECURITY, f"{label}: security parameter below 40")
        for field in ("dkg_transcript_sha256", "output_share_sha256"):
            validation.require(is_digest(receipt.get(field)), f"{label}: invalid receipt digest {field}")
        validation.require(
            receipt.get("dkg_transcript_sha256")
            == expected_party.get("attestation", {}).get("dkg_transcript_sha256"),
            f"{label}: DKG transcript is not custody-bound",
        )
        log_path = contained_file(bundle_root, item.get("log_path"))
        log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path else ""
        validation.require(log_path is not None and sha256_path(log_path) == item.get("log_sha256"), f"{label}: log digest mismatch")
        lowered = log_text.lower()
        validation.require("mldsa65_expandmask_complete" in log_text, f"{label}: completion marker absent from log")
        validation.require(not any(pattern in lowered for pattern in FORBIDDEN_LOG_PATTERNS), f"{label}: malicious-protocol failure marker present")
        output_share = contained_file(bundle_root, item.get("output_share_path"))
        validation.require(
            output_share is not None
            and sha256_path(output_share) == item.get("output_share_sha256")
            and item.get("output_share_sha256") == receipt.get("output_share_sha256"),
            f"{label}: output-share digest mismatch",
        )
        previous_digest = receipt_digest or ZERO_DIGEST

    valid, errors = validation.result()
    checks = {
        "completion_bundle_valid": valid,
        "exactly_6667_signed_completion_receipts": len(receipts) == TARGET_PARTIES and sorted(indexes) == list(range(TARGET_PARTIES)),
        "full_output_matches_independent_oracle": actual_raw == oracle_raw and bool(actual_raw),
        "global_transcript_digest_bound": transcript is not None and transcript_digest == completion.get("global_transcript_sha256"),
        "run_nonce_bound": completion.get("run_nonce") == run_nonce,
    }
    return valid, errors, checks


def descendants_rss_kib(root_pid):
    completed = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,rss="],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode != 0:
        return None
    records = []
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) == 3 and all(field.isdigit() for field in fields):
            records.append(tuple(map(int, fields)))
    selected = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, parent, _ in records:
            if parent in selected and pid not in selected:
                selected.add(pid)
                changed = True
    return sum(rss for pid, _, rss in records if pid in selected)


def run_bounded_probe(root, mp_spdz_root, out_dir, timeout_seconds):
    probe_out = Path(out_dir) / "bounded-two-party-probe"
    command = [
        os.environ.get("PYTHON", "python3"),
        str(Path(root) / "scripts/run_exact_expandmask_mpc_equivalence.py"),
        "--root",
        str(root),
        "--mp-spdz-root",
        str(mp_spdz_root),
        "--runtime-binary",
        "mama-party.x",
        "--signers",
        "2",
        "--components",
        str(COMPONENTS),
        "--coefficients",
        str(COEFFICIENTS),
        "--security-parameter",
        str(MIN_SECURITY),
        "--timeout-seconds",
        str(timeout_seconds),
        "--port",
        "22000",
        "--out",
        str(probe_out),
    ]
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    peak_rss_kib = 0
    outer_timed_out = False
    while process.poll() is None:
        rss = descendants_rss_kib(process.pid)
        peak_rss_kib = max(peak_rss_kib, rss or 0)
        if time.monotonic() - started > timeout_seconds + 30:
            os.killpg(process.pid, signal.SIGTERM)
            outer_timed_out = True
            break
        time.sleep(0.2)
    stdout, stderr = process.communicate()
    manifest_path = probe_out / "manifest.json"
    manifest = load_json(manifest_path) if manifest_path.is_file() else None
    passed = bool(
        process.returncode == 0
        and not outer_timed_out
        and isinstance(manifest, dict)
        and manifest.get("malicious_test_scale_execution_passed") is True
        and manifest.get("execution", {}).get("signers") == 2
        and manifest.get("execution", {}).get("statistical_security_parameter") >= MIN_SECURITY
    )
    return {
        "classification": "bounded_local_two_party_mama_probe_not_scale_evidence",
        "command": command,
        "duration_seconds": time.monotonic() - started,
        "exit_code": process.returncode,
        "manifest_path": str(manifest_path),
        "manifest_sha256": sha256_path(manifest_path),
        "outer_timed_out": outer_timed_out,
        "passed": passed,
        "peak_process_tree_rss_kib": peak_rss_kib or None,
        "stderr_tail": stderr[-4000:],
        "stdout_tail": stdout[-4000:],
    }, manifest


def local_addresses():
    addresses = set()
    try:
        completed = subprocess.run(
            ["ifconfig"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        for value in re.findall(r"\binet6?\s+([^%\s]+)", completed.stdout):
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if (
                not address.is_loopback
                and not address.is_unspecified
                and not address.is_link_local
            ):
                addresses.add(str(address))
    except OSError:
        pass
    return sorted(addresses)


def host_resources(root):
    soft_processes, hard_processes = resource.getrlimit(resource.RLIMIT_NPROC)
    soft_files, hard_files = resource.getrlimit(resource.RLIMIT_NOFILE)
    memory_bytes = None
    try:
        if sysctl := shutil.which("sysctl"):
            completed = subprocess.run(
                [sysctl, "-n", "hw.memsize"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if completed.stdout.strip().isdigit():
                memory_bytes = int(completed.stdout.strip())
    except OSError:
        pass
    disk = shutil.disk_usage(root)
    return {
        "cpu_count": os.cpu_count(),
        "local_host_count": 1,
        "local_topology_classification": "single_local_host",
        "memory_bytes": memory_bytes,
        "non_loopback_addresses": local_addresses(),
        "open_files_hard": hard_files,
        "open_files_soft": soft_files,
        "processes_hard": hard_processes,
        "processes_soft": soft_processes,
        "workspace_disk_free_bytes": disk.free,
    }


def measured_values(manifest):
    if not isinstance(manifest, dict):
        return None
    execution = manifest.get("execution", {})
    logs = execution.get("log_tails", {})
    per_party_mb = []
    global_mb = []
    benchmark_seconds = []
    rounds = []
    for text in logs.values() if isinstance(logs, dict) else []:
        match = re.search(r"Data sent = ([0-9.]+) MB", text)
        if match:
            per_party_mb.append(float(match.group(1)))
        match = re.search(r"Global data sent = ([0-9.]+) MB", text)
        if match:
            global_mb.append(float(match.group(1)))
        match = re.search(r"Time = ([0-9.]+) seconds", text)
        if match:
            benchmark_seconds.append(float(match.group(1)))
        match = re.search(r"~([0-9]+) rounds", text)
        if match:
            rounds.append(int(match.group(1)))
    signers = execution.get("signers")
    if not per_party_mb or not global_mb or not isinstance(signers, int) or signers < 2:
        return None
    return {
        "benchmark_seconds_max": max(benchmark_seconds) if benchmark_seconds else None,
        "global_data_mb": max(global_mb),
        "party_count": signers,
        "per_party_data_mb_max": max(per_party_mb),
        "rounds_max": max(rounds) if rounds else None,
        "runner_wall_seconds": execution.get("duration_seconds"),
        "security_parameter": execution.get("statistical_security_parameter"),
    }


def resource_estimates(measured, probe, host):
    estimates = {
        "all_to_all_pair_count": TARGET_PARTIES * (TARGET_PARTIES - 1) // 2,
        "minimum_party_processes": TARGET_PARTIES,
        "measured_source": measured,
        "notes": [
            "Two-party measurements do not establish 6,667-party feasibility.",
            "The optimistic traffic floor assumes measured per-party traffic does not grow with peers.",
            "The pairwise extrapolation assumes per-party traffic grows in proportion to n-1; it is a topology-sensitive planning bound, not a benchmark.",
            "Wall time, CPU, and RAM require a staged distributed campaign and cannot be inferred reliably from a two-party run.",
        ],
    }
    if measured:
        measured_n = measured["party_count"]
        per_party_mb = measured["per_party_data_mb_max"]
        optimistic_total_mb = per_party_mb * TARGET_PARTIES
        pairwise_per_party_mb = per_party_mb * (TARGET_PARTIES - 1) / (measured_n - 1)
        pairwise_total_mb = pairwise_per_party_mb * TARGET_PARTIES
        estimates.update(
            optimistic_total_network_mb=optimistic_total_mb,
            pairwise_extrapolated_per_party_network_mb=pairwise_per_party_mb,
            pairwise_extrapolated_total_network_mb=pairwise_total_mb,
            network_transfer_floor_seconds={
                str(gbps): {
                    "optimistic_total": optimistic_total_mb * 1_000_000 * 8 / (gbps * 1_000_000_000),
                    "pairwise_extrapolated_total": pairwise_total_mb * 1_000_000 * 8 / (gbps * 1_000_000_000),
                }
                for gbps in (10, 25, 100)
            },
        )
    peak = probe.get("peak_process_tree_rss_kib") if isinstance(probe, dict) else None
    if isinstance(peak, int) and peak > 0:
        estimates["bounded_probe_peak_process_tree_rss_kib"] = peak
        estimates["optimistic_linear_memory_floor_bytes"] = int(
            peak * 1024 / 2 * TARGET_PARTIES
        )
    estimates["local_host_process_limit_sufficient"] = (
        host.get("processes_hard") == resource.RLIM_INFINITY
        or host.get("processes_hard", 0) >= TARGET_PARTIES
    )
    return estimates


def run_orchestrator(command_path, root, completion_path, run_nonce, roster_digest, timeout_seconds):
    try:
        command = load_json(command_path)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {"invoked": False, "error": f"invalid orchestrator command JSON: {exc}"}
    if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
        return {"invoked": False, "error": "orchestrator command JSON must be a non-empty string array"}
    environment = os.environ.copy()
    environment.update(
        MAMA_CAMPAIGN_RUN_NONCE=run_nonce,
        MAMA_COMPLETION_BUNDLE=str(Path(completion_path).resolve()),
        MAMA_ROSTER_DIGEST=roster_digest,
    )
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
        return {
            "command": command,
            "duration_seconds": time.monotonic() - started,
            "exit_code": completed.returncode,
            "invoked": True,
            "stderr_tail": completed.stderr[-4000:],
            "stdout_tail": completed.stdout[-4000:],
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command,
            "duration_seconds": time.monotonic() - started,
            "exit_code": None,
            "invoked": True,
            "stderr_tail": (exc.stderr or "")[-4000:] if isinstance(exc.stderr, str) else "",
            "stdout_tail": (exc.stdout or "")[-4000:] if isinstance(exc.stdout, str) else "",
            "timed_out": True,
        }


def build_summary(manifest):
    resource_plan = manifest["resource_plan"]
    measured = resource_plan.get("measured_source") or {}
    blockers = "\n".join(f"- {item}" for item in manifest["blockers"])
    return f"""# Malicious-MAMA 6,667-party scale run

- Status: `{manifest['status']}`
- Classification: `{manifest['campaign_classification']}`
- Real cryptographic parties completed: `{str(manifest['claim_flags']['claims_real_malicious_mama_6667_custodial_execution']).lower()}`
- Theorem closure claimed: `false`
- Bounded local probe passed: `{str(manifest['bounded_probe'].get('passed') is True).lower()}`

## Measured basis

- Measured parties: `{measured.get('party_count')}`
- Security parameter: `{measured.get('security_parameter')}`
- Measured global data: `{measured.get('global_data_mb')} MB`
- Measured maximum per-party data: `{measured.get('per_party_data_mb_max')} MB`
- Measured protocol rounds: `{measured.get('rounds_max')}`
- Measured benchmark time: `{measured.get('benchmark_seconds_max')} seconds`

## Scale planning bounds

- Optimistic total traffic floor: `{resource_plan.get('optimistic_total_network_mb')} MB`
- Pairwise total traffic extrapolation: `{resource_plan.get('pairwise_extrapolated_total_network_mb')} MB`
- All-to-all peer pairs: `{resource_plan.get('all_to_all_pair_count')}`
- Local process hard limit: `{manifest['host']['processes_hard']}`
- Required party processes: `{TARGET_PARTIES}`

## Blockers

{blockers}

These results are preflight and bounded-probe evidence only. A local collection
of labels, ports, or subprocesses is not 6,667 distinct custodial signers.
"""


def write_artifacts(out_dir, manifest):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "manifest.json").write_text(pretty_json(manifest), encoding="utf-8")
    (out_dir / "summary.md").write_text(build_summary(manifest), encoding="utf-8")
    records = []
    for path in sorted(out_dir.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            records.append(f"{sha256_path(path)}  {path.relative_to(out_dir)}")
    (out_dir / "SHA256SUMS").write_text("\n".join(records) + "\n", encoding="ascii")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--inventory")
    parser.add_argument("--trusted-custody-root-sha256", action="append", default=[])
    parser.add_argument("--orchestrator-command-json")
    parser.add_argument("--completion-bundle")
    parser.add_argument("--orchestrator-timeout-seconds", type=int, default=86_400)
    parser.add_argument("--run-bounded-probe", action="store_true")
    parser.add_argument("--mp-spdz-root", default=os.environ.get("MP_SPDZ_ROOT"))
    parser.add_argument("--probe-timeout-seconds", type=int, default=300)
    parser.add_argument("--measured-evidence", default=DEFAULT_MEASURED)
    parser.add_argument("--out", default=DEFAULT_OUT)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    root = Path(args.root).resolve()
    out_dir = Path(args.out)
    if not out_dir.is_absolute():
        out_dir = root / out_dir
    measured_path = Path(args.measured_evidence)
    if not measured_path.is_absolute():
        measured_path = root / measured_path

    bounded_probe = {
        "classification": "not_requested",
        "passed": False,
    }
    measured_manifest = load_json(measured_path) if measured_path.is_file() else None
    if args.run_bounded_probe:
        if not args.mp_spdz_root:
            bounded_probe = {
                "classification": "not_run",
                "error": "--mp-spdz-root or MP_SPDZ_ROOT is required",
                "passed": False,
            }
        else:
            bounded_probe, probe_manifest = run_bounded_probe(
                root, Path(args.mp_spdz_root).resolve(), out_dir, args.probe_timeout_seconds
            )
            if probe_manifest is not None:
                measured_manifest = probe_manifest

    inventory_valid, inventory_errors, inventory_checks, party_context, inventory_context = validate_inventory(
        args.inventory, args.trusted_custody_root_sha256
    )
    run_nonce = secrets.token_hex(32)
    orchestrator = {"invoked": False, "reason": "production preflight did not pass"}
    if inventory_valid and args.orchestrator_command_json and args.completion_bundle:
        orchestrator = run_orchestrator(
            args.orchestrator_command_json,
            root,
            args.completion_bundle,
            run_nonce,
            inventory_context["roster_digest"],
            args.orchestrator_timeout_seconds,
        )
    elif inventory_valid:
        orchestrator = {
            "invoked": False,
            "reason": "both --orchestrator-command-json and --completion-bundle are required",
        }

    completion_valid = False
    completion_errors = ["completion validation was not attempted"]
    completion_checks = {}
    if inventory_valid and orchestrator.get("invoked") and orchestrator.get("exit_code") == 0:
        completion_valid, completion_errors, completion_checks = validate_completion(
            args.completion_bundle, inventory_context, party_context, run_nonce
        )

    real_completed = bool(
        inventory_valid
        and orchestrator.get("invoked")
        and orchestrator.get("exit_code") == 0
        and orchestrator.get("timed_out") is False
        and completion_valid
    )
    host = host_resources(root)
    measured = measured_values(measured_manifest)
    if measured is not None:
        measured["evidence_path"] = str(measured_path.resolve())
        measured["evidence_sha256"] = sha256_path(measured_path)
    plan = resource_estimates(measured, bounded_probe, host)
    blockers = []
    if not inventory_valid:
        blockers.extend(inventory_errors)
    if not plan["local_host_process_limit_sufficient"]:
        blockers.append(
            f"local hard process limit {host['processes_hard']} is below {TARGET_PARTIES} parties"
        )
    if host.get("local_host_count") == 1 and not inventory_valid:
        blockers.append(
            "preflight detected one local host; local interfaces, ports, or processes cannot represent 6,667 distinct custodial signer hosts"
        )
    if inventory_valid and not orchestrator.get("invoked"):
        blockers.append(orchestrator.get("reason", orchestrator.get("error", "external orchestrator was not invoked")))
    if orchestrator.get("invoked") and orchestrator.get("exit_code") != 0:
        blockers.append("external 6,667-party orchestrator did not complete successfully")
    if inventory_valid and orchestrator.get("invoked") and not completion_valid:
        blockers.extend(completion_errors)
    if measured is None:
        blockers.append("no parseable malicious-MAMA resource measurement is bound")
    blockers.extend(
        [
            "distributed CPU, memory, bandwidth, and round-latency capacity has not been reserved and measured",
            "6,667 production custody roots and signer endpoints are not available in this environment",
        ]
        if not real_completed
        else []
    )
    blockers = list(dict.fromkeys(blockers))
    manifest = {
        "schema": SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "real_malicious_mama_6667_completed" if real_completed else "blocked_fail_closed",
        "campaign_classification": (
            "real_malicious_mama_6667_custodial"
            if real_completed
            else (
                "distributed_nonproduction_probe"
                if inventory_valid
                else "local_simulation_or_preflight_only"
            )
        ),
        "target": {
            "party_count": TARGET_PARTIES,
            "threshold": TARGET_PARTIES,
            "validator_count": 10_000,
            "parameter_set": "ML-DSA-65",
            "output_coefficient_count": OUTPUT_COUNT,
        },
        "host": host,
        "bounded_probe": bounded_probe,
        "inventory": {
            "checks": inventory_checks,
            "errors": inventory_errors,
            "path": str(Path(args.inventory).resolve()) if args.inventory else None,
            "valid": inventory_valid,
        },
        "orchestrator": orchestrator,
        "completion": {
            "checks": completion_checks,
            "errors": completion_errors,
            "valid": completion_valid,
        },
        "resource_plan": plan,
        "blockers": blockers,
        "claim_flags": {
            "claims_bounded_two_party_mama_probe": bounded_probe.get("passed") is True,
            "claims_real_malicious_mama_6667_custodial_execution": real_completed,
            "claims_6667_distinct_cryptographic_parties": real_completed,
            "claims_production_private_share_custody": real_completed,
            "claims_production_threshold_mldsa_security": False,
            "claims_theorem_closure": False,
        },
    }
    write_artifacts(out_dir, manifest)
    print(f"status={manifest['status']}")
    print(f"campaign_classification={manifest['campaign_classification']}")
    print(f"artifact={out_dir / 'manifest.json'}")
    return 0 if real_completed else 2


if __name__ == "__main__":
    raise SystemExit(main())
