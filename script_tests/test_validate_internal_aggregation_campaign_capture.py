import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD_SCRIPT = ROOT / "scripts" / "build_internal_aggregation_campaign_request.py"
VALIDATE_SCRIPT = ROOT / "scripts" / "validate_internal_aggregation_campaign_capture.py"


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(value):
    return hashlib.sha256(value).hexdigest()


def canonical_json(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


CAPABILITY_FIELDS = [
    "distributed_dkg_vss",
    "fips204_exact_distributed_key_generation",
    "exact_distributed_keygen",
    "private_per_receiver_share_custody",
    "per_receiver_private_share_custody",
]


def capability_evidence_fixture(root):
    source_records = []
    source_root = root / "evidence" / "capability-sources"
    for role in (
        "distributed_dkg_vss_source",
        "fips_public_key_source",
        "share_transport_source",
        "receiver_custody_source",
        "strict_fips_sign_source",
        "campaign_emitter_source",
    ):
        source_path = source_root / f"{role}.rs"
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_bytes = f"contract capability source fixture:{role}\n".encode()
        source_path.write_bytes(source_bytes)
        source_records.append(
            {
                "role": role,
                "path": str(source_path),
                "sha256": digest(source_bytes),
            }
        )

    statuses = {}
    for field in CAPABILITY_FIELDS:
        status = {
            "field": field,
            "claim_value": False,
            "status": "contract_fixture_counterevidence",
            "source_roles": [source_records[0]["role"], source_records[-1]["role"]],
            "source_digests": [source_records[0], source_records[-1]],
            "positive_evidence": ["fixture source digest is present"],
            "counter_evidence": ["fixture keeps unsupported DKG/custody claim false"],
            "claim_boundary": "digest-bound primitive evidence only; unsupported campaign capability booleans remain false",
        }
        status["evidence_digest_hex"] = digest(canonical_json(status).encode())
        statuses[field] = status

    aggregate_input = {
        "schema": "lattice-threshold-backend-p1:dkg-custody-capability-evidence:v1",
        "source_digests": source_records,
        "capability_statuses": statuses,
    }
    aggregate_digest = digest(canonical_json(aggregate_input).encode())
    return {
        "schema": "lattice-threshold-backend-p1:dkg-custody-capability-evidence:v1",
        "capability_fields": CAPABILITY_FIELDS,
        "source_digests": source_records,
        "capability_statuses": statuses,
        "aggregate_evidence_digest_hex": aggregate_digest,
        "claim_boundary": {
            "claims_theorem_closure": False,
            "claims_production_threshold_mldsa_security": False,
        },
    }


def evidence_bundle(root, roles):
    records = []
    for role in roles:
        path = pathlib.Path("evidence") / f"{role}.bin"
        full_path = root / path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        if role == "dkg_custody_capability_evidence":
            path = pathlib.Path("evidence") / "dkg-custody-capability-evidence.json"
            full_path = root / path
            evidence = capability_evidence_fixture(root)
            content = canonical_json(evidence).encode()
            full_path.write_bytes(content)
            records.append(
                {
                    "role": role,
                    "path": path.as_posix(),
                    "sha256": digest(content),
                    "aggregate_evidence_digest_hex": evidence["aggregate_evidence_digest_hex"],
                }
            )
        else:
            content = f"contract-test:{role}\n".encode()
            full_path.write_bytes(content)
            records.append({"role": role, "path": path.as_posix(), "sha256": digest(content)})
    return records


class ReviewedAuthorizationVerifier:
    verifier_id = "test-reviewed-threshold-authorization-verifier-v1"
    implementation_sha256 = digest(b"reviewed-test-verifier-implementation-v1")

    def __call__(self, certificate, request):
        return (
            certificate.get("campaign_id") == request.get("campaign_id")
            and certificate.get("test_reviewed_signature_fixture") is True
        )


def verifier_profile(verifier):
    return {
        "verifier_id": verifier.verifier_id,
        "verifier_implementation_sha256": verifier.implementation_sha256,
    }


def install_valid_authorization(root, request, records, capture, validator):
    """Install a complete deterministic 6667-of-10000 reviewed test certificate."""
    validator_ids = list(range(1, 10_001))
    validator_set_digest = validator.sha256_text(validator.canonical_json(validator_ids))
    request_digest = validator.sha256_text(validator.canonical_json(request))
    authorizers = [
        {
            "validator_id": validator_id,
            "public_key_digest_hex": digest(f"pk:{validator_id}".encode()),
            "signature_hex": "01",
            "signature_digest_hex": digest(b"\x01"),
        }
        for validator_id in range(1, 6_668)
    ]
    committees = []
    for size in (8, 16, 32, 64):
        committee_ids = list(range(1, size + 1))
        committee_digest = validator.sha256_text(
            validator.canonical_json(committee_ids)
        )
        session_binding = validator.sha256_text(
            validator.canonical_json(
                {
                    "campaign_id": request["campaign_id"],
                    "request_sha256": request_digest,
                    "committee_size": size,
                    "committee_digest_hex": committee_digest,
                }
            )
        )
        committees.append(
            {
                "committee_size": size,
                "committee_validator_ids": committee_ids,
                "committee_digest_hex": committee_digest,
                "session_binding_digest_hex": session_binding,
                "authorizer_records": authorizers,
            }
        )
    transcript_digest = digest(b"reviewed authorization transcript")
    certificate = {
        "schema": "lattice-aggregation:threshold-authorization-certificate:v1",
        "campaign_id": request["campaign_id"],
        "request_sha256": request_digest,
        "validator_count": 10_000,
        "threshold": 6_667,
        "validator_ids": validator_ids,
        "validator_set_digest_hex": validator_set_digest,
        "committee_authorizations": committees,
        "authorization_transcript_digest_hex": transcript_digest,
        "test_reviewed_signature_fixture": True,
    }
    record = next(
        item for item in records if item["role"] == "authorization_certificate"
    )
    certificate_path = root / record["path"]
    certificate_path.write_text(validator.canonical_json(certificate), encoding="utf-8")
    certificate_digest = validator.sha256_path(certificate_path)
    record["sha256"] = certificate_digest
    capture["authorization"].update(
        {
            "authorized_validator_set_digest_hex": validator_set_digest,
            "committee_authorization_bundle_digest_hex": validator.sha256_text(
                validator.canonical_json(committees)
            ),
            "authorization_transcript_digest_hex": transcript_digest,
            "certificate_digest_hex": certificate_digest,
        }
    )
    capture["provenance"]["authorization_certificate_digest_hex"] = certificate_digest
    for execution in capture["executions"]:
        execution["authorization_certificate_digest_hex"] = certificate_digest
    return certificate


def capture_for(request, records):
    by_role = {record["role"]: record for record in records}
    authorization_digest = by_role["authorization_certificate"]["sha256"]
    core = {
        "core_mode": "distributed_threshold_mldsa65_partial_aggregation",
        "signature_origin": "threshold_partial_aggregation",
        "distributed_dkg_vss": False,
        "fips204_exact_distributed_key_generation": False,
        "exact_distributed_keygen": False,
        "private_per_receiver_share_custody": False,
        "per_receiver_private_share_custody": False,
        "live_distributed_nonce_generation": True,
        "exact_distributed_expand_mask": True,
        "exact_expand_mask_mpc": True,
        "partial_signing_over_secret_shares": True,
        "partial_z_i_hint_aggregation": True,
        "fips204_rejection_loop_over_threshold_partials": True,
        "no_secret_or_seed_reconstruction": True,
        "standard_wire_output": True,
        "committee_authorization_bound": True,
        "authorization_layer_validator_count": 10000,
        "authorization_layer_threshold": 6667,
        "simulation_used": False,
        "fixture_harness_used": False,
        "single_key_provider_used": False,
        "secret_or_seed_reconstruction_used": False,
        "centralized_signing_oracle_used": False,
        "digest_bound_capability_evidence": {
            "schema": "lattice-threshold-backend-p1:dkg-custody-capability-evidence-binding:v1",
            "evidence_file_role": "dkg_custody_capability_evidence",
            "evidence_file_digest_hex": by_role["dkg_custody_capability_evidence"]["sha256"],
            "aggregate_evidence_digest_hex": by_role["dkg_custody_capability_evidence"][
                "aggregate_evidence_digest_hex"
            ],
            "capability_fields": CAPABILITY_FIELDS,
        },
    }
    executions = []
    for case in request["cases"]:
        required = case["required_observations"]
        aggregate_emitted = required["aggregate_emitted"]
        executions.append(
            {
                "case_id": case["case_id"],
                "case_kind": case["case_kind"],
                "validator_count": case["validator_count"],
                "threshold": case["threshold"],
                "committee_size": case["committee_size"],
                "seed_id": case["seed_id"],
                "seed_sha256": case["seed_sha256"],
                "message_sha256": case["message"]["sha256"],
                "authorization_certificate_digest_hex": authorization_digest,
                "transcript_digest_hex": digest(case["case_id"].encode()),
                "protocol_outcome": required["protocol_outcome"],
                "aggregate_emitted": aggregate_emitted,
                "aggregate_signature_len": 3309 if aggregate_emitted else None,
                "aggregate_signature_digest_hex": (
                    digest((case["case_id"] + ":signature").encode())
                    if aggregate_emitted
                    else None
                ),
                "retry_count": required["retry_count_min"],
                "rejection_predicate_recorded": required["rejection_predicate_recorded"],
                "abort_recorded": required["abort_recorded"],
                "malicious_share_rejected": required["malicious_share_rejected"],
                "transcript_mutation_rejected": required["transcript_mutation_rejected"],
                "standard_verifier": {
                    "invoked": required["standard_verifier_invoked"],
                    "accepted": required["standard_verifier_accepted"],
                    "mutation_rejection": (
                        {"message": True, "public_key": True, "signature": True}
                        if aggregate_emitted
                        else None
                    ),
                },
            }
        )
    canonical_request = build_module().canonical_json(request).encode()
    return {
        "schema": "lattice-aggregation:internal-aggregation-campaign-capture:v1",
        "campaign_id": request["campaign_id"],
        "evidence_class": "actual_distributed_threshold_mldsa_campaign",
        "execution_mode": "actual_distributed_threshold_backend",
        "request_binding": {
            "schema": request["schema"],
            "request_sha256": digest(canonical_request),
        },
        "claim_flags": {flag: False for flag in request["claim_flags"]},
        "cryptographic_core": core,
        "provenance": {
            "source_class": "git_tracked_actual_backend",
            "source_commit": "1a" * 20,
            "backend_name": "distributed-threshold-mldsa65",
            "backend_command": "threshold-mldsa65 campaign-run",
            "repo_clean": True,
            "git_diff_empty": True,
            "untracked_files_empty": True,
            "capture_generated_from_clean_checkout": True,
            "backend_source_digest_hex": by_role["backend_source_archive"]["sha256"],
            "backend_implementation_digest_hex": by_role["backend_implementation_manifest"]["sha256"],
            "backend_binary_digest_hex": by_role["backend_binary"]["sha256"],
            "backend_test_results_digest_hex": by_role["backend_test_results"]["sha256"],
            "proof_artifact_bundle_digest_hex": by_role["proof_artifact_bundle"]["sha256"],
            "authorization_certificate_digest_hex": authorization_digest,
            "toolchain_lock_digest_hex": by_role["toolchain_lock"]["sha256"],
            "environment_digest_hex": by_role["environment_manifest"]["sha256"],
            "capture_command_digest_hex": digest(b"threshold-mldsa65 campaign-run"),
            "transcript_bundle_digest_hex": by_role["transcript_bundle"]["sha256"],
        },
        "authorization": {
            "schema": "lattice-aggregation:threshold-authorization-certificate:v1",
            "validator_count": 10000,
            "threshold": 6667,
            "authorized_validator_set_digest_hex": digest(b"authorized validators"),
            "committee_authorization_bundle_digest_hex": digest(b"selected committees"),
            "authorization_transcript_digest_hex": digest(b"authorization transcript"),
            "certificate_digest_hex": authorization_digest,
        },
        "standard_verifier": {
            "implementation_kind": "unmodified_mldsa65_standard_verifier",
            "parameter_set": "ML-DSA-65",
            "implementation_digest_hex": by_role["standard_verifier_binary"]["sha256"],
        },
        "kat_validation": {
            "parameter_set": "ML-DSA-65",
            "vector_types": ["keyGen", "sigGen", "sigVer"],
            "vector_count": 3,
            "passed_vector_count": 3,
            "failed_vector_count": 0,
            "vector_source_digest_hex": digest(b"NIST ACVP vectors"),
            "results_digest_hex": by_role["kat_results"]["sha256"],
        },
        "evidence_files": records,
        "executions": executions,
    }


def build_module():
    return load_module(BUILD_SCRIPT, "build_internal_aggregation_campaign_request")


class InternalAggregationCampaignCaptureValidationTests(unittest.TestCase):
    def test_cli_writes_blocked_manifest_when_capture_is_missing(self):
        builder = build_module()
        validator = load_module(VALIDATE_SCRIPT, "validate_internal_campaign_cli")
        request_report = builder.build_request("theorem-closure-internal-001")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            request_path = root / "request.json"
            request_path.write_text(request_report["request_json"], encoding="utf-8")
            out_dir = root / "validation"
            exit_code = validator.main(
                [
                    "--request",
                    str(request_path),
                    "--capture",
                    str(root / "missing-capture.json"),
                    "--out",
                    str(out_dir),
                ]
            )
            manifest = json.loads((out_dir / "manifest.json").read_text())

        self.assertEqual(exit_code, 2)
        self.assertEqual(manifest["campaign_status"], "blocked_fail_closed")
        self.assertFalse(manifest["internal_campaign_evidence_ready"])
        self.assertIsNone(manifest["capture_sha256"])
        self.assertTrue(
            manifest["blockers"][0].startswith("campaign capture unavailable or invalid")
        )

    def test_contract_remains_blocked_without_cryptographic_authorization_verifier(self):
        builder = build_module()
        validator = load_module(VALIDATE_SCRIPT, "validate_internal_campaign")
        request = builder.build_request("theorem-closure-internal-001")["request"]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            records = evidence_bundle(root, validator.REQUIRED_EVIDENCE_ROLES)
            capture = capture_for(request, records)
            report = validator.validate_campaign(request, capture, root)

        self.assertEqual(report["campaign_status"], "blocked_fail_closed")
        self.assertFalse(report["internal_campaign_evidence_ready"])
        self.assertEqual(report["validated_execution_count"], 24)
        self.assertEqual(report["preregistered_case_count"], 24)
        self.assertEqual(report["theorem_status"], "unclosed_pending_proof_and_independent_review")
        self.assertFalse(report["claims_theorem_closure"])
        self.assertFalse(report["claims_fips_validation"])
        self.assertEqual(len(report["request_sha256"]), 64)
        self.assertEqual(len(report["capture_sha256"]), 64)
        self.assertEqual(len(report["evidence_bundle_binding_sha256"]), 64)
        self.assertIn(
            "cryptographic authorization signature verification unavailable; campaign remains fail closed",
            report["blockers"],
        )

    def test_bound_reviewed_verifier_can_produce_deterministically_revalidated_result(self):
        builder = build_module()
        validator = load_module(VALIDATE_SCRIPT, "validate_internal_campaign_reviewed")
        verifier = ReviewedAuthorizationVerifier()
        request = builder.build_request(
            "theorem-closure-internal-001",
            authorization_verifier_profile=verifier_profile(verifier),
        )["request"]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            records = evidence_bundle(root, validator.REQUIRED_EVIDENCE_ROLES)
            capture = capture_for(request, records)
            install_valid_authorization(root, request, records, capture, validator)
            report = validator.validate_campaign(
                request, capture, root, authorization_verifier=verifier
            )
            repeated = validator.validate_campaign(
                request, capture, root, authorization_verifier=verifier
            )

        self.assertTrue(report["internal_campaign_evidence_ready"])
        self.assertEqual(report["blockers"], [])
        self.assertTrue(report["authorization_verification"]["verified"])
        self.assertEqual(report, repeated)

    def test_simulated_or_reconstructed_core_fails_closed(self):
        builder = build_module()
        validator = load_module(VALIDATE_SCRIPT, "validate_internal_campaign_simulated")
        request = builder.build_request("theorem-closure-internal-001")["request"]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            capture = capture_for(
                request, evidence_bundle(root, validator.REQUIRED_EVIDENCE_ROLES)
            )
            capture["cryptographic_core"]["simulation_used"] = True
            capture["cryptographic_core"]["secret_or_seed_reconstruction_used"] = True
            report = validator.validate_campaign(request, capture, root)

        self.assertEqual(report["campaign_status"], "blocked_fail_closed")
        self.assertFalse(report["internal_campaign_evidence_ready"])
        self.assertIn(
            "cryptographic core exclusion must be false: simulation_used",
            report["blockers"],
        )
        self.assertIn(
            "cryptographic core exclusion must be false: secret_or_seed_reconstruction_used",
            report["blockers"],
        )

    def test_missing_authorization_or_mutation_evidence_fails_closed(self):
        builder = build_module()
        validator = load_module(VALIDATE_SCRIPT, "validate_internal_campaign_missing")
        request = builder.build_request("theorem-closure-internal-001")["request"]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            capture = capture_for(
                request, evidence_bundle(root, validator.REQUIRED_EVIDENCE_ROLES)
            )
            capture["authorization"] = None
            accepted = next(
                execution
                for execution in capture["executions"]
                if execution["case_kind"] == "accepted"
            )
            accepted["standard_verifier"]["mutation_rejection"]["signature"] = False
            report = validator.validate_campaign(request, capture, root)

        self.assertEqual(report["campaign_status"], "blocked_fail_closed")
        self.assertIn("threshold authorization record missing", report["blockers"])
        self.assertTrue(
            any("verifier mutation rejection must be true: signature" in blocker for blocker in report["blockers"])
        )

    def test_dirty_provenance_and_tampered_evidence_fail_closed(self):
        builder = build_module()
        validator = load_module(VALIDATE_SCRIPT, "validate_internal_campaign_dirty")
        request = builder.build_request("theorem-closure-internal-001")["request"]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            records = evidence_bundle(root, validator.REQUIRED_EVIDENCE_ROLES)
            capture = capture_for(request, records)
            capture["provenance"]["repo_clean"] = False
            (root / "evidence" / "backend_binary.bin").write_bytes(b"tampered")
            report = validator.validate_campaign(request, capture, root)

        self.assertEqual(report["campaign_status"], "blocked_fail_closed")
        self.assertIn("clean provenance check must be true: repo_clean", report["blockers"])
        self.assertIn("evidence file digest mismatch: backend_binary", report["blockers"])


if __name__ == "__main__":
    unittest.main()
