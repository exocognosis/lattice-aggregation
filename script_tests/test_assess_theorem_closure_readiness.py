import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "assess_theorem_closure_readiness.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "assess_theorem_closure_readiness",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def criterion2_manifest():
    return {
        "schema": "lattice-aggregation.criterion-2-proof-substance.v1",
        "criterion_id": "aggregate_rejection_equivalence",
        "claim_boundary": {
            "scope": "criterion-2 proof payload only",
            "claims_theorem_closure": False,
            "claims_criterion_met": False,
            "claims_selected_backend_proof_closure": False,
            "claims_standard_verifier_compatibility_complete": False,
            "claims_rejection_distribution_preservation": False,
            "claims_cavp_acvts_validation": False,
            "claims_fips_validation": False,
            "claims_production_threshold_mldsa_security": False,
        },
        "promotion_requires": [
            "reviewed proof payload tying threshold-output, recomputation, bounds, rejection behavior, and standard verification",
            "full KAT/validation artifact package",
            "reviewed rejection-distribution preservation argument",
            "reviewed standard-verifier compatibility argument",
            "reviewed Batch 7 external-backend closure-candidate bundle populated from actual external nonce and real-threshold backend captures",
            "reviewed Batch 8 grouped external-evidence attempt with source_exclusion_passed true and close_candidate true",
            "reviewed Batch 9 external evidence package with review_package_binds_inputs true, source exclusions passed, and review digests present",
            "theorem-linkage review",
        ],
    }


def hypothesis_assessment():
    return {
        "overall_verdict": "partially_proven",
        "claim_boundary": "research scaffold evidence",
    }


def closure_candidate(ready):
    return {
        "schema": "lattice-aggregation:p1-external-backend-cryptographic-closure-candidate:v1",
        "close_candidate": ready,
        "blockers": [] if ready else ["actual external nonce capture readiness required"],
    }


def external_attempt(ready):
    return {
        "schema": "lattice-aggregation:p1-external-backend-evidence-attempt:v1",
        "attempt_status": (
            "external_evidence_close_candidate_ready"
            if ready
            else "blocked_external_evidence_missing"
        ),
        "close_candidate": ready,
        "checks": {
            "source_exclusion_passed": ready,
            "review_package_binds_inputs": ready,
            "review_package_present": ready,
            "review_package_claim_boundary_passed": ready,
            "review_package_source_exclusions_passed": ready,
            "review_package_review_digests_present": ready,
        },
        "blockers": [] if ready else ["reviewed external evidence package is missing"],
    }


def theorem_review(ready=True, claim_boundary=None):
    return {
        "schema": "lattice-aggregation:theorem-closure-review:v1",
        "claim_boundary": (
            claim_boundary
            if claim_boundary is not None
            else "readiness preflight only; pending theorem-closure review"
        ),
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "review_status": "theorem_closure_review_ready" if ready else "blocked",
        "review_flags": {
            "proof_payload_reviewed": ready,
            "full_kat_validation_reviewed": ready,
            "rejection_distribution_preservation_reviewed": ready,
            "standard_verifier_compatibility_reviewed": ready,
            "theorem_linkage_reviewed": ready,
        },
        "claim_flags": {
            "claims_theorem_closure": False,
            "claims_criterion_met": False,
            "claims_selected_backend_proof_closure": False,
            "claims_rejection_distribution_preservation": False,
            "claims_standard_verifier_compatibility_complete": False,
            "claims_production_threshold_mldsa_security": False,
            "claims_cavp_acvts_validation": False,
            "claims_fips_validation": False,
        },
    }


def write_minimal_inputs(root, *, external_ready, review_ready=None):
    criterion2_path = root / "criterion2.json"
    hypothesis_path = root / "assessment.json"
    candidate_path = root / "candidate.json"
    attempt_path = root / "attempt.json"
    review_path = root / "review.json"
    write_json(criterion2_path, criterion2_manifest())
    write_json(hypothesis_path, hypothesis_assessment())
    write_json(candidate_path, closure_candidate(external_ready))
    write_json(attempt_path, external_attempt(external_ready))
    if review_ready is not None:
        write_json(review_path, theorem_review(review_ready))
    return {
        "criterion2_manifest_path": criterion2_path,
        "hypothesis_assessment_path": hypothesis_path,
        "closure_candidate_path": candidate_path,
        "external_attempt_path": attempt_path,
        "theorem_review_path": review_path,
    }


class TheoremClosureReadinessTests(unittest.TestCase):
    def test_current_checked_in_artifacts_remain_blocked_before_assessment(self):
        module = load_module()

        report = module.build_report(ROOT, generated_at="2026-07-04T00:00:00Z")

        manifest = report["manifest"]
        self.assertEqual(
            manifest["readiness_status"],
            "blocked_before_theorem_closure_assessment",
        )
        self.assertFalse(manifest["theorem_closure_assessment_ready"])
        self.assertFalse(manifest["claims_theorem_closure"])
        self.assertFalse(manifest["checks"]["external_evidence_attempt_ready"])
        self.assertFalse(manifest["checks"]["theorem_review_manifest_present"])
        self.assertIn(
            "reviewed external evidence package is missing",
            " ".join(manifest["blocker_groups"]["external_backend_evidence"]),
        )

    def test_external_ready_bundle_without_theorem_review_stays_blocked(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            paths = write_minimal_inputs(root, external_ready=True, review_ready=None)
            report = module.build_report(
                root,
                generated_at="2026-07-04T00:00:00Z",
                **paths,
            )

        manifest = report["manifest"]
        self.assertTrue(manifest["checks"]["external_evidence_attempt_ready"])
        self.assertFalse(manifest["checks"]["theorem_review_manifest_present"])
        self.assertFalse(manifest["theorem_closure_assessment_ready"])
        self.assertIn(
            "theorem review manifest is missing required ready flag: proof_payload_reviewed",
            manifest["blocker_groups"]["proof_payload_review"],
        )
        self.assertIn(
            "theorem review manifest is missing required ready flag: full_kat_validation_reviewed",
            manifest["blocker_groups"]["validation"],
        )

    def test_ready_external_and_review_bundle_can_start_assessment_without_closure_claims(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            paths = write_minimal_inputs(root, external_ready=True, review_ready=True)
            report = module.build_report(
                root,
                generated_at="2026-07-04T00:00:00Z",
                **paths,
            )

        manifest = report["manifest"]
        self.assertEqual(
            manifest["readiness_status"],
            "ready_for_theorem_closure_assessment",
        )
        self.assertTrue(manifest["theorem_closure_assessment_ready"])
        self.assertTrue(all(manifest["checks"][key] for key in manifest["ready_checks"]))
        self.assertFalse(any(manifest[key] for key in module.CLAIM_FLAG_KEYS))
        self.assertTrue(all(len(group) == 0 for group in manifest["blocker_groups"].values()))

    def test_theorem_review_claim_boundary_blocks_readiness(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            paths = write_minimal_inputs(root, external_ready=True, review_ready=True)
            bad_review = theorem_review(True, claim_boundary="theorem closure")
            write_json(paths["theorem_review_path"], bad_review)
            report = module.build_report(
                root,
                generated_at="2026-07-04T00:00:00Z",
                **paths,
            )

        manifest = report["manifest"]
        self.assertFalse(manifest["theorem_closure_assessment_ready"])
        self.assertFalse(manifest["checks"]["theorem_review_manifest_boundary_valid"])
        self.assertIn(
            "theorem review manifest boundary is invalid",
            manifest["blocker_groups"]["proof_payload_review"],
        )

    def test_strict_main_returns_two_until_ready(self):
        module = load_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            out_dir = root / "readiness"
            code = module.main(
                [
                    "--root",
                    str(root),
                    "--out",
                    str(out_dir),
                    "--strict",
                ]
            )
            manifest_written = (out_dir / "manifest.json").is_file()

        self.assertEqual(code, 2)
        self.assertTrue(manifest_written)


if __name__ == "__main__":
    unittest.main()
