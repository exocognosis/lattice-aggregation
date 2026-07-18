import importlib.util
import pathlib
import subprocess
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "model_distributed_mask_mpc_feasibility.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "model_distributed_mask_mpc_feasibility", SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DistributedMaskMpcFeasibilityTests(unittest.TestCase):
    def test_model_keeps_non_closure_claim_flags_false(self):
        module = load_module()

        model = module.build_model()

        self.assertEqual(
            model["schema"],
            "lattice-aggregation:distributed-mask-mpc-feasibility-model:v1",
        )
        self.assertEqual(model["status"], "feasibility_model_only")
        self.assertEqual(model["evidence_status"], "evidence_present_unclosed")
        self.assertEqual(model["overall_verdict_preserved"], "partially_proven")
        self.assertEqual(
            model["criterion_status_preserved"]["aggregate_mask_distribution"],
            "partially_met",
        )
        self.assertFalse(any(model["claim_flags"].values()))
        self.assertFalse(model["claim_flags"]["claims_selected_backend_proof_closure"])
        self.assertFalse(model["claim_flags"]["claims_epsilon_mask_closed"])
        self.assertIn("does not close epsilon_mask", model["non_closure_guards"])
        self.assertIn("joint ExpandMask-uniform y sampling", model["mpc_scope"]["inside_mpc"])

    def test_go_no_go_pins_epoch_go_and_fast_block_no_go(self):
        module = load_module()

        results = {entry["target"]: entry for entry in module.build_model()["go_no_go"]}

        self.assertEqual(results["solana_0_4s_block"]["verdict"], "no_go")
        self.assertEqual(
            results["epoch_certificate_6_4min"]["verdict"],
            "go_even_worst_case",
        )
        self.assertLess(
            results["epoch_certificate_6_4min"]["worst_case_seconds"],
            results["epoch_certificate_6_4min"]["budget_seconds"],
        )

    def test_json_cli_emits_canonical_model(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertIn('"status": "feasibility_model_only"', completed.stdout)
        self.assertIn('"claims_theorem_closure": false', completed.stdout)


if __name__ == "__main__":
    unittest.main()
