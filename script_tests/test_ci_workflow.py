import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


class CiWorkflowTests(unittest.TestCase):
    def test_ci_runs_python_script_tests(self):
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("Python script tests", workflow)
        self.assertIn(
            "python3 -m unittest discover -s script_tests -p 'test_*.py'",
            workflow,
        )

    def test_ci_runs_nonce_producer_handoff_replay(self):
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("Nonce producer handoff replay", workflow)
        self.assertIn(
            "python3 scripts/run_nonce_producer_handoff_replay.py --root . --out /tmp/lattice-nonce-producer-handoff-replay",
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
