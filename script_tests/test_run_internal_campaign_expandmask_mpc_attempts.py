import importlib.util
import json
import pathlib
import shutil
import types
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_internal_campaign_expandmask_mpc_attempts.py"
BUILD_REQUEST = ROOT / "scripts" / "build_internal_aggregation_campaign_request.py"


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InternalCampaignExpandMaskMpcAttemptTests(unittest.TestCase):
    def test_required_cases_are_accepted_and_retry_only(self):
        runner = load_module(SCRIPT, "campaign_mpc_attempt_runner_cases")
        builder = load_module(BUILD_REQUEST, "campaign_request_builder_cases")
        request = builder.build_request("theorem-closure-internal-001")["request"]

        cases = runner.required_cases(request)

        self.assertEqual(len(cases), 8)
        self.assertEqual({case["case_kind"] for case in cases}, {"accepted", "retry"})
        self.assertEqual(cases[0]["case_id"], "k08-accepted-001")

    def test_emit_inputs_uses_campaign_message_hex(self):
        runner = load_module(SCRIPT, "campaign_mpc_attempt_runner_emit")
        calls = []

        def fake_command_result(command, cwd, timeout_seconds, env=None):
            calls.append(command)
            run_dir = pathlib.Path(command[command.index("--run-dir") + 1])
            run_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / "params.json").write_text(
                json.dumps(
                    {
                        "schema": "small-distributed-aggregation:params:v1",
                        "local_rejected_attempts": 0,
                        "local_accepted_kappa_base": 0,
                    }
                ),
                encoding="utf-8",
            )
            return {
                "command": command,
                "cwd": str(cwd),
                "exit_code": 0,
                "duration_seconds": 0.01,
                "timed_out": False,
                "stdout": "",
                "stderr": "",
            }

        original = runner.command_result
        runner.command_result = fake_command_result
        try:
            temp_root = pathlib.Path("/tmp/campaign-mpc-attempt-test")
            if temp_root.exists():
                shutil.rmtree(temp_root)
            temp_root.mkdir()
            args = types.SimpleNamespace(
                root=ROOT,
                small_driver_bin="/opt/small-driver",
                signers=2,
                validator_count=10_000,
                preflight_timeout_seconds=1,
            )
            case = {
                "case_id": "k08-accepted-001",
                "message": {"encoding": "hex", "value": "00ff"},
            }
            _result, params = runner.emit_inputs(
                args,
                case,
                "ab" * 32,
                bytes([0x71]) * 32,
                0,
                temp_root / "work",
            )
        finally:
            runner.command_result = original

        self.assertEqual(params["local_rejected_attempts"], 0)
        self.assertIn("--message-hex", calls[0])
        self.assertNotIn("--message", calls[0])
        self.assertIn("00ff", calls[0])

    def test_choose_counter_selects_retry_counter_and_kappas(self):
        runner = load_module(SCRIPT, "campaign_mpc_attempt_runner_counter")
        calls = []

        def fake_emit_inputs(_args, _case, _request_sha256, _seed, counter, _work_dir):
            calls.append(counter)
            rejected = 0 if counter == 0 else 2
            return (
                {
                    "exit_code": 0,
                    "timed_out": False,
                    "stdout": "",
                    "stderr": "",
                },
                {"local_rejected_attempts": rejected},
            )

        original = runner.emit_inputs
        runner.emit_inputs = fake_emit_inputs
        try:
            args = types.SimpleNamespace(max_counter_search=3)
            case = {"case_id": "k08-retry-001", "case_kind": "retry"}
            selected = runner.choose_counter(args, case, "cd" * 32, bytes([0x71]) * 32)
        finally:
            runner.emit_inputs = original

        self.assertEqual(calls, [0, 1])
        self.assertEqual(selected["counter"], 1)
        self.assertEqual(selected["kappas"], [0, 5, 10])

    def test_run_kappa_blocks_unsafe_full_scale_local_launch(self):
        runner = load_module(SCRIPT, "campaign_mpc_attempt_runner_kappa")
        temp_root = pathlib.Path("/tmp/campaign-mpc-attempt-kappa-test")
        if temp_root.exists():
            shutil.rmtree(temp_root)
        input_dir = temp_root / "input-binding"
        (input_dir / "Player-Data").mkdir(parents=True)
        (input_dir / "Player-Data" / "Input-P0-0").write_text("0\n", encoding="ascii")
        mp_spdz = temp_root / "MP-SPDZ"
        mp_spdz.mkdir()
        (mp_spdz / "mama-party.x").write_text("", encoding="ascii")
        args = types.SimpleNamespace(
            root=temp_root,
            mp_spdz_root=mp_spdz,
            runtime_binary="mama-party.x",
            signers=6667,
            max_local_parties=64,
            allow_large_local_run=False,
            compile_missing=False,
            compile_timeout_seconds=1,
            mpc_timeout_seconds=1,
            port_base=20000,
            security_parameter=40,
            keep_execution_dirs=False,
        )

        attempt = runner.run_kappa(args, temp_root / "case" / "counter-000", input_dir, 0, 0, 0)

        self.assertFalse(attempt["malicious_mpc_verified"])
        self.assertTrue(
            any("exceeds safe limit" in blocker for blocker in attempt["blockers"])
        )

    def test_run_kappa_retries_sigkill_and_accepts_clean_second_launch(self):
        runner = load_module(SCRIPT, "campaign_mpc_attempt_runner_retry")
        temp_root = pathlib.Path("/tmp/campaign-mpc-attempt-retry-test")
        if temp_root.exists():
            shutil.rmtree(temp_root)
        input_dir = temp_root / "input-binding"
        (input_dir / "Player-Data").mkdir(parents=True)
        for player in range(2):
            (input_dir / "Player-Data" / f"Input-P{player}-0").write_text(
                "0\n", encoding="ascii"
            )
        args = types.SimpleNamespace(
            root=temp_root,
            mp_spdz_root=temp_root / "MP-SPDZ",
            runtime_binary="mama-party.x",
            signers=2,
            max_local_parties=2,
            allow_large_local_run=False,
            compile_missing=False,
            compile_timeout_seconds=1,
            mpc_timeout_seconds=1,
            port_base=20000,
            security_parameter=40,
            keep_execution_dirs=False,
            mpc_launch_retries=1,
            inter_attempt_delay_seconds=0,
        )
        args.mp_spdz_root.mkdir(parents=True)
        (args.mp_spdz_root / "mama-party.x").write_text("", encoding="ascii")

        launches = []

        def fake_compile(_args, _kappa_base):
            return {
                "program_name": "mldsa65_expandmask-2-0-5-256",
                "schedule": "fixture",
                "schedule_present": True,
                "compile_result": None,
                "source_sync": None,
                "copied_program_files": [],
            }

        def fake_launch(_args, run_dir, _program_name, _port):
            launches.append(run_dir)
            if len(launches) == 1:
                return {
                    "exit_codes": [-9, -9],
                    "timed_out": False,
                    "duration_seconds": 0.01,
                }
            for player in range(2):
                (run_dir / "Player-Data" / f"Binary-Output-P{player}-0").write_bytes(
                    b"\0" * 10240
                )
            return {
                "exit_codes": [0, 0],
                "timed_out": False,
                "duration_seconds": 0.01,
            }

        original_compile = runner.compile_program
        original_launch = runner.launch_parties
        runner.compile_program = fake_compile
        runner.launch_parties = fake_launch
        try:
            attempt = runner.run_kappa(
                args, temp_root / "case" / "counter-000", input_dir, 0, 0, 0
            )
        finally:
            runner.compile_program = original_compile
            runner.launch_parties = original_launch

        self.assertEqual(len(launches), 2)
        self.assertTrue(attempt["malicious_mpc_verified"])
        self.assertEqual(attempt["blockers"], [])
        self.assertEqual(attempt["execution"]["exit_codes"], [0, 0])


if __name__ == "__main__":
    unittest.main()
