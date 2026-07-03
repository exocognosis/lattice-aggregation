#!/usr/bin/env python3
"""Reference P1 nonce-producer CLI for the external command contract."""

import argparse
import importlib.util
import sys
from pathlib import Path


def load_emitter(root):
    """Load the canonical capture builder without using its CLI entrypoint."""
    script = Path(root) / "scripts" / "emit_reviewed_nonce_producer_capture.py"
    spec = importlib.util.spec_from_file_location(
        "p1_nonce_producer_reference_capture_builder",
        script,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description=(
            "Emit canonical P1 nonce-producer capture JSON for reference CLI "
            "handoff validation"
        )
    )
    parser.add_argument("command", nargs="?", default="emit")
    parser.add_argument("--request", required=True, help="repo-generated request JSON")
    parser.add_argument("--root", default=".", help="repository root")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    if args.command != "emit":
        raise SystemExit("supported command: emit")
    root = Path(args.root)
    emitter = load_emitter(root)
    capture = emitter.build_capture(Path(args.request), root=root)
    sys.stdout.write(emitter.canonical_json(capture))


if __name__ == "__main__":
    main()
