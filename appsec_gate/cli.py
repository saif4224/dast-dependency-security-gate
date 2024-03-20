"""Command-line entry point.

    # Demo mode - spins up the bundled vulnerable target app on
    # localhost, scans it live, checks a demo dependency manifest
    # against real (fixture-frozen) OSV.dev data, and enforces the gate.
    python -m appsec_gate.cli --demo

    # Live mode - scans a real target you own/control, and a real
    # requirements.txt against the live OSV.dev API.
    python -m appsec_gate.cli --live --target http://localhost:5001 \\
        --requirements requirements.txt --fail-on high
"""
from __future__ import annotations

import argparse
import logging
import socket
import sys
import threading
import time
from pathlib import Path

from werkzeug.serving import make_server

from appsec_gate.pipeline import run_pipeline
from appsec_gate.sca.manifest_parser import parse_requirements
from appsec_gate.sca.osv_client import OSVClient
from appsec_gate.target.vulnerable_app import create_app

REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO_REQUIREMENTS = REPO_ROOT / "data" / "demo_requirements.txt"
DEMO_OSV_FIXTURE = REPO_ROOT / "data" / "osv_fixture.json"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _BackgroundServer:
    def __init__(self, app, host: str, port: int):
        self._server = make_server(host, port, app)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()
        time.sleep(0.2)  # give the server a moment to bind before the first request

    def stop(self) -> None:
        self._server.shutdown()
        self._thread.join(timeout=5)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DAST + Dependency (SCA) Security Gate")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true", help="Run end-to-end against the bundled vulnerable target.")
    mode.add_argument("--live", action="store_true", help="Run against a real target/manifest you control.")

    parser.add_argument("--target", type=str, help="Base URL of the target to scan (required for --live).")
    parser.add_argument("--requirements", type=str, help="Path to a requirements.txt to check (for --live).")
    parser.add_argument("--fail-on", type=str, default="high", choices=["low", "medium", "high", "critical"])
    parser.add_argument(
        "--report-only", action="store_true", help="Always exit 0; still reports the gate decision."
    )
    parser.add_argument("--output-dir", type=str, default="output")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def run_demo(fail_on: str, output_dir: str) -> dict:
    logging.info("Running in DEMO mode: bundled vulnerable target app + real (fixture-frozen) OSV.dev data.")
    port = _free_port()
    server = _BackgroundServer(create_app(), "127.0.0.1", port)
    server.start()
    try:
        dependency_findings = OSVClient().from_fixture_file(DEMO_OSV_FIXTURE)
        target_url = f"http://127.0.0.1:{port}"
        return run_pipeline(target_url, dependency_findings, fail_on=fail_on, output_dir=output_dir)
    finally:
        server.stop()


def run_live(args: argparse.Namespace) -> dict:
    if not args.target:
        raise SystemExit("--target is required for --live mode")

    dependency_findings = []
    if args.requirements:
        logging.info("Querying live OSV.dev API for %s", args.requirements)
        packages = parse_requirements(args.requirements)
        dependency_findings = OSVClient().query_live(packages)

    return run_pipeline(args.target, dependency_findings, fail_on=args.fail_on, output_dir=args.output_dir)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(levelname)s %(message)s")

    report = run_demo(args.fail_on, args.output_dir) if args.demo else run_live(args)

    gate = report["gate"]
    print("\n=== Security Gate Summary ===")
    print(f"target: {report['target']}")
    print(f"DAST findings: {len(report['dast_findings'])}")
    print(f"Vulnerable dependencies: {sum(1 for f in report['dependency_findings'] if f['vulnerabilities'])}")
    print(f"risk_score: {report['risk_score']}/100")
    print(f"gate: {'PASS' if gate['passed'] else 'FAIL'} (fail-on={gate['fail_on']}) - {gate['reason']}")
    print(f"\nFull report: {Path(args.output_dir) / 'scan_report.json'}")

    if args.report_only:
        return 0
    return 0 if gate["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
