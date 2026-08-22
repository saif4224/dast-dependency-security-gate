"""Orchestrates the full lifecycle: live DAST scan of a target URL +
already-produced dependency findings -> gate decision -> consolidated
report + evidence visuals.

DAST scanning can't be meaningfully "pre-computed" the way the other
portfolio pipelines' inputs are - dynamic testing means actually
talking to a running application. So this module does perform the live
HTTP scan itself; SCA/gate/reporting stay pure functions over typed
data for testability - see tests/test_pipeline.py, which spins up the
bundled vulnerable app on localhost as its real (not mocked) target.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from appsec_gate.dast.scanner import DASTScanner
from appsec_gate.gate.security_gate import evaluate_gate
from appsec_gate.models import DependencyFinding
from appsec_gate.report.report_builder import build_scan_report, scan_report_to_dict
from appsec_gate.report.visualize import plot_findings_by_severity, plot_findings_by_type

logger = logging.getLogger(__name__)


def run_pipeline(
    target_url: str,
    dependency_findings: list[DependencyFinding],
    fail_on: str = "high",
    output_dir: str | Path = "output",
    scanner: DASTScanner | None = None,
) -> dict:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    scanner = scanner or DASTScanner()
    dast_findings = scanner.scan(target_url)
    logger.info("DAST scan of %s: %d finding(s)", target_url, len(dast_findings))

    vulnerable_deps = sum(1 for f in dependency_findings if f.is_vulnerable)
    logger.info(
        "SCA scan: %d/%d dependencies have known vulnerabilities", vulnerable_deps, len(dependency_findings)
    )

    gate = evaluate_gate(dast_findings, dependency_findings, fail_on=fail_on)
    report = build_scan_report(target_url, dast_findings, dependency_findings, gate)
    report_dict = scan_report_to_dict(report)

    report_path = output_dir / "scan_report.json"
    report_path.write_text(json.dumps(report_dict, indent=2))
    logger.info("Wrote scan report to %s", report_path)
    logger.info("Gate decision: %s - %s", "PASS" if gate.passed else "FAIL", gate.reason)

    plot_findings_by_severity(dast_findings, dependency_findings, output_dir / "findings_by_severity.png")
    plot_findings_by_type(dast_findings, dependency_findings, output_dir / "findings_by_type.png")

    return report_dict
