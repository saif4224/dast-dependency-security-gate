"""Assembles the final scan report: DAST findings + dependency
findings + the gate decision, with a heuristic 0-100 risk score.
"""
from __future__ import annotations

from dataclasses import asdict

from appsec_gate.models import DASTFinding, DependencyFinding, GateDecision, ScanReport

_SEVERITY_WEIGHT = {"info": 2, "low": 8, "medium": 20, "high": 35, "critical": 50}


def _compute_risk_score(dast_findings: list[DASTFinding], dependency_findings: list[DependencyFinding]) -> int:
    score = sum(_SEVERITY_WEIGHT.get(f.severity, 0) for f in dast_findings)
    score += sum(_SEVERITY_WEIGHT.get(v.severity, 0) for f in dependency_findings for v in f.vulnerabilities)
    return int(max(0, min(100, score)))


def build_scan_report(
    target: str, dast_findings: list[DASTFinding], dependency_findings: list[DependencyFinding], gate: GateDecision
) -> ScanReport:
    return ScanReport(
        target=target,
        dast_findings=dast_findings,
        dependency_findings=dependency_findings,
        gate=gate,
        risk_score=_compute_risk_score(dast_findings, dependency_findings),
    )


def scan_report_to_dict(report: ScanReport) -> dict:
    return asdict(report)
