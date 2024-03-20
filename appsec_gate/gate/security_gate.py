"""The CI/CD gate decision: given every DAST and dependency finding,
should this build be allowed to ship?

This is the part that turns "a scanner" into "a security gate" - a
scanner that only reports is advisory; a gate makes (and the CLI
enforces, via its exit code) an actual pass/fail call a pipeline can
act on.
"""
from __future__ import annotations

from appsec_gate.models import SEVERITY_ORDER, DASTFinding, DependencyFinding, GateDecision


def evaluate_gate(
    dast_findings: list[DASTFinding], dependency_findings: list[DependencyFinding], fail_on: str = "high"
) -> GateDecision:
    fail_on_rank = SEVERITY_ORDER.get(fail_on, SEVERITY_ORDER["high"])

    blocking_dast = [f for f in dast_findings if f.severity_rank >= fail_on_rank]
    blocking_deps = [
        f for f in dependency_findings for v in f.vulnerabilities if v.severity_rank >= fail_on_rank
    ]
    blocking_count = len(blocking_dast) + len(blocking_deps)

    all_ranks = [f.severity_rank for f in dast_findings] + [
        v.severity_rank for f in dependency_findings for v in f.vulnerabilities
    ]
    highest_rank = max(all_ranks, default=0)
    highest_severity = next((name for name, rank in SEVERITY_ORDER.items() if rank == highest_rank), "info")

    passed = blocking_count == 0
    reason = (
        f"No findings at or above '{fail_on}' severity."
        if passed
        else f"{blocking_count} finding(s) at or above '{fail_on}' severity (highest: {highest_severity})."
    )

    return GateDecision(
        passed=passed, fail_on=fail_on, highest_severity=highest_severity, blocking_findings=blocking_count,
        reason=reason,
    )
