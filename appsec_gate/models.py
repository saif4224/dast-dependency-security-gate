"""Core data model shared across the DAST scanner, the SCA dependency
checker, and the CI/CD gate decision.
"""
from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class DASTFinding:
    check_name: str
    severity: str  # info | low | medium | high | critical
    url: str
    description: str
    evidence: str = ""

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)


@dataclass
class Vulnerability:
    vuln_id: str
    summary: str
    severity: str
    aliases: list[str] = field(default_factory=list)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)


@dataclass
class DependencyFinding:
    package: str
    version: str
    ecosystem: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    @property
    def is_vulnerable(self) -> bool:
        return len(self.vulnerabilities) > 0

    @property
    def max_severity_rank(self) -> int:
        return max((v.severity_rank for v in self.vulnerabilities), default=0)


@dataclass
class GateDecision:
    passed: bool
    fail_on: str
    highest_severity: str
    blocking_findings: int
    reason: str


@dataclass
class ScanReport:
    target: str
    dast_findings: list[DASTFinding]
    dependency_findings: list[DependencyFinding]
    gate: GateDecision
    risk_score: int  # 0-100
