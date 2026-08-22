"""Client for OSV.dev (osv.dev) - Google's open, free, no-auth-required
vulnerability database covering PyPI, npm, and most major ecosystems.

Live mode makes real requests against the real public API
(https://api.osv.dev). Offline/demo mode loads a fixture that was
itself captured from a real OSV.dev query (see data/osv_fixture.json's
header comment for exactly which query and when) - not fabricated CVE
data, just a frozen copy of a real response for CI-safe reproducibility.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import requests

from appsec_gate.models import DependencyFinding, Vulnerability

logger = logging.getLogger(__name__)

OSV_API_BASE = "https://api.osv.dev/v1"
MAX_DETAIL_LOOKUPS_PER_PACKAGE = 10  # cap outbound requests for heavily-flagged packages

DEFAULT_FIXTURE_PATH = Path(__file__).resolve().parents[2] / "data" / "osv_fixture.json"


def _severity_from_vuln_detail(detail: dict) -> str:
    db_severity = detail.get("database_specific", {}).get("severity")
    if db_severity:
        return db_severity.lower()
    if detail.get("severity"):
        return "high"  # a CVSS vector is present but not pre-classified; treat as high pending manual triage
    return "medium"


class OSVClient:
    def __init__(self, session: requests.Session | None = None):
        self.session = session or requests.Session()

    def query_live(self, packages: list[tuple[str, str]], ecosystem: str = "PyPI") -> list[DependencyFinding]:
        queries = [
            {"package": {"name": name, "ecosystem": ecosystem}, "version": version} for name, version in packages
        ]
        resp = self.session.post(f"{OSV_API_BASE}/querybatch", json={"queries": queries}, timeout=15)
        resp.raise_for_status()
        batch_results = resp.json().get("results", [])

        findings = []
        for (name, version), result in zip(packages, batch_results):
            vuln_ids = [v["id"] for v in result.get("vulns", [])][:MAX_DETAIL_LOOKUPS_PER_PACKAGE]
            vulnerabilities = [self._fetch_vuln_detail(vid) for vid in vuln_ids]
            findings.append(
                DependencyFinding(
                    package=name, version=version, ecosystem=ecosystem, vulnerabilities=vulnerabilities
                )
            )
        return findings

    def _fetch_vuln_detail(self, vuln_id: str) -> Vulnerability:
        resp = self.session.get(f"{OSV_API_BASE}/vulns/{vuln_id}", timeout=10)
        resp.raise_for_status()
        detail = resp.json()
        return Vulnerability(
            vuln_id=detail["id"],
            summary=detail.get("summary", ""),
            severity=_severity_from_vuln_detail(detail),
            aliases=detail.get("aliases", []),
        )

    def from_fixture_file(self, path: str | Path = DEFAULT_FIXTURE_PATH) -> list[DependencyFinding]:
        data = json.loads(Path(path).read_text())
        findings = []
        for key, entry in data["results"].items():
            name, _, version = key.partition("==")
            vulnerabilities = [
                Vulnerability(
                    vuln_id=v["vuln_id"], summary=v["summary"], severity=v["severity"],
                    aliases=v.get("aliases", []),
                )
                for v in entry["vulnerabilities"]
            ]
            findings.append(
                DependencyFinding(
                    package=name, version=version, ecosystem=entry["ecosystem"], vulnerabilities=vulnerabilities
                )
            )
        return findings
