"""Renders evidence visuals for the combined DAST + SCA scan.
Headless-safe (Agg backend) for CI/Docker.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from appsec_gate.models import DASTFinding, DependencyFinding

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SEVERITY_COLOR = {
    "info": "#6b7280", "low": "#0891b2", "medium": "#d97706", "high": "#dc2626", "critical": "#7f1d1d",
}


def _agg_pyplot():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    return plt


def _all_severities(dast_findings: list[DASTFinding], dependency_findings: list[DependencyFinding]) -> list[str]:
    severities = [f.severity for f in dast_findings]
    severities += [v.severity for f in dependency_findings for v in f.vulnerabilities]
    return severities


def plot_findings_by_severity(
    dast_findings: list[DASTFinding], dependency_findings: list[DependencyFinding], out_path: str | Path
) -> Path:
    plt = _agg_pyplot()

    counts = Counter(_all_severities(dast_findings, dependency_findings))
    present = [s for s in SEVERITY_ORDER if counts.get(s, 0) > 0] or ["(none)"]
    values = [counts.get(s, 0) for s in present]
    colors = [SEVERITY_COLOR.get(s, "#6b7280") for s in present]

    fig, ax = plt.subplots(figsize=(6.5, 4.5))
    ax.bar([s.capitalize() for s in present], values, color=colors)
    ax.set_ylabel("Findings")
    ax.set_title("Findings by Severity (DAST + Dependencies)")
    fig.tight_layout()

    out_path = Path(out_path)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def plot_findings_by_type(
    dast_findings: list[DASTFinding], dependency_findings: list[DependencyFinding], out_path: str | Path
) -> Path:
    plt = _agg_pyplot()

    dast_counts = Counter(f"DAST: {f.check_name.replace('_', ' ')}" for f in dast_findings)
    dep_counts = Counter(
        f"SCA: {f.package}=={f.version}" for f in dependency_findings if f.is_vulnerable
    )
    combined = {**dast_counts, **dep_counts}
    if not combined:
        combined = {"(no findings)": 0}

    labels, values = zip(*sorted(combined.items(), key=lambda kv: kv[1]))
    colors = ["#dc2626" if label.startswith("DAST") else "#9333ea" for label in labels]

    fig, ax = plt.subplots(figsize=(9, max(3, 0.5 * len(labels))))
    ax.barh(labels, values, color=colors)
    ax.set_xlabel("Findings")
    ax.set_title("Findings by Check / Vulnerable Dependency")
    fig.tight_layout()

    out_path = Path(out_path)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path
