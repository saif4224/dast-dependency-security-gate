import tempfile
from pathlib import Path

from appsec_gate.models import DASTFinding, DependencyFinding, Vulnerability
from appsec_gate.report.visualize import plot_findings_by_severity, plot_findings_by_type


def _sample_findings():
    dast = [DASTFinding(check_name="reflected_xss", severity="high", url="u", description="d")]
    dep = [
        DependencyFinding(
            package="pkg", version="1.0", ecosystem="PyPI",
            vulnerabilities=[Vulnerability(vuln_id="X", summary="s", severity="critical")],
        )
    ]
    return dast, dep


def test_plot_findings_by_severity_writes_png():
    dast, dep = _sample_findings()
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "sev.png"
        plot_findings_by_severity(dast, dep, out)
        assert out.exists() and out.stat().st_size > 0


def test_plot_findings_by_type_writes_png():
    dast, dep = _sample_findings()
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "type.png"
        plot_findings_by_type(dast, dep, out)
        assert out.exists() and out.stat().st_size > 0


def test_plots_handle_empty_findings():
    with tempfile.TemporaryDirectory() as tmp:
        out1 = Path(tmp) / "sev.png"
        out2 = Path(tmp) / "type.png"
        plot_findings_by_severity([], [], out1)
        plot_findings_by_type([], [], out2)
        assert out1.stat().st_size > 0
        assert out2.stat().st_size > 0
