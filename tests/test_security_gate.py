from appsec_gate.gate.security_gate import evaluate_gate
from appsec_gate.models import DASTFinding, DependencyFinding, Vulnerability


def test_no_findings_passes():
    decision = evaluate_gate([], [], fail_on="high")
    assert decision.passed
    assert decision.blocking_findings == 0


def test_dast_finding_below_threshold_passes():
    findings = [DASTFinding(check_name="x", severity="low", url="u", description="d")]
    decision = evaluate_gate(findings, [], fail_on="high")
    assert decision.passed


def test_dast_finding_at_threshold_blocks():
    findings = [DASTFinding(check_name="x", severity="high", url="u", description="d")]
    decision = evaluate_gate(findings, [], fail_on="high")
    assert not decision.passed
    assert decision.blocking_findings == 1


def test_dependency_vulnerability_blocks():
    dep = DependencyFinding(
        package="pkg", version="1.0", ecosystem="PyPI",
        vulnerabilities=[Vulnerability(vuln_id="X", summary="s", severity="critical")],
    )
    decision = evaluate_gate([], [dep], fail_on="high")
    assert not decision.passed
    assert decision.highest_severity == "critical"


def test_fail_on_critical_ignores_high_findings():
    findings = [DASTFinding(check_name="x", severity="high", url="u", description="d")]
    decision = evaluate_gate(findings, [], fail_on="critical")
    assert decision.passed
