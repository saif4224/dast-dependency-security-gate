from appsec_gate.gate.security_gate import evaluate_gate
from appsec_gate.models import DASTFinding, DependencyFinding, Vulnerability
from appsec_gate.report.report_builder import build_scan_report, scan_report_to_dict


def test_clean_scan_scores_zero_risk():
    gate = evaluate_gate([], [], fail_on="high")
    report = build_scan_report("http://x", [], [], gate)
    assert report.risk_score == 0


def test_critical_findings_score_high_risk():
    findings = [DASTFinding(check_name="sqli", severity="critical", url="u", description="d")]
    gate = evaluate_gate(findings, [], fail_on="high")
    report = build_scan_report("http://x", findings, [], gate)
    assert report.risk_score >= 40


def test_to_dict_is_json_serializable():
    import json

    dep = DependencyFinding(
        package="pkg", version="1.0", ecosystem="PyPI",
        vulnerabilities=[Vulnerability(vuln_id="X", summary="s", severity="high")],
    )
    gate = evaluate_gate([], [dep], fail_on="high")
    report = build_scan_report("http://x", [], [dep], gate)
    payload = scan_report_to_dict(report)
    json.dumps(payload)  # must not raise
    assert payload["gate"]["passed"] is False
