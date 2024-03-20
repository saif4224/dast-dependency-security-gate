import requests

from appsec_gate.dast.checks import (
    check_info_disclosure,
    check_missing_security_headers,
    check_reflected_xss,
    check_sql_injection,
)


def test_reflected_xss_detected(live_target_url):
    findings = check_reflected_xss(requests.Session(), live_target_url)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_sql_injection_detected(live_target_url):
    findings = check_sql_injection(requests.Session(), live_target_url)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_missing_security_headers_detected(live_target_url):
    findings = check_missing_security_headers(requests.Session(), live_target_url)
    assert len(findings) == 1
    assert "X-Content-Type-Options" in findings[0].evidence


def test_info_disclosure_detected(live_target_url):
    findings = check_info_disclosure(requests.Session(), live_target_url)
    assert len(findings) == 1
    assert findings[0].severity == "high"
