from appsec_gate.dast.scanner import DASTScanner


def test_scan_finds_all_four_known_bugs(live_target_url):
    findings = DASTScanner().scan(live_target_url)
    check_names = {f.check_name for f in findings}
    assert check_names == {"reflected_xss", "sql_injection", "missing_security_headers", "information_disclosure"}


def test_scan_survives_unreachable_target():
    findings = DASTScanner(timeout=1).scan("http://127.0.0.1:1")  # nothing listens on port 1
    assert findings == []
