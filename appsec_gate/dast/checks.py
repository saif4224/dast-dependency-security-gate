"""Individual DAST checks. Each sends a real HTTP request (via the
supplied requests.Session) to the target and inspects the real
response - no mocked network calls, even in demo mode, since the
"demo mode" here is running the bundled vulnerable target app on
localhost and scanning that.
"""
from __future__ import annotations

import requests

from appsec_gate.models import DASTFinding

XSS_MARKER = "<script>xsstest123marker</script>"
SQLI_PAYLOAD = "1' OR '1'='1"
SQL_ERROR_SIGNATURES = ("OperationalError", "syntax error", "sqlite3")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "prevents MIME-sniffing attacks",
    "X-Frame-Options": "prevents clickjacking via iframe embedding",
    "Content-Security-Policy": "restricts which resources the page can load/execute",
}


def check_reflected_xss(session: requests.Session, base_url: str) -> list[DASTFinding]:
    resp = session.get(f"{base_url}/search", params={"q": XSS_MARKER}, timeout=5)
    if XSS_MARKER in resp.text:
        return [
            DASTFinding(
                check_name="reflected_xss",
                severity="high",
                url=resp.url,
                description="The 'q' parameter is reflected into the HTML response without escaping.",
                evidence=f"Payload {XSS_MARKER!r} found unescaped in response body.",
            )
        ]
    return []


def check_sql_injection(session: requests.Session, base_url: str) -> list[DASTFinding]:
    resp = session.get(f"{base_url}/user", params={"id": SQLI_PAYLOAD}, timeout=5)
    body = resp.text
    if resp.status_code == 500 and any(sig in body for sig in SQL_ERROR_SIGNATURES):
        return [
            DASTFinding(
                check_name="sql_injection",
                severity="critical",
                url=resp.url,
                description="The 'id' parameter is concatenated directly into a SQL query (error-based SQLi).",
                evidence=f"Payload {SQLI_PAYLOAD!r} triggered a raw database error in the response.",
            )
        ]
    return []


def check_missing_security_headers(session: requests.Session, base_url: str) -> list[DASTFinding]:
    resp = session.get(base_url, timeout=5)
    missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
    if not missing:
        return []
    return [
        DASTFinding(
            check_name="missing_security_headers",
            severity="medium",
            url=resp.url,
            description=f"Missing {len(missing)} recommended security header(s): {', '.join(missing)}.",
            evidence="; ".join(f"{h} ({SECURITY_HEADERS[h]})" for h in missing),
        )
    ]


def check_info_disclosure(session: requests.Session, base_url: str) -> list[DASTFinding]:
    resp = session.get(f"{base_url}/debug-info", timeout=5)
    if resp.status_code == 200 and "secret_key" in resp.text.lower():
        return [
            DASTFinding(
                check_name="information_disclosure",
                severity="high",
                url=resp.url,
                description="An unauthenticated endpoint returns internal configuration (secret key).",
                evidence="Response body contains 'secret_key'.",
            )
        ]
    return []


ALL_CHECKS = [check_reflected_xss, check_sql_injection, check_missing_security_headers, check_info_disclosure]
