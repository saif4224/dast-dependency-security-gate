"""Orchestrates the DAST checks against a live target URL.

Always sends real HTTP requests - there's no "offline" DAST mode, since
dynamic testing is inherently about observing a running application's
real behavior. Demo mode achieves reproducibility by running the
bundled vulnerable target app locally (see pipeline.py) and scanning
that, rather than by mocking responses.

Only ever point this at a target you own and are authorized to test.
"""
from __future__ import annotations

import logging

import requests

from appsec_gate.dast.checks import ALL_CHECKS
from appsec_gate.models import DASTFinding

logger = logging.getLogger(__name__)


class DASTScanner:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.session = requests.Session()

    def scan(self, base_url: str) -> list[DASTFinding]:
        base_url = base_url.rstrip("/")
        findings: list[DASTFinding] = []

        for check in ALL_CHECKS:
            try:
                results = check(self.session, base_url)
                findings.extend(results)
                logger.info("%s: %d finding(s)", check.__name__, len(results))
            except requests.RequestException as exc:
                logger.warning("%s failed: %s", check.__name__, exc)

        return findings
