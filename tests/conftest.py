"""Session-scoped fixture that runs the bundled vulnerable target app
on a real localhost socket for the whole test session, so DAST tests
exercise real HTTP requests/responses rather than mocks.
"""
from __future__ import annotations

import socket
import threading
import time

import pytest
from werkzeug.serving import make_server

from appsec_gate.target.vulnerable_app import create_app


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def live_target_url():
    port = _free_port()
    server = make_server("127.0.0.1", port, create_app())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)

    yield f"http://127.0.0.1:{port}"

    server.shutdown()
    thread.join(timeout=5)
