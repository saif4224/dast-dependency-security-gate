"""A small, deliberately vulnerable Flask app used ONLY as a DAST
scanner test target.

This is not a real application and must never be exposed beyond
localhost/the demo Docker network. It exists so dast/scanner.py has
something real to send HTTP requests to and get real (not mocked)
findings back - the same "authorized, self-owned target only" posture
as a DVWA/Juice Shop style training app, kept minimal and in-repo so
the whole demo is self-contained.

Bugs, on purpose:
  - /search        reflects the `q` parameter unescaped -> XSS
  - /user           builds SQL via string formatting -> SQL injection
  - (site-wide)     no security headers set
  - /debug-info     leaks internal config -> information disclosure
"""
from __future__ import annotations

import sqlite3

from flask import Flask, request


def _seed_db(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)")
    conn.executemany(
        "INSERT INTO users VALUES (?, ?, ?)",
        [(1, "alice", "alice@example.test"), (2, "bob", "bob@example.test")],
    )
    conn.commit()


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "not-a-real-secret-this-is-a-demo-fixture"  # intentionally weak, for the demo

    db = sqlite3.connect(":memory:", check_same_thread=False)
    _seed_db(db)

    @app.route("/")
    def index():
        return "<h1>Demo target app</h1><p>Intentionally vulnerable - DAST test target only.</p>"

    @app.route("/search")
    def search():
        term = request.args.get("q", "")
        # VULNERABLE: reflects user input into HTML without escaping (reflected XSS)
        return f"<h1>Results for {term}</h1><p>No results found.</p>"

    @app.route("/user")
    def user():
        user_id = request.args.get("id", "1")
        # VULNERABLE: builds SQL via string formatting instead of parameterized query
        query = f"SELECT id, username, email FROM users WHERE id = {user_id}"
        try:
            cursor = db.execute(query)
            rows = cursor.fetchall()
            return {"rows": rows}
        except sqlite3.OperationalError as exc:
            # VULNERABLE: leaks the raw DB error (and implicitly the query) to the client
            return {"error": str(exc), "query": query}, 500

    @app.route("/debug-info")
    def debug_info():
        # VULNERABLE: information disclosure - internal config exposed to any caller
        return {"secret_key": app.config["SECRET_KEY"], "debug": True, "db_backend": "sqlite3:memory"}

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5001)
