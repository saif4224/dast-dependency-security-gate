"""Parses a pip-style requirements.txt into pinned (name, version) pairs.

Only handles exact pins (`package==version`) - deliberately simple,
since the point of this module is feeding a version-specific
vulnerability lookup, not being a general requirements-file resolver.
"""
from __future__ import annotations

from pathlib import Path


def parse_requirements(path: str | Path) -> list[tuple[str, str]]:
    packages = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line:
            continue
        name, _, version = line.partition("==")
        packages.append((name.strip(), version.strip()))
    return packages
