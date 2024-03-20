from pathlib import Path

from appsec_gate.sca.manifest_parser import parse_requirements

FIXTURE = Path(__file__).parent.parent / "data" / "demo_requirements.txt"


def test_parses_all_pinned_packages():
    packages = parse_requirements(FIXTURE)
    assert ("pyyaml", "5.3") in packages
    assert ("flask", "0.12") in packages
    assert ("click", "8.1.7") in packages
    assert ("certifi", "2024.7.4") in packages
    assert len(packages) == 4


def test_ignores_comments_and_blank_lines(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("# a comment\n\npackage-a==1.0\n\n# another\npackage-b==2.0\n")
    packages = parse_requirements(manifest)
    assert packages == [("package-a", "1.0"), ("package-b", "2.0")]


def test_ignores_unpinned_lines(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("package-a\npackage-b>=1.0\npackage-c==3.0\n")
    packages = parse_requirements(manifest)
    assert packages == [("package-c", "3.0")]
