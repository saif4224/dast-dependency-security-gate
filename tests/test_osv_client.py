from appsec_gate.sca.osv_client import OSVClient


def test_from_fixture_parses_all_packages():
    findings = OSVClient().from_fixture_file()
    packages = {(f.package, f.version) for f in findings}
    assert packages == {("pyyaml", "5.3"), ("flask", "0.12"), ("click", "8.1.7"), ("certifi", "2024.7.4")}


def test_vulnerable_packages_flagged_correctly():
    findings = OSVClient().from_fixture_file()
    by_package = {f.package: f for f in findings}
    assert by_package["pyyaml"].is_vulnerable
    assert len(by_package["pyyaml"].vulnerabilities) == 2
    assert by_package["pyyaml"].vulnerabilities[0].severity == "critical"


def test_clean_package_not_flagged():
    findings = OSVClient().from_fixture_file()
    by_package = {f.package: f for f in findings}
    assert not by_package["certifi"].is_vulnerable


def test_real_cve_aliases_present():
    findings = OSVClient().from_fixture_file()
    by_package = {f.package: f for f in findings}
    all_aliases = [a for v in by_package["pyyaml"].vulnerabilities for a in v.aliases]
    assert "CVE-2020-1747" in all_aliases
