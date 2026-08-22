import json
import tempfile
from pathlib import Path

from appsec_gate.pipeline import run_pipeline
from appsec_gate.sca.osv_client import OSVClient


def test_full_pipeline_end_to_end_against_live_local_target(live_target_url):
    dependency_findings = OSVClient().from_fixture_file()

    with tempfile.TemporaryDirectory() as tmp:
        report = run_pipeline(live_target_url, dependency_findings, fail_on="high", output_dir=tmp)

        assert report["target"] == live_target_url
        assert len(report["dast_findings"]) == 4
        assert report["gate"]["passed"] is False  # deliberately-vulnerable target must fail a 'high' gate
        assert report["risk_score"] > 0

        for name in ("scan_report.json", "findings_by_severity.png", "findings_by_type.png"):
            assert (Path(tmp) / name).exists(), f"missing {name}"

        on_disk = json.loads((Path(tmp) / "scan_report.json").read_text())
        assert on_disk["target"] == live_target_url


def test_gate_passes_with_no_dependency_findings_and_lenient_threshold(live_target_url):
    with tempfile.TemporaryDirectory() as tmp:
        report = run_pipeline(live_target_url, [], fail_on="critical", output_dir=tmp)
        # only the SQLi DAST finding is 'critical'; everything else is below that threshold
        assert report["gate"]["blocking_findings"] == 1
