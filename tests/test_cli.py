import tempfile

from appsec_gate.cli import main


def test_demo_mode_gate_blocks_and_exits_nonzero(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        exit_code = main(["--demo", "--output-dir", tmp])
        captured = capsys.readouterr()

        assert exit_code == 1  # the bundled target is deliberately vulnerable; the gate must block it
        assert "Security Gate Summary" in captured.out
        assert "gate: FAIL" in captured.out


def test_demo_mode_report_only_always_exits_zero():
    with tempfile.TemporaryDirectory() as tmp:
        exit_code = main(["--demo", "--report-only", "--output-dir", tmp])
        assert exit_code == 0


def test_live_mode_without_target_exits():
    try:
        main(["--live"])
        assert False, "expected SystemExit"
    except SystemExit:
        pass
