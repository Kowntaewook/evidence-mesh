import json
import subprocess
import sys


def test_cli_report_and_no_overwrite(tmp_path):
    report = tmp_path / "report.json"
    command = [
        sys.executable,
        "-m",
        "engine.cli",
        "sample",
        "--db",
        str(tmp_path / "case.sqlite3"),
        "--output",
        str(report),
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    assert json.loads(result.stdout)["correlations"] == 16
    saved = json.loads(report.read_text())
    assert len(saved["timeline"]["events"]) == 9
    assert all(edge["reasons"] for edge in saved["analysis"]["correlations"])
    before = report.read_bytes()
    again = subprocess.run(command, capture_output=True, text=True)
    assert again.returncode != 0
    assert "FileExistsError" in again.stderr
    assert report.read_bytes() == before
