
import subprocess
from unittest.mock import patch

import pytest

from src.scanner import run_json_scanner


def test_bandit_findings_are_accepted():
    """Bandit exit code 1 can mean vulnerabilities were found."""
    fake_result = subprocess.CompletedProcess(
        args=["bandit"],
        returncode=1,
        stdout='{"results": [{"test_id": "B307"}], "errors": []}',
        stderr="",
    )

    with patch("src.scanner.subprocess.run", return_value=fake_result):
        data = run_json_scanner(["bandit"], {0, 1})

    assert data["results"][0]["test_id"] == "B307"


def test_scanner_failure_is_rejected():
    """A scanner execution error must not count as a clean scan."""
    fake_result = subprocess.CompletedProcess(
        args=["bandit"],
        returncode=2,
        stdout="",
        stderr="Scanner failed",
    )

    with patch("src.scanner.subprocess.run", return_value=fake_result):
        with pytest.raises(RuntimeError):
            run_json_scanner(["bandit"], {0, 1})



@pytest.mark.parametrize("output", [
    "not valid JSON",
    '{"errors": []}',
    '{"results": {}, "errors": []}',
])
def test_invalid_scanner_output(output):
    """Reject malformed or incomplete scanner responses."""

    fake_result = subprocess.CompletedProcess(
        args=["bandit"],
        returncode=0,
        stdout=output,
        stderr=""
    )

    with patch("src.scanner.subprocess.run",
               return_value=fake_result):
        with pytest.raises(RuntimeError):
            run_json_scanner(["bandit"], {0, 1})


def test_scanner_reports_errors():
    """Scanner-reported errors must be detected."""

    fake_result = subprocess.CompletedProcess(
        args=["semgrep"],
        returncode=0,
        stdout='{"results": [], "errors": [{"message": "Invalid rule"}]}',
        stderr=""
    )

    with patch("src.scanner.subprocess.run",
               return_value=fake_result):
        with pytest.raises(RuntimeError, match="reported errors"):
            run_json_scanner(["semgrep"], {0})


def test_scanner_timeout():
    """The program should handle a scanner timeout."""

    with patch(
        "src.scanner.subprocess.run",
        side_effect=subprocess.TimeoutExpired(
            cmd=["bandit"], timeout=120
        )
    ):
        with pytest.raises(RuntimeError, match="could not run"):
            run_json_scanner(["bandit"], {0, 1})


def test_missing_file(tmp_path):
    """Reject nonexistent input files."""

    from src.scanner import scan_file

    missing = tmp_path / "missing.py"

    with pytest.raises(ValueError):
        scan_file(missing)



def test_scan_records_fingerprint_and_detects_changes(tmp_path):
    import hashlib
    from src.scanner import scan_file
    source = tmp_path / "sample.py"
    source.write_bytes(b"eval(user_input)\n")
    with patch("src.scanner.run_json_scanner", side_effect=[{"results": [], "metrics":{str(source):{}}}, {"results": [], "paths":{"scanned":[str(source)]}}]):
        result = scan_file(source)
    assert result["bandit"]["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()

    def changed_scan(*args, **kwargs):
        source.write_bytes(b"changed = True\n")
        return {"results": [], "metrics":{str(source):{}}, "paths":{"scanned":[str(source)]}}

    with patch("src.scanner.run_json_scanner", side_effect=changed_scan):
        with pytest.raises(RuntimeError, match="Source changed"):
            scan_file(source)
