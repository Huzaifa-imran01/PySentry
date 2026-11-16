
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
