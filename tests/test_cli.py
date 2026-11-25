
import sys
import pytest

from src import scanner


@pytest.mark.parametrize("scope", ["directory", "history", "off"])
def test_credential_scan_cli_aliases(scope):
    parser = scanner.scan_help_parser()
    required = scope != "off"
    current = parser.parse_args(["--credential-scan", scope] + (["--require-credential-scan"] if required else []))
    legacy = parser.parse_args(["--secrets", scope] + (["--require-secrets"] if required else []))
    assert current == legacy
    assert current.credential_scan == scope
    assert current.require_credential_scan == required


def test_cli_accepts_path_option(monkeypatch, tmp_path):
    """The --path argument should be accepted."""

    def fake_scan(path, *args):
        assert path == "sample.py"
        return {
            "bandit": {"results": []},
            "semgrep": {"results": []}
        }

    monkeypatch.setattr(scanner, "scan_target", lambda path,*args: (fake_scan(path), [], {"status":"completed", "files":[]}))
    monkeypatch.setattr(scanner, "ROOT", tmp_path)

    monkeypatch.setattr(
        sys, "argv", ["scanner", "--path", "sample.py"]
    )

    scanner.main()

    assert len(list((tmp_path / "reports").glob("*/findings.json"))) == 1


@pytest.mark.parametrize("arguments", [
    [],
    ["sample.py", "--path", "other.py"],
])
def test_cli_rejects_invalid_arguments(monkeypatch, arguments):
    """Missing or conflicting paths should be rejected."""

    monkeypatch.setattr(
        sys, "argv", ["scanner", *arguments]
    )

    with pytest.raises(SystemExit) as error:
        scanner.main()

    assert error.value.code == 2
