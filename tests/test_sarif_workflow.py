"""Exercise the scanner checkpoint, saved-report CLI and desktop export entry points."""
import json
from pathlib import Path
import sys
from unittest.mock import MagicMock

import pytest

from src import export_sarif, scanner
from src.reporting import load_report


@pytest.fixture
def scan(tmp_path, monkeypatch, capsys):
    target = tmp_path / "app" / "demo.py"
    target.parent.mkdir()
    target.write_text("eval(user_input)\n", encoding="utf-8")
    monkeypatch.setattr(scanner, "ROOT", tmp_path)
    def scanner_response(command, *args, **kwargs):
        if "scan" in command:
            return {"results": [], "paths": {"scanned": [str(target)]}}
        return {"results": [{"test_id": "B307", "issue_severity": "MEDIUM", "issue_text": "Review eval",
                             "line_number": 1, "filename": str(target)}]}
    monkeypatch.setattr(scanner, "run_json_scanner", scanner_response)

    def run(*options):
        monkeypatch.setattr(sys, "argv", ["scan", str(target), "--no-llm", "--skip-dependencies",
                                          "--secrets", "off", *map(str, options)])
        try:
            scanner.main()
            code = 0
        except SystemExit as exc:
            code = exc.code
        event = json.loads(capsys.readouterr().out.splitlines()[-1])
        path = Path(event["report_path"])
        assert event["event"] == "scan_finished" and event["exit_code"] == code
        assert load_report(path)["exit_code"] == code
        return code, path
    return run


def test_scan_and_reexport_under_repository_root(scan, tmp_path):
    destination = tmp_path / "first.sarif"
    code, native = scan("--sarif", destination, "--sarif-root", tmp_path, "--fail-on", "low")
    assert code == 1
    original = native.read_bytes()
    report = load_report(native)
    assert report["policy"]["result"] == "failed"
    assert report["exports"]["sarif"]["status"] == "completed"
    first = json.loads(destination.read_bytes())
    results = [r for run in first["runs"] for r in run["results"]]
    assert any(loc["physicalLocation"]["artifactLocation"]["uri"] == "app/demo.py"
               for item in results for loc in item["locations"])
    second = tmp_path / "saved.sarif"
    export_sarif.main([str(native.parent), str(second), "--source-root", str(tmp_path)])
    assert json.loads(second.read_bytes())["runs"][0]["results"] == first["runs"][0]["results"]
    assert native.read_bytes() == original


def test_failed_export_preserves_scan_and_policy(scan, tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise ValueError("test export failure")
    monkeypatch.setattr(export_sarif, "write_export", fail)
    code, native = scan("--sarif", tmp_path / "x.sarif", "--fail-on", "low")
    report = load_report(native)
    assert code == 2 and report["scan_status"] == "completed"
    assert report["policy"]["result"] == "failed" and report["findings"]
    assert report["exports"]["sarif"]["status"] == "failed"
    assert "sarif_export_failed" in report["execution"]["reasons"]


def test_existing_native_report_cannot_be_overwritten(scan):
    _, native = scan()
    original = native.read_bytes()
    with pytest.raises(SystemExit) as error:
        export_sarif.main([str(native), str(native)])
    assert error.value.code == 2 and native.read_bytes() == original


def test_desktop_button_exports_displayed_report(scan, tmp_path, monkeypatch):
    import tkinter as tk
    from src.gui import ReviewApp

    _, native = scan()
    destination = tmp_path / "displayed.sarif"
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"Desktop unavailable: {exc}")
    root.withdraw()
    try:
        app = ReviewApp(root)
        app.display_report(load_report(native), native)
        app.sarif_root.set(str(tmp_path))
        assert str(app.sarif_button["state"]) == "normal"
        monkeypatch.setattr("src.gui.filedialog.asksaveasfilename", lambda **kwargs: str(destination))
        monkeypatch.setattr("src.gui.messagebox.showerror", lambda *args, **kwargs: pytest.fail(str(args)))
        app.sarif_button.invoke()
        result = json.loads(destination.read_bytes())["runs"][0]["results"][0]
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/demo.py"
    finally:
        root.destroy()


@pytest.mark.parametrize("busy,version,state,enabled", [
    (False,1,"finished",True), (True,1,"finished",False),
    (False,1,"running",False), (False,None,None,False)])
def test_desktop_sarif_export_eligibility(busy,version,state,enabled):
    from src.gui import ReviewApp
    app = MagicMock()
    app.busy = busy
    app.report = {"schema_version":version, "run_status":state}
    ReviewApp.update_export_controls(app)
    app.sarif_button.configure.assert_called_once_with(state="normal" if enabled else "disabled")
    app.export_button.configure.assert_called_once_with(state="disabled" if busy else "normal")
