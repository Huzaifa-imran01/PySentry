"""Tests for the additive GUI adapter; no scans, paid API calls, or source edits."""
import json
import os
from pathlib import Path
from queue import Queue
from unittest.mock import MagicMock

import pytest
from src.gui_support import (KEY_ENV, ScanOptions, load_report, overview_text,
                             run_scan, scanner_command)


def sample_report(target, status="completed"):
    return {"file":{"path":str(target)},"scan_status":status,"findings":[
        {"scanner":"bandit","rule_id":"B307","severity":"MEDIUM","file":str(target),"line":1,"message":"Unsafe eval"}],
        "ai":{"status":"skipped","reason":"disabled_by_flag","results":[]},
        "dependencies":{"status":"completed","packages":[],"findings":[]},
        "coverage":{"files":[],"excluded":[],"eligible_files":1,"completed_files":1,"completeness":1.0}}


def test_command_keeps_existing_cli_flags_and_no_secret(tmp_path):
    source=tmp_path/"source with spaces.py";source.write_text("pass")
    requirements=tmp_path/"requirements.txt";requirements.write_text("requests==2.19.1")
    options=ScanOptions(str(source),"model",requirements=str(requirements),max_files=8)
    options.validate()
    command=scanner_command(options,True,python="C:/env/pythonw.exe")
    assert Path(command[0]).name=="python.exe"
    assert command[command.index("--path")+1]==str(source.resolve())
    assert command[command.index("--api-key-env")+1]==KEY_ENV
    assert command[command.index("--max-files")+1]=="8"
    assert "--requirements" in command and "--no-llm" not in command


def test_basic_command_does_not_enable_ai(tmp_path):
    options=ScanOptions(str(tmp_path),"model",skip_dependencies=True)
    command=scanner_command(options,False)
    assert "--no-llm" in command and "--api-key-env" not in command
    assert "--skip-dependencies" in command


@pytest.mark.parametrize("field,value",[("max_files",0),("scanner_timeout",float("inf")),("total_timeout",float("nan")),("max_file_bytes",-1)])
def test_invalid_limits_rejected(tmp_path,field,value):
    with pytest.raises(ValueError):
        ScanOptions(str(tmp_path),"model",**{field:value}).validate()


def test_dependency_scope_rejected(tmp_path):
    target=tmp_path/"target";target.mkdir()
    outside=tmp_path/"outside";outside.mkdir()
    with pytest.raises(ValueError,match="inside"):
        ScanOptions(str(target),"model",dependency_path=str(outside)).validate()


def test_open_report_rejects_other_json(tmp_path):
    path=tmp_path/"report.json";path.write_text("[]")
    with pytest.raises(ValueError):load_report(path)


def fake_process(monkeypatch, root, target, *, report=None, output=(), returncode=0):
    process=MagicMock()
    process.__enter__.return_value=process
    process.stdout=iter(output)
    process.wait.return_value=returncode
    captured={}
    def launch(command,**kwargs):
        captured["command"]=command
        captured["env"]=dict(kwargs["env"])
        captured["stdin"]=kwargs["stdin"]
        if report is not None:
            run_id = command[command.index("--run-id") + 1]
            path = root / "reports" / run_id / "report.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({**report, "run_id": run_id, "schema_version": 1,
                                       "run_status": "finished", "exit_code": returncode,
                                       "execution": {}, "policy": {}}))
            process.stdout = iter([*output, json.dumps({"event":"scan_finished","run_id":run_id,
                                                        "report_path":str(path),"exit_code":returncode})])
        return process
    monkeypatch.setattr("src.gui_support.subprocess.Popen",launch)
    return captured


def test_worker_key_is_ephemeral_and_logs_redacted(tmp_path,monkeypatch):
    source=tmp_path/"source.py";source.write_text("pass")
    monkeypatch.delenv(KEY_ENV,raising=False)
    captured=fake_process(monkeypatch,tmp_path,source,report=sample_report(source),output=["error secret-key\n"])
    events=Queue()
    run_scan(ScanOptions(str(source),"model"),"secret-key",events,tmp_path)
    assert captured["env"][KEY_ENV]=="secret-key"
    assert "secret-key" not in " ".join(captured["command"])
    assert KEY_ENV not in os.environ
    assert events.get()==("log","error [REDACTED]\n")
    kind,payload=events.get()
    assert kind=="finished" and payload["report"]["scan_status"]=="completed"


def test_worker_preserves_partial_report_on_nonzero_exit(tmp_path,monkeypatch):
    source=tmp_path/"source.py";source.write_text("pass")
    fake_process(monkeypatch,tmp_path,source,report=sample_report(source,"partial"),returncode=2)
    events=Queue();run_scan(ScanOptions(str(source),"model"),"",events,tmp_path)
    _,payload=events.get()
    assert payload["returncode"]==2 and payload["report"]["scan_status"]=="partial"


def test_worker_does_not_show_stale_report(tmp_path,monkeypatch):
    source=tmp_path/"source.py";source.write_text("pass")
    (tmp_path/"reports").mkdir()
    (tmp_path/"reports/report.json").write_text(json.dumps(sample_report(source)))
    fake_process(monkeypatch,tmp_path,source,returncode=1)
    events=Queue();run_scan(ScanOptions(str(source),"model"),"",events,tmp_path)
    _,payload=events.get()
    assert payload["report"] is None and "No new report" in payload["problem"]


def test_worker_rejects_concurrent_report_for_other_target(tmp_path,monkeypatch):
    source=tmp_path/"source.py";source.write_text("pass")
    fake_process(monkeypatch,tmp_path,source,report=sample_report(tmp_path/"other.py"))
    events=Queue();run_scan(ScanOptions(str(source),"model"),"",events,tmp_path)
    _,payload=events.get()
    assert payload["report"] is None and "different target" in payload["problem"]


def test_partial_overview_is_explicit():
    assert "INCOMPLETE SCAN" in overview_text(sample_report(Path("test.py"),"partial"))


def test_desktop_report_views_and_filtering(tmp_path, monkeypatch):
    import tkinter as tk
    from src.gui import ReviewApp
    try:
        root=tk.Tk()
    except tk.TclError as exc:
        pytest.skip("Desktop not available: "+str(exc))
    root.withdraw()
    try:
        app=ReviewApp(root)
        report=sample_report(tmp_path/"source.py","partial")
        report["ai"]={"status":"partial","reason":"review_failures","results":[
            {"status":"reviewed","finding":report["findings"][0],"review":{"explanation":"unsafe", "suggested_fix":"def f():\n    pass"},"fix_status":"syntax_valid_unverified","related_findings":report["findings"]}]}
        report["dependencies"]["findings"]=[{"package":"example","version":"1.0","advisory_id":"CVE-example","fixed_versions":["2.0"]}]
        report["coverage"]["files"]=[{"path":"source.py","status":"partial","errors":{"semgrep":"failed"}}]
        report["logical_issues"]=[{"issue_id":"1","category":"unsafe_eval","normalized_severity":"MEDIUM","evidence":report["findings"]}]
        report["secrets"]={"status":"completed","findings":[{"scope":"directory","detector":"example","file":"source.py","line":1,"fingerprint":"fingerprint"}]}
        app.display_report(report,"test-report.json")
        assert len(app.issues_table.tree.get_children())==len(app.secrets_table.tree.get_children())==1
        root.update_idletasks()
        assert {"Logical issues", "Credentials"}.issubset({app.notebook.tab(tab,"text") for tab in app.notebook.tabs()})
        assert len(app.finding_table.tree.get_children())==1
        assert len(app.ai_table.tree.get_children())==1
        assert len(app.dep_table.tree.get_children())==1
        assert len(app.coverage_table.tree.get_children())==1
        assert "INCOMPLETE SCAN" in app.overview.get("1.0","end")
        assert "def f():\n    pass" in app.ai_table.details.get("1.0","end")
        export = tmp_path / "saved report.json"
        monkeypatch.setattr("src.gui.filedialog.asksaveasfilename", lambda **kwargs: str(export))
        app.export_report()
        assert load_report(export) == report
        app.fail_on.set("high")
        app.require_rules.set(True)
        app.search.set("not present")
        assert not app.finding_table.tree.get_children()
        app.search.set("")
        app.severity.set("HIGH")
        assert not app.finding_table.tree.get_children()
        app.severity.set("All severities")
        assert len(app.finding_table.tree.get_children())==1
        app.set_busy(True)
        assert str(app.scan_button["state"])=="disabled"
        app.set_busy(False)
        assert str(app.scan_button["state"])=="normal"
        source=tmp_path/"source.py"
        source.write_text("pass")
        app.target.set(str(source))
        app.key.set("test-key")
        thread=MagicMock()
        monkeypatch.setattr("src.gui.threading.Thread",thread)
        app.start_scan()
        assert app.busy and app.key.get()==""
        assert app.notebook.tab(app.notebook.select(),"text")=="Messages"
        assert thread.call_args.kwargs["args"][1]=="test-key"
        options = thread.call_args.kwargs["args"][0]
        assert app.profile.get() == "default" and options.profile == "standard"
        assert options.fail_on == "high" and options.require_validated_rules
        thread.return_value.start.assert_called_once()
        app.set_busy(False)
        check_desktop_hover_tips(app)
    finally:
        root.destroy()


def check_desktop_hover_tips(app):
    import tkinter as tk
    from tkinter import ttk

    root = app.root
    root.deiconify()

    def wait_for_hover():
        elapsed = tk.BooleanVar(root)
        root.after(1050, elapsed.set, True)
        root.wait_variable(elapsed)

    root.update()
    combo = app.scope_combos[0]
    root.tk.call("ttk::combobox::Post", combo)
    root.update()
    popup = root.tk.call("ttk::combobox::PopdownWindow", combo)
    listbox = f"{popup}.f.l"
    if not root.tk.call("winfo", "exists", listbox):
        root.tk.call("ttk::combobox::Unpost", combo)
        return

    def hover_row(index):
        _, y, _, height = root.tk.call(listbox, "bbox", index)
        root.tk.call("event", "generate", listbox, "<Motion>", "-x", 4, "-y", y + height // 2)

    hover_row(2)
    assert app.tooltips.window is None
    wait_for_hover()
    assert app.tooltips.window.winfo_children()[0].cget("text") == "Default scan + framework-specific checks for risks"
    assert combo.get() == "default"
    hover_row(0)
    assert app.tooltips.window is None
    root.tk.call("ttk::combobox::Unpost", combo)
    root.update()
    assert app.tooltips.timer is None

    checkbox = next(w for w in app.inputs if isinstance(w, ttk.Checkbutton) and w.cget("text") == "Require credential scan")
    checkbox.event_generate("<Enter>")
    wait_for_hover()
    assert app.tooltips.window.winfo_children()[0].cget("text") == "Require the credential scan to complete successfully."
    checkbox.event_generate("<Leave>")
    assert app.tooltips.window is None
    assert not app.require_secrets.get()
