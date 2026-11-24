import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from src import scanner, rule_validation
from src.reporting import load_report, save_json
from src.scanner_response import validate_response


def bandit(path, line=1):
    return {"test_id":"B307", "issue_text":"Check eval", "issue_severity":"MEDIUM",
            "filename":str(path), "line_number":line}


def semgrep(path):
    return {"check_id":"eval", "path":str(path), "start":{"line":1},
            "extra":{"severity":"WARNING","message":"Check eval","metadata":{"confidence":"MEDIUM"}}}


@pytest.mark.parametrize("tool", ["bandit", "semgrep"])
def test_valid_evidence_survives_broken_sibling_and_error(tmp_path, tool):
    target = tmp_path / "demo.PY"
    valid = bandit(target.name) if tool == "bandit" else semgrep(target.name)
    invalid = ({"line_number":True}, {"filename":"wrong.py"}, {"issue_severity":[]}) if tool == "bandit" else (
        {"start":{"line":True}}, {"path":"elsewhere.py"}, {"extra":[]}, {"extra":{"metadata":42}})
    rows = [None, valid, *({**valid, **change} for change in invalid)]
    data = {"results":rows, "errors":[{"message":"warning"}], "paths":{"scanned":[target.name]}}
    result = validate_response(tool, data, target, tmp_path)
    assert len(result["results"]) == 1 and result["scan_status"] == "partial"
    assert len(result["error"].split("; ")) == len(rows)
    assert result["results"][0].get("filename",result["results"][0].get("path")) == str(target)


@pytest.mark.parametrize("paths,expected", [(None,"unknown"), ({"scanned":["wrong.py"]},"unknown"),
    ({"scanned":[]},"skipped"), ({"scanned":["Demo.PY"]},"analyzed"), ({"scanned":[22]},"unknown")])
def test_semgrep_coverage(tmp_path, paths, expected):
    data = validate_response("semgrep", {"results":[],"paths":paths}, tmp_path/"Demo.PY", tmp_path)
    assert data["coverage"] == expected
    assert (data["scan_status"] == "completed") == (expected == "analyzed")


@pytest.mark.parametrize("option,value", [("--scanner-timeout","nan"),("--total-timeout","inf"),
    ("--max-files","0"),("--max-file-bytes","1.1")])
def test_invalid_cli_limit(monkeypatch, option, value):
    monkeypatch.setattr(sys,"argv",["scan","example.py",option,value])
    with pytest.raises(SystemExit) as exc:
        scanner.main()
    assert exc.value.code == 2


@pytest.fixture
def cli(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner,"ROOT",tmp_path)
    source = tmp_path/"Demo.PY"
    source.write_text("value = 42")
    settings = SimpleNamespace(findings=[], dep_status="completed", dep_reason="audit_finished",
                               advisories=[], approval="passed", source="completed")
    def response(command, *args, **kwargs):
        if "scan" in command:
            if settings.source == "partial":
                raise RuntimeError("engine timeout")
            return {"results":[], "paths":{"scanned":[str(source)]}}
        return {"results":settings.findings, "metrics":{str(source):{}}}
    monkeypatch.setattr(scanner,"run_json_scanner",response)
    monkeypatch.setattr(rule_validation,"validation_state",lambda: {
        "status":settings.approval, "bundle_sha256":"test", "reason":"test approval"})
    monkeypatch.setattr("src.dependency_audit.audit_dependencies", lambda *a: {
        "status":settings.dep_status, "reason":settings.dep_reason, "findings":settings.advisories, "packages":[]})
    def run(*flags, target=source):
        monkeypatch.setattr(sys,"argv",["scan",str(target),"--no-llm",*flags])
        before = set(tmp_path.glob("reports/*/report.json"))
        try:
            scanner.main()
            code = 0
        except SystemExit as exc:
            code = exc.code
        path, = set(tmp_path.glob("reports/*/report.json")) - before
        result = load_report(path)
        assert result["exit_code"] == code and result["run_id"] == path.parent.name
        return result
    return settings, source, run


def test_policy_findings_and_execution_precedence(cli):
    state, path, run = cli
    assert run("--fail-on","high")["exit_code"] == 0
    state.findings = [bandit(path)]
    assert run("--fail-on","high")["exit_code"] == 0
    first = run("--fail-on","medium")
    assert first["execution"]["overall"] == "completed" and first["policy"]["result"] == "failed"
    assert first["exit_code"] == 1
    state.source = "partial"
    mixed = run("--fail-on","low")
    assert mixed["exit_code"] == 2 and mixed["policy"]["result"] == "not_evaluable"
    assert mixed["policy"]["violations"] and "source_partial" in mixed["policy"]["reasons"]
    assert mixed["findings"][0]["rule_id"] == "B307"


def test_advisories_and_unknown_severity(cli):
    state, path, run = cli
    state.advisories = [{"advisory_id":"advisory-without-severity"}]
    assert run("--require-dependencies")["exit_code"] == 0
    assert run("--fail-on","high")["exit_code"] == 1
    state.advisories = []
    state.findings = [{**bandit(path), "issue_severity":"UNDEFINED"}]
    assert run("--fail-on","high")["policy"]["violations"]


@pytest.mark.parametrize("status,reason",[("unsupported","unpinned"),("skipped","no_target_manifest"),
    ("failed","audit_timeout"),("partial","package_skipped")])
def test_required_dependency_execution(cli,status,reason):
    state, _, run = cli
    state.dep_status, state.dep_reason = status, reason
    assert run()["exit_code"] == 0
    report = run("--require-dependencies")
    assert report["exit_code"] == 2 and report["policy"]["result"] == "not_evaluable"
    assert report["execution"]["dependencies"] == status


def test_fallback_and_empty_target(cli,tmp_path,capsys):
    state, _, run = cli
    state.approval = "pending"
    assert run()["exit_code"] == 0
    report = run("--require-validated-rules")
    assert report["exit_code"] == 2 and report["rule_validation"]["effective_rule_ids"] == ["insecure-eval"]
    assert "WARNING: Reduced" in capsys.readouterr().out
    folder = tmp_path/"empty"
    folder.mkdir()
    assert run(target=folder)["exit_code"] == 2


def test_profile_digest_survives_checkout_line_endings(tmp_path, monkeypatch):
    monkeypatch.setattr(rule_validation, "ROOT", tmp_path)
    fixture = tmp_path / "benchmarks/development/sample.py"
    fixture.parent.mkdir(parents=True)
    fixture.write_bytes(b"def f():\n    pass\n")
    digest = rule_validation.bundle_digest()
    fixture.write_bytes(fixture.read_bytes().replace(b"\n", b"\r\n"))
    assert rule_validation.bundle_digest() == digest


@pytest.mark.parametrize("mutate", ["rule", "fixture", "engine", "missing"])
def test_approval_identity(tmp_path,monkeypatch,mutate):
    monkeypatch.setattr(rule_validation, "ROOT", tmp_path)
    monkeypatch.setattr(rule_validation,"engine_version",lambda:"1")
    rules = tmp_path/"rules"
    rules.mkdir()
    fixtures = tmp_path/"benchmarks/development"
    fixtures.mkdir(parents=True)
    rule, fixture = rules/"code_execution.yml", fixtures/"sample.py"
    rule.write_text("rules: []")
    fixture.write_text("pass")
    stamp = rules/"validation.json"
    stamp.write_text(json.dumps({"status":"passed","profile":"standard","engine_version":"1",
                                 "bundle_sha256":rule_validation.bundle_digest()}))
    assert rule_validation.active_config() == rules
    if mutate == "missing":
        stamp.unlink()
    elif mutate == "engine":
        monkeypatch.setattr(rule_validation,"engine_version",lambda:"2")
    else:
        (rule if mutate == "rule" else fixture).write_text("# modified")
    assert rule_validation.active_config() == rule


def test_atomic_replacement_failure_and_legacy_export(tmp_path,monkeypatch):
    source = tmp_path/"legacy.json"
    old = {"scan_status":"completed","findings":[]}
    save_json(source,old)
    exported = tmp_path/"export.json"
    save_json(exported,load_report(source))
    assert load_report(exported) == old
    def interrupt(*args):
        raise OSError("interrupted")
    monkeypatch.setattr("src.reporting.os.replace",interrupt)
    with pytest.raises(OSError, match="interrupted"):
        save_json(source,{"findings":[1]})
    assert load_report(source) == old and not list(tmp_path.glob(".report-*"))


@pytest.mark.parametrize("same_target", [True, False])
def test_simultaneous_cli_runs(tmp_path, same_target):
    from subprocess import run
    project = Path(scanner.__file__).resolve().parents[1]
    targets = [tmp_path/"first.py", tmp_path/("first.py" if same_target else "second.py")]
    for path in targets:
        path.write_text("def invalid(:")
    script = ("import sys; from pathlib import Path; from src import scanner; "
              "scanner.ROOT=Path(sys.argv.pop(1));scanner.main()")
    def scan(path):
        proc = run([sys.executable,"-B","-c",script,str(tmp_path),str(path),"--no-llm","--skip-dependencies"],
                   cwd=project, capture_output=True, text=True, timeout=50)
        assert proc.returncode == 2, proc.stderr
        event = json.loads(proc.stdout.splitlines()[-1])
        report = load_report(event["report_path"])
        assert report["file"]["path"] == str(path) and report["run_id"] == event["run_id"]
        return event["report_path"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        paths = list(pool.map(scan, targets))
    assert len(set(paths)) == 2
