import ast
import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from src import scanner
from src.dependency_audit import audit_dependencies
from src.llm_advisor import get_code_context, check_fix
from src.identities import enrich_identity


def fake_scan(path, **kwargs):
    return {"bandit":{"results":[{"test_id":"B307","filename":str(path),"line_number":1}],"scan_status":"completed"},"semgrep":{"results":[],"scan_status":"completed"}}


def test_directory_paths_hashes_and_exclusions(tmp_path,monkeypatch):
    for name in ("a.py","b.py"):(tmp_path/name).write_text("eval(input())")
    (tmp_path/".venv").mkdir();(tmp_path/".venv/x.py").write_text("eval(input())")
    monkeypatch.setattr(scanner,"scan_file",fake_scan)
    _,findings,coverage=scanner.scan_target(tmp_path)
    assert {Path(f["file"]).name for f in findings} == {"a.py","b.py"}
    assert all(f["source_sha256"] and f["statement_sha256"] for f in findings)
    assert coverage["completeness"] == 1
    assert len(coverage["excluded"]) == 1


def test_partial_size_parse_and_limit(tmp_path,monkeypatch):
    (tmp_path/"a.py").write_text("eval(input())")
    (tmp_path/"b.py").write_text("def invalid(:")
    (tmp_path/"c.py").write_text("#"*100)
    monkeypatch.setattr(scanner,"scan_file",fake_scan)
    _, findings,coverage=scanner.scan_target(tmp_path,max_bytes=50)
    assert len(findings)==1
    assert coverage["status"]=="partial"
    assert coverage["completeness"]==pytest.approx(1/3)
    assert {f["status"] for f in coverage["files"]}=={"completed","failed","skipped"}
    _,_,limited=scanner.scan_target(tmp_path,max_files=1)
    assert limited["status"]=="partial"


def test_scanner_failure_retains_other_scanner(tmp_path,monkeypatch):
    p=tmp_path/"a.py";p.write_text("eval(input())")
    monkeypatch.setattr(scanner,"run_json_scanner",MagicMock(side_effect=[{"results":[{"test_id":"B307","filename":str(p),"line_number":1,"issue_severity":"MEDIUM","issue_text":"unsafe eval"}]},RuntimeError("failed")]))
    _,findings,coverage=scanner.scan_target(p)
    assert len(findings)==1
    assert coverage["status"]=="partial"


def test_dependencies_do_not_default_to_own_environment(tmp_path,monkeypatch):
    monkeypatch.setattr("src.dependency_audit.subprocess.run",lambda *a,**k:pytest.fail("executed"))
    assert audit_dependencies(tmp_path)["status"]=="skipped"
    (tmp_path/"requirements.txt").write_text("some-package>=1")
    assert audit_dependencies(tmp_path)["status"]=="unsupported"


def test_dependency_findings_and_pinned_scope(tmp_path,monkeypatch):
    (tmp_path/"requirements.txt").write_text("example==1.0")
    mock=MagicMock(return_value=MagicMock(returncode=1,stdout=json.dumps({"dependencies":[{"name":"example","version":"1.0","vulns":[{"id":"PYSEC-example","aliases":["CVE-example"],"fix_versions":["2.0"]}]}]})))
    monkeypatch.setattr("src.dependency_audit.subprocess.run",mock)
    report=audit_dependencies(tmp_path)
    assert report["status"]=="completed"
    assert report["findings"][0]["fixed_versions"]==["2.0"]
    assert "--disable-pip" in mock.call_args.args[0]
    assert "-r" in mock.call_args.args[0]


def test_context_enclosing_function_and_imports(tmp_path):
    p=tmp_path/"a.py"
    p.write_text("import ast\nimport os\ndef f(x):\n    value = x\n    return ast.literal_eval(value)\n\ndef unrelated():\n    return 'unrelated'\n")
    context=get_code_context({"file":str(p),"line":5,"source_sha256":hashlib.sha256(p.read_bytes()).hexdigest()})
    assert "import ast" in context and "def f" in context
    assert "unrelated" not in context and "import os" not in context


def test_fix_unresolved_import_is_visible():
    checks=check_fix({"suggested_fix":"def f(x):\n    return ast.literal_eval(x)"})
    assert checks["compiles"] and "ast" in checks["unresolved_external_names"]
    assert not checks["behavior_verified"]


def test_statement_identity_survives_line_shift():
    a={"line":2};b={"line":4}
    enrich_identity(a,b"def f(x):\n    eval(x)\n")
    enrich_identity(b,b"# extra\n\ndef f(x):\n    eval(x)\n")
    assert a["statement_sha256"]==b["statement_sha256"] and a["scope"]==b["scope"]


def test_context_is_bounded(tmp_path):
    p=tmp_path/"large.py"
    p.write_text("def f():\n"+"    value = '"+"x"*20000+"'\n")
    context=get_code_context({"file":str(p),"line":2,"source_sha256":hashlib.sha256(p.read_bytes()).hexdigest()})
    assert len(context)<=12000 and "truncated" in context


def test_directory_unexpected_source_path_is_partial(tmp_path,monkeypatch):
    (tmp_path/"a.py").write_text("eval(input())")
    def wrong(path,**kwargs):
        result=fake_scan(path,**kwargs)
        result["bandit"]["results"][0]["filename"]=str(tmp_path.parent/"elsewhere.py")
        return result
    monkeypatch.setattr(scanner,"scan_file",wrong)
    _,findings,coverage=scanner.scan_target(tmp_path)
    assert not findings and coverage["status"]!="completed"


def test_rule_gate_requires_current_successful_bundle(monkeypatch,tmp_path):
    from src import rule_validation
    (tmp_path/"rules").mkdir()
    (tmp_path/"benchmarks/development").mkdir(parents=True)
    (tmp_path/"rules/code_execution.yml").write_text("rules: []")
    monkeypatch.setattr(rule_validation,"ROOT",tmp_path)
    assert rule_validation.active_config().name=="code_execution.yml"
    (tmp_path/"rules/validation.json").write_text(json.dumps({"status":"passed","bundle_sha256":rule_validation.bundle_digest(), "profile":"standard", "engine_version":rule_validation.engine_version()}))
    assert rule_validation.active_config().name=="rules"
    (tmp_path/"rules/new.yml").write_text("rules: []")
    assert rule_validation.active_config().name=="code_execution.yml"
