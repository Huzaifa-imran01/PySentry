import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest
from src import llm_advisor, secrets_scan
from src.dependency_audit import audit_dependencies
from src.issues import logical_issues, deduplicate
from src.identities import enrich_identity
from src.manifests import discover
from src.osv_adapter import audit_lock
from src.reporting import save_json, scanner_evidence


def test_report_and_prompt_boundary(tmp_path,monkeypatch):
    value="synthetic-private-"+"sample123"
    evidence={"results":[{"test_id":"B105","code":value,"unexpected":value,"issue_text":f"Password: '{value}'"}]}
    path=tmp_path/"report.json"
    save_json(path,scanner_evidence("bandit",evidence))
    assert value not in path.read_text()
    prompts=[]
    monkeypatch.setattr(secrets_scan,"screen_prompt",prompts.append)
    def reply(key,model,prompt,**kw):
        assert prompt==prompts[0] and value not in prompt
        return json.dumps({k:"safe guidance" for k in llm_advisor.REVIEW_SCHEMA["required"]})
    monkeypatch.setattr(llm_advisor,"generate",reply)
    llm_advisor.review_finding({"message":f"Password: '{value}'"},f'1: password = "{value}"\n2: # {value}',"key")
    assert "<credential>" in prompts[0]


def test_redaction_failure_never_calls_provider(monkeypatch,capsys):
    def fail(prompt):
        raise ValueError("cloud_context_redaction_incomplete")
    monkeypatch.setattr(secrets_scan,"screen_prompt",fail)
    monkeypatch.setattr(llm_advisor,"generate",lambda *a,**k:pytest.fail("cloud request"))
    monkeypatch.setattr(llm_advisor,"get_code_context",lambda f:'token = "synthetic-private-value"')
    row,=llm_advisor.review_all_findings([{"rule_id":"B105","line":1}])
    assert row["status"]=="skipped" and row["error"]=="cloud_context_redaction_incomplete"
    assert "synthetic-private-value" not in str(row)+capsys.readouterr().out


def test_source_sites_and_severity():
    def row(rule, line, source):
        r=dict(rule_id=rule,line=line,file="file.py",source_sha256="filehash",severity="WARNING",
               scanner="bandit" if rule=="B307" else "semgrep")
        enrich_identity(r,source.encode())
        return r
    source="eval(x)\neval(x)\neval(x); eval(y)\n"
    detections=[row(rule,n,source) for rule in ("B307","insecure-eval") for n in (1,2,3)]
    groups=logical_issues(detections)
    assert sorted(len(x["evidence"]) for x in groups)==[1,1,2,2]
    assert {r["normalized_severity"] for r in groups}=={"MEDIUM"}
    assert len(logical_issues([detections[0],{**detections[0],"rule_id":"B602"}]))==2
    assert len(logical_issues([detections[0]]*2))==1


def test_advisory_aliases_and_versions():
    base=dict(package="Example_Pkg",version="1",advisory_id="GHSA-example",aliases=["CVE-example"],manifest="a")
    rows=deduplicate([base,{**base,"advisory_id":"CVE-example","package":"example-pkg","manifest":"b"},{**base,"version":"2"}])
    assert len(rows)==2 and {e["manifest"] for e in rows[0]["evidence"]}=={"a","b"}


def test_nested_manifest_precedence(tmp_path):
    for folder,name in (("a","uv.lock"),("a","requirements.txt"),("b","requirements-dev.txt"),("c","pyproject.toml"),(".venv","poetry.lock")):
        p=tmp_path/folder/name;p.parent.mkdir(exist_ok=True);p.touch()
    files,shadowed,errors=discover(tmp_path)
    assert not errors and {p.name for p in files}=={"uv.lock","requirements-dev.txt","pyproject.toml"}
    assert shadowed==[str(tmp_path/"a"/"requirements.txt")]
    report=audit_dependencies(tmp_path/"c")
    assert report["status"]=="unsupported" and report["inputs"][0]["resolution"]=="declared_constraints"


@pytest.mark.parametrize("failure",["missing","offline","malformed","timeout"])
def test_lock_failure_visible(tmp_path,monkeypatch,failure):
    p=tmp_path/"uv.lock";p.write_text("broken" if failure=="malformed" else '[[package]]\nname="example"\nversion="1"\n')
    def tool(*args):
        if failure=="missing":raise RuntimeError("osv-scanner_not_installed")
        return "tool"
    def run(*args,**kwargs):
        if failure=="timeout":raise subprocess.TimeoutExpired("tool",1)
        return SimpleNamespace(returncode=2 if failure=="offline" else 0,stdout=b'{"results":[{}]}')
    monkeypatch.setattr("src.osv_adapter.pinned_tool",tool)
    monkeypatch.setattr("src.osv_adapter.subprocess.run",run)
    assert audit_lock(p,2)["status"]=="failed"

def test_named_pylock_uses_only_pinned_metadata(tmp_path,monkeypatch):
    p=tmp_path/"pylock.test.toml"
    p.write_text('lock-version="1.0"\n[[packages]]\nname="Example_Pkg"\nversion="1.1"\n')
    def pinned(target,manifest,skip,timeout):
        assert manifest.read_text()=="example-pkg==1.1\n"
        return {"status":"completed","reason":"audit_finished","packages":[{"name":"example-pkg","version":"1.1"}],"findings":[]}
    monkeypatch.setattr("src.dependency_audit.audit_pinned",pinned)
    result=audit_dependencies(tmp_path)
    assert result["status"]=="completed"
    entry,=result["inputs"]
    assert entry["tool"]=="pip-audit" and entry["resolution"]=="lockfile" and entry["sha256"]


def test_incomplete_extractor_inventory(tmp_path, monkeypatch):
    p=tmp_path/"poetry.lock"
    p.write_text('[[package]]\nname="one"\nversion="1"\n[[package]]\nname="two"\nversion="2"\n')
    output={"results":[{"source":{"path":str(p)},"packages":[{"package":{"ecosystem":"PyPI","name":"one","version":"1"}}]}]}
    monkeypatch.setattr("src.osv_adapter.pinned_tool",lambda *args:"tool")
    monkeypatch.setattr("src.osv_adapter.subprocess.run",lambda *a,**k:SimpleNamespace(returncode=0,stdout=json.dumps(output)))
    result=audit_dependencies(tmp_path)
    assert result["status"]=="partial" and result["reason"]=="lock_entries_not_analyzed"


def test_prompt_screen_fails_closed_on_missing_output(monkeypatch):
    monkeypatch.setattr(secrets_scan,"pinned_tool",lambda *a:"tool")
    monkeypatch.setattr(secrets_scan.subprocess,"run",lambda *a,**k:SimpleNamespace(returncode=0,stdout=b""))
    with pytest.raises(ValueError,match="cloud_context_redaction_incomplete"):
        secrets_scan.screen_prompt("sample")
