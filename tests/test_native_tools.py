"""Opt-in subprocess integration checks; never transmit source or use Gemini."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
from src.secrets_scan import detect, screen_prompt

pytestmark=pytest.mark.skipif(os.getenv("REVIEW_NATIVE_TESTS")!="1",reason="native integration job")


def test_worktree_and_opt_in_history(tmp_path):
    def git(*args):
        subprocess.run(["git","-C",str(tmp_path),*args],check=True,capture_output=True)
    git("init")
    key="synthetic-example-"+"private-8675309"
    p=tmp_path/"app.py"
    p.write_text(f'password = "{key}" # gitleaks:allow\n')
    first=detect(tmp_path)
    assert first["status"]=="completed" and first["findings"]
    assert all(r["scope"]=="directory" for r in first["findings"]) and key not in json.dumps(first)
    git("add","app.py")
    git("-c","user.name=Test","-c","user.email=test@example.invalid","commit","-m","fixture")
    p.write_text('password = "<credential>"\n')
    history=detect(tmp_path,history=True)
    assert history["status"]=="completed" and {r["scope"] for r in history["findings"]}=={"history"}
    assert key not in json.dumps(history)


@pytest.mark.parametrize("source,exit_code",[("print(1)",0),("eval(input())",1),("def broken(:",2)])
def test_real_policy_exit(tmp_path,source,exit_code):
    p=tmp_path/"sample.py";p.write_text(source)
    cmd=[sys.executable,"-m","src.scanner",str(p),"--no-llm","--skip-dependencies","--require-secrets","--fail-on","low"]
    result=subprocess.run(cmd,text=True,capture_output=True,timeout=150)
    event=json.loads(result.stdout.splitlines()[-1])
    report=json.loads(Path(event["report_path"]).read_text())
    if os.getenv("REVIEW_ARTIFACTS"):
        dest=Path(os.environ["REVIEW_ARTIFACTS"]);dest.mkdir(exist_ok=True)
        shutil.copyfile(event["report_path"],dest/f"controlled-policy-{exit_code}.json")
    assert result.returncode==exit_code, result.stdout
    assert report["run_id"]==event["run_id"] and report["schema_version"]==1
    assert report["policy"]["result"]=={0:"passed",1:"failed",2:"not_evaluable"}[exit_code]


@pytest.mark.skipif(os.getenv("REVIEW_LIVE_ADVISORIES")!="1",reason="separate live advisory job")
@pytest.mark.parametrize("name", ["Pipfile.lock","poetry.lock","uv.lock","pdm.lock","pylock.toml"])
def test_lock_live(tmp_path,name):
    from src.dependency_audit import audit_dependencies
    p=tmp_path/name
    if name=="Pipfile.lock":
        p.write_text(json.dumps({"_meta":{"pipfile-spec":6},"default":{"requests":{"version":"==2.19.1"}},"develop":{}}))
    else:
        header={"pylock.toml":'lock-version="1.0"\n[[packages]]',"uv.lock":"version=1\n[[package]]"}.get(name,"[[package]]")
        p.write_text(header+'\nname="requests"\nversion="2.19.1"\n')
    report=audit_dependencies(tmp_path, timeout=90)
    assert report["status"]=="completed" and report["findings"]
    assert all(r["package"]=="requests" for r in report["findings"])

def test_native_prompt_and_saved_report(tmp_path):
    value="synthetic-review-"+"test-314159"
    text=f'password = "{value}"'
    with pytest.raises(ValueError,match="cloud_context_redaction_incomplete"):
        screen_prompt(text)
    screen_prompt('password = "<credential>"')
    p=tmp_path/"credential.py"
    p.write_text(text)
    proc=subprocess.run([sys.executable,"-m","src.scanner",str(p),"--no-llm","--skip-dependencies"],
                        capture_output=True,text=True,timeout=150)
    assert proc.returncode==0 and value not in proc.stdout+proc.stderr
    report_path=Path(json.loads(proc.stdout.splitlines()[-1])["report_path"])
    assert json.loads(report_path.read_text())["secrets"]["findings"]
    for sidecar in report_path.parent.glob("*.json"):
        assert value not in sidecar.read_text()
