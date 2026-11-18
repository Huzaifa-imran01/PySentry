"""Audit only explicit target dependency information, never the agent environment."""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def audit_dependencies(target, requirements=None, skip=False, timeout=120, installed_path=None):
    root = target.resolve() if target.is_dir() else target.resolve().parent
    report = {"status":"skipped", "reason":"no_target_manifest", "packages":[], "findings":[],
              "scope":"explicit declared versions only; transitive coverage requires a complete lock export"}
    if skip:
        report["reason"]="disabled_by_flag"; return report
    manifest = Path(requirements).resolve() if requirements else root/"requirements.txt"
    cache = Path(tempfile.gettempdir()) / "secure-review-pip-audit-cache"
    cache.mkdir(exist_ok=True)
    command = [sys.executable,"-m","pip_audit","--format=json","--cache-dir",str(cache),"--progress-spinner=off","--timeout",str(max(1,int(timeout)))]
    if installed_path:
        path = Path(installed_path).resolve()
        if not path.is_dir() or not path.is_relative_to(root):
            return {**report,"status":"failed","reason":"dependency_path_must_be_inside_target_root"}
        command += ["--path",str(path)]
        report.update(input=str(path),scope="installed distribution metadata under explicitly selected target path")
    else:
        if not manifest.is_file(): return report
        report["input"] = str(manifest)
        # Avoid executing builds/resolvers from untrusted projects: require a fully pinned export.
        try:
            lines=[line.split(" #",1)[0].strip() for line in manifest.read_text(encoding="utf-8").splitlines()]
        except OSError:
            return {**report,"status":"failed","reason":"manifest_unreadable"}
        entries=[x for x in lines if x and not x.startswith("#")]
        if not entries or any(not re.fullmatch(r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+!-]+",x) for x in entries):
            return {**report,"status":"unsupported","reason":"export_complete_pinned_name_equals_version_manifest"}
        command += ["-r",str(manifest),"--no-deps","--disable-pip"]
    try:
        proc=subprocess.run(command,capture_output=True,text=True,encoding="utf-8",timeout=timeout)
        if proc.returncode not in (0,1):
            return {**report,"status":"failed","reason":"pip_audit_execution_error"}
        data=json.loads(proc.stdout)
        deps=data["dependencies"]
        if not isinstance(deps,list): raise ValueError("dependencies")
        for dep in deps:
            report["packages"].append({"name":dep["name"],"version":dep.get("version"),"skip_reason":dep.get("skip_reason")})
            for vuln in dep.get("vulns",[]):
                report["findings"].append({"package":dep["name"],"version":dep.get("version"),
                    "advisory_id":vuln["id"],"aliases":vuln.get("aliases",[]),"fixed_versions":vuln.get("fix_versions",[])})
        if proc.returncode == 1 and not report["findings"]:
            return {**report,"status":"failed","reason":"unexplained_nonzero_exit"}
        report.update(status="partial" if any(p["skip_reason"] for p in report["packages"]) else "completed", reason="audit_finished")
    except subprocess.TimeoutExpired:
        report.update(status="failed",reason="audit_timeout")
    except (OSError,ValueError,KeyError,TypeError):
        report.update(status="failed",reason="audit_unavailable_or_invalid_response")
    return report
