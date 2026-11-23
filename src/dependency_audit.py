"""Audit only explicit target dependency information, never the agent environment."""
import json
from importlib.metadata import version, PackageNotFoundError
from contextlib import nullcontext
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def audit_pinned(target, requirements=None, skip=False, timeout=120, installed_path=None):
    root = target.resolve() if target.is_dir() else target.resolve().parent
    report = {"status":"skipped", "reason":"no_target_manifest", "packages":[], "findings":[],
              "scope":"explicit declared versions only; transitive coverage requires a complete lock export"}
    if skip:
        report["reason"]="disabled_by_flag"; return report
    manifest = Path(requirements).resolve() if requirements else root/"requirements.txt"
    cache = Path(tempfile.gettempdir()) / "secure-review-pip-audit-cache"
    cache.mkdir(exist_ok=True)
    command = [sys.executable,"-m","pip_audit","--format=json","--cache-dir",str(cache),"--progress-spinner=off","--timeout",str(max(1,int(timeout)))]
    entries = None
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
            raw = manifest.read_bytes()
            # UTF-16 requires a BOM; otherwise decode strictly as UTF-8 (optional BOM).
            if raw.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
                raise UnicodeError("UTF-32 manifests are not supported")
            encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
            text = raw.decode(encoding)
            lines=[line.split(" #",1)[0].strip() for line in text.splitlines()]
        except UnicodeError:
            return {**report,"status":"failed","reason":"manifest_decoding_error"}
        except OSError:
            return {**report,"status":"failed","reason":"manifest_unreadable"}
        entries=[x for x in lines if x and not x.startswith("#")]
        if not entries or any(not re.fullmatch(r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+!-]+",x) for x in entries):
            return {**report,"status":"unsupported","reason":"export_complete_pinned_name_equals_version_manifest"}
    try:
        with tempfile.TemporaryDirectory(prefix="secure-review-manifest-") if entries is not None else nullcontext() as temporary:
            if entries is not None:
                normalized = Path(temporary) / "requirements.txt"
                normalized.write_text("\n".join(entries) + "\n", encoding="utf-8", newline="\n")
                command += ["-r",str(normalized),"--no-deps","--disable-pip"]
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

def audit_pylock(target, path, timeout):
    """The pinned OSV release lacks PEP 751 extraction. Export exact metadata only."""
    import tomllib
    from .issues import canonical
    from packaging.version import Version
    failure = {"status":"failed","reason":"invalid_pylock","tool":"pip-audit","packages":[],"findings":[]}
    try:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
        if data.get("lock-version")!="1.0" or not isinstance(data["packages"],list):
            return failure
        pins = set()
        unresolved = False
        for item in data["packages"]:
            name = item["name"]
            if not isinstance(name,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*",name):
                return failure
            if not item.get("version"):
                unresolved=True
                continue
            version = str(Version(item["version"]))
            pins.add((canonical(name),version))
        if not pins:
            return {**failure,"status":"unsupported","reason":"no_resolved_packages"}
        with tempfile.TemporaryDirectory() as folder:
            export=Path(folder)/"requirements.txt"
            export.write_text("".join(f"{n}=={v}\n" for n,v in sorted(pins)),encoding="utf-8")
            part=audit_pinned(target,export,False,timeout)
        analyzed={(canonical(row["name"]),row["version"]) for row in part["packages"]}
        if part["status"]=="completed" and (unresolved or pins-analyzed):
            part.update(status="partial",reason="lock_entries_not_analyzed")
        return {**part,"tool":"pip-audit"}
    except (ValueError, OSError, KeyError, TypeError, AttributeError):
        return failure


def audit_dependencies(target, requirements=None, skip=False, timeout=120, installed_path=None):
    from .manifests import discover, LOCKS, is_pylock, subproject
    from .osv_adapter import audit_lock
    from .issues import deduplicate
    from hashlib import sha256
    import time
    root = target.resolve() if target.is_dir() else target.resolve().parent
    if skip:
        return audit_pinned(target, skip=True)
    ignored, errors = [], []
    if installed_path:
        inputs = [Path(installed_path).resolve()]
    elif requirements:
        inputs = [Path(requirements).resolve()]
    else:
        inputs, ignored, errors = discover(root)
    if not inputs and not errors:
        return {"status":"skipped","reason":"no_target_manifest","packages":[],"findings":[],
                "inputs":[],"scope":"target project manifests"}
    audits = []
    packages = []
    raw = []
    deadline = time.monotonic() + timeout
    for path in inputs:
        resolution = "installed" if installed_path else "lockfile" if path.name in LOCKS or is_pylock(path) else "pinned_declaration"
        digest = None
        try:
            if not installed_path and path.is_file():
                with path.open("rb") as stream:
                    content = stream.read(8_000_001)
                if len(content)>8_000_000:
                    raise ValueError
                digest = sha256(content).hexdigest()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                part = {"status":"failed","reason":"audit_timeout"}
            elif is_pylock(path) and not installed_path:
                part = audit_pylock(target, path, remaining)
            elif resolution=="lockfile":
                part = audit_lock(path, remaining)
            elif path.name=="pyproject.toml":
                resolution = "declared_constraints"
                part = {"status":"unsupported","reason":"resolved_versions_required"}
            else:
                part = audit_pinned(target, None if installed_path else path, False, remaining, installed_path)
        except (OSError, ValueError):
            part = {"status":"failed","reason":"manifest_unreadable_or_oversized"}
        if digest is not None:
            try:
                with path.open("rb") as stream:
                    changed = sha256(stream.read(8_000_001)).hexdigest() != digest
            except OSError:
                changed = True
            if changed:
                part.update(status="partial",reason="manifest_changed_during_audit")
        tool = part.get("tool","pip-audit" if resolution != "declared_constraints" else None)
        for row in part.get("packages",[]):
            packages.append({**row,"manifest":str(path),"resolution":resolution})
        for row in part.get("findings",[]):
            raw.append({**row,"manifest":str(path),"resolution":resolution,"tool":tool})
        tool_version=part.get("tool_version")
        if tool=="pip-audit":
            try:
                tool_version=version("pip-audit")
            except PackageNotFoundError:
                tool_version=None
        audits.append({"path":str(path),"subproject":str(subproject(path,root)),"sha256":digest,"tool":tool,"tool_version":tool_version,"resolution":resolution,
                       "status":part["status"],"reason":part["reason"]})
    states={a["status"] for a in audits}
    status = states.pop() if len(states)==1 and not errors else "partial" if audits else "failed"
    return {"status":status,"reason":audits[0]["reason"] if len(audits)==1 and not errors else "discovery_or_audit_"+status,
            "input":str(inputs[0]) if len(inputs)==1 else str(root),"inputs":audits,"shadowed":ignored,"errors":errors,
            "scope":"explicit target versions from selected manifests or installed metadata",
            "packages":packages,"detections":raw,"findings":deduplicate(raw)}
