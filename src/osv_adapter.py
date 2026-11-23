import json
from pathlib import Path
import subprocess
import tempfile
import tomllib
from .issues import canonical
from .tooling import pinned_tool

VERSION = "2.2.2"


def declared_packages(path):
    """Inventory exact lock entries independently, so missing extractor output is visible."""
    if path.name=="Pipfile.lock":
        data = json.loads(path.read_bytes())
        groups = [values for key,values in data.items() if key!="_meta"]
        if not groups or any(not isinstance(group,dict) for group in groups):
            raise ValueError
        records = [(name,entry.get("version","").removeprefix("==")) for group in groups for name,entry in group.items()]
    else:
        with path.open("rb") as stream:
            data=tomllib.load(stream)
        entries=data["package"]
        records=[(row["name"],row.get("version","")) for row in entries]
    return {(canonical(name),version) for name,version in records}


def audit_lock(path, timeout):
    report = {"input":str(path),"packages":[],"findings":[],"tool":"osv-scanner","tool_version":VERSION,
              "status":"failed","reason":"osv_unavailable_or_invalid_response"}
    try:
        expected = declared_packages(path)
        executable = pinned_tool("osv-scanner",VERSION)
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp)/"osv-scanner.toml"
            config.write_text("",encoding="utf-8")
            cmd = [executable,"scan","source","--no-resolve","--all-packages","--format","json",
                   "--config",str(config),"--lockfile",str(path)]
            proc = subprocess.run(cmd,cwd=temp,capture_output=True,timeout=timeout)
        if proc.returncode not in (0,1):
            return report
        blocks = json.loads(proc.stdout)["results"]
        if not isinstance(blocks,list) or not blocks:
            return report
        for block in blocks:
            if Path(block["source"]["path"]).resolve() != path or not isinstance(block["packages"],list):
                raise ValueError
            for item in block["packages"]:
                pkg=item["package"]
                if pkg["ecosystem"]!="PyPI" or not all(isinstance(pkg[k],str) and pkg[k] for k in ("name","version")):
                    raise ValueError
                record={"name":pkg["name"],"version":pkg["version"],"manifest":str(path),"resolution":"lockfile"}
                report["packages"].append(record)
                for vuln in item.get("vulnerabilities",[]):
                    fixes=set()
                    for affected in vuln.get("affected",[]):
                        ap=affected.get("package",{})
                        if ap.get("ecosystem")=="PyPI" and canonical(ap.get("name",""))==canonical(pkg["name"]):
                            fixes.update(e["fixed"] for r in affected.get("ranges",[]) for e in r["events"] if "fixed" in e)
                    aliases=vuln.get("aliases",[])
                    if not isinstance(vuln["id"],str) or not isinstance(aliases,list) or not all(isinstance(a,str) for a in aliases):
                        raise ValueError
                    report["findings"].append({"package":pkg["name"],"version":pkg["version"],"advisory_id":vuln["id"],
                        "aliases":aliases,"fixed_versions":sorted(fixes),"manifest":str(path),"tool":"osv-scanner"})
        if bool(proc.returncode) != bool(report["findings"]):
            return report
        actual={(canonical(p["name"]),p["version"]) for p in report["packages"]}
        missing=expected-actual
        report.update(status="partial" if missing else "completed",
                      reason="lock_entries_not_analyzed" if missing else "audit_finished",
                      missing_packages=len(missing))
    except subprocess.TimeoutExpired:
        report.update(reason="audit_timeout")
    except RuntimeError as exc:
        report.update(reason=str(exc))
    except (OSError, KeyError, ValueError, AttributeError,TypeError):
        pass
    return report
