"""Reproducible, non-executing rule tests and labelled detection evaluation."""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from src.rule_validation import ROOT, PROFILE, bundle_digest, engine_version, profile_rules, profile_root, PROFILES


def semgrep(args, timeout=180):
    # Isolate writable CLI state; do not depend on user login or global settings.
    with tempfile.TemporaryDirectory(prefix="security-rule-test-") as directory:
        env=dict(os.environ)
        env.update(SEMGREP_SETTINGS_FILE=str(Path(directory)/"settings.yml"),
                   SEMGREP_LOG_FILE=str(Path(directory)/"semgrep.log"),SEMGREP_SEND_METRICS="off")
        env.pop("SEMGREP_APP_TOKEN",None)
        executable = Path(sys.executable).parent / ("semgrep.exe" if os.name=="nt" else "semgrep")
        if os.name=="nt":
            # Native annotated tests require each rule and its matching fixture side by side.
            if "--test" in args:
                paired = Path(directory)/"annotated"
                paired.mkdir()
                index = args.index("--config")
                rules, fixtures = map(Path,args[index+1:index+3])
                for source in [*rules.glob("*.yml"), *fixtures.glob("*.py")]:
                    shutil.copyfile(source,paired/source.name)
                args = [*args[:index],"--experimental",str(paired)]
            args = [*args,"--x-parmap",*([] if "--experimental" in args else ["--experimental"])]
        command=[str(executable),*args,"--metrics=off","--disable-version-check","--jobs=1"]
        try:
            result=subprocess.run(command,cwd=ROOT,env=env,text=True,capture_output=True,encoding="utf-8",timeout=timeout)
            data=json.loads(result.stdout)
            return result.returncode,data
        except subprocess.TimeoutExpired:
            return 2,{"error":"engine_timeout"}
        except (OSError,ValueError):
            return 2,{"error":"engine_unavailable_or_invalid_output"}


def validate(profile=PROFILE):
    root = profile_root(profile)
    digest=bundle_digest(profile)
    code,data=semgrep(["--test","--strict","--json","--config",str(root/"rules"),str(root/"benchmarks/development")])
    checks=[(name.split(".")[-1],check) for result in data.get("results",{}).values() for name,check in result.get("checks",{}).items()]
    import yaml
    rule_ids=[r["id"] for p in profile_rules(profile) for r in yaml.safe_load(p.read_text())["rules"]]
    expected=len(rule_ids)
    passed=code==0 and not data.get("config_with_errors") and len(checks)==expected and {name for name,_ in checks}==set(rule_ids) and all(c.get("passed") for _,c in checks) and bundle_digest(profile)==digest
    state={"status":"passed" if passed else "failed", "bundle_sha256":digest,
           "profile":profile, "engine_version":engine_version(), "expected_rules":expected,"tested_rules":len(checks),"timestamp":datetime.now(timezone.utc).isoformat(),
           "reason":None if passed else "Rule tests failed, missing, or engine unavailable; inspect benchmarks/results/rule_tests.json"}
    output=profile_root(profile)/"benchmarks/results";output.mkdir(parents=True,exist_ok=True)
    # Keep recorded evidence navigable after a temporary fixture directory is removed.
    if passed:
        checked={}
        for name,row in data["results"].items():
            rule_path=root/"rules"/Path(name).name
            checked[rule_path.relative_to(ROOT).as_posix()]=row
            for check in row.get("checks",{}).values():
                check["matches"]={(root/"benchmarks/development"/Path(path).name).relative_to(ROOT).as_posix():value
                                  for path,value in check.get("matches",{}).items()}
        data["results"]=checked
    (output/"rule_tests.json").write_text(json.dumps(data,indent=2),encoding="utf-8")
    (root/"rules/validation.json").write_text(json.dumps(state,indent=2))
    return state


def labels(directory):
    result={}
    for path in sorted(directory.glob("*.py")):
        lines=path.read_text().splitlines()
        for i,line in enumerate(lines):
            match=re.search(r"# (ruleid|ok|todoruleid): ([\w-]+)",line)
            if match:
                kind,rule=match.groups()
                result[(str(path.resolve()),i+2,rule)]=kind
    return result


def detection_metrics(expected, actual):
    # Known unsupported positive cases remain false negatives in overall recall.
    positives={k for k,v in expected.items() if v in ("ruleid","todoruleid")}
    known_misses={k for k,v in expected.items() if v=="todoruleid"}
    actual=set(actual)
    tp=len(actual & positives); fp=len(actual-positives); fn=len(positives-actual)
    supported=positives-known_misses
    return {"true_positives":tp,"false_positives":fp,"false_negatives":fn,
            "precision":tp/(tp+fp) if tp+fp else None,"recall":tp/(tp+fn) if tp+fn else None,
            "supported_case_recall":len(actual & supported)/len(supported) if supported else None,
            "known_limit_cases":len(known_misses),"known_limit_misses":len(known_misses-actual)}


def evaluate(split,profile=PROFILE):
    directory=profile_root(profile)/"benchmarks"/split
    expected=labels(directory)
    fixture_digest=hashlib.sha256()
    for path in sorted(directory.glob("*.py")):
        fixture_digest.update(path.name.encode()+b"\0"+hashlib.sha256(path.read_bytes()).digest())
    code,data=semgrep(["scan","--json","--config",str(profile_root(profile)/"rules"),"--no-git-ignore",str(directory)])
    result={"profile":profile,"fixture_sha256":fixture_digest.hexdigest(),"split":split,"bundle_sha256":bundle_digest(profile),"timestamp":datetime.now(timezone.utc).isoformat(),
            "scope":"Semgrep rules only; not Bandit accuracy or general application security", "status":"failed"}
    if code or data.get("errors") or "results" not in data:
        result["reason"]="engine_failure_or_partial_scan";result["metrics"]=None
        return result
    actual={(str((ROOT/Path(x["path"])).resolve()),x["start"]["line"],x["check_id"].split(".")[-1]) for x in data["results"]}
    files={str(p.resolve()) for p in directory.glob("*.py")}
    scanned={str((ROOT/Path(p)).resolve()) for p in data.get("paths",{}).get("scanned",[])}
    result.update(status="completed" if files<=scanned else "partial",metrics=detection_metrics(expected,actual),
                  scan_completeness=len(files & scanned)/len(files) if files else None,
                  by_rule={rule:detection_metrics({k:v for k,v in expected.items() if k[2]==rule},{k for k in actual if k[2]==rule}) for rule in sorted({k[2] for k in expected})})
    return result


def quality_metrics(judgments):
    """Accept explicit human labels; unknown fields stay unknown, never inferred from JSON success."""
    def score(field):
        values=[r[field] for r in judgments if type(r.get(field)) is bool]
        return {"labelled":len(values),"passed":sum(values),"rate":sum(values)/len(values) if values else None}
    return {"explanation_accuracy":score("explanation_correct"),"usable_fix_rate":score("fix_usable"),
            "scanner_improvement":score("scanner_improved"),"behavior_contract_pass":score("behavior_passed"),
            "note":"Human labels/explicit verification records only; syntax validity is reported separately."}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--validate",action="store_true")
    parser.add_argument("--split",choices=["development","holdout"],default="holdout")
    parser.add_argument("--judgments",type=Path)
    parser.add_argument("--profile", choices=PROFILES, default=PROFILE)
    args=parser.parse_args()
    profile=args.profile
    if args.validate:
        state=validate(profile);print(json.dumps(state,indent=2))
        if state["status"]!="passed": raise SystemExit(1)
    report=evaluate(args.split, profile)
    report["quality"]=quality_metrics(json.loads(args.judgments.read_text()) if args.judgments else [])
    output=profile_root(profile)/"benchmarks/results";output.mkdir(parents=True,exist_ok=True)
    (output/f"{args.split}.json").write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))
    if report["status"]!="completed":raise SystemExit(1)


if __name__=="__main__":main()
