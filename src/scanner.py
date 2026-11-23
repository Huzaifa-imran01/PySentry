
import argparse
import hashlib
import json
import math
import uuid
from datetime import datetime, timezone
from src.scanner_response import validate_response
from src.policy import evaluate
import os
import subprocess
import sys
from pathlib import Path
from src.findings import normalize_findings


ROOT = Path(__file__).resolve().parents[1]
RULES_FILE = ROOT / "rules"


def scanner_executable(name):
    suffix = ".exe" if os.name == "nt" else ""
    return str(Path(sys.executable).parent / f"{name}{suffix}")


def run_json_scanner(command, allowed_exit_codes, timeout=120):
    """Run a security scanner and parse its JSON output."""
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Scanner could not run: {exc}") from exc

    try:
        data = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Scanner returned invalid JSON"
        ) from exc

    
    if not isinstance(data, dict):
        raise RuntimeError(
            "Expected a JSON object from scanner"
        )

    if process.returncode not in allowed_exit_codes:
        errors = data.get("errors", [])
        data["errors"] = (errors if isinstance(errors, list) else [errors]) + [
            f"Scanner exit {process.returncode}"]
    if data.get("errors") and not data.get("results"):
        raise RuntimeError(
            "Scanner reported errors"
        )

    if not isinstance(data.get("results"), list):
        raise RuntimeError(
            "Scanner JSON is missing a valid results list"
        )

    return data



def scan_file(file_path, timeout=120, allow_partial=False, config=None):
    """Scan a Python file using Bandit and Semgrep."""
    target = Path(file_path).resolve()

    if not target.is_file() or target.suffix.lower() != ".py":
        raise ValueError("Provide an existing Python (.py) file")

    source_hash = hashlib.sha256(target.read_bytes()).hexdigest()
    print(f"Scanning: {target}")

    from src.rule_validation import active_config
    commands = {
        "bandit": ([scanner_executable("bandit"), "-f", "json", str(target)], {0, 1}),
        "semgrep": ([scanner_executable("semgrep"), "scan", "--config", str(config or active_config()),
                     "--json", "--metrics=off", "--disable-version-check", "--no-git-ignore",
                     "--max-target-bytes=0", "--jobs=1", *(["--experimental","--x-parmap"] if os.name == "nt" else []), str(target)], {0}),
    }
    reports = {}
    for name, (command, codes) in commands.items():
        try:
            data = run_json_scanner(command, codes, timeout=timeout)
            data = validate_response(name, data, target, Path.cwd())
            if not allow_partial and data["scan_status"] != "completed":
                raise RuntimeError(data["error"])
            reports[name] = data
        except RuntimeError as exc:
            if not allow_partial:
                raise
            reports[name] = {"results": [], "scan_status": "failed", "coverage":"failed", "error": str(exc)}
    if hashlib.sha256(target.read_bytes()).hexdigest() != source_hash:
        raise RuntimeError("Source changed during scanning. Run the scan again.")
    reports["bandit"]["source_sha256"] = source_hash
    return reports


def scan_target(target, max_bytes=1_000_000, timeout=120, max_files=1000, total_timeout=600, config=None):
    """Enumerate an explicit root; retain successes and report every exclusion/failure."""
    import ast
    import time
    import tokenize
    selected = Path(target).resolve()
    if not selected.exists() or (selected.is_file() and selected.suffix.lower() != ".py"):
        raise ValueError("Provide an existing Python file or directory")
    if (type(max_bytes) is not int or type(max_files) is not int or min(max_files, max_bytes) <= 0
            or any(not math.isfinite(v) or v <= 0 for v in (timeout, total_timeout))):
        raise ValueError("Scan limits must be positive")
    root = selected if selected.is_dir() else selected.parent
    excluded = {".git", ".venv", "venv", "env", "__pycache__", ".pytest_cache", ".mypy_cache", ".cache", "node_modules", "reports", "build", "dist", ".tox"}
    skipped, paths = [], []
    started = time.monotonic()
    if selected.is_file():
        paths = [selected]
    else:
        for directory, dirs, files in os.walk(selected, followlinks=False, onerror=lambda exc: skipped.append({"path":str(exc.filename), "reason":"directory_unreadable"})):
            if time.monotonic()-started >= total_timeout:
                skipped.append({"path":str(directory),"reason":"enumeration_budget"})
                dirs.clear()
                continue
            for name in list(dirs):
                path = Path(directory) / name
                if name in excluded or path.is_symlink():
                    skipped.append({"path":str(path),"reason":"excluded_directory_or_symlink"})
                    dirs.remove(name)
            for name in sorted(files):
                path = Path(directory)/name
                if path.suffix.lower() == ".py":
                    paths.append(path)
    combined = {"bandit":{"results":[]}, "semgrep":{"results":[]}}
    records, findings = [], []
    for index, path in enumerate(sorted(paths)):
        record = {"path":str(path),"status":"skipped", "source_sha256":None,
                  "scanner_coverage":{name: "skipped" for name in combined}}
        records.append(record)
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            record["reason"] = "outside_root_or_symlink"; continue
        if index >= max_files:
            record["reason"] = "file_limit"; continue
        remaining = total_timeout - (time.monotonic()-started)
        if remaining <= 0:
            record["reason"] = "execution_budget"; continue
        try:
            if path.stat().st_size > max_bytes:
                record["reason"] = "size_limit"; continue
            with path.open("rb") as stream:
                raw = stream.read(max_bytes+1)
            if len(raw)>max_bytes:
                record["reason"]="size_limit"; continue
            record["source_sha256"] = hashlib.sha256(raw).hexdigest()
            with tokenize.open(path) as stream:
                ast.parse(stream.read(), filename=str(path))
            result = scan_file(path, timeout=min(timeout, max(0.1, remaining/2)), allow_partial=True, config=config)
            if result["bandit"].get("source_sha256", record["source_sha256"]) != record["source_sha256"]:
                raise RuntimeError("Source changed between enumeration and scanning")
            record["scanners"] = {name: result[name].get("scan_status","completed") for name in combined}
            record["scanner_coverage"] = {name: result[name].get("coverage", "unknown") for name in combined}
            record["errors"] = {name:result[name]["error"] for name in combined if "error" in result[name]}
            statuses = set(record["scanners"].values())
            record["status"] = "completed" if statuses == {"completed"} else "failed" if statuses == {"failed"} else "partial"
            for name in combined:
                combined[name]["results"].extend(result[name]["results"])
            current = normalize_findings(result)
            for finding in current:
                actual = Path(finding["file"]).resolve()
                if actual != path.resolve():
                    record["status"] = "partial"
                    record["errors"]["provenance"] = "Scanner returned an unexpected source path"
                    continue
                finding["file"] = str(actual)
                finding["source_sha256"] = record["source_sha256"]
                finding["scan_root"] = str(root)
                from src.identities import enrich_identity
                enrich_identity(finding, raw)
                findings.append(finding)
        except (OSError, ValueError, SyntaxError, UnicodeError, RuntimeError) as exc:
            record.update(status="failed", reason=str(exc))
    completed = sum(f["status"]=="completed" for f in records)
    status = "completed" if completed == len(records) and records else "partial" if findings or completed or any("completed" in row.get("scanners", {}).values() for row in records) else "failed"
    if any(item["reason"] in ("directory_unreadable", "enumeration_budget") for item in skipped):
        status = "partial" if completed else "failed"
    combined["bandit"]["source_sha256"] = records[0]["source_sha256"] if selected.is_file() and records else None
    return combined, findings, {"root":str(root),"status":status,"files":records,"excluded":skipped,
        "eligible_files":len(records),"completed_files":completed,
        "completeness":completed/len(records) if records else None,
        "limits":{"max_bytes":max_bytes,"per_scanner_seconds":timeout,"max_files":max_files,"total_seconds":total_timeout}}



def main():
    parser = argparse.ArgumentParser(
        description="Scan Python code for security issues"
    )

    parser.add_argument(
        "path",
        nargs="?",
        help="Python file to scan"
    )

    parser.add_argument(
        "--path",
        dest="flag_path",
        help="Python file to scan (named option)"
    )

    from src.gemini_provider import MODEL, prepare_ai
    from src.reporting import ai_report, basic_report, save_json, scanner_metadata, scanner_evidence
    parser.add_argument("--no-llm", action="store_true", help="Skip all Gemini requests and prompting")
    parser.add_argument("--api-key-env", help="Consume a Gemini key from this environment variable (CI)")
    parser.add_argument("--model", default=MODEL, help="Gemini model for validation and review")
    parser.add_argument("--max-file-bytes", type=int, default=1_000_000)
    parser.add_argument("--scanner-timeout", type=float, default=120)
    parser.add_argument("--max-files", type=int, default=1000)
    parser.add_argument("--total-timeout", type=float, default=600)
    parser.add_argument("--requirements", help="Select a pinned requirements export or supported Python lockfile")
    parser.add_argument("--dependency-path", help="Explicit target site-packages directory inside scan root")
    parser.add_argument("--skip-dependencies", action="store_true")
    parser.add_argument("--fail-on", choices=("none", "low", "medium", "high"), default="none",
                        help="Block at this source severity, on unknown severity, any advisory, or any secret finding.")
    parser.add_argument("--require-dependencies", action="store_true", help="Require a completed dependency audit")
    parser.add_argument("--require-validated-rules", action="store_true", help="Require current annotated rule approval")
    parser.add_argument("--run-id", type=uuid.UUID, help=argparse.SUPPRESS)
    parser.add_argument("--profile", choices=("basic","standard","deep"), default="standard", help="Select a separately approved Semgrep rule set")
    parser.add_argument("--secrets", choices=("directory","history","off"), default="directory",
                        help="Scan working files, additionally scan Git history, or disable secret detection")
    parser.add_argument("--require-secrets", action="store_true")
    args = parser.parse_args()
    if args.require_secrets and args.secrets == "off":
        parser.error("--require-secrets conflicts with --secrets off")
    if args.require_dependencies and args.skip_dependencies:
        parser.error("--require-dependencies conflicts with --skip-dependencies")
    if args.max_file_bytes <= 0 or args.max_files <= 0 or any(
            not math.isfinite(v) or v <= 0 for v in (args.scanner_timeout, args.total_timeout)):
        parser.error("scan limits must be finite and positive")

    if bool(args.path) == bool(args.flag_path):
        parser.error(
            "Provide exactly one file path, either "
            "positionally or using --path"
        )

    target = args.flag_path or args.path

    from src.rule_validation import active_config, validation_state
    run_id = (args.run_id or uuid.uuid4()).hex
    report_dir = ROOT / "reports" / run_id
    try:
        report_dir.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        parser.exit(2, f"Cannot create run directory: {exc}\n")
    report_path = report_dir / "report.json"
    started = datetime.now(timezone.utc).isoformat()
    def selected_approval():
        return validation_state() if args.profile == "standard" else validation_state(args.profile)
    approval = selected_approval()
    rules = dict(approval)
    config = active_config(rules)
    metadata = scanner_metadata(config)
    effective = metadata.get("semgrep", {}).get("enabled_rules") or []
    rules.update(selected_profile=args.profile, effective_profile=args.profile if rules["status"]=="passed" else "fallback",
                 active_config=str(config), effective_rule_count=len(effective), effective_rule_ids=effective)
    if rules["status"] != "passed":
        print("WARNING: Reduced Semgrep coverage. " + rules["reason"], flush=True)
    print(f"Semgrep profile {rules['effective_profile']}: {len(effective)} rules, {config}, digest {rules['bundle_sha256']}", flush=True)
    key, ai_reason = prepare_ai(args.no_llm, args.api_key_env, args.model)
    print("AI review: " + ai_reason)
    error = None
    try:
        results, unified, coverage = scan_target(target, args.max_file_bytes, args.scanner_timeout, args.max_files, args.total_timeout, config)
    except (OSError, ValueError, RuntimeError) as exc:
        error = str(exc).replace(key, "[REDACTED]") if key else str(exc)
        results, unified = {}, []
        coverage = {"status":"failed", "files":[], "error":error}

    # Persist basic evidence before dependency auditing or finding review.
    skipped = ai_report(unified, None, "pending_review" if key else ai_reason, args.model)
    if error:
        skipped.update(reason="scan_failed", status="skipped")
    report = basic_report(Path(target).resolve(), results, unified, metadata, skipped, error)
    report.update(schema_version=1, run_id=run_id, started_at=started, finished_at=None, run_status="running")
    from src.issues import logical_issues
    from src.secrets_scan import detect
    report["logical_issues"] = logical_issues(report["findings"])
    report["counts"].update(logical_issues=len(report["logical_issues"]), scanner_detections=len(unified))
    report["secrets"] = {"status":"pending","findings":[]} if args.secrets != "off" else {"status":"skipped","reason":"disabled_by_flag","findings":[]}
    report["rule_validation"] = rules
    report["coverage"] = coverage
    report["scan_status"] = coverage["status"]
    report["file"]["fingerprint_verified_by_scan"] = coverage["status"] == "completed" and Path(target).is_file()
    for name in metadata:
        statuses = [f.get("scanners",{}).get(name,"not_scanned") for f in coverage["files"]]
        metadata[name]["scan_status"] = "completed" if statuses and all(x=="completed" for x in statuses) else "partial_or_failed"
    report["dependencies"] = {"status":"pending", "reason":"audit_not_completed", "packages":[], "findings":[]}
    for name in ("bandit", "semgrep"):
        save_json(report_dir / f"{name}.json", scanner_evidence(name,results.get(name, {"status": "failed", "error": error})), key)
    save_json(report_dir / "findings.json", unified, key)
    policy_args = (args.fail_on, args.require_dependencies, args.require_validated_rules)
    report["require_secrets"] = args.require_secrets
    if key and unified:
        report["ai"]["status"] = "pending"
    evaluate(report, *policy_args, final=False)
    save_json(report_dir / "ai_reviews.json", skipped, key)
    save_json(report_path, report, key)

    if args.secrets != "off":
        try:
            report["secrets"] = detect(target, history=args.secrets=="history", timeout=args.scanner_timeout)
        except Exception as exc:
            report["secrets"] = {"status":"failed","reason":type(exc).__name__,"findings":[]}
        evaluate(report, *policy_args, final=False)
        save_json(report_path, report, key)
    from src.dependency_audit import audit_dependencies
    try:
        report["dependencies"] = audit_dependencies(Path(target), args.requirements, args.skip_dependencies,
                                                     args.scanner_timeout, args.dependency_path)
    except Exception as exc:
        # An adapter failure must leave other stages and the source evidence usable.
        report["dependencies"].update(status="failed", reason="audit_error", error=type(exc).__name__)
    evaluate(report, *policy_args, final=False)
    save_json(report_path, report, key)

    try:
        ai = ai_report(unified, key, ai_reason, args.model)
    except Exception as exc:
        ai = {**skipped, "status":"failed", "reason":"review_error", "error":type(exc).__name__}
    if not unified and coverage["status"] != "completed":
        ai.update(status="skipped", reason="scan_" + coverage["status"])
    report["ai"] = ai
    report["mode"] = "ai_enhanced" if ai["reviewed"] else "basic"
    current = selected_approval() if rules["status"] == "passed" else approval
    if any(current.get(k)!=approval.get(k) for k in ("status","bundle_sha256","engine_version","profile")):
        rules.update(status="pending", reason="Rule approval changed during run")
        report["scan_status"] = report["coverage"]["status"] = "partial"
    code = evaluate(report, *policy_args)
    report.update(run_status="finished", finished_at=datetime.now(timezone.utc).isoformat())
    save_json(report_dir / "ai_reviews.json", ai, key)
    save_json(report_path, report, key)
    secret_result = report["secrets"]
    dependency_result = report["dependencies"]
    print(f"Secret scan {secret_result['status']} ({args.secrets})")
    for scope,state in secret_result.get("scopes",{}).items():
        if state!="completed":
            print(f"  {scope}: {state}")
    print(f"Dependency audit {dependency_result['status']} ({dependency_result.get('reason','')}). "
          f"{len(dependency_result.get('inputs',[]))} inputs, "
          f"{len(dependency_result.get('detections',[]))} advisory detections")
    print(f"Execution {report['execution']['overall']}, policy {report['policy']['result']}, {len(report['logical_issues'])} logical issues, {len(unified)} scanner detections, {len(report['secrets']['findings'])} secret findings, {len(report['dependencies']['findings'])} advisories")
    print(json.dumps({"event":"scan_finished", "run_id":run_id, "report_path":str(report_path), "exit_code":code}))
    if code:
        raise SystemExit(code)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Scanner execution failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
