
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



def scan_help_parser():
    from src.gemini_provider import MODEL

    parser = argparse.ArgumentParser(
        prog="python -m src.scanner",
        description=(
            "PySentry scans Python files with Bandit and local Semgrep rules. It groups\n"
            "related findings and keeps the scanner, rule and location behind each one.\n"
            "It can also detect credentials, audit dependencies and request Gemini advice."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Reading a report
  Each run saves reports/<run_id>/report.json. Check Files & coverage for
  skipped files, syntax errors, limits and scanner failures. Zero findings
  on a partial scan leaves some code unevaluated. Source findings show each
  detection; Logical issues groups related evidence. AI fixes are proposals.
  Syntax checks and scanner comparisons do not establish correct behavior.

Exit codes
  0  Required checks completed and policy passed. The default is report-only.
  1  Required checks completed and findings violated the configured policy.
  2  A mandatory check was incomplete, configuration was invalid, or a
     requested export failed. The native report preserves available evidence.

Examples (from the project directory)
  Scan one file without Gemini or dependency lookups:
    python -m src.scanner app.py --no-llm --skip-dependencies
  Scan a project with Deep rules and require a completed dependency audit:
    python -m src.scanner . --profile deep --require-dependencies --fail-on high --no-llm
  Export repository-relative locations while scanning a subdirectory:
    python -m src.scanner src --sarif review.sarif --sarif-root . --no-llm

Related commands
  python -m src.gui                            Open the desktop interface
  python -m src.benchmark --validate           Test Standard rules and measure holdout coverage
  python -m src.llm_advisor --help             Review findings from a saved report
  python -m src.export_sarif --help            Export a saved report without rescanning""",
    )
    target = parser.add_argument_group("Scan target and rule profile")
    target.add_argument("path", nargs="?", help="Python (.py) file or project directory. Supply exactly one target.")
    target.add_argument("--path", dest="flag_path", metavar="PATH", help="Named alternative to the positional target.")
    target.add_argument("--profile", choices=("basic", "standard", "deep"), default="standard",
                        help="Basic checks eval, deserialization, TLS and weak digests. Standard (default) adds "
                             "Flask/Django flows and configuration checks. Deep adds selected FastAPI/Starlette "
                             "flows and more query, file, URL, shell and template checks. A stale or missing "
                             "approval activates a one-rule fallback.")

    ai = parser.add_argument_group("Optional Gemini review")
    ai.add_argument("--no-llm", action="store_true",
                    help="Skip the key prompt and all Gemini requests. Interactively, a blank key also skips AI. "
                         "A supplied key is checked with a source-free model request that may incur a charge.")
    ai.add_argument("--api-key-env", metavar="NAME",
                    help="Read the Gemini key from the named environment variable for this run. "
                         "Noninteractive scanning defaults to basic review without an explicit credential.")
    ai.add_argument("--model", default=MODEL,
                    help="Gemini model for access checks and reviews (default: %(default)s). "
                         "AI review attempts every unique finding group. "
                         "Selected source context is masked and screened before transmission. "
                         "Unavailable credentials or an unsuccessful screen leave basic findings available.")

    deps = parser.add_argument_group("Dependency audit")
    deps.add_argument("--requirements", metavar="FILE",
                      help="Select one pinned requirements file or supported lockfile. By default PySentry "
                           "discovers target manifests by subproject. OSV-Scanner reads uv, Poetry, Pipfile "
                           "and PDM locks. Pip-audit checks pinned requirements and versions from pylock files. "
                           "Advisory lookups use package names and versions; unresolved constraints give limited coverage.")
    deps.add_argument("--dependency-path", metavar="DIR",
                      help="As an alternative to a manifest, audit installed distribution metadata in a "
                           "target site-packages directory inside the scan root.")
    deps.add_argument("--skip-dependencies", action="store_true", help="Skip dependency auditing and its advisory lookups.")

    secrets = parser.add_argument_group("Secret detection")
    secrets.add_argument("--secrets", choices=("directory", "history", "off"), default="directory",
                         help="Gitleaks scans working files by default. History also checks local Git history "
                              "when the target is a repository root. Off skips the inventory. Reports redact "
                              "secret values; optional Gemini review still requires a separate prompt screen.")

    limits = parser.add_argument_group("Scan limits (positive values)")
    limits.add_argument("--max-file-bytes", type=int, default=1_000_000,
                        help="Maximum size of a Python source file in bytes (default: %(default)s).")
    limits.add_argument("--max-files", type=int, default=1000,
                        help="Maximum number of Python files selected for analysis (default: %(default)s).")
    limits.add_argument("--scanner-timeout", type=float, default=120,
                        help="Time limit in seconds for scanner invocations; also used for secret and "
                             "dependency checks (default: %(default)s).")
    limits.add_argument("--total-timeout", type=float, default=600,
                        help="Source file enumeration and scanning budget in seconds (default: %(default)s). "
                             "Files skipped because of limits appear in coverage.")

    policy = parser.add_argument_group("Execution requirements and security policy")
    policy.add_argument("--fail-on", choices=("none", "low", "medium", "high"), default="none",
                        help="None (default) reports findings. An enabled threshold blocks on source issues "
                             "at or above that severity, unknown severity, any dependency advisory or any secret finding.")
    policy.add_argument("--require-dependencies", action="store_true",
                        help="Require the dependency audit to complete. Incompatible with --skip-dependencies.")
    policy.add_argument("--require-secrets", action="store_true",
                        help="Require the selected secret scan to complete. Incompatible with --secrets off.")
    policy.add_argument("--require-validated-rules", action="store_true",
                        help="Require current Semgrep rule approval. Fallback coverage makes the run incomplete.")

    output = parser.add_argument_group("Report export")
    output.add_argument("--sarif", metavar="FILE", type=Path,
                        help="Also export a finished native report as validated SARIF 2.1.0. "
                             "Choose a .sarif or .sarif.json file.")
    output.add_argument("--sarif-root", metavar="DIR",
                        help="With --sarif, choose the checkout root for relative source locations. "
                             "Defaults to the scan root.")
    parser.add_argument("--run-id", type=uuid.UUID, help=argparse.SUPPRESS)
    return parser


def main():
    from src.gemini_provider import prepare_ai
    from src.reporting import ai_report, basic_report, save_json, scanner_metadata, scanner_evidence

    parser = scan_help_parser()
    args = parser.parse_args()
    if args.sarif_root and args.sarif is None:
        parser.error("--sarif-root requires --sarif")
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
    if args.sarif is not None:
        from src.export_sarif import write_export
        from src.reporting import load_report

        # Export the persisted, redacted evidence. Preserve it if the optional output fails.
        try:
            output = write_export(load_report(report_path), report_path, args.sarif, source_root=args.sarif_root)
            report["exports"] = {"sarif": {"status": "completed", "path": str(output)}}
            print(f"Exported SARIF: {output}")
        except (ImportError, OSError, RuntimeError, ValueError) as exc:
            report["exports"] = {"sarif": {"status": "failed", "error": type(exc).__name__}}
            report["execution"]["reasons"].append("sarif_export_failed")
            if report["execution"]["overall"] == "completed":
                report["execution"]["overall"] = "incomplete"
            code = report["exit_code"] = 2
            print(f"SARIF export failed: {exc}", file=sys.stderr)
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
