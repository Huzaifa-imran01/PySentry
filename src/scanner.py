
import argparse
import hashlib
import json
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

    if process.returncode not in allowed_exit_codes:
        raise RuntimeError(
            f"Scanner failed (exit {process.returncode}): "
            f"{process.stderr or process.stdout}"
        )

    try:
        data = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Scanner returned invalid JSON: {process.stderr}"
        ) from exc

    
    if not isinstance(data, dict):
        raise RuntimeError(
            "Expected a JSON object from scanner"
        )

    if data.get("errors"):
        raise RuntimeError(
            f"Scanner reported errors: {data['errors']}"
        )

    if not isinstance(data.get("results"), list):
        raise RuntimeError(
            "Scanner JSON is missing a valid results list"
        )

    return data



def scan_file(file_path, timeout=120, allow_partial=False):
    """Scan a Python file using Bandit and Semgrep."""
    target = Path(file_path).resolve()

    if not target.is_file() or target.suffix != ".py":
        raise ValueError("Provide an existing Python (.py) file")

    source_hash = hashlib.sha256(target.read_bytes()).hexdigest()
    print(f"Scanning: {target}")

    from src.rule_validation import active_config
    commands = {
        "bandit": ([scanner_executable("bandit"), "-f", "json", str(target)], {0, 1}),
        "semgrep": ([scanner_executable("semgrep"), "scan", "--config", str(active_config()),
                     "--json", "--metrics=off", "--disable-version-check", "--no-git-ignore",
                     "--max-target-bytes=0", "--jobs=1", str(target)], {0}),
    }
    reports = {}
    for name, (command, codes) in commands.items():
        try:
            data = run_json_scanner(command, codes, timeout=timeout)
            if name == "semgrep" and "paths" in data and not data["paths"].get("scanned"):
                raise RuntimeError("Semgrep did not analyze the requested file")
            data["scan_status"] = "completed"
            reports[name] = data
        except RuntimeError as exc:
            if not allow_partial:
                raise
            reports[name] = {"results": [], "scan_status": "failed", "error": str(exc)}
    if hashlib.sha256(target.read_bytes()).hexdigest() != source_hash:
        raise RuntimeError("Source changed during scanning. Run the scan again.")
    reports["bandit"]["source_sha256"] = source_hash
    return reports


def scan_target(target, max_bytes=1_000_000, timeout=120, max_files=1000, total_timeout=600):
    """Enumerate an explicit root; retain successes and report every exclusion/failure."""
    import ast
    import time
    import tokenize
    selected = Path(target).resolve()
    if not selected.exists() or (selected.is_file() and selected.suffix.lower() != ".py"):
        raise ValueError("Provide an existing Python file or directory")
    if min(max_bytes, timeout, max_files, total_timeout) <= 0:
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
        record = {"path":str(path),"status":"skipped", "source_sha256":None}
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
                ast.parse(stream.read())
            result = scan_file(path, timeout=min(timeout, max(0.1, remaining/2)), allow_partial=True)
            if result["bandit"].get("source_sha256", record["source_sha256"]) != record["source_sha256"]:
                raise RuntimeError("Source changed between enumeration and scanning")
            record["scanners"] = {name: result[name].get("scan_status","completed") for name in combined}
            record["errors"] = {name:result[name]["error"] for name in combined if "error" in result[name]}
            record["status"] = "completed" if all(v=="completed" for v in record["scanners"].values()) else "partial"
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
    status = "completed" if completed == len(records) and records else "partial" if findings or completed else "failed"
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
    from src.reporting import ai_report, basic_report, save_json, scanner_metadata
    parser.add_argument("--no-llm", action="store_true", help="Skip all Gemini requests and prompting")
    parser.add_argument("--api-key-env", help="Consume a Gemini key from this environment variable (CI)")
    parser.add_argument("--model", default=MODEL, help="Gemini model for validation and review")
    parser.add_argument("--max-file-bytes", type=int, default=1_000_000)
    parser.add_argument("--scanner-timeout", type=float, default=120)
    parser.add_argument("--max-files", type=int, default=1000)
    parser.add_argument("--total-timeout", type=float, default=600)
    parser.add_argument("--requirements", help="Target project's fully pinned requirements/lock export")
    parser.add_argument("--dependency-path", help="Explicit target site-packages directory inside scan root")
    parser.add_argument("--skip-dependencies", action="store_true")
    args = parser.parse_args()

    if bool(args.path) == bool(args.flag_path):
        parser.error(
            "Provide exactly one file path, either "
            "positionally or using --path"
        )

    target = args.flag_path or args.path

    key, ai_reason = prepare_ai(args.no_llm, args.api_key_env, args.model)
    print("AI review: " + ai_reason)
    from src.rule_validation import active_config, validation_state
    metadata = scanner_metadata(active_config())
    report_dir = ROOT / "reports"
    report_dir.mkdir(exist_ok=True)
    error = None
    try:
        results, unified, coverage = scan_target(target, args.max_file_bytes, args.scanner_timeout, args.max_files, args.total_timeout)
    except (OSError, ValueError, RuntimeError) as exc:
        error = str(exc).replace(key, "[REDACTED]") if key else str(exc)
        results, unified = {}, []
        coverage = {"status":"failed", "files":[], "error":error}

    # Persist basic evidence before attempting any finding review.
    skipped = ai_report(unified, None, "pending_review" if key else ai_reason, args.model)
    if error:
        skipped.update(reason="scan_failed", status="skipped")
    report = basic_report(Path(target).resolve(), results, unified, metadata, skipped, error)
    report["rule_validation"] = validation_state()
    report["coverage"] = coverage
    report["scan_status"] = coverage["status"]
    report["file"]["fingerprint_verified_by_scan"] = coverage["status"] == "completed" and Path(target).is_file()
    for name in metadata:
        statuses = [f.get("scanners",{}).get(name,"not_scanned") for f in coverage["files"]]
        metadata[name]["scan_status"] = "completed" if statuses and all(x=="completed" for x in statuses) else "partial_or_failed"
    from src.dependency_audit import audit_dependencies
    report["dependencies"] = audit_dependencies(Path(target), args.requirements, args.skip_dependencies, args.scanner_timeout, args.dependency_path)
    for name in ("bandit", "semgrep"):
        save_json(report_dir / f"{name}.json", results.get(name, {"status": "failed", "error": error}), key)
    save_json(report_dir / "findings.json", unified, key)
    save_json(report_dir / "report.json", report, key)
    save_json(report_dir / "ai_reviews.json", skipped, key)
    if error:
        parser.exit(1, f"Scan incomplete: {error}\nBasic report saved to {report_dir / 'report.json'}\n")

    ai = ai_report(unified, key, ai_reason, args.model)
    report["ai"] = ai
    report["mode"] = "ai_enhanced" if ai["reviewed"] else "basic"
    save_json(report_dir / "report.json", report, key)
    save_json(report_dir / "ai_reviews.json", ai, key)
    print(f"Unified findings: {len(unified)}")
    print(f"AI reviews: {ai['reviewed']} completed, {ai['failed']} failed ({ai['reason']})")
    print(f"Report saved to: {report_dir / 'report.json'}")
    if coverage["status"] != "completed":
        parser.exit(1, "Source scan incomplete; inspect coverage in report.json.\n")


if __name__ == "__main__":
    main()
