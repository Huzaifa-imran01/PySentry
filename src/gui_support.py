"""Desktop adapter only: invoke the existing CLI and read its unchanged JSON report."""
from dataclasses import dataclass
import uuid
import json
import math
import os
from pathlib import Path
from src.reporting import load_report
import subprocess
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
KEY_ENV = "SECURE_REVIEW_GUI_GEMINI_KEY"


@dataclass(frozen=True)
class ScanOptions:
    target: str
    model: str
    skip_dependencies: bool = False
    requirements: str = ""
    dependency_path: str = ""
    max_file_bytes: int = 1_000_000
    scanner_timeout: float = 120
    max_files: int = 1000
    total_timeout: float = 600

    fail_on: str = "none"
    require_dependencies: bool = False
    require_validated_rules: bool = False

    profile: str = "standard"
    secrets: str = "directory"
    require_secrets: bool = False

    def validate(self):
        if self.require_secrets and self.secrets == "off":
            raise ValueError("Enable credential scanning when it is required.")
        if self.require_dependencies and self.skip_dependencies:
            raise ValueError("A required dependency audit cannot be skipped.")
        path = Path(self.target).expanduser()
        if not self.target.strip() or not path.exists():
            raise ValueError("Choose an existing Python file or project folder.")
        if path.is_file() and path.suffix.lower() != ".py":
            raise ValueError("Single-file scans require a Python (.py) file.")
        if not self.model.strip():
            raise ValueError("Enter a Gemini model name, or use the default.")
        for name in ("max_file_bytes", "scanner_timeout", "max_files", "total_timeout"):
            value = getattr(self, name)
            if not math.isfinite(value) or value <= 0:
                raise ValueError("All scan limits must be finite positive numbers.")
        if not self.skip_dependencies:
            if self.requirements and not Path(self.requirements).is_file():
                raise ValueError("The requirements file does not exist.")
            if self.dependency_path and not Path(self.dependency_path).is_dir():
                raise ValueError("The installed dependency directory does not exist.")
            if self.requirements and self.dependency_path:
                raise ValueError("Select either a requirements file or installed dependencies, not both.")
            root = path.resolve() if path.is_dir() else path.resolve().parent
            if self.dependency_path and not Path(self.dependency_path).resolve().is_relative_to(root):
                raise ValueError("Installed dependencies must be inside the selected scan root.")


def scanner_command(options, use_ai, python=None):
    executable = Path(python or sys.executable)
    if executable.name.lower() == "pythonw.exe":
        executable = executable.with_name("python.exe")
    command = [str(executable), "-u", "-B", "-m", "src.scanner", "--path",
               str(Path(options.target).expanduser().resolve()), "--model", options.model.strip(),
               "--max-file-bytes", str(options.max_file_bytes), "--scanner-timeout", str(options.scanner_timeout),
               "--max-files", str(options.max_files), "--total-timeout", str(options.total_timeout)]
    command += ["--api-key-env", KEY_ENV] if use_ai else ["--no-llm"]
    if options.skip_dependencies:
        command += ["--skip-dependencies"]
    else:
        if options.requirements:
            command += ["--requirements", str(Path(options.requirements).resolve())]
        if options.dependency_path:
            command += ["--dependency-path", str(Path(options.dependency_path).resolve())]
    command += ["--fail-on", options.fail_on, "--profile",options.profile, "--credential-scan",options.secrets]
    if options.require_secrets:
        command.append("--require-credential-scan")
    if options.require_dependencies:
        command.append("--require-dependencies")
    if options.require_validated_rules:
        command.append("--require-validated-rules")
    return command


def run_scan(options, api_key, events, project_root=PROJECT_ROOT):
    """Worker: never touches Tk widgets, changes scanner code, or puts credentials in argv."""
    key = api_key.strip()
    run_id = uuid.uuid4().hex
    report_path = project_root / "reports" / run_id / "report.json"
    def clean(text):
        from .secrets_scan import scrub
        return scrub(str(text).replace(key, "[REDACTED]") if key else str(text))
    try:
        options.validate()
        command = scanner_command(options, bool(key)) + ["--run-id", run_id]
        completion = None
        environment = dict(os.environ)
        environment.pop(KEY_ENV, None)
        environment["PYTHONIOENCODING"] = "utf-8"
        if key:
            environment[KEY_ENV] = key
        kwargs = dict(cwd=project_root, env=environment, stdin=subprocess.DEVNULL,
                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                      encoding="utf-8", errors="replace", bufsize=1)
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        with subprocess.Popen(command, **kwargs) as process:
            environment.pop(KEY_ENV, None)
            for line in process.stdout:
                try:
                    event = json.loads(line) if line.startswith("{") else None
                except ValueError:
                    event = None
                if isinstance(event, dict) and event.get("event") == "scan_finished":
                    completion = event
                else:
                    events.put(("log", clean(line)))
            returncode = process.wait()
        report = None
        problem = None
        if report_path.is_file():
            candidate = load_report(report_path)
            if candidate.get("run_id") != run_id:
                problem = "Report run ID mismatch."
            elif Path(candidate["file"]["path"]).resolve() != Path(options.target).expanduser().resolve():
                problem = "Report belongs to a different target."
            elif (completion != {"event":"scan_finished", "run_id":run_id,
                                 "report_path":str(report_path), "exit_code":returncode}
                  or candidate.get("run_status") != "finished" or candidate.get("exit_code") != returncode):
                if candidate.get("run_status") == "running":
                    report = candidate
                problem = "Scan interrupted. Only saved intermediate evidence is available."
            else:
                report = candidate
        else:
            problem = "No new report was produced. See Messages for the scanner error."
        events.put(("finished", {"returncode": returncode, "report": report,
                                 "path": str(report_path), "problem": problem}))
    except Exception as exc:
        events.put(("finished", {"returncode": None, "report": None, "path": None,
                                 "problem": "Unable to run the scanner: " + clean(exc)}))


def as_dict(value):
    return value if isinstance(value, dict) else {}


def dict_rows(value):
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def overview_text(report):
    ai = as_dict(report.get("ai"))
    coverage = as_dict(report.get("coverage"))
    deps = as_dict(report.get("dependencies"))
    rules = as_dict(report.get("rule_validation"))
    lines = ["SCAN SUMMARY", "", f"Target: {as_dict(report.get('file')).get('path', 'Unknown')}",
             f"Generated: {report.get('generated_at', 'Unknown')}",
             f"Source scan: {report.get('scan_status', 'Unknown')}",
             f"Report mode: {report.get('mode', 'Unknown')}",
             f"Source findings: {len(report.get('findings', []))}",
             f"Completed / eligible files: {coverage.get('completed_files', '—')} / {coverage.get('eligible_files', '—')}"]
    execution = report.get("execution", {})
    policy = report.get("policy", {})
    lines += ["", "Execution: " + execution.get("overall", "unrecorded (legacy report)"),
              "Security policy: " + policy.get("result", "unrecorded (legacy report)"),
              "Severity threshold: " + policy.get("fail_on", "unrecorded"),
              "Credential scan: " + execution.get("secrets", "unrecorded")]
    for reason in policy.get("reasons", []):
        if reason.startswith("secret_detections:"):
            reason = "Credential findings:" + reason.removeprefix("secret_detections:")
        elif reason.startswith("secrets_"):
            reason = "Credential scan: " + reason.removeprefix("secrets_")
        lines.append(reason)
    for scope,status in report.get("secrets",{}).get("scopes",{}).items():
        lines.append(f"Credential scan ({scope}): {status}")
    for item in deps.get("inputs",[]):
        lines.append(f"{item['path']} ({item['resolution']}): {item['status']} / {item['reason']}")
    lines.extend("Overlapping input skipped: " + p for p in deps.get("shadowed",[]))
    lines.extend(deps.get("errors",[]))
    if rules.get("effective_profile"):
        profile = rules["effective_profile"]
        profile_label = "default" if profile == "standard" else profile
        lines += [f"Semgrep profile: {profile_label} ({rules['effective_rule_count']} rules)",
                  f"Configuration: {rules['active_config']}", f"Bundle: {rules['bundle_sha256']}"]
        if profile == "fallback":
            lines.insert(0, "WARNING: Reduced Semgrep coverage. " + str(rules.get("reason")))
    completeness = coverage.get("completeness")
    if isinstance(completeness, (int, float)):
        lines.append(f"Scan completeness: {completeness:.1%}")
    if report.get("scan_status") != "completed":
        lines += ["", "INCOMPLETE SCAN — zero findings would not mean the target is safe."]
    if report.get("scan_error"):
        lines.append("Scan error: " + str(report["scan_error"]))
    lines += ["", "AI REVIEW", f"Status: {ai.get('status', 'Unknown')} — {ai.get('reason', '')}",
              f"Credential check: {ai.get('credential_status', 'Unknown')}",
              f"Model: {ai.get('model', 'Unknown')}",
              f"Reviewed: {ai.get('reviewed', 0)} | Failed: {ai.get('failed', 0)} | Unattempted groups: {ai.get('unattempted_groups', 0)}",
              "", "DEPENDENCIES", f"Status: {deps.get('status', 'Unknown')} — {deps.get('reason', '')}",
              f"Input: {deps.get('input', 'No dependency input selected/found')}",
              f"Package occurrences: {len(dict_rows(deps.get('packages')))} | Logical advisories: {len(dict_rows(deps.get('findings')))} | Advisory detections: {len(dict_rows(deps.get('detections')))}",
              f"Scope: {deps.get('scope', '')}", "", "RULE VALIDATION",
              f"Status: {rules.get('status', 'Unknown')}", str(rules.get('reason') or ''), "", "SCANNERS"]
    for name, info in as_dict(report.get("scanners")).items():
        info = as_dict(info)
        rules_list = info.get("enabled_rules")
        count = len(rules_list) if isinstance(rules_list, list) else "unknown"
        lines.append(f"{name}: version {info.get('version', '?')} | {info.get('scan_status', '?')} | {count} enabled rules")
    lines += ["", "Findings and proposed fixes are not security certification. Generated fixes are not automatically applied or executed.",
              "Select rows in the other tabs for full details; Raw report retains all report fields."]
    return "\n".join(lines)
