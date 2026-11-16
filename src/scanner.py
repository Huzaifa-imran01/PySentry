
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from src.findings import normalize_findings


ROOT = Path(__file__).resolve().parents[1]
RULES_FILE = ROOT / "rules" / "security.yml"


def scanner_executable(name):
    suffix = ".exe" if os.name == "nt" else ""
    return str(Path(sys.executable).parent / f"{name}{suffix}")


def run_json_scanner(command, allowed_exit_codes):
    """Run a security scanner and parse its JSON output."""
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
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



def scan_file(file_path):
    """Scan a Python file using Bandit and Semgrep."""
    target = Path(file_path).resolve()

    if not target.is_file() or target.suffix != ".py":
        raise ValueError("Provide an existing Python (.py) file")

    print(f"Scanning: {target}")

    bandit = run_json_scanner(
        [scanner_executable("bandit"), "-f", "json", str(target)],
        allowed_exit_codes={0, 1},
    )

    semgrep = run_json_scanner(
        [
            scanner_executable("semgrep"),
            "scan",
            "--config",
            str(RULES_FILE),
            "--json",
            "--metrics=off",
            str(target),
        ],
        allowed_exit_codes={0},
    )

    return {"bandit": bandit, "semgrep": semgrep}



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

    args = parser.parse_args()

    if bool(args.path) == bool(args.flag_path):
        parser.error(
            "Provide exactly one file path, either "
            "positionally or using --path"
        )

    target = args.flag_path or args.path

    try:
        results = scan_file(target)
    except (ValueError, RuntimeError) as exc:
        parser.exit(1, f"Error: {exc}\n")

    report_dir = ROOT / "reports"
    report_dir.mkdir(exist_ok=True)

    for name, data in results.items():
        output = report_dir / f"{name}.json"
        output.write_text(
            json.dumps(data, indent=2),
            encoding="utf-8",
        )

        findings = data.get("results", [])
        print(f"{name.capitalize()}: {len(findings)} findings")

    print(f"Reports saved to: {report_dir}")

    unified = normalize_findings(results)

    output = report_dir / "findings.json"
    output.write_text(
        json.dumps(unified, indent=2),
        encoding="utf-8"
    )

    print(f"Unified findings: {len(unified)}")


if __name__ == "__main__":
    main()
