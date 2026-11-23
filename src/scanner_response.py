"""Check each tool's evidence at the subprocess boundary."""
from pathlib import Path


def location(value, cwd):
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError("invalid file path")
    return (cwd / value).resolve()


def required_text(row, key):
    if not isinstance(row.get(key), str) or not row[key].strip():
        raise ValueError(f"invalid {key}")


def check_row(tool, row, target, cwd):
    if not isinstance(row, dict):
        raise ValueError("finding must be an object")
    if tool == "bandit":
        fields = ("test_id", "issue_severity", "issue_text")
        if "issue_confidence" in row:
            required_text(row, "issue_confidence")
        for field in fields:
            required_text(row, field)
        path_key, line = "filename", row.get("line_number")
    else:
        required_text(row, "check_id")
        extra, start = row.get("extra"), row.get("start")
        if not isinstance(extra, dict) or not isinstance(start, dict):
            raise ValueError("invalid extra or start")
        for field in ("severity", "message"):
            required_text(extra, field)
        if "metadata" in extra and not isinstance(extra["metadata"], dict):
            raise ValueError("invalid metadata")
        metadata = extra.get("metadata", {})
        if "confidence" in metadata:
            required_text(metadata, "confidence")
        path_key, line = "path", start.get("line")
    if type(line) is not int or line < 1:
        raise ValueError("invalid line number")
    if location(row.get(path_key), cwd) != target:
        raise ValueError("finding outside requested target")
    return {**row, path_key: str(target)}


def semgrep_coverage(paths, target, cwd):
    if not isinstance(paths, dict) or not isinstance(paths.get("scanned"), list):
        raise ValueError("missing or malformed Semgrep scanned paths")
    scanned = {location(value, cwd) for value in paths["scanned"]}
    skipped = paths.get("skipped", [])
    if not isinstance(skipped, list) or any(not isinstance(row, dict) for row in skipped):
        raise ValueError("malformed Semgrep skipped paths")
    omitted = {location(row.get("path"), cwd) for row in skipped}
    if target in omitted:
        return "skipped"
    if target in scanned:
        return "analyzed"
    return "unknown" if scanned else "skipped"


def validate_response(tool, data, target, cwd):
    errors = []
    valid = []
    diagnostics = data.get("errors", [])
    if not isinstance(diagnostics, list):
        errors.append("malformed scanner errors")
    else:
        errors.extend("scanner_reported_error" for entry in diagnostics)
    for index, row in enumerate(data["results"]):
        try:
            valid.append(check_row(tool, row, target, cwd))
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append(f"result {index}: {exc}")
    evidence = "unknown"
    try:
        if tool == "semgrep":
            evidence = semgrep_coverage(data.get("paths"), target, cwd)
        else:
            metrics = data.get("metrics", {})
            if not isinstance(metrics, dict):
                raise ValueError("malformed Bandit metrics")
            if valid or any(location(key, cwd) == target for key in metrics if key != "_totals"):
                evidence = "analyzed"
    except (OSError, RuntimeError, ValueError) as exc:
        errors.append(str(exc))
    if evidence != "analyzed":
        errors.append(f"target coverage {evidence}")
    result = {**data, "results": valid, "coverage": evidence,
              "scan_status": "partial" if errors else "completed"}
    if errors:
        result["error"] = "; ".join(errors)
    return result
