"""Export completed native reports without reading the scanned source tree."""
from collections import Counter
from functools import lru_cache
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import quote

from jsonschema import Draft7Validator, FormatChecker

from .issues import canonical, logical_issues
from .reporting import write_atomic
from .secrets_scan import safe_fields

SCHEMA_URI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
SCHEMA_FILE = Path(__file__).resolve().parents[1] / "schemas" / "sarif-schema-2.1.0.json"
LEVELS = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


@lru_cache(maxsize=1)
def _validator():
    schema = json.loads(SCHEMA_FILE.read_bytes())
    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema, format_checker=FormatChecker())


def validate_sarif(document):
    error = next(_validator().iter_errors(document), None)
    if error:
        raise ValueError(f"Invalid SARIF at {error.json_path} ({error.validator})")


def _absolute(path):
    value = str(path)
    windows = PureWindowsPath(value)
    if windows.is_absolute():
        return windows
    return PurePosixPath(value) if value.startswith("/") else Path(value).resolve()


def _uri(path, scan_root, source_root):
    """Resolve recorded paths lexically, even when the exporter runs on another OS."""
    path_type = PureWindowsPath if isinstance(scan_root, PureWindowsPath) else PurePosixPath
    path = path_type(path)
    if ".." in path.parts or (path.anchor and not path.is_absolute()):
        return None
    try:
        relative = (scan_root / path).relative_to(source_root)
    except ValueError:
        return None
    return quote(relative.as_posix(), safe="/") if relative.parts else None


def _location(uri, line=None):
    physical = {"artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"}}
    if line is not None:
        if type(line) is not int or line < 1:
            raise ValueError("Invalid native finding line")
        physical["region"] = {"startLine": line}
    return {"physicalLocation": physical}


def _source_results(report, scan_root, source_root):
    issues = report.get("logical_issues")
    if issues is None:
        issues = logical_issues(report["findings"])
    for issue in issues:
        evidence = sorted(issue["evidence"], key=lambda r: (r["line"], r["scanner"], r["rule_id"]))
        first = evidence[0]
        uri = _uri(first["file"], scan_root, source_root)
        if not uri:
            raise ValueError("A source finding is outside the selected SARIF source root")
        rules = sorted({r["rule_id"] for r in evidence})
        severity = issue["normalized_severity"]
        category = issue["category"]
        message = first["message"] or f"Review {category}."
        result = {
            "ruleId": f"source/{category}", "level": LEVELS.get(severity, "warning"),
            "message": {"text": message}, "locations": [_location(uri, first["line"])],
            "properties": {
                "normalizedSeverity": severity,
                "evidence": [{k: row[k] for k in ("scanner", "rule_id", "line", "severity", "confidence", "message")
                              if k in row} for row in evidence],
            },
        }
        # Native issue_id includes a checkout path, source hash and statement line.
        # The AST digest and scope survive unrelated edits, unlike those fields.
        statement = first.get("statement_sha256") or message
        ambiguity = rules if first.get("ambiguous_site") else []
        yield result, [uri, first.get("scope"), statement, ambiguity], first["line"]


def _dependency_results(report, scan_root, source_root):
    for advisory in report.get("dependencies", {}).get("findings", []):
        package = canonical(advisory["package"])
        version = advisory["version"]
        advisory_id = advisory["advisory_id"]
        # Prefer a CVE when one source uses it as an alias and another as its ID.
        identifiers = {advisory_id, *advisory.get("aliases", [])}
        stable_id = min(identifiers, key=lambda i: (not i.startswith("CVE-"), i))
        fixes = advisory.get("fixed_versions", [])
        evidence = advisory.get("evidence") or [advisory]
        manifests = set()
        for row in evidence:
            if row.get("manifest") and row.get("resolution") != "installed":
                uri = _uri(row["manifest"], scan_root, source_root)
                if uri:
                    manifests.add(uri)
        message = f"{package} {version} is affected by {advisory_id}."
        if fixes:
            message += " Fixed versions include " + ", ".join(fixes) + "."
        result = {
            "ruleId": f"dependency/{stable_id}", "level": "warning",
            "message": {"text": message},
            "properties": {"normalizedSeverity": "UNKNOWN", "package": package, "version": version,
                           "identifiers": sorted(identifiers), "manifests": sorted(manifests),
                           "engines": sorted({r["tool"] for r in evidence if r.get("tool")})},
        }
        if manifests:
            result["locations"] = [_location(min(manifests))]
        else:
            result["properties"]["locationLimitation"] = "No in-repository manifest location was recorded."
        yield result, [package, version], 0


def _secret_results(report, scan_root, source_root):
    for finding in report.get("secrets", {}).get("findings", []):
        uri = _uri(finding["file"], scan_root, source_root)
        if not uri:
            raise ValueError("A secret finding is outside the selected SARIF source root")
        detector = finding["detector"]
        result = {
            "ruleId": f"secret/{detector}", "level": "warning",
            "message": {"text": f"Potential credential detected by {detector}. The value was withheld."},
            "properties": {"normalizedSeverity": "UNKNOWN", "scope": finding["scope"]},
        }
        commit = finding.get("commit")
        if finding["scope"] == "history":
            result["properties"].update(historicalArtifact=uri, commit=commit, historicalLine=finding["line"],
                                        locationLimitation="Historical finding has no confirmed working-tree location.")
        else:
            result["locations"] = [_location(uri, finding["line"])]
        yield result, [uri, finding["scope"], commit], finding["line"]


def _tool_versions(report):
    versions = {name: scanner.get("version") for name, scanner in report["scanners"].items()}
    secrets = report.get("secrets", {})
    if secrets.get("version"):
        versions["gitleaks"] = secrets["version"]
    for manifest in report.get("dependencies", {}).get("inputs", []):
        if manifest.get("tool") and manifest.get("tool_version"):
            versions[manifest["tool"]] = manifest["tool_version"]
    return [{"name": name, "version": version} for name, version in sorted(versions.items()) if version]


def _convert(report, source_root):
    coverage = report.get("coverage", {})
    target = _absolute(report["file"]["path"])
    fallback_root = target.parent if report["file"].get("source_sha256") else target
    scan_root = _absolute(coverage["root"]) if coverage.get("root") else fallback_root
    source_root = _absolute(source_root) if source_root is not None else scan_root
    if not scan_root.is_relative_to(source_root):
        raise ValueError("SARIF source root must contain the native report's scan root")

    entries = []
    for convert in (_source_results, _dependency_results, _secret_results):
        for result, identity, line in convert(report, scan_root, source_root):
            key = json.dumps([result["ruleId"], *identity], ensure_ascii=False, separators=(",", ":"))
            entries.append((key, line, result))
    rules = sorted({r["ruleId"] for _, _, r in entries})
    indexes = {rule: i for i, rule in enumerate(rules)}
    ordinals = Counter()
    results = []
    for key, _, result in sorted(entries, key=lambda item: item[:2]):
        ordinals[key] += 1
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        result["partialFingerprints"] = {"primaryLocationLineHash": f"{digest}:{ordinals[key]}"}
        result["ruleIndex"] = indexes[result["ruleId"]]
        results.append(result)
    descriptors = [{"id": rule, "shortDescription": {"text": rule.partition("/")[2].replace("_", " ")},
                    "properties": {"tags": ["security"]}} for rule in rules]
    execution = report["execution"]
    rules_state = report.get("rule_validation", {})
    rule_metadata = {k: rules_state[k] for k in ("status","effective_profile","selected_profile","effective_rule_count",
                                                 "bundle_sha256","reason") if k in rules_state}
    coverage_metadata = {k: coverage[k] for k in ("status", "eligible_files", "completed_files", "completeness", "limits")
                         if k in coverage}
    coverage_metadata["excludedEntries"] = len(coverage.get("excluded", []))
    coverage_metadata["exclusionsByReason"] = dict(Counter(row.get("reason", "unknown")
                                                          for row in coverage.get("excluded", [])))
    coverage_metadata["incompleteFiles"] = [
        {"uri": _uri(row["path"], scan_root, source_root), "status": row.get("status"),
         "scannerCoverage": row.get("scanner_coverage", {})} for row in coverage.get("files", [])
        if row.get("status") != "completed"]
    stages = {}
    for stage in ("dependencies", "secrets", "ai"):
        section = report.get(stage, {})
        stages[stage] = {key: section[key] for key in ("status", "reason", "scopes") if key in section}
    run = {
        "tool": {"driver": {"name": "PySentry", "rules": descriptors},
                 "extensions": _tool_versions(report)},
        "originalUriBaseIds": {"%SRCROOT%": {"description": {"text": "Source checkout root"}}},
        "invocations": [{"executionSuccessful": execution["overall"] == "completed", "exitCode": report["exit_code"]}],
        "results": results,
        "properties": {"nativeSchemaVersion": 1, "nativeRunId": report["run_id"], "execution": execution,
                       "policy": report["policy"], "stages": stages, "coverage": coverage_metadata, "ruleProfile": rule_metadata,
                       "resultsWithoutCurrentLocation": sum("locations" not in result for result in results)},
    }
    return {"$schema": SCHEMA_URI, "version": "2.1.0", "runs": [run]}


def build_sarif(report, *, source_root=None):
    if not isinstance(report, dict) or type(report.get("schema_version")) is not int or report["schema_version"] != 1:
        raise ValueError("SARIF export requires a version 1 native scan report")
    if report.get("run_status") != "finished":
        raise ValueError("SARIF export requires a finished native scan report")
    try:
        document = _convert(safe_fields(report), source_root)
    except (AttributeError, IndexError, KeyError, TypeError) as exc:
        raise ValueError("Malformed native report for SARIF export") from exc
    validate_sarif(document)
    return document


def export_sarif(report, destination, *, source_root=None):
    destination = Path(destination)
    if not destination.name.lower().endswith((".sarif", ".sarif.json")):
        raise ValueError("Use a .sarif or .sarif.json destination")
    document = build_sarif(report, source_root=source_root)
    write_atomic(destination, json.dumps(document, ensure_ascii=False, indent=2))
    return destination
