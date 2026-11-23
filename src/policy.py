"""Report execution separately from configured finding thresholds."""
from collections import Counter

LEVEL = {"LOW": 1, "INFO": 1, "MEDIUM": 2, "WARNING": 2, "HIGH": 3,
         "ERROR": 3, "CRITICAL": 4}


def evaluate(report, fail_on, require_dependencies, require_validated_rules, final=True):
    source = report["scan_status"]
    deps = report["dependencies"]
    missing = []
    violations = []
    secrets = report.get("secrets", {"status":"skipped","findings":[]})
    if report.get("require_secrets") and secrets["status"] != "completed":
        missing.append("secrets_" + secrets["status"])
    if source != "completed":
        missing.append("source_" + source)
    if require_dependencies and deps["status"] != "completed":
        missing.append("dependency_" + deps.get("reason", deps["status"]))
    if require_validated_rules and report["rule_validation"]["status"] != "passed":
        missing.append("validated_rules_unavailable")
    if fail_on != "none":
        threshold = LEVEL[fail_on.upper()]
        severities = Counter(str(row.get("severity", "UNKNOWN")).upper() for row in report["findings"])
        if "logical_issues" in report:
            severities = Counter(issue["normalized_severity"] for issue in report["logical_issues"])
        for severity, count in sorted(severities.items()):
            if severity not in LEVEL or LEVEL[severity] >= threshold:
                violations.append(f"source_severity_{severity}: {count}")
        if secrets["findings"]:
            violations.append(f"secret_detections: {len(secrets['findings'])}")
        if deps["findings"]:
            violations.append(f"dependency_advisories_any_severity: {len(deps['findings'])}")
    overall = "completed"
    if missing:
        overall = "failed" if source == "failed" else "incomplete"
    execution = {"source": source, "dependencies": deps["status"], "rules": report["rule_validation"]["status"],
                 "secrets": secrets["status"], "secret_reason": secrets.get("reason"), "ai": report["ai"]["status"],
                 "overall": overall if final else "running", "reasons": missing}
    result = "not_evaluable" if missing or not final else "failed" if violations else "passed"
    policy = {"fail_on": fail_on, "require_dependencies": require_dependencies,
              "require_secrets": report.get("require_secrets", False), "require_validated_rules": require_validated_rules, "result": result,
              "violations": violations, "reasons": missing + violations}
    code = 2 if missing else 1 if violations else 0
    report.update(execution=execution, policy=policy, exit_code=code if final else None)
    return code
