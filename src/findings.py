
def normalize_findings(reports):
    """Convert Bandit and Semgrep findings into one format."""
    findings = []

    for issue in reports["bandit"].get("results", []):
        findings.append({
            "scanner": "bandit",
            "rule_id": issue.get("test_id", "unknown"),
            "severity": issue.get("issue_severity", "UNKNOWN"),
            "message": issue.get("issue_text", ""),
            "file": issue.get("filename", ""),
            "line": issue.get("line_number"),
            "confidence": issue.get("issue_confidence"),
        })

    for issue in reports["semgrep"].get("results", []):
        extra = issue.get("extra") or {}
        start = issue.get("start") or {}

        findings.append({
            "scanner": "semgrep",
            "rule_id": issue.get("check_id", "unknown"),
            "severity": extra.get("severity", "UNKNOWN"),
            "message": extra.get("message", ""),
            "file": issue.get("path", ""),
            "line": start.get("line"),
            "confidence": None,
        })

    return findings
