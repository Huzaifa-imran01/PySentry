
from src.findings import normalize_findings


def test_normalize_findings():
    reports = {
        "bandit": {
            "results": [{
                "test_id": "B307",
                "issue_severity": "MEDIUM",
                "issue_text": "Unsafe eval",
                "filename": "sample.py",
                "line_number": 5,
                "issue_confidence": "HIGH",
            }]
        },
        "semgrep": {
            "results": [{
                "check_id": "insecure-eval",
                "path": "sample.py",
                "start": {"line": 5},
                "extra": {
                    "severity": "ERROR",
                    "message": "Avoid eval",
                },
            }]
        },
    }

    findings = normalize_findings(reports)

    assert len(findings) == 2
    assert findings[0]["scanner"] == "bandit"
    assert findings[1]["scanner"] == "semgrep"
    assert findings[0]["line"] == 5
    assert findings[1]["rule_id"] == "insecure-eval"


def test_empty_findings():
    reports = {
        "bandit": {"results": []},
        "semgrep": {"results": []},
    }

    assert normalize_findings(reports) == []
