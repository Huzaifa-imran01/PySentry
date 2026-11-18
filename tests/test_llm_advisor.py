

import json
from unittest.mock import patch

import pytest

from src.llm_advisor import review_finding


SAMPLE_FINDING = {
    "scanner": "bandit",
    "rule_id": "B307",
    "severity": "MEDIUM",
    "message": "Unsafe eval",
    "file": "sample.py",
    "line": 2,
    "confidence": "HIGH",
}

VALID_REVIEW = {
    "explanation": "eval can execute arbitrary code.",
    "security_impact": "Possible code execution.",
    "suggested_fix": "Use ast.literal_eval for literals.",
}


def test_valid_ai_response():
    with patch("src.llm_advisor.generate", return_value=json.dumps(VALID_REVIEW)) as generate:
        assert review_finding(SAMPLE_FINDING, "code", api_key="secret") == VALID_REVIEW
    assert generate.call_args.args[0] == "secret"
    assert "code" in generate.call_args.args[2]
    assert generate.call_args.kwargs["schema"]["required"] == list(VALID_REVIEW)


@pytest.mark.parametrize("review", [{"explanation": "Unsafe eval"}, [], {**VALID_REVIEW, "suggested_fix": ""}])
def test_invalid_review(review):
    with patch("src.llm_advisor.generate", return_value=json.dumps(review)):
        with pytest.raises(RuntimeError):
            review_finding(SAMPLE_FINDING, "code", api_key="secret")


def test_invalid_json():
    with patch("src.llm_advisor.generate", return_value="not json"):
        with pytest.raises(RuntimeError, match="invalid JSON"):
            review_finding(SAMPLE_FINDING, "code", api_key="secret")


def test_batch_failure_does_not_crash_or_reuse_previous_review():
    from src.llm_advisor import review_all_findings
    with patch("src.llm_advisor.get_code_context", side_effect=[ValueError("bad"), "code", ValueError("bad")]), patch("src.llm_advisor.review_finding", return_value={**VALID_REVIEW, "suggested_fix": "def f(): pass"}):
        results = review_all_findings([SAMPLE_FINDING]*3, api_key="secret")
    assert [r["status"] for r in results] == ["failed", "reviewed", "failed"]
    assert [r["fix_status"] for r in results] == ["not_available", "syntax_valid_unverified", "not_available"]


def test_external_source_and_changed_source(tmp_path):
    import hashlib
    from src.llm_advisor import get_code_context
    source = tmp_path / "external.py"
    source.write_bytes(b"eval(user_input)\n")
    finding = {"file": str(source), "line": 1,
               "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
    assert get_code_context(finding) == "1: eval(user_input)"
    source.write_bytes(b"print('changed')\n")
    with pytest.raises(ValueError, match="Source changed"):
        get_code_context(finding)


def test_legacy_findings_require_rescan():
    from src.llm_advisor import get_code_context
    with pytest.raises(ValueError, match="Run the scan again"):
        get_code_context(SAMPLE_FINDING)


def test_empty_findings_replace_old_report(tmp_path, monkeypatch):
    from src import llm_advisor
    monkeypatch.setattr(llm_advisor, "ROOT", tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "findings.json").write_text("[]")
    output = reports / "ai_reviews.json"
    output.write_text('{"reviewed": 4}')
    monkeypatch.setattr("sys.argv", ["advisor", "--no-llm"])
    llm_advisor.main()
    report = json.loads(output.read_text())
    assert report["reviewed"] == 0
    assert report["results"] == []



def test_descriptive_fix_is_guidance_only():
    from src.llm_advisor import classify_fix

    review = {
        "suggested_fix": "Replace eval with a safer parser."
    }

    assert classify_fix(review) == "guidance_only"


def test_valid_function_is_candidate():
    from src.llm_advisor import classify_fix

    review = {
        "suggested_fix": (
            "import ast\n"
            "def evaluate_expression(user_input):\n"
            "    return ast.literal_eval(user_input)\n"
        )
    }

    assert classify_fix(review) == "syntax_valid_unverified"


def test_duplicate_eval_findings_are_grouped():
    from src.llm_advisor import group_duplicate_findings

    bandit = {
        "scanner": "bandit",
        "rule_id": "B307",
        "file": "sample.py",
        "line": 6,
        "source_sha256": "abc123",
    }

    semgrep = {
        "scanner": "semgrep",
        "rule_id": "rules.insecure-eval",
        "file": "sample.py",
        "line": 6,
        "source_sha256": "abc123",
    }

    shell = {
        "scanner": "bandit",
        "rule_id": "B602",
        "file": "sample.py",
        "line": 10,
        "source_sha256": "abc123",
    }

    groups = group_duplicate_findings(
        [bandit, semgrep, shell]
    )

    assert len(groups) == 2
    assert len(groups[0]["related_findings"]) == 2
    assert len(groups[1]["related_findings"]) == 1


def test_different_source_versions_not_grouped():
    from src.llm_advisor import group_duplicate_findings

    findings = [
        {
            "scanner": "bandit",
            "rule_id": "B307",
            "file": "sample.py",
            "line": 6,
            "source_sha256": "version1",
        },
        {
            "scanner": "semgrep",
            "rule_id": "rules.insecure-eval",
            "file": "sample.py",
            "line": 6,
            "source_sha256": "version2",
        },
    ]

    groups = group_duplicate_findings(findings)

    assert len(groups) == 2
