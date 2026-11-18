
import hashlib

import pytest

from src import verifier
from src.verifier import compare_security_reports



@pytest.fixture
def sample_file(tmp_path, monkeypatch):
    monkeypatch.setattr(verifier, "ROOT", tmp_path)

    fixture_dir = tmp_path / "tests" / "fixtures"
    fixture_dir.mkdir(parents=True)

    source = fixture_dir / "sample.py"
    source.write_text(
        "def evaluate_expression(user_input):\n"
        "    return eval(user_input)\n",
        encoding="utf-8",
    )

    fingerprint = hashlib.sha256(
        source.read_bytes()
    ).hexdigest()

    return source, fingerprint


def test_valid_candidate_preserves_original(sample_file):
    source, fingerprint = sample_file
    original = source.read_text(encoding="utf-8")

    replacement = (
        "def evaluate_expression(user_input):\n"
        "    return int(user_input)\n"
    )

    with verifier.stage_candidate(
        source,
        "evaluate_expression",
        replacement,
        fingerprint,
    ) as candidate:
        assert candidate.exists()
        assert "return int(user_input)" in candidate.read_text()
        assert source.read_text() == original

        temporary_path = candidate

    assert not temporary_path.exists()


def test_invalid_replacement_syntax(sample_file):
    source, fingerprint = sample_file

    with pytest.raises(ValueError, match="syntax"):
        with verifier.stage_candidate(
            source,
            "evaluate_expression",
            "def evaluate_expression(:",
            fingerprint,
        ):
            pass


def test_wrong_function_rejected(sample_file):
    source, fingerprint = sample_file

    replacement = (
        "def different_function():\n"
        "    return 1\n"
    )

    with pytest.raises(ValueError, match="matching function"):
        with verifier.stage_candidate(
            source,
            "evaluate_expression",
            replacement,
            fingerprint,
        ):
            pass


def test_changed_source_rejected(sample_file):
    source, fingerprint = sample_file

    source.write_text(
        "print('modified')\n",
        encoding="utf-8",
    )

    replacement = (
        "def evaluate_expression(user_input):\n"
        "    return int(user_input)\n"
    )

    with pytest.raises(ValueError, match="fingerprint"):
        with verifier.stage_candidate(
            source,
            "evaluate_expression",
            replacement,
            fingerprint,
        ):
            pass


def test_external_file_rejected(tmp_path, sample_file):
    _, fingerprint = sample_file

    external = tmp_path / "external.py"
    external.write_text("def example(): pass\n")

    with pytest.raises(ValueError, match="outside trusted"):
        with verifier.stage_candidate(
            external,
            "example",
            "def example():\n    return True\n",
            fingerprint,
        ):
            pass

def make_report(bandit_rules=(), semgrep_rules=()):
    return {
        "bandit": {
            "results": [
                {"test_id": rule}
                for rule in bandit_rules
            ]
        },
        "semgrep": {
            "results": [
                {"check_id": rule}
                for rule in semgrep_rules
            ]
        },
    }


TARGET = [
    {"scanner": "bandit", "rule_id": "B307"},
    {"scanner": "semgrep", "rule_id": "rules.insecure-eval"},
]


def test_vulnerability_reduction():
    original = make_report(
        ["B307", "B602"],
        ["rules.insecure-eval"],
    )

    candidate = make_report(["B602"])

    result = compare_security_reports(
        original, candidate, TARGET
    )

    assert result["status"] == "scanner_reduction_unverified"
    assert result["targets_reduced"] is True
    assert result["behavior_verified"] is False


def test_unresolved_vulnerability():
    original = make_report(
        ["B307"],
        ["rules.insecure-eval"],
    )

    result = compare_security_reports(
        original, original, TARGET
    )

    assert result["status"] == "target_not_reduced"


def test_new_vulnerability_detected():
    original = make_report(
        ["B307"],
        ["rules.insecure-eval"],
    )

    candidate = make_report(["B602"])

    result = compare_security_reports(
        original, candidate, TARGET
    )

    assert result["status"] == "regression_detected"
    assert result["new_or_increased_findings"]["bandit:B602"] == 1


def test_missing_baseline_target_is_inconclusive():
    original = make_report(["B602"])
    candidate = make_report([])

    result = compare_security_reports(
        original, candidate, TARGET
    )

    assert result["status"] == "inconclusive"
