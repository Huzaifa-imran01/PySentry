import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from src import gemini_provider as provider, scanner
from src.reporting import ai_report, save_json


@pytest.mark.parametrize("code, reason", [(401,"authentication_failed"), (403,"permission_denied"), (429,"quota_or_rate_limit"), (503,"service_unavailable"), (404,"model_unavailable"), (400,"invalid_request_or_credential")])
def test_error_categories(code, reason):
    assert provider.failure_reason(SimpleNamespace(code=code)) == reason


def test_invalid_key_detail():
    assert provider.failure_reason(SimpleNamespace(code=400, details="API_KEY_INVALID")) == "authentication_failed"


def test_no_llm_never_prompts_or_calls_provider(monkeypatch):
    monkeypatch.setattr(provider.getpass, "getpass", lambda *a: pytest.fail("prompted"))
    monkeypatch.setattr(provider, "generate", lambda *a, **k: pytest.fail("network"))
    assert provider.prepare_ai(True) == (None, "disabled_by_flag")


def test_noninteractive_never_prompts(monkeypatch):
    monkeypatch.setattr(provider.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(provider.getpass, "getpass", lambda *a: pytest.fail("prompted"))
    assert provider.prepare_ai() == (None, "noninteractive_no_key")


def test_blank_key_skips_validation(monkeypatch):
    monkeypatch.setattr(provider.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(provider.getpass, "getpass", lambda *a: "   ")
    monkeypatch.setattr(provider, "generate", lambda *a, **k: pytest.fail("network"))
    assert provider.prepare_ai() == (None, "no_key")


def test_preflight_is_source_free_and_consumes_explicit_env(monkeypatch):
    monkeypatch.setenv("TEST_GEMINI_CREDENTIAL", "secret")
    mock = MagicMock(return_value="OK")
    monkeypatch.setattr(provider, "generate", mock)
    assert provider.prepare_ai(key_env="TEST_GEMINI_CREDENTIAL", model="chosen") == ("secret", "ready")
    mock.assert_called_once_with("secret", "chosen", "Reply with OK.", preflight=True)
    assert "TEST_GEMINI_CREDENTIAL" not in provider.os.environ


@pytest.mark.parametrize("reason", ["authentication_failed", "permission_denied", "quota_or_rate_limit", "service_unavailable", "network_error"])
def test_failed_preflight_disables_ai(monkeypatch, reason):
    monkeypatch.setenv("TEST_GEMINI_CREDENTIAL", "secret")
    monkeypatch.setattr(provider, "generate", MagicMock(side_effect=provider.GeminiUnavailable(reason)))
    assert provider.prepare_ai(key_env="TEST_GEMINI_CREDENTIAL") == (None, reason)


def test_sdk_exception_is_not_exposed(monkeypatch):
    from google import genai
    mock = MagicMock(side_effect=RuntimeError("secret-token"))
    monkeypatch.setattr(genai, "Client", mock)
    with pytest.raises(provider.GeminiUnavailable) as error:
        provider.generate("secret-token", "model", "OK")
    assert "secret-token" not in str(error.value)


def test_sdk_preflight_and_review_use_same_model(monkeypatch):
    from google import genai
    factory = MagicMock()
    client = factory.return_value.__enter__.return_value
    client.models.generate_content.return_value.text = "OK"
    monkeypatch.setattr(genai, "Client", factory)
    assert provider.generate("secret", "chosen", "Reply with OK.", preflight=True) == "OK"
    assert factory.call_args.kwargs["api_key"] == "secret"
    assert client.models.generate_content.call_args.kwargs["model"] == "chosen"
    assert client.models.generate_content.call_args.kwargs["config"].max_output_tokens == 16


def test_report_redacts_reflected_key(tmp_path):
    path = tmp_path / "report.json"
    save_json(path, {"error":"returned secret-value"}, "secret-value")
    assert "secret-value" not in path.read_text()


@pytest.mark.parametrize("ready", [False, True])
def test_cli_saves_basic_report_before_review(tmp_path, monkeypatch, ready):
    source = tmp_path / "sample.py"
    source.write_text("eval(input())")
    monkeypatch.setattr(scanner, "ROOT", tmp_path)
    monkeypatch.setattr("sys.argv", ["scanner", str(source)])
    events = []
    def prepare(*a):
        events.append("validation")
        return ("secret" if ready else None), ("ready" if ready else "authentication_failed")
    def scan(*a, **kwargs):
        events.append("scan")
        return {"bandit":{"source_sha256":__import__("hashlib").sha256(source.read_bytes()).hexdigest(), "results":[{"test_id":"B307", "line_number":1, "filename":str(source)}]}, "semgrep":{"results":[]}}
    monkeypatch.setattr(provider,"prepare_ai",prepare)
    monkeypatch.setattr(scanner,"scan_file",scan)
    from src import llm_advisor
    def review(*a, **k):
        assert (tmp_path/"reports/report.json").exists()
        assert k["api_key"] == "secret"
        return [{"status":"failed","error":"service_unavailable", "verification_status":"not_verified"}]
    monkeypatch.setattr(llm_advisor,"review_all_findings", review if ready else lambda *a, **k: pytest.fail("reviewed"))
    scanner.main()
    report = json.loads((tmp_path/"reports/report.json").read_text())
    assert events == ["validation", "scan"]
    assert report["scan_status"] == "completed"
    assert report["file"]["source_sha256"] is not None
    assert report["findings"][0]["remediation_guidance"]["source"] == "predefined_rule_guidance"
    assert report["ai"]["reason"] == ("review_failures" if ready else "authentication_failed")
    assert "secret" not in (tmp_path/"reports/report.json").read_text()


def test_scan_failure_overwrites_stale_report(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner,"ROOT",tmp_path)
    monkeypatch.setattr("sys.argv",["scanner","missing.py","--no-llm"])
    monkeypatch.setattr(scanner,"scan_file",MagicMock(side_effect=RuntimeError("scanner unavailable")))
    with pytest.raises(SystemExit):
        scanner.main()
    report=json.loads((tmp_path/"reports/report.json").read_text())
    assert report["scan_status"] == "failed"
    assert report["ai"]["reason"] == "scan_failed"


def test_successful_enrichment_and_group_limit(monkeypatch):
    from src import llm_advisor
    findings = [{"scanner":"bandit", "rule_id":"B602", "file":str(i), "line":1} for i in range(6)]
    reviews = [{"status":"reviewed", "review":{"suggested_fix":"def f(): pass"}, "verification_status":"not_verified"} for _ in range(5)]
    monkeypatch.setattr(llm_advisor,"review_all_findings",MagicMock(return_value=reviews))
    report = ai_report(findings, "secret", "ready", "chosen")
    assert report["reviewed"] == 5
    assert report["reason"] == "review_limit"
    assert report["unattempted_groups"] == 1
    assert report["verification_status"] == "not_verified"


def test_completed_ai_report(monkeypatch):
    from src import llm_advisor
    monkeypatch.setattr(llm_advisor,"review_all_findings",MagicMock(return_value=[{"status":"reviewed"}]))
    report=ai_report([{"scanner":"bandit","rule_id":"B602"}],"secret","ready","chosen")
    assert report["status"] == "completed"
    assert report["credential_status"] == "ready"


def test_empty_scan_does_not_call_review(monkeypatch):
    from src import llm_advisor
    monkeypatch.setattr(llm_advisor,"review_all_findings",lambda *a,**k: pytest.fail("reviewed"))
    assert ai_report([],"secret","ready","chosen")["reason"] == "no_findings"


def test_hidden_input_failure_never_falls_back_to_visible(monkeypatch):
    monkeypatch.setattr(provider.sys.stdin,"isatty",lambda: True)
    def unavailable(*a):
        raise provider.getpass.GetPassWarning("cannot hide")
    monkeypatch.setattr(provider.getpass,"getpass",unavailable)
    assert provider.prepare_ai() == (None,"hidden_input_unavailable")


def test_sdk_actual_invalid_key_is_classified():
    from google.genai.errors import ClientError
    error=ClientError(400,{"error":{"message":"not logged", "details":[{"reason":"API_KEY_INVALID"}]}})
    assert provider.failure_reason(error) == "authentication_failed"
