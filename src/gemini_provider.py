"""Optional Gemini access. Credentials stay in memory; errors never echo responses."""
import getpass
import os
import sys
import warnings

MODEL = "gemini-3.8-flash"


class GeminiUnavailable(RuntimeError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__("Gemini unavailable: " + reason)


def failure_reason(exc):
    code = getattr(exc, "code", None)
    # Inspect structured reasons without exposing provider messages or credentials.
    details = str(getattr(exc, "details", ""))
    if code == 401 or "API_KEY_INVALID" in details:
        return "authentication_failed"
    if code == 403:
        return "permission_denied"
    if code == 429:
        return "quota_or_rate_limit"
    if code in (500, 502, 503, 504):
        return "service_unavailable"
    if code == 404:
        return "model_unavailable"
    if code == 400:
        return "invalid_request_or_credential"
    if isinstance(exc, (TimeoutError, ConnectionError, OSError)):
        return "network_error"
    if type(exc).__name__ in ("ConnectError", "ReadTimeout", "ConnectTimeout", "RemoteProtocolError"):
        return "network_error"
    return "provider_error"


def generate(api_key, model, prompt, *, schema=None, system=None, preflight=False):
    if not api_key:
        raise GeminiUnavailable("no_key")
    try:
        from google import genai
        from google.genai import types
    except ImportError:
        raise GeminiUnavailable("sdk_not_installed") from None
    config = {"temperature": 0.1}
    if schema is not None:
        config.update(response_mime_type="application/json", response_json_schema=schema)
    if system:
        config["system_instruction"] = system
    if preflight:
        config["max_output_tokens"] = 1024
    try:
        with genai.Client(api_key=api_key, vertexai=False,
                          http_options=types.HttpOptions(timeout=20000 if preflight else 120000)) as client:
            response = client.models.generate_content(
                model=model, contents=prompt, config=types.GenerateContentConfig(**config))
            text = response.text
    except Exception as exc:
        raise GeminiUnavailable(failure_reason(exc)) from None
    if not isinstance(text, str) or not text.strip():
        raise GeminiUnavailable("empty_or_blocked_response")
    return text


def prepare_ai(no_llm=False, key_env=None, model=MODEL):
    """Return a run-local key and public status; never prompt in noninteractive runs."""
    if no_llm:
        return None, "disabled_by_flag"
    if key_env:
        # Consume the explicit credential so scanner subprocesses do not inherit it.
        key = os.environ.pop(key_env, "").strip()
    elif sys.stdin.isatty():
        print("Optional Gemini review sends finding context to Google. "
              "Key validation uses a small source-free request and may incur a charge.")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                key = getpass.getpass("Gemini API key (Enter for basic scan): ").strip()
        except (EOFError, getpass.GetPassWarning):
            return None, "hidden_input_unavailable"
    else:
        return None, "noninteractive_no_key"
    if not key:
        return None, "no_key"
    try:
        generate(key, model, "Reply with OK.", preflight=True)
    except GeminiUnavailable as exc:
        return None, exc.reason
    return key, "ready"
