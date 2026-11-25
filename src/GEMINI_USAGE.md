# Optional Gemini review in PySentry

Run from the project root:

```powershell
.\.venv\Scripts\python.exe -m src.scanner --path tests/fixtures/insecure_sample.py
```

Interactive terminals prompt for a hidden Gemini key. Press Enter for basic scanning. A supplied key is validated before scanning using a small source-free generation request that may incur an API charge. Finding review sends selected finding metadata and locally screened source context to Google. Keys are held only in memory, never saved by the program.

Use `--no-llm` to skip prompting and every Gemini request. Noninteractive runs default to basic scanning. CI can explicitly supply a secret through `--api-key-env GEMINI_API_KEY`; configure that variable in the CI secret store. The value is consumed from the process environment before scanner subprocesses run. Ambient keys are not automatically used. Never pass the secret as a command-line argument.

Use `--model MODEL_ID` to override the default gemini-3.8-flash. Validation and reviews use the same model. Gemini requires the google-genai package in the project venv. If it is unavailable, basic scanning continues with an explicit reason.

`reports/<run_id>/report.json` combines basic evidence and optional AI review. It includes fingerprints, scanner versions and enabled rules, completion status, counts, original findings, and labelled predefined guidance. `bandit.json`, `semgrep.json`, and `findings.json` retain scanner evidence. `ai_reviews.json` is refreshed even when AI is skipped. Basic evidence is saved before finding review starts.

Authentication, permission, quota/rate-limit, model availability, network, and server errors have distinct reason codes. Some malformed requests or credentials are reported as invalid_request_or_credential when the provider offers no more specific classification. A successful preflight does not guarantee later availability. Once validation succeeds, PySentry attempts every unique finding group. It records individual failures and continues to the next group.

Inspect the coverage section for failed, skipped and partially analyzed files. Valid findings from a scanner are retained when a second scanner fails. Incomplete mandatory checks exit 2. Gemini failures are recorded per review and leave the source findings available.

Review statuses are not security guarantees. Syntax-valid fixes remain unverified, originals are not modified, and generated code is not executed automatically. The existing trusted-fixture verifier is unchanged.

For standalone review of existing findings, use `python -m src.llm_advisor --report <report-path-or-run-directory>` with the same provider flags. Each review writes a separate file beside the selected report.

Tests: `.\.venv\Scripts\python.exe -m pytest -q`. Provider tests are mocked and need no real key.

Selected source literals and comments are masked locally. The exact prompt must pass a local Gitleaks 8.24.3 screen before transmission. An incomplete redaction is recorded against the individual review.
