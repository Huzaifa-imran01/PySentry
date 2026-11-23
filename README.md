# Secure Code Review Agent

Python-only source scanning with Bandit, reviewed local Semgrep configurations, optional Gemini advice, explicit dependency auditing, and trusted-fixture repair checks.

## Current validation boundary

The standard Semgrep profile is approved by annotated tests for its exact rule bundle, development fixtures, and Semgrep package version. A missing, legacy, stale, or unsuccessful approval selects the one-rule fallback and emits a warning. Revalidate after changing the engine, rules, or fixtures. Every report records the effective configuration, IDs, digest, engine versions, and reason.

From an ordinary terminal with the project venv, run:

```powershell
.\.venv\Scripts\python.exe -m src.benchmark --validate
```

This invokes Semgrep's `--test --strict --json` mechanism, requires a passing result for every rule and zero configuration errors, records the bundle fingerprint, then evaluates held-out cases. Only the development test pass activates the expanded bundle. Any later rule or development-fixture edit invalidates approval. Inspect `rules/validation.json` and `benchmarks/results/rule_tests.json`. If tests fail, fix the documented mismatches before claiming coverage. Do not manually mark validation passed.

## Installation and scanning

Use Python 3.12. Pinned agent tool versions are in `requirements-agent.txt`, deliberately distinct from a target application's dependency manifest.

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-agent.txt
.\.venv\Scripts\python.exe scripts/install_scanners.py
.\.venv\Scripts\python.exe -m src.scanner --path C:\path\to\project --no-llm
.\.venv\Scripts\python.exe -m src.scanner --path C:\path\to\file.py
```

Both files and directories are supported. An interactive run prompts for a hidden optional Gemini key; Enter skips AI. `--no-llm` makes no Gemini requests. Noninteractive runs skip AI unless `--api-key-env NAME` explicitly supplies a CI secret. Keys remain in memory. A source-free preflight precedes scanning; AI sends only selected source context plus finding metadata. `--model` selects the Gemini model.

Limits: `--max-file-bytes 1000000`, `--scanner-timeout 120`, `--max-files 1000`, `--total-timeout 600` (source enumeration/scanning budget). Directory exclusions include virtual environments, Git metadata, caches, reports, build/dist, and node_modules. Symlinks and paths outside the selected root are not followed. Excluded directories are listed as directory-level exclusions; skipped Python files, syntax failures, provenance failures, and scanner failures have individual records. A partial scan exits nonzero. Findings from a successful scanner are retained even if the other fails.

`reports/<run_id>/report.json` includes `coverage`, per-file fingerprints, actual finding paths, scanner versions and active rule IDs, `rule_validation`, separate `dependencies`, and optional `ai`. Findings are never removed merely because AI failed. Zero findings on a partial/failed scan is not a clean bill of health.

## Dependency auditing

Directory scans discover manifests by subproject under the selected root. Discovery skips symlinks, junctions, virtual environments, caches and generated directories. The limits are 10,000 directory entries and 8 MB per manifest. A limit or unreadable input appears in coverage. Within each directory the precedence is `pylock.toml`, `uv.lock`, `poetry.lock`, `Pipfile.lock`, then `pdm.lock`. Without a lock the auditor uses the discovered `requirements*.txt` files. A standalone `pyproject.toml` is reported as unresolved declarations. The agent's own requirements file is excluded from discovery. Each selected input records its fingerprint, subproject, tool, resolution type and outcome. Overlapping inputs are listed separately.

OSV-Scanner 2.2.2 reads uv, Poetry, Pipfile and PDM locks with resolution disabled. Standardized `pylock.toml` and `pylock.*.toml` files use a validated metadata-only export of their exact package versions to pip-audit. Named pylocks in one subproject are audited together. The adapter checks its version, exit status, response path and package inventory. Pinned requirements and explicitly selected installed metadata use pip-audit. Advisory lookups send package identifiers and versions to the advisory service. Package names are canonicalized, versions are kept separate and advisory records are merged only on shared IDs or aliases. Each logical advisory retains its scanner and manifest occurrences. Use `--requirements PATH` to select a specific lock or pinned export.

```powershell
.\.venv\Scripts\python.exe -m src.scanner --path C:\app --requirements C:\app\requirements-audit.txt --no-llm
.\.venv\Scripts\python.exe -m src.scanner --path C:\app --dependency-path C:\app\.venv\Lib\site-packages --no-llm
```

An explicitly selected installed-distribution directory must be inside the target root. No default audit of the agent environment occurs. `--skip-dependencies` disables this network-backed check. Pinned manifests use pip-audit `--disable-pip --no-deps`, avoiding untrusted build/resolver execution. Unpinned/VCS/editable/includes/hash-format manifests are reported unsupported; export a complete pinned list first. Transitive coverage is only as complete as the input export. Results include package/version, advisory ID, aliases and fix versions. Audit failures and skipped packages remain visible, independently of source-scan status. A live lookup of the intentionally old requests 2.19.1 benchmark returned 10 advisories; it was not installed.

## Coverage and honest limits

Candidate rule categories: code execution; request-to-shell, SQL, file, URL, unsafe HTML and template sinks; pickle/unsafe YAML; MD5/SHA1; disabled TLS verification; literal password assignments; disabled JWT signatures; Django CSRF exemptions; client-controlled Stripe amounts; Django-style DEBUG=True settings.

Framework sources cover selected Flask request args/form/values/JSON/uploads and Django GET/POST/body idioms. Assignment propagation is supplied by Semgrep's taint engine. HTML escaping sanitizes HTML-marking sinks only, not template code or other categories. SQL sinks focus on query text, URL sinks on URLs. There is no generic validator sanitizer.

These checks do NOT prove authentication correctness, ownership authorization, tenant isolation, pricing/business invariants, production deployment safety, exploitability, or absence of vulnerabilities. CSRF exemption is a configuration warning, not proof of missing authorization. Hardcoded-password, weak-digest and debug patterns can be legitimate in examples/nonsecurity contexts. Cross-function wrappers and dynamic dispatch are known limits of these local rules. Bandit has additional default checks; benchmark metrics are explicitly Semgrep-only.

Provenance: `rules/PROVENANCE.md` pins the reviewed community reference. Local code-execution policy retains the original broad eval warning; no changing remote rule registry or copied proprietary rules are used.

## Benchmarks and metrics

`benchmarks/development` contains two positive variants, a safe example, and a declared known-limit example per category. `benchmarks/holdout` contains separately authored positive/safe/known-limit cases, not used to tune the rules. Fixtures are parsed/scanned only, never executed. Synthetic examples are not a representative security-accuracy study.

```powershell
.\.venv\Scripts\python.exe -m src.benchmark --split development
.\.venv\Scripts\python.exe -m src.benchmark --split holdout
```

Annotation-based precision/recall are measured separately. Overall recall includes known-limit positives as false negatives if missed; supported-case recall is also labelled separately. False positives include unexpected detections. Scan completeness records analyzed versus eligible files. Failed engine runs produce null metrics, never fabricated success.

Optional `--judgments PATH` accepts explicit human labels using `benchmarks/judgments.example.json`: explanation correctness, usable fix, scanner improvement, behavior pass. Each metric retains its own labelled denominator; unknown values stay null. JSON response success and syntax acceptance are not proxies for AI correctness. No live Gemini quality benchmark was performed.

## Fix checks and verification

AI context includes the enclosing function and relevant module imports, capped at 12000 characters with explicit truncation. Prompt instructions treat source as untrusted data, focus on the reported finding, preserve behavior, permit multiline code, and prohibit claims of verification. Individual batch failures do not reuse prior reviews.

`fix_checks` compiles suggestions and reports unresolved external names without executing code. `syntax_valid_unverified` remains advisory. The verifier still stages exactly one matching undecorated function in trusted fixtures, preserves originals, and compares scanner evidence. Where target line information is supplied, it additionally compares AST statement fingerprints and function scopes to avoid relying solely on whole-file rule totals. Line shifts alone do not change these identities; statement edits and identical duplicate statements remain limitations. Comparisons remain conservative and unverified.

The five trusted literal-parser behavior tests use handwritten reviewed code. They are not tests of arbitrary Gemini fixes. No model-generated code is automatically executed, applied, or certified safe.

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```


## Policy and run reports

The default is report-only. Source coverage is always required. Optional dependency or AI failures are recorded separately. Secret scanning defaults to working files. Use `--require-secrets` to make incomplete secret detection an execution failure. Every secret finding blocks an enabled security threshold.

- `--fail-on none|low|medium|high` sets the source blocking threshold. INFO/LOW, WARNING/MEDIUM and ERROR/HIGH share levels; CRITICAL is above HIGH. An unrecognized severity blocks at any enabled threshold. Any reported dependency advisory also blocks at any enabled threshold, including advisories without a severity.
- `--require-dependencies` requires a completed audit independently of the finding threshold. Combine it with `--fail-on` to require both completion and acceptable findings.
- `--require-validated-rules` requires current native rule approval. A fallback scan still collects evidence and produces a diagnostic report.
- Exit 0 means required checks completed and the configured policy passed. Exit 1 means a finding violated policy. Exit 2 means invalid configuration or incomplete required execution. If findings violate policy during an incomplete run, violations are retained and the policy result is `not_evaluable`.

Each invocation writes its own schema version 1 JSON artifacts in `reports/<run_id>/`. Source evidence is checkpointed before later stages. Each update replaces the individual file atomically. A finished report records execution, policy, exit code, and completion time. The final JSON event on stdout identifies its run and absolute report path. The GUI can also open older unversioned reports; execution and policy fields absent from those reports are displayed as unrecorded.

To review saved findings, use `python -m src.llm_advisor --report <report-path-or-run-directory>`. Each standalone review writes a separate AI review file beside the selected report.

## Reviewed profiles and source evidence

| Profile | Approved rule families |
| --- | --- |
| Basic | Four checks for eval, deserialization, TLS verification and weak digests |
| Standard (default) | The original 15 rules, including selected Flask and Django flows |
| Deep | Standard plus eight rules for framework SQL, outbound URLs, file operations, shells, templates, YAML, insecure session transport and password hashing |

Select a profile with `--profile basic|standard|deep` or the GUI's Rule profile control. Each profile owns a frozen rule list and independent fixtures, approval digest and Semgrep version. The effective rule IDs are enumerated in each report. Run `python -m src.benchmark --validate --profile deep` to retest and measure Deep. Basic and Deep snapshots live under `profiles/`; synchronize shared rules deliberately when updating them. The extra rules were authored locally. The original upstream reference remains documented in `rules/PROVENANCE.md`.

Deep follows supported FastAPI route arguments, selected Form/Body/Query/Path parameters, Pydantic fields, explicitly typed request methods and upload reads. Its sinks include SQLAlchemy query text, Django raw queries, httpx and urllib URLs, typed aiohttp session requests, pathlib I/O and selected extraction calls. Path construction alone is allowed. Bound SQL values and HTTP query parameters are outside these sinks.

`findings` retains each source detection with its native severity, confidence, message and location. `logical_issues` groups compatible evidence at the same unambiguous AST statement and source version. Distinct calls at an ambiguous location remain separate. Unmapped rules retain scanner-specific categories. INFO/LOW, WARNING/MEDIUM and ERROR/HIGH normalize to LOW, MEDIUM and HIGH. CRITICAL is retained. Unrecognized levels remain UNKNOWN. Select a logical issue in the GUI to see its supporting records.

## Secrets and cloud review

The installer checks SHA-256 release digests before placing Gitleaks 8.24.3 and OSV-Scanner 2.2.2 beside the agent interpreter on x64 Windows or Linux. `--secrets directory` scans working files by default. `history` additionally scans all local Git refs when the target is a repository root. `off` skips the inventory. Missing tools, timeouts and failed scopes are visible in the report. The adapter pins the configuration, uses an empty trusted ignore file, and ignores target `gitleaks:allow` comments. Embedded detector allowlists, project exclusions and binary-file handling limit coverage. Reported matches need human review.

The detector writes redacted JSON to a pipe. Saved findings retain a detector, scope, path, line, redacted description and location fingerprint. Scanner source excerpts are omitted from sidecars. Before each Gemini review, literals and comments are masked and the exact proposed prompt is screened with pinned Gitleaks. An unavailable screen or unsafe context skips that review even when the optional repository-wide secret scan is disabled. Masking can reduce the specificity of a proposed fix.

## Continuous integration

Pull requests and pushes run Python 3.12 checks on Windows and Linux. The workflow separates deterministic tests, per-profile annotated Semgrep tests and holdouts, native Gitleaks history tests, and CLI policy tests for exits 0, 1 and 2. Scheduled or manually dispatched runs also query live advisories. No Gemini credential is configured. The workflow uses read-only contents permission, commit-pinned actions and short-lived artifacts from controlled test inputs.
