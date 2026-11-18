# Secure Code Review Agent

Python-only source scanning with Bandit, reviewed local Semgrep configurations, optional Gemini advice, explicit dependency auditing, and trusted-fixture repair checks.

## Current validation boundary

81 Python tests passed in the development environment. All 15 YAML rule files passed Semgrep's Python JSON-schema validator. Native Semgrep rule tests could not run successfully: its engine returned `Permission denied: socketpair` inside the Codex sandbox. Therefore the expanded rules are **pending**, not advertised as verified or silently enabled. The original broad eval rule remains the active Semgrep baseline until real annotated tests pass. Bandit's default checks still run.

From an ordinary terminal with the project venv, run:

```powershell
.\.venv\Scripts\python.exe -m src.benchmark --validate
```

This invokes Semgrep's `--test --strict --json` mechanism, requires a passing result for every rule and zero configuration errors, records the bundle fingerprint, then evaluates held-out cases. Only the development test pass activates the expanded bundle. Any later rule or development-fixture edit invalidates approval. Inspect `rules/validation.json` and `benchmarks/results/rule_tests.json`. If tests fail, fix the documented mismatches before claiming coverage. Do not manually mark validation passed.

## Installation and scanning

Pinned agent tool versions are in `requirements-agent.txt`, deliberately distinct from a target application's dependency manifest.

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-agent.txt
.\.venv\Scripts\python.exe -m src.scanner --path C:\path\to\project --no-llm
.\.venv\Scripts\python.exe -m src.scanner --path C:\path\to\file.py
```

Both files and directories are supported. An interactive run prompts for a hidden optional Gemini key; Enter skips AI. `--no-llm` makes no Gemini requests. Noninteractive runs skip AI unless `--api-key-env NAME` explicitly supplies a CI secret. Keys remain in memory. A source-free preflight precedes scanning; AI sends only selected source context plus finding metadata. `--model` selects the Gemini model.

Limits: `--max-file-bytes 1000000`, `--scanner-timeout 120`, `--max-files 1000`, `--total-timeout 600` (source enumeration/scanning budget). Directory exclusions include virtual environments, Git metadata, caches, reports, build/dist, and node_modules. Symlinks and paths outside the selected root are not followed. Excluded directories are listed as directory-level exclusions; skipped Python files, syntax failures, provenance failures, and scanner failures have individual records. A partial scan exits nonzero. Findings from a successful scanner are retained even if the other fails.

`reports/report.json` includes `coverage`, per-file fingerprints, actual finding paths, scanner versions and active rule IDs, `rule_validation`, separate `dependencies`, and optional `ai`. Findings are never removed merely because AI failed. Zero findings on a partial/failed scan is not a clean bill of health.

## Dependency auditing

The scanner discovers `requirements.txt` only in the target root (the parent for a single-file target), or uses `--requirements PATH`. Provide a complete pinned export with `name==version` entries. For example, produce a freeze export using the **target application's** environment, then supply it; do not freeze the agent's environment as a proxy for another application.

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
