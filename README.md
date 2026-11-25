# PySentry

Scan a Python file or project directory with Bandit and local Semgrep rules. The CLI and desktop GUI share the same scanner. Each run produces a versioned JSON report containing findings, their supporting evidence, coverage and policy results. Export a finished run as SARIF 2.1.0 to use it in code-review tools.

## Install and run

Use Python 3.12. Start in the extracted source directory or the repository root. The native-tool installer supports x64 Windows and Linux, downloads the pinned Gitleaks and OSV-Scanner releases, verifies their SHA-256 checksums and installs them beside the selected interpreter. Use a Python installation with Tk for the GUI. Git is needed for history scans and release tooling.

```powershell
py -3.12 -m venv .venv
$python = (Resolve-Path .venv/Scripts/python.exe).Path
& $python -m pip install -r requirements-agent.txt
& $python scripts/install_scanners.py
& $python -m pip check
& $python -m src.scanner tests/fixtures/insecure_sample.py --no-llm --skip-dependencies
& $python -m src.gui
```

On Linux, create the environment with `python3.12 -m venv .venv` and use `.venv/bin/python`. On Windows, `start_gui.bat` also starts the GUI after installation. Select a file or directory, choose a profile, and click **Start scan**. The Overview shows status and coverage. The Logical issues tab opens individual scanner records. Separate tabs show secret locations, dependency advisories, AI reviews and messages. [Desktop guide](GUI_README.md)

## Scope and profiles

| Semgrep profile | Reviewed scope |
| --- | --- |
| Basic | 4 rules for eval, unsafe deserialization, disabled TLS verification and weak digests |
| Standard (default) | 15 rules including selected Flask and Django request flows, credential patterns, insecure configuration, templates, SQL and client-controlled payments |
| Deep | 23 rules including Standard and additional FastAPI, Starlette, file, URL, query, shell, template, YAML, session and password-handling checks |

Choose `--profile basic|standard|deep`. Bandit uses its own rules. A Semgrep approval binds the chosen rules and development fixtures to their digest and engine version. An absent or stale approval activates a one-rule fallback and a warning. The report records the effective rule IDs. CI can require current approval. [Rule provenance](rules/PROVENANCE.md)

Directory scans record per-file fingerprints, scanner outcomes and omissions. Source limits default to 1,000 files, 1,000,000 bytes per file, 120 seconds per scanner invocation and a 600-second source budget. Use `python -m src.scanner --help` for overrides. Review coverage whenever a scan produces zero findings. Local patterns can miss cross-function flows, authorization requirements, tenant isolation and business invariants.

## Interpreting a run

The authoritative artifact is `reports/<run_id>/report.json`. Source evidence is saved before later checks. Reports are updated atomically. The final CLI event identifies the run and report path. `findings` retains individual detections. `logical_issues` groups compatible evidence and records a normalized severity. Each supporting record retains the scanner's severity, confidence, rule, message and location.

**Execution** records whether mandatory checks completed. Source scanning is mandatory. Add `--require-dependencies`, `--require-secrets` or `--require-validated-rules` for additional requirements. **Policy** evaluates completed evidence against `--fail-on none|low|medium|high`. The default is report-only. Any advisory, secret finding or unrecognized source severity blocks an enabled threshold.

| CLI exit | Meaning |
| --- | --- |
| 0 | Required checks completed and the configured policy passed |
| 1 | Required checks completed and findings violated policy |
| 2 | Invalid configuration, failed mandatory execution or requested export failure |

Incomplete mandatory checks produce `not_evaluable` and preserve known violations. A SARIF export error preserves the native scan and its recorded policy outcome.

## Dependencies, secrets and AI

Dependency discovery is bounded to the target root and groups inputs by subproject. Standardized Python locks take precedence, followed by uv, Poetry, Pipfile and PDM locks, then pinned requirements. The report identifies shadowed manifests and unresolved declarations. OSV-Scanner handles uv, Poetry, Pipfile and PDM. Pip-audit handles pinned requirements, exact versions from standardized Python locks and explicitly selected installed metadata. Package names, versions, advisory IDs, aliases, fixes and manifest occurrences remain inspectable. Transitive coverage depends on the input inventory. A live advisory service can change its findings over time.

Use `--requirements PATH` for one manifest, `--dependency-path PATH` for a target's installed metadata inside the scan root, or `--skip-dependencies` to disable auditing. The agent's own requirements file is excluded from automatic discovery.

Gitleaks scans working files by default. `--secrets history` adds local Git history for a repository root. `--secrets off` skips the inventory. A controlled detector configuration ignores target suppression comments and uses a trusted ignore file. Detector allowlists, excluded directories, binary handling and available local Git history limit coverage.

An interactive scan accepts an optional hidden Gemini key. A source-free request checks model access and can incur a charge. An unavailable credential leaves basic scanning available. CI can supply a credential explicitly with `--api-key-env NAME`. `--no-llm` disables Gemini requests and prompting. Each proposed review masks literals and comments and screens the outgoing context with Gitleaks. Failed screening skips that review. PySentry attempts a review for every unique finding group, with up to 12,000 characters of source context per group. Suggested fixes are proposals. Syntax checks, scanner comparisons and trusted fixture behavior tests provide different kinds of evidence. [Gemini usage](src/GEMINI_USAGE.md)

## Export SARIF

To scan a repository subdirectory and produce paths relative to the repository checkout:

```powershell
& $python -m src.scanner C:\work\app\src --sarif-root C:\work\app --sarif review.sarif --no-llm
```

To export again from an existing report, pass a report file or run directory. Replace the sample paths with the recorded run and repository root:

```powershell
& $python -m src.export_sarif reports/RUN_ID review.sarif --source-root C:\work\app
```

The default path base is the scan root. For a subdirectory scan, select its containing checkout as the base for GitHub. In the GUI use **Export SARIF…** on a finished version 1 report. The repository root is under **Advanced options**. Older reports remain viewable and exportable as native JSON.

The exporter validates against the bundled OASIS schema. It maps logical issues to rule descriptors and results, retains provenance and scanner versions, and includes coverage and execution metadata. High and critical map to `error`, medium to `warning`, and low to `note`. Unknown severity is retained and displayed as a warning. Source fingerprints use relative paths and available statement and scope identities. GitHub's upload action may warn that its text-based hash differs and retain the supplied fingerprint. Moving a statement down the file preserves its fingerprint. Renaming it, changing its contents or adding indistinguishable occurrences can affect matching. Dependency advisories with a known manifest use file-level locations. Findings without a current source location have limited inline display in code-review tools.

### GitHub code scanning

In an eligible repository with code scanning enabled, set the Actions repository variable `ENABLE_SARIF_UPLOAD` to `true`. The optional job runs on pushes to the default branch or a manual dispatch on that branch. It validates Standard, scans the agent's `src` directory with repository-relative locations, uploads a completed source analysis under a stable category and waits for GitHub processing. Only this job requests `security-events: write`; pull requests run the ordinary read-only checks. Confirm the category, paths and alert locations in the repository's code scanning results. Public GitHub.com repositories and eligible organization-owned repositories with GitHub Code Security enabled can use the integration. [GitHub upload requirements](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)

## Verify and release

```powershell
& $python -m pytest -q
foreach ($profile in 'basic','standard','deep') {
    & $python -m src.benchmark --profile $profile --validate
    if ($LASTEXITCODE -ne 0) { throw "Validation failed for $profile" }
}
```

The benchmark runs genuine annotated Semgrep tests, writes the profile's approval and measures a separate holdout. Inspect precision, recall, known misses and file coverage in the generated results. These measurements apply to the labelled Semgrep fixtures. AI quality metrics require explicit judgments. For native integration tests, set `REVIEW_NATIVE_TESTS=1`. The separate live lockfile tests also require `REVIEW_LIVE_ADVISORIES=1` and network access.

Build a source ZIP from a selected commit using `python scripts/build_release.py HEAD dist/source.zip`. The builder checks the archived file list and contents against the committed tree. Uncommitted edits are excluded. Direct Python requirements and native tools are pinned; resolved transitive Python packages can vary over time. Run the clean-install and compatibility checks before publishing. [Release checklist](RELEASE_CHECKLIST.md)
