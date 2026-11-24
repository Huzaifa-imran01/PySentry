# PySentry source release checklist

## Select and inspect the revision

- [ ] Select the commit that contains the intended scanner, export schema, rules, fixtures and documentation. Review `git status --short`, `git log -1` and `git ls-tree -r --name-only HEAD`. Substitute the intended tag or commit for `HEAD` when releasing a different revision.
- [ ] Build the ZIP from that commit. The builder resolves the revision once, uses `git archive`, checks the ZIP's revision and member list, and compares each file's bytes to its Git blob. Staged, unstaged and untracked edits are excluded. Keep the printed commit ID and archive SHA-256 with the release.
- [ ] Review the ZIP listing and the builder's excluded-file list. Check for private project material, credentials, environments, caches, runtime reports and local tool binaries. The builder screens common private-key and credential signatures. Unusual credential formats still require review. Understand any synthetic fixture matches before publishing. Preserve rule approvals and labelled examples. Regenerate benchmark output on the recipient machine.

From the repository root in PowerShell:

```powershell
$revision = git rev-parse HEAD
$archive = Join-Path (Get-Location).Path "dist/PySentry-$revision.zip"
py -3.12 scripts/build_release.py $revision $archive
if ($LASTEXITCODE -ne 0) { throw "Release build failed" }
py -3.12 -m zipfile -l $archive
Get-FileHash -Algorithm SHA256 $archive
```

## Verify a clean installation

- [ ] Extract this exact ZIP into a new directory outside the checkout. Install using Python 3.12. Use Git on PATH for repository history scans and Git-based release tests. Use an x64 Windows or Linux host for the bundled native-tool installer. Python packages and native releases require access to their distribution endpoints.
- [ ] Record the platform, Python and Git versions and the installed package versions alongside verification results. Direct dependencies are pinned. Record the resolved environment when comparing results across dates.
- [ ] Use the new environment's Python for every check. Run the complete test suite, including native integration tests. Keep live advisory queries separate when comparing deterministic results.

```powershell
$clean = Join-Path ([IO.Path]::GetTempPath()) ("PySentry-" + [guid]::NewGuid())
Expand-Archive -LiteralPath $archive -DestinationPath $clean
Set-Location -LiteralPath $clean
py -3.12 -m venv .venv
$python = (Resolve-Path .venv/Scripts/python.exe).Path
& $python -m pip install -r requirements-agent.txt
& $python scripts/install_scanners.py
& $python -m pip check
& $python -m pip freeze
$env:REVIEW_NATIVE_TESTS = '1'
& $python -m pytest -q
```

On Linux use `python3.12 -m venv .venv` and `.venv/bin/python`. For a live advisory-service check, set both `REVIEW_LIVE_ADVISORIES=1` and `REVIEW_NATIVE_TESTS=1` and run `python -m pytest -q tests/test_native_tools.py -k lock_live`. Record failures and skips, especially desktop tests on headless runners.

## Verify coverage, compatibility and limitations

- [ ] Validate every supported profile against its annotated rules. Inspect the holdout metrics, per-rule results, scan completeness and known misses. Capture the engine version and the bundle digest for each run.

```powershell
foreach ($profile in 'basic','standard','deep') {
    & $python -m src.benchmark --validate --profile $profile
    if ($LASTEXITCODE -ne 0) { throw "Validation failed for $profile" }
}
```

- [ ] Scan the controlled fixture without cloud credentials and export SARIF. Check the native report path in the completion event. Verify the native report has its run ID, version, stage outcomes and evidence. Confirm the SARIF opens, has repository-relative artifact locations, and agrees with the logical issues. The native report remains the full record for coverage, dependency and AI details.

```powershell
& $python -m src.scanner tests/fixtures/insecure_sample.py --no-llm --skip-dependencies --require-validated-rules --sarif fixture.sarif --sarif-root .
& $python -m src.gui
```

- [ ] Open the completed report in the GUI and export its SARIF. Open an existing legacy native report to verify the compatibility reader. Check empty findings, incomplete mandatory checks and policy violations. The CLI records these separately and gives exit codes 0, 2 and 1 respectively when the other mandatory stages complete.
- [ ] In an eligible repository, opt in to the GitHub upload workflow, run the workflow on the default branch containing the release revision and inspect an alert on its source line. Review access restrictions and the upload job's permissions. Record hosted upload as unverified whenever this check is unavailable.
- [ ] Summarize known limits alongside the release. Static rules cover demonstrated patterns, dependency results depend on resolved inventory and advisory availability, and Gemini suggestions require independent review. Record the commit, archive hash, test commands, platform, rule results and any checks that could not run.
