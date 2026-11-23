# Desktop GUI

Double-click `start_gui.bat` in the project folder, or run:

```powershell
cd C:\Users\Test\Documents\Projects\secure-code-review-agent
.\.venv\Scripts\python.exe -m src.gui
```

The GUI uses Python's built-in Tkinter. Keep the existing project virtual environment and scanner dependencies installed.

1. Choose a Python file or project folder.
2. Optionally enter a Gemini API key. Leave it blank for basic scanning. The key field is masked and cleared when the scan starts. The key is passed only in the scanner child process environment, not stored in settings or placed in command-line arguments. Existing Gemini validation and fallback behavior applies; validation may incur a charge, and AI reviews send selected source context to Google.
3. Choose automatic dependency detection, a requirements file, an installed-package folder inside the scan root, or skip dependency auditing.
4. Optionally adjust the existing scanner limits under Advanced limits.
5. Click Start scan. The interface stays responsive and Messages shows scanner output.

The Overview shows completion and AI/dependency status. Source findings supports text search and severity filtering. Select a row to read its full details. Separate tabs show AI reviews (including multiline proposed code), dependency advisories, analyzed/excluded files, live messages, and the complete JSON report. Open report loads an existing combined report; Export report saves a JSON copy.

This is an additive front end to the existing CLI. Existing scanner, rules, reports, Gemini behavior, and verification functionality are unchanged. Fixes are not automatically applied or executed. The GUI does not add a repair-verification workflow; use the existing verification tools as before.

Each scan writes to its own run directory. Overview shows execution, policy reasons, coverage, and effective rules. The severity threshold blocks on matching source findings, unrecognized severities, or any known dependency advisory. The separate dependency and validated-rule checkboxes require those checks to complete. Export saves an atomic JSON copy. Closing during a scan offers to close after completion.

Choose a rule profile and secret-scan scope in Scan setup. History includes the working tree and local Git history. Require secret scan makes incomplete secret coverage fail the run. Logical issues opens the supporting scanner evidence. Secrets shows redacted locations. Overview lists audited and shadowed project manifests. Dependency advisories include original occurrence records.
