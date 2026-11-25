# PySentry desktop GUI

From the project root, start `.venv\Scripts\python.exe -m src.gui` or double-click `start_gui.bat` on Windows. The GUI uses Tkinter and the same scanner, rules and policy options as the CLI. [Installation](README.md#install-and-run)

1. Choose a Python file or a project folder. Select **basic**, **default** or **deep**. The Overview identifies which rules actually ran and warns when a profile fell back.
2. Leave the Gemini key blank for a basic review. Entering a key enables a source-free model access check that can incur a charge. An enhanced review sends selected, masked and screened context. The key field is cleared when scanning starts.
3. Choose **Auto-detect Dependency files**, **Dependency file provided**, an installed-package folder inside the target, or skip the dependency audit. Under **Credential scan**, scan the working directory, add history for a repository root, or turn credential detection off.
4. For a blocking policy, select a severity threshold and the checks that must complete. **Advanced options** includes scan limits and a SARIF repository root. Click **Start scan**. Messages displays progress.

**Overview** shows execution, policy reasons, stage status, source coverage, effective rules and audited or shadowed manifests. **Source findings** supports search and severity filtering. **Logical issues** groups related detections and shows each scanner's evidence. Other tabs show redacted credential locations, dependency advisories, AI proposals, files and coverage, messages, and the native report.

**Open report** loads a saved combined report. **Export JSON…** saves an atomic copy of the displayed native JSON. **Export SARIF…** is available for finished version 1 reports, including finished runs with incomplete coverage. The export is schema-validated and preserves coverage status. For code scanned under a subdirectory, enter the original checkout root in **Advanced options** so SARIF locations match repository paths. Select a separate `.sarif` file as the destination.

Proposed fixes are advisory. A syntax classification or a reduction in scanner findings leaves behavior and security subject to review. [CLI usage, export options and verification](README.md)
