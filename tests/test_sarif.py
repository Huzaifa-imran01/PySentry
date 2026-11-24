"""Contract for the offline schema validator and the GitHub-supported result fields."""
import copy
import hashlib
import json

import pytest

from src.sarif import SCHEMA_FILE, build_sarif, export_sarif, validate_sarif


def native(root=r"C:\Agent\checkout", relative="pkg/caf\u00e9 #1.py", line=4):
    target = root + "/" + relative
    base = {"file": target, "line": line, "scope": "parse", "statement_sha256": "abc",
            "message": "Untrusted expression evaluated.", "source_sha256": "version",
            "severity": "HIGH", "confidence": "MEDIUM"}
    detections = [{**base, "scanner": tool, "rule_id": rule}
                  for tool, rule in [("semgrep", "insecure-eval"), ("bandit", "B307")]]
    return {
        "schema_version": 1, "run_status": "finished", "run_id": "sample", "file": {"path": target},
        "coverage": {"root": root, "status": "completed", "eligible_files": 1, "completed_files": 1},
        "scanners": {"bandit": {"version": "1.9.4"}, "semgrep": {"version": "1.185.0"}},
        "execution": {"overall": "completed", "source": "completed"}, "exit_code": 1,
        "policy": {"result": "failed"}, "findings": detections,
        "logical_issues": [{"category": "unsafe_eval", "normalized_severity": "HIGH", "evidence": detections}],
    }


def test_github_result_contract_and_official_schema(tmp_path):
    report = native()
    unchanged = copy.deepcopy(report)
    destination = export_sarif(report, tmp_path/"review.sarif")
    assert report == unchanged
    document = json.loads(destination.read_bytes())
    assert document == build_sarif(report)
    assert document["version"] == "2.1.0"
    validate_sarif(document)
    run, = document["runs"]
    result, = run["results"]
    assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] == result["ruleId"]
    assert len(run["tool"]["extensions"]) == 2
    assert result["level"] == "error" and result["message"]["text"]
    assert result["partialFingerprints"]["primaryLocationLineHash"]
    assert len(result["properties"]["evidence"]) == 2
    location, = result["locations"]
    assert location["physicalLocation"] == {
        "artifactLocation": {"uri": "pkg/caf%C3%A9%20%231.py", "uriBaseId": "%SRCROOT%"},
        "region": {"startLine": 4}}
    assert "C:" not in destination.read_text()
    assert run["invocations"][0] == {"executionSuccessful": True, "exitCode": 1}
    assert run["properties"]["policy"]["result"] == "failed"
    del location["physicalLocation"]["artifactLocation"]
    result["level"] = "HIGH"
    with pytest.raises(ValueError, match="Invalid SARIF"):
        validate_sarif(document)


def test_moved_lines_and_another_checkout_have_the_same_fingerprint():
    def fingerprints(root, line):
        report = native(root=root, line=line)
        duplicate = copy.deepcopy(report["logical_issues"][0])
        for row in duplicate["evidence"]:
            row.update(line=line+9, source_sha256="another-file-content-hash")
        report["logical_issues"].insert(0, duplicate)
        results = build_sarif(report)["runs"][0]["results"]
        return [r["partialFingerprints"]["primaryLocationLineHash"] for r in results]
    original = fingerprints(r"D:\checkout", 4)
    assert len(set(original)) == 2
    assert original == fingerprints("/home/ci/src", 44)


def test_repository_root_override_and_unc():
    report = native(root=r"\\checker\share\checkout\service")
    result, = build_sarif(report, source_root=r"\\checker\share\checkout")["runs"][0]["results"]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("service/pkg/")
    with pytest.raises(ValueError, match="source root"):
        build_sarif(report, source_root=r"E:\unrelated")


def test_empty_or_incomplete_report_retains_coverage():
    report = native()
    report.update(findings=[], logical_issues=[], exit_code=2)
    report["coverage"].update(status="partial", completed_files=0,
                               files=[{"path":report["file"]["path"], "status":"failed"}])
    report["execution"].update(overall="incomplete")
    report["policy"].update(result="not_evaluable")
    run, = build_sarif(report)["runs"]
    assert run["results"] == run["tool"]["driver"]["rules"] == []
    assert run["properties"]["coverage"]["incompleteFiles"][0]["status"] == "failed"
    assert run["invocations"][0] == {"executionSuccessful": False, "exitCode": 2}


def test_advisory_manifest_file_and_secret_history():
    report = native(root="/review", line=11)
    advisory = {"package":"Some_Lib","version":"1.2","advisory_id":"GHSA-example","aliases":["CVE-example"],
                "fixed_versions":["1.4"],"evidence":[{"tool":"pip-audit","manifest":"/review/requirements.txt"}]}
    report["dependencies"] = {"findings":[advisory], "inputs":[{"tool":"pip-audit","tool_version":"2.10.1"}]}
    secret = {"detector":"literal","scope":"directory","file":"pkg/module.py","line":8}
    report["secrets"] = {"version":"8.24.3","findings":[secret,{**secret,"scope":"history","commit":"a"*40}]}
    run = build_sarif(report)["runs"][0]
    dep, = [r for r in run["results"] if r["ruleId"]=="dependency/CVE-example"]
    assert dep["locations"] == [{"physicalLocation": {"artifactLocation": {"uri":"requirements.txt","uriBaseId":"%SRCROOT%"}}}]
    assert dep["properties"]["normalizedSeverity"] == "UNKNOWN"
    history, = [r for r in run["results"] if r["properties"].get("scope")=="history"]
    assert "locations" not in history and history["properties"]["historicalLine"] == 8
    assert run["properties"]["resultsWithoutCurrentLocation"] == 1
    advisory["evidence"][0]["manifest"]="/other/requirements.txt"
    dep, = [r for r in build_sarif(report)["runs"][0]["results"] if r["ruleId"].startswith("dependency/")]
    assert "locations" not in dep and dep["properties"]["locationLimitation"]


@pytest.mark.parametrize("patch", [{"run_status":"running"}, {"schema_version":True}, {"schema_version":None}])
def test_invalid_report_preserves_previous_export(tmp_path,patch):
    path=tmp_path/"review.sarif"
    path.write_bytes(b"previous")
    with pytest.raises(ValueError):
        export_sarif({**native(),**patch},path)
    assert path.read_bytes()==b"previous"


def test_refuses_native_destination_and_traversal(tmp_path):
    with pytest.raises(ValueError, match="destination"):
        export_sarif(native(),tmp_path/"report.json")
    with pytest.raises(ValueError,match="outside"):
        build_sarif(native(relative="../unrelated.py"))


def test_pinned_schema_identity():
    # Git may check text files out with platform-specific newlines.
    canonical=SCHEMA_FILE.read_bytes().replace(b"\r\n",b"\n")
    assert hashlib.sha256(canonical).hexdigest()=="2b19d2358baef0251d7d24e208d05ffabf1b2a3ab5e1b3a816066fc57fd4a7e8"
