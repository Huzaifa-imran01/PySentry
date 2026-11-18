
import ast
import hashlib
import tempfile
from collections import Counter
from src.scanner import scan_file
from contextlib import contextmanager
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def stage_candidate(
    source_path,
    function_name,
    replacement_code,
    expected_sha256,
):
    """Stage a replacement in a temporary file without executing it."""

    source = Path(source_path).resolve()
    trusted_dir = (ROOT / "tests" / "fixtures").resolve()

    # Day 6: Only work on our trusted test fixtures.
    if not source.is_relative_to(trusted_dir):
        raise ValueError("Source is outside trusted fixtures")

    if not source.is_file() or source.suffix != ".py":
        raise ValueError("Source must be an existing Python file")

    original_bytes = source.read_bytes()
    actual_hash = hashlib.sha256(original_bytes).hexdigest()

    if not expected_sha256 or actual_hash != expected_sha256:
        raise ValueError("Source fingerprint mismatch")

    original_text = original_bytes.decode("utf-8")

    try:
        original_tree = ast.parse(original_text)
        replacement_tree = ast.parse(replacement_code)
    except (SyntaxError, TypeError) as exc:
        raise ValueError("Invalid Python syntax") from exc

    # The proposed replacement must be one complete function.
    if (
        len(replacement_tree.body) != 1
        or not isinstance(replacement_tree.body[0], ast.FunctionDef)
        or replacement_tree.body[0].name != function_name
        or replacement_tree.body[0].decorator_list
    ):
        raise ValueError(
            "Replacement must contain exactly one matching function"
        )

    # Find the original top-level function.
    matches = [
        node
        for node in original_tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == function_name
    ]

    if len(matches) != 1 or matches[0].decorator_list:
        raise ValueError(
            "Expected exactly one undecorated target function"
        )

    target = matches[0]

    lines = original_text.splitlines(keepends=True)

    replacement = replacement_code.rstrip() + "\n"

    updated_text = (
        "".join(lines[:target.lineno - 1])
        + replacement
        + "".join(lines[target.end_lineno:])
    )

    try:
        ast.parse(updated_text)
    except SyntaxError as exc:
        raise ValueError(
            "Combined source has invalid Python syntax"
        ) from exc

    # TemporaryDirectory cleans up after the context exits.
    with tempfile.TemporaryDirectory(
        prefix="secure-review-"
    ) as directory:
        candidate_path = Path(directory) / source.name

        candidate_path.write_text(
            updated_text,
            encoding="utf-8",
        )

        yield candidate_path


def count_security_findings(reports):
    """Count scanner findings by scanner name and rule ID."""

    counts = Counter()

    for issue in reports["bandit"]["results"]:
        counts[("bandit", issue["test_id"])] += 1

    for issue in reports["semgrep"]["results"]:
        counts[("semgrep", issue["check_id"])] += 1

    return counts


def compare_security_reports(
    original_reports,
    candidate_reports,
    targeted_findings,
):
    """Compare scanner findings before and after a proposed fix."""

    before = count_security_findings(original_reports)
    after = count_security_findings(candidate_reports)

    targets = {
        (finding["scanner"], finding["rule_id"])
        for finding in targeted_findings
    }

    if not targets:
        raise ValueError("No target findings provided")

    missing_targets = [
        key for key in targets
        if before[key] == 0
    ]

    # Detect newly introduced or increased findings.
    regressions = {
        f"{scanner}:{rule}": count - before[(scanner, rule)]
        for (scanner, rule), count in after.items()
        if count > before[(scanner, rule)]
    }

    targets_reduced = all(
        after[key] < before[key]
        for key in targets
    )

    if missing_targets:
        status = "inconclusive"
    elif regressions:
        status = "regression_detected"
    elif targets_reduced:
        status = "scanner_reduction_unverified"
    else:
        status = "target_not_reduced"

    return {
        "status": status,
        "target_rules": [
            f"{scanner}:{rule}"
            for scanner, rule in sorted(targets)
        ],
        "original_findings": sum(before.values()),
        "candidate_findings": sum(after.values()),
        "targets_reduced": targets_reduced,
        "new_or_increased_findings": regressions,
        "behavior_verified": False,
    }


def rescan_candidate(
    source_path,
    function_name,
    replacement_code,
    expected_sha256,
    targeted_findings,
):
    """Stage a candidate, scan both versions, and compare."""

    with stage_candidate(
        source_path,
        function_name,
        replacement_code,
        expected_sha256,
    ) as candidate_path:

        print("Scanning original source...")
        original_reports = scan_file(source_path)

        print("Scanning staged candidate...")
        candidate_reports = scan_file(candidate_path)

        if original_reports["bandit"].get("source_sha256") != expected_sha256:
            raise ValueError("Baseline changed since candidate staging")
        comparison = compare_security_reports(original_reports, candidate_reports, targeted_findings)
        from src.identities import identity_counts, enrich_identity
        before_sites = identity_counts(original_reports)
        after_sites = identity_counts(candidate_reports)
        target_sites = []
        for finding in targeted_findings:
            enriched = dict(finding)
            if "line" in enriched:
                enrich_identity(enriched, Path(source_path).read_bytes())
                if "statement_sha256" in enriched:
                    target_sites.append((enriched["scanner"],enriched["rule_id"],enriched["scope"],enriched["statement_sha256"]))
        comparison["identity_comparison"] = {
            "precision":"statement_and_scope" if len(target_sites)==len(targeted_findings) else "rule_counts_only_or_partial",
            "targets_located":len(target_sites),
            "target_sites_reduced":all(after_sites[k]<before_sites[k] for k in target_sites) if target_sites else None,
            "new_statement_findings":sum((after_sites-before_sites).values()),
            "limitation":"Statement edits change identity; identical statements in one scope can coincide."}
        if target_sites and any(before_sites[k]==0 for k in target_sites):
            comparison["status"]="inconclusive"
        elif target_sites and not all(after_sites[k]<before_sites[k] for k in target_sites):
            comparison["status"]="target_not_reduced"
        elif after_sites-before_sites:
            comparison["status"]="regression_detected"

    # Temporary candidate has now been cleaned up.
    return comparison
