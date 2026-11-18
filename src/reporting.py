"""Basic scanner evidence and optional AI enrichment, with explicit completion status."""
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from importlib.metadata import version, PackageNotFoundError

GUIDANCE = {
    "B307": "Avoid evaluating untrusted code. Use ast.literal_eval only when literal values are the intended input contract.",
    "insecure-eval": "Avoid evaluating untrusted code. Use a parser appropriate to the expected input language.",
    "B602": "Avoid shell interpretation of untrusted input. Use a fixed executable and validated argument list without a shell.",
    "B404": "Review subprocess calls for command injection; importing subprocess alone does not prove a vulnerability.",
    "B608": "Use parameterized queries for values; allowlist dynamic SQL identifiers.",
    "B501": "Enable TLS certificate verification and configure a trusted CA bundle.",
    "B301": "Do not deserialize untrusted pickle data; use a suitable data-only format and validate its structure.",
}


def save_json(path, data, api_key=None):
    text = json.dumps(data, indent=2)
    if api_key:
        text = text.replace(api_key, "[REDACTED]").replace(json.dumps(api_key)[1:-1], "[REDACTED]")
    path.write_text(text, encoding="utf-8")


def scanner_metadata(rules_file):
    info = {}
    for name in ("bandit", "semgrep"):
        try:
            installed = version(name)
        except PackageNotFoundError:
            installed = "not_installed"
        info[name] = {"version": installed}
    try:
        from bandit.core import extension_loader
        manager = extension_loader.MANAGER
        info["bandit"]["enabled_rules"] = sorted(set(manager.plugins_by_id) | set(manager.blacklist_by_id))
        info["bandit"]["profile"] = "default; source suppression comments may apply"
    except ImportError:
        info["bandit"]["enabled_rules"] = None
    try:
        import yaml
        files = sorted(rules_file.glob("*.yml")) if rules_file.is_dir() else [rules_file]
        content = b"".join(p.name.encode()+p.read_bytes() for p in files)
        info["semgrep"].update(
            enabled_rules=[rule["id"] for p in files for rule in yaml.safe_load(p.read_bytes())["rules"]],
            rules_file=str(rules_file), rules_sha256=hashlib.sha256(content).hexdigest())
    except (OSError, ValueError, KeyError, TypeError, ImportError):
        info["semgrep"]["enabled_rules"] = None
    return info


def ai_report(findings, api_key, reason, model):
    from src.llm_advisor import group_duplicate_findings, review_all_findings
    credential_status = reason
    groups = group_duplicate_findings(findings)
    results = []
    if not findings:
        status, reason = "skipped", "no_findings"
    elif not api_key:
        status = "skipped"
    else:
        results = review_all_findings(findings, api_key=api_key, model=model)
        failed = sum(r["status"] == "failed" for r in results)
        status = "failed" if failed == len(results) else "partial" if failed or len(groups) > len(results) else "completed"
        reason = "review_failures" if failed else "review_limit" if len(groups) > len(results) else "completed"
    reviewed = sum(r["status"] == "reviewed" for r in results)
    return {"provider": "gemini", "model": model, "status": status, "reason": reason, "credential_status": credential_status,
            "total_findings": len(findings), "unique_groups": len(groups), "limit": 5,
            "attempted": len(results), "reviewed": reviewed, "failed": len(results)-reviewed,
            "unattempted_groups": len(groups)-len(results), "results": results,
            "verification_status": "not_verified"}


def basic_report(target, results, findings, metadata, ai, scan_error=None):
    enriched = []
    for finding in findings:
        item = dict(finding)
        guidance = GUIDANCE.get(str(item["rule_id"]).split(".")[-1])
        if guidance:
            item["remediation_guidance"] = {"source": "predefined_rule_guidance", "text": guidance}
        enriched.append(item)
    fingerprint = results.get("bandit", {}).get("source_sha256")
    for name in metadata:
        metadata[name]["scan_status"] = "completed" if not scan_error else "not_confirmed"
    if scan_error and fingerprint is None:
        try:
            fingerprint = hashlib.sha256(target.read_bytes()).hexdigest()
        except OSError:
            pass
    return {"generated_at": datetime.now(timezone.utc).isoformat(),
            "file": {"path": str(target), "source_sha256": fingerprint, "fingerprint_verified_by_scan": not bool(scan_error)},
            "scan_status": "failed" if scan_error else "completed", "scan_error": scan_error,
            "scanners": metadata,
            "counts": {"total": len(findings), "by_scanner": dict(Counter(f["scanner"] for f in findings)),
                       "by_severity": dict(Counter(f["severity"] for f in findings))},
            "findings": enriched, "ai": ai,
            "mode": "ai_enhanced" if ai["reviewed"] else "basic",
            "verification_status": "not_verified"}
