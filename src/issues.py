"""Conservative equivalences and provenance-preserving counts."""
from collections import defaultdict
import hashlib
import json
import re
from .policy import LEVEL

CATEGORIES = {
    "B307":"unsafe_eval", "insecure-eval":"unsafe_eval",
    "B501":"tls_verification_disabled", "tls-verification-disabled":"tls_verification_disabled",
    "B602":"shell_execution", "request-shell-command":"shell_execution",
    "B608":"sql_construction", "request-sql-query":"sql_construction",
    "framework-shell":"shell_execution", "framework-sql":"sql_construction",
    "framework-url":"request_outbound_url", "framework-files":"request_file_access",
    "request-file-path":"request_file_access", "request-outbound-url":"request_outbound_url",
}


def logical_issues(findings):
    groups = defaultdict(list)
    for index, row in enumerate(findings):
        rule = row.get("rule_id","unknown").split(".")[-1]
        category = CATEGORIES.get(rule, row.get("scanner","unknown") + ":" + rule)
        key = (row.get("file"), row.get("source_sha256"), row.get("scope"),
               row.get("statement_sha256"), row.get("statement_line",row.get("line")), category)
        # Never collapse multiple same-tool hits at an ambiguous location.
        groups[key].append((index,row))
    issues = []
    for key, entries in groups.items():
        merge = (key[1] and key[3] and key[4] 
                 and not any(row.get("ambiguous_site") for _,row in entries))
        for group in ([entries] if merge else [[item] for item in entries]):
            evidence = [row for _,row in group]
            levels = [LEVEL.get(str(row.get("severity")).upper()) for row in evidence]
            severity = "UNKNOWN" if None in levels else ["UNKNOWN","LOW","MEDIUM","HIGH","CRITICAL"][max(levels)]
            identity = [key, None if merge else group[0][0]]
            issues.append({"issue_id":hashlib.sha256(json.dumps(identity).encode()).hexdigest(),
                           "category":key[-1],"normalized_severity":severity,"evidence":evidence})
    return issues


def canonical(name):
    return re.sub(r"[-_.]+","-",name).lower()


def deduplicate(rows):
    buckets = defaultdict(list)
    for row in rows:
        bucket = buckets[(canonical(row["package"]),row["version"])]
        ids = {row["advisory_id"], *row.get("aliases",[])}
        matches = [entry for entry in bucket if entry[0] & ids]
        evidence = [row]
        for entry in matches:
            ids.update(entry[0])
            evidence.extend(entry[1])
            bucket.remove(entry)
        bucket.append((ids,evidence))
    result=[]
    for (package,version), groups in buckets.items():
        for ids,evidence in groups:
            primary = sorted(ids,key=lambda i:(not i.startswith("CVE-"),i))[0]
            # Prefer the source ID for a single-source record.
            original_ids = {r["advisory_id"] for r in evidence}
            if len(original_ids)==1:
                primary=next(iter(original_ids))
            result.append({"package":package,"version":version,"advisory_id":primary,
                           "aliases":sorted(ids-{primary}), "fixed_versions":sorted({v for r in evidence for v in r.get("fixed_versions",[])}),
                           "evidence":evidence})
    return result
