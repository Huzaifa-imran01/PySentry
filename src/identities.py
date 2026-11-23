"""Best-effort statement identities stable across line movement and staged paths."""
import ast
import hashlib
import io
import tokenize


def enrich_identity(finding, raw):
    encoding,_=tokenize.detect_encoding(io.BytesIO(raw).readline)
    tree=ast.parse(raw.decode(encoding))
    line=finding.get("line")
    if not isinstance(line,int): return
    nodes=[n for n in ast.walk(tree) if isinstance(n,ast.stmt) and n.lineno<=line<=n.end_lineno]
    if not nodes: return
    node=min(nodes,key=lambda n:n.end_lineno-n.lineno)
    scopes=[n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and n.lineno<=line<=n.end_lineno]
    scope=".".join(n.name for n in sorted(scopes,key=lambda n:n.lineno))
    dump=ast.dump(node,include_attributes=False)
    finding["statement_sha256"]=hashlib.sha256(dump.encode()).hexdigest()
    finding["statement_line"] = node.lineno
    finding["ambiguous_site"] = (sum(isinstance(n, ast.Call) for n in ast.walk(node)) > 1 or
                                 sum(n.lineno == node.lineno and n.end_lineno == node.end_lineno for n in nodes) > 1)
    finding["scope"]=scope
    finding["end_line"]=node.end_lineno
    finding["identity_precision"]="statement_and_scope; identical statements in the same scope may coincide"


def identity_counts(reports):
    from collections import Counter
    from src.findings import normalize_findings
    from pathlib import Path
    counts=Counter()
    for finding in normalize_findings(reports):
        try:
            enrich_identity(finding,Path(finding["file"]).read_bytes())
        except (OSError,ValueError,SyntaxError,TypeError):
            continue
        if "statement_sha256" in finding:
            counts[(finding["scanner"],finding["rule_id"],finding["scope"],finding["statement_sha256"])]+=1
    return counts
