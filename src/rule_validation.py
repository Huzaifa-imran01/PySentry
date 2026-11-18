"""New rules become active only after real Semgrep annotated tests pass."""
import hashlib
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def bundle_digest():
    files=sorted((ROOT/"rules").glob("*.yml"))+sorted((ROOT/"benchmarks/development").glob("*.py"))
    return hashlib.sha256(b"".join(str(p.relative_to(ROOT)).encode()+p.read_bytes() for p in files)).hexdigest()


def validation_state():
    try:
        state=json.loads((ROOT/"rules/validation.json").read_text())
        if state.get("status")=="passed" and state.get("bundle_sha256")==bundle_digest():
            return state
    except (OSError,ValueError): pass
    return {"status":"pending", "reason":"New rule bundle requires real Semgrep annotated test validation", "bundle_sha256":bundle_digest()}


def active_config():
    return ROOT/"rules" if validation_state()["status"]=="passed" else ROOT/"rules/code_execution.yml"
