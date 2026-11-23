"""Bind approval to the tested rule profile, fixtures, and Semgrep version."""
import hashlib
import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "standard"


def engine_version():
    try:
        return version("semgrep")
    except PackageNotFoundError:
        return None


PROFILES = ("basic", "standard", "deep")


def profile_root(profile):
    if profile not in PROFILES:
        raise ValueError("Unknown rule profile")
    return ROOT if profile == PROFILE else ROOT / "profiles" / profile


def profile_rules(profile=PROFILE):
    return sorted(p for p in (profile_root(profile) / "rules").rglob("*") if p.is_file() and p.suffix.lower() in (".yml", ".yaml"))


def bundle_digest(profile=PROFILE):
    fixtures = sorted((profile_root(profile) / "benchmarks/development").rglob("*.py"))
    digest = hashlib.sha256()
    for path in profile_rules(profile) + fixtures:
        digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def validation_state(profile=PROFILE):
    digest = bundle_digest(profile)
    engine = engine_version()
    try:
        saved = json.loads((profile_root(profile) / "rules/validation.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        saved = {}
    if not isinstance(saved, dict):
        saved = {}
    if saved.get("status") != "passed":
        reason = "Missing or unsuccessful annotated rule tests"
    elif saved.get("bundle_sha256") != digest:
        reason = "Rules or development fixtures changed since validation"
    elif saved.get("profile") != profile or not engine or saved.get("engine_version") != engine:
        reason = "Profile or Semgrep version differs from the validation record"
    else:
        return {**saved, "current_engine_version": engine}
    return {"status": "pending", "reason": reason, "bundle_sha256": digest, "profile": profile,
            "engine_version": saved.get("engine_version"), "current_engine_version": engine}


def active_config(state=None):
    if state is None:
        state = validation_state()
    return profile_root(state.get("profile", PROFILE)) / "rules" if state["status"] == "passed" else ROOT / "rules/code_execution.yml"
