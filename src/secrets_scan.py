"""Gitleaks results are consumed in memory. Persist only allowlisted fields."""
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tokenize
from .tooling import pinned_tool

CONFIG = Path(__file__).resolve().parents[1] / "config"
VERSION = "8.24.3"
TOKEN = re.compile(r"(?i)\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{20,}|AIza[\w-]{30,}|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9_-]{16,})")
ASSIGN = re.compile(r"""(?i)((?:password|passwd|secret|token|api[_-]?key|authorization)['"]?\s*[:=]\s*)(["'])(.*?)\2""")
QUOTED = re.compile(r"""(['"])(?:\\.|(?!\1).)*\1""")
PRIVATE = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|\Z)", re.S)


def scrub(text):
    text = TOKEN.sub("<credential>", PRIVATE.sub("<private-key>", text))
    return ASSIGN.sub(lambda m: m[1] + m[2] + "<credential>" + m[2], text)


def message(text):
    return QUOTED.sub("<literal>", scrub(text))


def cloud_context(context):
    # Strip source line numbers before tokenizing; incomplete snippets fail closed.
    lines = [re.sub(r"^\d+: ", "", line) for line in context.splitlines()]
    tokens = []
    try:
        for item in tokenize.generate_tokens(io.StringIO("\n".join(lines)).readline):
            kind = tokenize.tok_name[item.type]
            if kind.startswith("FSTRING") or item.type == tokenize.ERRORTOKEN and item.string.strip():
                raise ValueError
            value = item.string
            if kind == "STRING":
                value = '"<credential>"' if re.search(r"(?i)password|secret|token|api.?key",item.line[:item.start[1]]) else '"<string-literal>"'
            elif kind == "COMMENT":
                value = "# <comment>"
            elif kind == "NUMBER":
                value = "0"
            tokens.append(item._replace(string=value))
        return scrub(tokenize.untokenize(tokens))
    except (SyntaxError, tokenize.TokenError, ValueError):
        raise ValueError("cloud_context_redaction_incomplete") from None


def command_args(executable):
    return [executable, "--config", str(CONFIG/"gitleaks.toml"), "--ignore-gitleaks-allow",
            "--gitleaks-ignore-path", str(CONFIG/"empty.ignore"), "--redact=100",
            "--no-banner", "--report-format=json", "--report-path=-", "--exit-code=10"]


def detect(target, history=False, timeout=120):
    target = Path(target).resolve()
    report = {"status":"completed", "tool":"gitleaks", "version":VERSION, "findings":[], "scopes":{},
              "config_sha256":hashlib.sha256((CONFIG/"gitleaks.toml").read_bytes()).hexdigest()}
    scopes = ["directory", "history"] if history else ["directory"]
    for scope in scopes:
        try:
            executable = pinned_tool("gitleaks", VERSION)
            if not target.exists() or scope == "history" and not (target/".git").exists():
                raise RuntimeError("missing_target_or_git_root")
            args = command_args(executable) + (["git", "--log-opts=--all"] if scope=="history" else ["dir"])
            proc = subprocess.run([*args, str(target)], cwd=CONFIG, capture_output=True, timeout=timeout)
            if proc.returncode not in (0,10):
                raise RuntimeError("gitleaks_execution_failed")
            rows = json.loads(proc.stdout)
            if not isinstance(rows,list) or bool(rows) != (proc.returncode == 10):
                raise ValueError
            for row in rows:
                detector = row["RuleID"]
                path = Path(row["File"])
                base = target if target.is_dir() else target.parent
                if path.is_absolute():
                    path = path.relative_to(base)
                if ".." in path.parts or not re.fullmatch(r"[a-zA-Z0-9_-]+", detector):
                    raise ValueError
                line = row["StartLine"]
                if type(line) is not int or line < 1:
                    raise ValueError
                commit = row.get("Commit","")
                if commit and not re.fullmatch(r"[a-fA-F0-9]{40,64}",commit):
                    raise ValueError
                identity = json.dumps([scope, path.as_posix(), detector, line, row.get("Commit",""),row.get("StartColumn")])
                report["findings"].append({"scope":scope,"detector":detector,"file":scrub(path.as_posix()),
                    "line":line,"description":"Potential credential (value withheld)",
                    "commit":commit or None,"fingerprint":hashlib.sha256(identity.encode()).hexdigest()})
            report["scopes"][scope] = "completed"
        except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
            report["scopes"][scope] = str(exc) if type(exc) is RuntimeError else "gitleaks_incomplete"
    states = list(report["scopes"].values())
    if any(s != "completed" for s in states):
        report["status"] = "partial" if "completed" in states else "failed"
    return report


def screen_prompt(prompt):
    try:
        proc = subprocess.run(command_args(pinned_tool("gitleaks", VERSION)) + ["stdin"],
                              cwd=CONFIG, input=prompt.encode(), capture_output=True, timeout=15)
        if proc.returncode != 0 or json.loads(proc.stdout) != []:
            raise ValueError
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired):
        raise ValueError("cloud_context_redaction_incomplete") from None

def safe_fields(value, field=""):
    """Strip scanner source payloads before writing any artifact, including temporary JSON."""
    if isinstance(value, list):
        return [safe_fields(item, field) for item in value]
    if isinstance(value, dict):
        withheld = {"code", "lines", "metavars", "dataflow_trace", "Secret", "Match"}
        cleaned = {k: safe_fields(v, k) for k, v in value.items() if k not in withheld}
        if value.get("test_id",value.get("rule_id")) in ("B105","B106","B107"):
            for key in ("message","issue_text"):
                if key in cleaned:
                    cleaned[key] = "Possible hardcoded password (credential withheld)"
        return cleaned
    if isinstance(value, str):
        return message(value) if field in {"message", "issue_text"} else scrub(value)
    return value
