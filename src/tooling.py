import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


def pinned_tool(name, version):
    filename = name + (".exe" if os.name == "nt" else "")
    local = Path(sys.executable).parent / filename
    executable = str(local) if local.is_file() else shutil.which(filename)
    if not executable:
        raise RuntimeError(name + "_not_installed")
    proc = subprocess.run([executable, "version" if name == "gitleaks" else "--version"],
                          capture_output=True, timeout=10, text=True)
    first = proc.stdout.splitlines()[:1]
    if proc.returncode or not first or not re.fullmatch(r"(?:osv-scanner version: )?v?" + re.escape(version), first[0].strip()):
        raise RuntimeError(name + "_version_mismatch")
    return executable
