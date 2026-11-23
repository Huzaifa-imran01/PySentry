"""Bounded, metadata-only discovery. Group overlapping inputs by directory."""
from collections import defaultdict
import os
from pathlib import Path

LOCKS=("pylock.toml","uv.lock","poetry.lock","Pipfile.lock","pdm.lock")
EXCLUDE={".git",".venv","venv","env","__pycache__",".tox",".pytest_cache","node_modules","build","dist","reports",
         ".cache",".mypy_cache",".ruff_cache",".nox",".eggs","__pypackages__"}


def is_pylock(path):
    return path.name == "pylock.toml" or path.match("pylock.*.toml")


def subproject(path, root):
    if path.suffix==".txt" and path.parent.name=="requirements" and path.parent!=root:
        return path.parent.parent
    return path.parent


def discover(root, limit=10000, max_bytes=8_000_000):
    selected, ignored, errors = [], [], []
    groups=defaultdict(list)
    count=0
    for directory, dirs, names in os.walk(root,onerror=lambda _:errors.append("directory_unreadable")):
        parent=Path(directory)
        dirs[:]=sorted(d for d in dirs if d.lower() not in EXCLUDE and not (parent/d).is_symlink()
                       and not (parent/d).is_junction())
        count+=len(names)+len(dirs)
        if count>limit:
            errors.append("discovery_limit")
            break
        inputs=[parent/n for n in sorted(names) if n in (*LOCKS,"pyproject.toml") or is_pylock(parent/n)
                or ((n.startswith("requirements") or parent.name=="requirements") and n.endswith(".txt") and n!="requirements-agent.txt")]
        for path in inputs:
            try:
                if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root) or path.stat().st_size>max_bytes:
                    errors.append(f"excluded_manifest: {path}")
                else:
                    groups[subproject(path,root)].append(path)
            except OSError:
                errors.append(f"unreadable_manifest: {path}")
    for safe in groups.values():
        pylocks=[p for p in safe if is_pylock(p)]
        locks=sorted((p for p in safe if p.name in LOCKS),key=lambda p:LOCKS.index(p.name))
        requirements=[p for p in safe if p.name.endswith(".txt")]
        chosen=pylocks or locks[:1] or requirements or safe
        selected.extend(chosen)
        ignored.extend(str(p) for p in safe if p not in chosen)
    return selected, ignored, errors
