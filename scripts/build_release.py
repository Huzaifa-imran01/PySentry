"""Create and inspect a source ZIP using only the selected Git commit."""
import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
from tempfile import TemporaryDirectory
import zipfile


# Apply the same policy to the selected revision, including revisions without release attributes.
OMIT = (
    ".git", ".venv", "venv", "env", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".cache", ".tox", ".nox", "node_modules", "*.egg-info",
    "reports", "dist", "build", "ci-results", "ci-tests.xml", "benchmarks/results",
    ".env", ".env.*", ".aws", ".ssh", ".netrc", "_netrc", ".pypirc", ".npmrc",
    "credentials.json", "id_rsa", "id_ed25519", "*.key", "*.p12", "*.pfx", "*.pem",
    "*.pyc", "*.pyo", "*.sarif", "*.sarif.json", ".coverage", ".coverage.*",
    "*.zip", "*.tar.gz", "*.exe", "*.log", "Thumbs.db", ".DS_Store",
)
CREDENTIAL = re.compile(
    rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----|"
    rb"\b(?:AIza[\w-]{35}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[A-Z0-9]{16})\b"
)


def excluded(name):
    parts = PurePosixPath(name.lower()).parts
    candidates = [*parts, *("/".join(pair) for pair in zip(parts, parts[1:]))]
    return any(fnmatch.fnmatchcase(value, pattern.lower()) for value in candidates for pattern in OMIT)


def git(repo, *args):
    # Archive blobs using Git's stored line endings. No local checkout is needed.
    return subprocess.run(["git", "-C", str(repo), "-c", "core.autocrlf=false", *args],
                          env={**os.environ, "TZ": "UTC"}, check=True, stdout=subprocess.PIPE).stdout


def tracked_files(repo, commit):
    files = {}
    omitted = []
    for record in git(repo, "ls-tree", "-rz", commit).split(b"\0"):
        if not record:
            continue
        metadata, path = record.split(b"\t", 1)
        mode, _, oid = metadata.decode("ascii").split()
        name = path.decode("utf-8")
        if excluded(name):
            omitted.append(name)
            continue
        if mode not in {"100644", "100755"} or "\\" in name or ":" in name or ".." in PurePosixPath(name).parts:
            raise ValueError(f"Unsupported source entry: {name}")
        files[name] = oid
    return files, omitted


def inspect(archive, files, commit):
    with zipfile.ZipFile(archive) as source:
        if source.comment.decode("ascii") != commit:
            raise ValueError("Archive revision differs from the selected commit")
        entries = [info for info in source.infolist() if not info.is_dir()]
        if len(entries) != len(files) or {item.filename for item in entries} != files.keys():
            raise ValueError("Archive file list differs from the reviewed Git tree")
        for entry in entries:
            data = source.read(entry)
            oid = files[entry.filename]
            digest = hashlib.new("sha1" if len(oid) == 40 else "sha256")
            digest.update(f"blob {len(data)}\0".encode())
            digest.update(data)
            if digest.hexdigest() != oid:
                raise ValueError(f"Archive content differs from the Git blob: {entry.filename}")
            if CREDENTIAL.search(data):
                raise ValueError(f"Possible credential in {entry.filename}. Review before release.")


def build_release(repo, revision, destination):
    if destination.suffix.lower() != ".zip":
        raise ValueError("Select a .zip output file")
    commit = git(repo, "rev-parse", "--verify", "--end-of-options", revision + "^{commit}").decode().strip()
    files, omitted = tracked_files(repo, commit)
    if not files:
        raise ValueError("Selected revision contains no releasable files")
    pathspecs = [spec for pattern in OMIT for spec in (
        f":(exclude,glob,icase)**/{pattern}", f":(exclude,glob,icase)**/{pattern}/**")]
    destination.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=destination.parent) as temporary:
        candidate = Path(temporary) / "source.zip"
        git(repo, "archive", "--format=zip", "-0", "-o", str(candidate.resolve()), commit, "--", ".", *pathspecs)
        inspect(candidate, files, commit)
        with candidate.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        os.replace(candidate, destination)
    return {"revision": commit, "files": len(files), "excluded_tracked_files": omitted,
            "sha256": digest, "archive": str(destination.resolve())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("revision", help="Commit, tag or branch to archive")
    parser.add_argument("output", type=Path, help="Output .zip path")
    args = parser.parse_args()
    try:
        result = build_release(Path(__file__).resolve().parents[1], args.revision, args.output)
    except (ValueError, OSError, zipfile.BadZipFile, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Release failed: {exc}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
