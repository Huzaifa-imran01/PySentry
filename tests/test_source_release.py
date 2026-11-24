import subprocess
import zipfile
from pathlib import Path

import pytest

from scripts.build_release import build_release


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=Release test",
                           "-c", "user.email=test@example.invalid", "-c", "core.autocrlf=false",
                           *args], check=True, capture_output=True).stdout.strip()


@pytest.fixture
def repository(tmp_path):
    repo = tmp_path / "checkout"
    repo.mkdir()
    git(repo, "init")
    tracked = {
        "src/scanner.py": "print('committed')\n",
        "README.md": "Install from a clean Python environment.\n",
        "tests/fixtures/sample.py": "pass\n",
        "rules/validation.json": "{}\n",
        "benchmarks/results/environment.json": "runtime metadata",
        "profiles/deep/benchmarks/results/holdout.json": "machine-specific data",
        "config/.env.local": "test",
        ".venv/bin/python": "test",
        "project/Reports/report.json": "test",
        "cache/__pycache__/info.pyc": "test",
    }
    for name, value in tracked.items():
        path = repo / name
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_bytes(value.encode())
    git(repo, "add", "-f", ".")
    git(repo, "commit", "-m", "Initial controlled fixture")
    return repo


def test_archive_reproduces_selected_commit(repository, tmp_path):
    commit = git(repository, "rev-parse", "HEAD").decode()
    (repository / "README.md").write_text("later revision")
    git(repository, "commit", "-am", "Second revision")
    (repository / "README.md").write_text("uncommitted")
    (repository / "untracked.py").write_text("pass")

    output = tmp_path / "source.zip"
    first = build_release(repository, commit, output)
    second = build_release(repository, "HEAD~1", tmp_path / "second.zip")
    assert first["sha256"] == second["sha256"] and first["revision"] == commit
    assert len(first["excluded_tracked_files"]) == 6
    with zipfile.ZipFile(output) as archive:
        assert {i.filename for i in archive.infolist() if not i.is_dir()} == {
            "src/scanner.py", "README.md", "tests/fixtures/sample.py", "rules/validation.json",
        }
        assert archive.read("README.md").startswith(b"Install from a clean")


def test_archive_rejects_credential_without_echo_or_replacing_output(repository, tmp_path):
    marker = "AIza" + "X" * 35
    (repository / "README.md").write_text(marker)
    git(repository, "commit", "-am", "Synthetic credential")
    dest = tmp_path / "source.zip"
    dest.write_bytes(b"previous release")
    with pytest.raises(ValueError, match="Possible credential in README.md") as error:
        build_release(repository, "HEAD", dest)
    assert marker not in str(error.value)
    assert dest.read_bytes() == b"previous release"


def test_unexpected_export_omission_fails_inspection(repository, tmp_path):
    (repository / ".gitattributes").write_text("src export-ignore\n")
    git(repository, "add", ".gitattributes")
    git(repository, "commit", "-m", "Unexpected archive attribute")
    with pytest.raises(ValueError, match="file list differs"):
        build_release(repository, "HEAD", tmp_path / "bad.zip")
