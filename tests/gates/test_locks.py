"""NFR-011 dependency locks, including rejection fixtures."""

import shutil
from pathlib import Path

import pytest

from scripts.check import check_locks

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.req("NFR-011", kind="configuration check", part="dependency-locks")
def test_dependency_locks() -> None:
    check_locks(ROOT)


@pytest.mark.parametrize("mutation", ["missing", "stale", "hash"])
def test_invalid_locks(tmp_path: Path, mutation: str) -> None:
    for name in ("pyproject.toml", "uv.lock", ".python-version"):
        shutil.copy(ROOT / name, tmp_path / name)
    lock = tmp_path / "uv.lock"
    if mutation == "missing":
        lock.unlink()
    elif mutation == "stale":
        project = tmp_path / "pyproject.toml"
        project.write_text(project.read_text().replace("pytest==", "pytest==0."))
    else:
        import re

        lock.write_text(re.sub(r'hash = "sha256:[^"]+",? ', "", lock.read_text()))
    with pytest.raises((ValueError, RuntimeError)):
        check_locks(tmp_path)
