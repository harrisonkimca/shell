"""Exercise the configured tools, not replicas of their policies."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def run(*args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False)


@pytest.mark.parametrize(
    "tool,content",
    [("ruff", "import os\n"), ("pyright", "def broken(value):\n    return value\n")],
)
def test_tool_rejects_violation(tmp_path: Path, tool: str, content: str) -> None:
    target = tmp_path / "bad.py"
    target.write_text(content)
    args = (
        ("ruff", "check", "--config", str(ROOT / "pyproject.toml"))
        if tool == "ruff"
        else ("pyright", "--project", str(ROOT / "pyproject.toml"))
    )
    result = run(*args, str(target))
    assert result.returncode != 0
    assert "error" in result.stdout.lower() or "F401" in result.stdout


@pytest.fixture
def fixture_repo(tmp_path: Path) -> Path:
    shutil.copytree(ROOT / "apps/api/src/shell_api", tmp_path / "shell_api")
    shutil.copytree(
        tmp_path / "shell_api/contexts/identity",
        tmp_path / "shell_api/contexts/example",
    )
    (tmp_path / ".importlinter").write_text(
        (ROOT / ".importlinter")
        .read_text()
        .replace(
            "containers = \n    shell_api.shared\n    shell_api.contexts.identity",
            (
                "containers = \n    shell_api.shared\n    shell_api.contexts.identity\n"
                "    shell_api.contexts.example"
            ),
        )
    )
    shutil.copytree(ROOT / "scripts", tmp_path / "scripts")
    return tmp_path


def lint(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(Path(sys.executable).parent / "lint-imports"), "--no-cache"],
        cwd=root,
        env={**os.environ, "PYTHONPATH": str(root)},
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.mark.parametrize(
    "source,target",
    [
        ("shared.domain", "shell_api.shared.application"),
        ("shared.presentation", "shell_api.shared.infrastructure"),
        ("shared.infrastructure", "shell_api.shared.presentation"),
        ("shared.domain", "httpx"),
        ("shared.application", "shell_api.contexts.identity.infrastructure"),
        ("shared.infrastructure", "fastapi"),
        ("core", "sqlalchemy"),
        ("contexts.identity.infrastructure", "redis"),
        ("shared.infrastructure", "jwt"),
        ("contexts.identity.infrastructure", "jinja2"),
        ("shared.infrastructure", "shell_api.contexts.identity.infrastructure.idp.ory"),
        ("contexts.identity.presentation", "shell_api.contexts.example.domain"),
        ("shared.presentation", "shell_api.contexts.identity.application.api"),
        ("contexts.identity.presentation", "shell_api.core"),
    ],
)
def test_import_breach(fixture_repo: Path, source: str, target: str) -> None:
    path = fixture_repo / "shell_api" / Path(*source.split(".")) / "breach.py"
    path.write_text(f"import {target}\n")
    result = lint(fixture_repo)
    assert result.returncode != 0, result.stdout
    assert "BROKEN" in result.stdout, result.stdout + result.stderr


def test_permitted_imports(fixture_repo: Path) -> None:
    imports = {
        "main": "shell_api.core",
        "contexts.identity.presentation": "shell_api.contexts.example.application.api",
        "contexts.identity.infrastructure.idp": "jwt",
        "shared.infrastructure.email": "jinja2",
        "core": "redis",
    }
    for source, target in imports.items():
        path = fixture_repo / "shell_api" / Path(*source.split("."))
        if path.is_dir():
            path = path / "allowed.py"
        else:
            path = path.with_suffix(".py")
        path.write_text(f"import {target}\n")
    result = lint(fixture_repo)
    assert result.returncode == 0, result.stdout + result.stderr


def test_pure_core_rejects_indirect_external_import(fixture_repo: Path) -> None:
    (fixture_repo / "shell_api/contexts/identity/infrastructure/bridge.py").write_text(
        "import httpx\n"
    )
    (fixture_repo / "shell_api/contexts/identity/domain/breach.py").write_text(
        "import shell_api.contexts.identity.infrastructure.bridge\n"
    )
    result = lint(fixture_repo)
    assert "Pure core BROKEN" in result.stdout


def test_contexts_have_all_concrete_layers() -> None:
    import configparser

    config = configparser.ConfigParser()
    config.read(ROOT / ".importlinter")
    assert config["importlinter"]["include_external_packages"] == "True"
    containers = config["importlinter:contract:1"]["containers"].split()
    for context in (ROOT / "apps/api/src/shell_api/contexts").iterdir():
        if not context.is_dir() or context.name.startswith("_"):
            continue
        assert f"shell_api.contexts.{context.name}" in containers
        for layer in ("domain", "application", "infrastructure", "presentation"):
            assert (context / layer / "__init__.py").is_file()


def test_layers_allow_indirection_via_other_context_api(fixture_repo: Path) -> None:
    (fixture_repo / "shell_api/contexts/identity/application/allowed.py").write_text(
        "import shell_api.contexts.example.application.api\n"
    )
    (
        fixture_repo / "shell_api/contexts/example/application/api/__init__.py"
    ).write_text("import shell_api.contexts.identity.application.api\n")
    result = lint(fixture_repo)
    assert result.returncode == 0, result.stdout


@pytest.mark.parametrize("contract", ["1", "7"])
def test_direct_contracts_allow_indirect_paths(
    fixture_repo: Path, contract: str
) -> None:
    source = fixture_repo / "shell_api/contexts/identity/domain/allowed.py"
    source.write_text("import shell_api.bridge\n")
    target = (
        "shell_api.contexts.identity.presentation"
        if contract == "1"
        else "shell_api.contexts.example.domain"
    )
    (fixture_repo / "shell_api/bridge.py").write_text(f"import {target}\n")
    result = subprocess.run(
        [
            str(Path(sys.executable).parent / "lint-imports"),
            "--no-cache",
            "--contract",
            contract,
        ],
        cwd=fixture_repo,
        env={**os.environ, "PYTHONPATH": str(fixture_repo)},
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_tests_and_migrations_are_exempt(fixture_repo: Path) -> None:
    for folder in ("tests", "migrations"):
        directory = fixture_repo / folder
        directory.mkdir()
        (directory / "breach.py").write_text("import shell_api.core\nimport fastapi\n")
    result = lint(fixture_repo)
    assert result.returncode == 0, result.stdout
