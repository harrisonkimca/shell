"""Exercise the configured tools, not replicas of their policies."""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from scripts import check

ROOT = Path(__file__).resolve().parents[2]


def run(*args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False)


@pytest.fixture
def commands(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    captured: list[list[str]] = []

    def record(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        captured.append(command)
        return subprocess.CompletedProcess(command, 0)

    def ignore_locks(root: Path) -> None:
        pass

    with monkeypatch.context() as patch:
        patch.setattr(check, "check_locks", ignore_locks)
        patch.setattr(check.subprocess, "run", record)
        check.main()
    return captured


def test_required_quality_commands(commands: list[list[str]]) -> None:
    for required in (
        ["ruff", "check", "."],
        ["ruff", "format", "--check", "."],
        ["pyright"],
        ["lint-imports"],
    ):
        assert required in commands


@pytest.mark.parametrize(
    "tool,content,diagnostic",
    [
        ("ruff", "import os\n", "F401"),
        (
            "pyright",
            "def broken(value):\n    return value\n",
            "reportMissingParameterType",
        ),
    ],
)
def test_tool_rejects_violation(
    tmp_path: Path, commands: list[list[str]], tool: str, content: str, diagnostic: str
) -> None:
    shutil.copy(ROOT / "pyproject.toml", tmp_path / "pyproject.toml")
    target = tmp_path / "apps/api/src/bad.py"
    target.parent.mkdir(parents=True)
    target.write_text(content)
    command = next(c for c in commands if c[0] == tool)
    result = run(*command, cwd=tmp_path)
    assert result.returncode != 0
    assert diagnostic in result.stdout, result.stdout + result.stderr


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
            "containers =\n    shell_api.shared\n    shell_api.contexts.identity",
            (
                "containers =\n    shell_api.shared\n    shell_api.contexts.identity\n"
                "    shell_api.contexts.example"
            ),
        )
    )
    shutil.copytree(ROOT / "scripts", tmp_path / "scripts")
    return tmp_path


def lint(root: Path, commands: list[list[str]]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*next(c for c in commands if c[0] == "lint-imports"), "--no-cache"],
        cwd=root,
        env={**os.environ, "PYTHONPATH": str(root)},
        text=True,
        capture_output=True,
        check=False,
    )


# Architecture §14 is the independent policy oracle; do not derive expected
# forbidden entries from the configuration being tested.
PURE = (
    "fastapi",
    "starlette",
    "pydantic",
    "pydantic_settings",
    "sqlalchemy",
    "asyncpg",
    "alembic",
    "redis",
    "arq",
    "httpx",
    "authlib",
    "jwt",
    "jinja2",
    "babel",
)
PACKAGES = (
    "shared",
    *(
        f"contexts.{path.name}"
        for path in sorted((ROOT / "apps/api/src/shell_api/contexts").iterdir())
        if path.is_dir() and not path.name.startswith("_")
    ),
    "contexts.example",
)
BREACHES = (
    [
        ("Layers", f"{package}.{source}", f"shell_api.{package}.{target}")
        for package in PACKAGES
        for source, target in (
            ("domain", "application"),
            ("domain", "infrastructure"),
            ("domain", "presentation"),
            ("application", "infrastructure"),
            ("application", "presentation"),
            ("presentation", "infrastructure"),
            ("infrastructure", "presentation"),
        )
    ]
    + [
        ("Pure core", f"{package}.{layer}", target)
        for package in PACKAGES
        for layer in ("domain", "application")
        for target in PURE
    ]
    + [
        ("Web", "contexts.identity.application", target)
        for target in ("fastapi", "starlette", "pydantic")
    ]
    + [("Persistence", "core", target) for target in ("sqlalchemy", "asyncpg")]
    + [
        ("Persistence", "contexts.identity.infrastructure", target)
        for target in ("redis", "arq")
    ]
    + [
        ("Libraries", "core", target)
        for target in ("authlib", "jwt", "httpx", "jinja2", "babel")
    ]
    + [
        (
            "Vendor code",
            "contexts.identity.infrastructure",
            "shell_api.contexts.identity.infrastructure.idp.ory",
        ),
        (
            "Vendor code",
            "contexts.identity.presentation",
            "shell_api.contexts.identity.presentation.ory",
        ),
        (
            "Contexts",
            "contexts.identity.presentation",
            "shell_api.contexts.example.domain",
        ),
        (
            "Contexts",
            "contexts.example.infrastructure",
            "shell_api.contexts.identity.infrastructure",
        ),
        (
            "Shared",
            "shared.presentation",
            "shell_api.contexts.identity.application.api",
        ),
        ("Shared", "shared.presentation", "shell_api.core"),
        ("Composition root", "contexts.identity.presentation", "shell_api.core"),
    ]
)


def write_import(root: Path, source: str, target: str) -> None:
    path = root / "shell_api" / Path(*source.split("."))
    if path.is_dir():
        path = path / "probe.py"
    else:
        path = path.with_suffix(".py")
    path.write_text(f"import {target}\n")


@pytest.mark.parametrize("contract,source,target", BREACHES)
def test_import_breach(
    fixture_repo: Path,
    commands: list[list[str]],
    contract: str,
    source: str,
    target: str,
) -> None:
    write_import(fixture_repo, source, target)
    result = lint(fixture_repo, commands)
    assert result.returncode != 0, result.stdout
    assert f"{contract} BROKEN" in result.stdout, result.stdout + result.stderr
    if contract == "Vendor code":
        assert "1 broken" in result.stdout, result.stdout


def test_permitted_imports(fixture_repo: Path, commands: list[list[str]]) -> None:
    imports = {
        "main": "shell_api.core",
        "contexts.identity.presentation": "shell_api.contexts.example.application.api",
        "contexts.identity.infrastructure.idp": "jwt",
        "shared.infrastructure.email": "jinja2",
        "core": "redis",
        "core.a": "shell_api.core.b",
        "contexts.identity.infrastructure.idp.ory.a": (
            "shell_api.contexts.identity.infrastructure.idp.ory.b"
        ),
        "contexts.identity.presentation.ory.a": (
            "shell_api.contexts.identity.presentation.ory.b"
        ),
    }
    for folder in (
        "core",
        "contexts/identity/infrastructure/idp/ory",
        "contexts/identity/presentation/ory",
    ):
        (fixture_repo / "shell_api" / folder / "b.py").touch()
    for source, target in imports.items():
        path = fixture_repo / "shell_api" / Path(*source.split("."))
        if path.is_dir():
            path = path / "allowed.py"
        else:
            path = path.with_suffix(".py")
        path.write_text(f"import {target}\n")
    result = lint(fixture_repo, commands)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("target", PURE)
def test_pure_core_rejects_indirect_external_import(
    fixture_repo: Path, commands: list[list[str]], target: str
) -> None:
    (fixture_repo / "shell_api/contexts/identity/infrastructure/bridge.py").write_text(
        f"import {target}\n"
    )
    (fixture_repo / "shell_api/contexts/identity/domain/breach.py").write_text(
        "import shell_api.contexts.identity.infrastructure.bridge\n"
    )
    result = lint(fixture_repo, commands)
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


def test_layers_allow_indirection_via_other_context_api(
    fixture_repo: Path, commands: list[list[str]]
) -> None:
    (fixture_repo / "shell_api/contexts/identity/application/allowed.py").write_text(
        "import shell_api.contexts.example.application.api\n"
    )
    (
        fixture_repo / "shell_api/contexts/example/application/api/__init__.py"
    ).write_text("import shell_api.contexts.identity.application.api\n")
    result = lint(fixture_repo, commands)
    assert result.returncode == 0, result.stdout


@pytest.mark.parametrize(
    "contract,source,target",
    [
        ("1", "contexts.identity.domain", "shell_api.contexts.identity.presentation"),
        ("3", "contexts.identity.infrastructure", "fastapi"),
        ("4", "contexts.identity.presentation", "sqlalchemy"),
        ("5", "contexts.identity.presentation", "jwt"),
        (
            "6",
            "contexts.identity.presentation",
            "shell_api.contexts.identity.infrastructure.idp.ory",
        ),
        ("7", "contexts.identity.domain", "shell_api.contexts.example.domain"),
        ("8", "shared.presentation", "shell_api.contexts.identity.domain"),
        ("9", "contexts.identity.presentation", "shell_api.core"),
    ],
)
def test_direct_contracts_allow_indirect_paths(
    fixture_repo: Path,
    commands: list[list[str]],
    contract: str,
    source: str,
    target: str,
) -> None:
    # The intermediate module must itself be a permitted caller for this rule.
    bridge = {
        "3": "contexts.identity.presentation.bridge",
        "4": "contexts.identity.infrastructure.bridge",
        "5": "contexts.identity.infrastructure.idp.bridge",
        "6": "core.bridge",
        "9": "main",
    }.get(contract, "bridge")
    write_import(fixture_repo, source, f"shell_api.{bridge}")
    write_import(fixture_repo, bridge, target)
    result = subprocess.run(
        [
            *next(c for c in commands if c[0] == "lint-imports"),
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


def test_tests_and_migrations_are_exempt(
    fixture_repo: Path, commands: list[list[str]]
) -> None:
    import configparser

    config = configparser.ConfigParser()
    config.read(ROOT / ".importlinter")
    assert config["importlinter"]["root_package"] == "shell_api"
    package = ROOT / "apps/api/src/shell_api"
    for exempt in (ROOT / "tests", ROOT / "apps/api/migrations"):
        assert not exempt.is_relative_to(package)
    assert not (package / "tests").exists()
    assert not (package / "migrations").exists()
    for folder in ("tests", "apps/api/migrations"):
        directory = fixture_repo / folder
        directory.mkdir(parents=True)
        (directory / "breach.py").write_text("import shell_api.core\nimport fastapi\n")
    result = lint(fixture_repo, commands)
    assert result.returncode == 0, result.stdout


def test_layers_use_configured_order(
    fixture_repo: Path, commands: list[list[str]]
) -> None:
    config = fixture_repo / ".importlinter"
    config.write_text(
        config.read_text().replace(
            "    application\n    domain", "    domain\n    application"
        )
    )
    write_import(
        fixture_repo,
        "contexts.identity.application",
        "shell_api.contexts.identity.domain",
    )
    result = lint(fixture_repo, commands)
    assert "Layers BROKEN" in result.stdout, result.stdout


PERMITTED = (
    [
        (f"{package}.{source}", f"shell_api.{package}.{target}")
        for package in PACKAGES
        for source, target in (
            ("presentation", "application"),
            ("presentation", "domain"),
            ("infrastructure", "application"),
            ("infrastructure", "domain"),
            ("application", "domain"),
        )
    ]
    + [
        (f"{package}.presentation", target)
        for package in PACKAGES
        for target in ("fastapi", "starlette", "pydantic")
    ]
    + [
        (f"{package}.infrastructure", target)
        for package in PACKAGES
        for target in ("pydantic", "sqlalchemy", "asyncpg", "httpx")
    ]
    + [
        ("core", target)
        for target in ("fastapi", "starlette", "pydantic", "redis", "arq")
    ]
    + [("shared.infrastructure", target) for target in ("redis", "arq")]
    + [
        ("contexts.identity.infrastructure.idp", target)
        for target in ("authlib", "jwt")
    ]
    + [("shared.infrastructure.email", target) for target in ("jinja2", "babel")]
    + [
        ("core", "shell_api.contexts.identity.infrastructure.idp.ory"),
        ("core", "shell_api.contexts.identity.presentation.ory"),
        ("worker", "shell_api.core"),
        ("core", "shell_api.core"),
    ]
)


@pytest.mark.parametrize("source,target", PERMITTED)
def test_permitted_architecture_edges(
    fixture_repo: Path, commands: list[list[str]], source: str, target: str
) -> None:
    write_import(fixture_repo, source, target)
    result = lint(fixture_repo, commands)
    assert result.returncode == 0, result.stdout + result.stderr


def test_type_checking_imports_obey_boundaries(
    fixture_repo: Path, commands: list[list[str]]
) -> None:
    (fixture_repo / "shell_api/shared/domain/probe.py").write_text(
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import sqlalchemy\n"
    )
    result = lint(fixture_repo, commands)
    assert "Pure core BROKEN" in result.stdout, result.stdout
