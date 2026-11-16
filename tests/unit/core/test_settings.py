"""Development settings and server wiring (architecture sections 10/13)."""

from collections.abc import Callable
from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from shell_api.core.app import create_app
from shell_api.core.settings import load_settings
from shell_api.main import serve


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    for key in ("SHELL_ENV", "SHELL_ENVIRONMENT", "SHELL_HOST", "SHELL_PORT"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("SHELL_ENV", "development")


def test_development_dotenv_and_environment_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    Path(".env").write_text("SHELL_PORT=8123\nUNRELATED_SECRET=synthetic-secret\n")
    assert load_settings().port == 8123
    monkeypatch.setenv("SHELL_PORT", "8124")
    assert load_settings().port == 8124


@pytest.mark.parametrize("environment", ["production"])
def test_dotenv_is_development_only(
    monkeypatch: pytest.MonkeyPatch, environment: str
) -> None:
    Path(".env").write_text("SHELL_PORT=invalid-sensitive-value\n")
    monkeypatch.setenv("SHELL_ENV", environment)
    assert load_settings().port == 8000


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("SHELL_PORT", "synthetic-secret"),
        ("SHELL_PORT", "0"),
        ("SHELL_PORT", "65536"),
        ("SHELL_HOST", "not-an-ip"),
        ("SHELL_ENV", "invalid-sensitive-value"),
        ("SHELL_ENV", "test"),
        ("SHELL_ENV", ""),
    ],
)
def test_invalid_settings_fail_without_values(
    monkeypatch: pytest.MonkeyPatch,
    key: str,
    value: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(key, value)
    with pytest.raises(ValueError) as error:
        load_settings()
    assert str(error.value) == "Invalid Shell settings"
    assert capsys.readouterr() == ("", "")


def test_malformed_dotenv_fails_without_values() -> None:
    Path(".env").write_text("SHELL_PORT=synthetic-secret\n")
    with pytest.raises(ValueError, match="^Invalid Shell settings$"):
        load_settings()


def test_server_loads_settings_once_and_disables_proxy_trust(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = Mock()
    load = Mock(wraps=load_settings)
    monkeypatch.setattr("shell_api.main.uvicorn.run", run)
    monkeypatch.setattr("shell_api.main.load_settings", load)
    factory_load = Mock(side_effect=AssertionError("settings loaded twice"))
    monkeypatch.setattr("shell_api.core.app.load_settings", factory_load)
    serve()
    load.assert_called_once_with()
    factory_load.assert_not_called()
    app = run.call_args.args[0]
    assert isinstance(app, FastAPI)
    run.assert_called_once_with(
        app,
        host="127.0.0.1",
        port=8000,
        proxy_headers=False,
        server_header=False,
        access_log=False,
    )


def test_dotenv_cannot_override_environment() -> None:
    Path(".env").write_text("SHELL_ENV=production\nSHELL_PORT=8123\n")
    assert load_settings().env == "development"
    assert load_settings().port == 8123


@pytest.mark.parametrize("start", [load_settings, create_app, serve])
@pytest.mark.parametrize("environment", [None, "test", "invalid-sensitive-value"])
def test_environment_selection_is_required_before_dotenv(
    monkeypatch: pytest.MonkeyPatch,
    start: Callable[[], object],
    environment: str | None,
) -> None:
    monkeypatch.setattr(
        "shell_api.main.uvicorn.run",
        Mock(side_effect=AssertionError("server started before settings validation")),
    )
    monkeypatch.delenv("SHELL_ENV", raising=False)
    if environment is not None:
        monkeypatch.setenv("SHELL_ENV", environment)
    # Neither a dotenv value nor the old variable may select development.
    monkeypatch.setenv("SHELL_ENVIRONMENT", "development")
    Path(".env").write_text("SHELL_ENV=development\nSHELL_PORT=8123\n")
    read = Mock(side_effect=AssertionError("dotenv read before selection"))
    monkeypatch.setattr(
        "pydantic_settings.sources.providers.dotenv.DotEnvSettingsSource._read_env_files",
        read,
    )
    with pytest.raises(ValueError, match="^Invalid Shell settings$"):
        start()
    read.assert_not_called()
