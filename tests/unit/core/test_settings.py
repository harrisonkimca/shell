"""Development settings and server wiring (architecture sections 10/13)."""

from pathlib import Path
from unittest.mock import Mock

import pytest
from shell_api.core.settings import load_settings
from shell_api.main import serve


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    for key in ("SHELL_ENVIRONMENT", "SHELL_HOST", "SHELL_PORT"):
        monkeypatch.delenv(key, raising=False)


def test_development_dotenv_and_environment_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    Path(".env").write_text("SHELL_PORT=8123\nUNRELATED_SECRET=synthetic-secret\n")
    assert load_settings().port == 8123
    monkeypatch.setenv("SHELL_PORT", "8124")
    assert load_settings().port == 8124


@pytest.mark.parametrize("environment", ["production", "test"])
def test_dotenv_is_development_only(
    monkeypatch: pytest.MonkeyPatch, environment: str
) -> None:
    Path(".env").write_text("SHELL_PORT=invalid-sensitive-value\n")
    monkeypatch.setenv("SHELL_ENVIRONMENT", environment)
    assert load_settings().port == 8000


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("SHELL_PORT", "synthetic-secret"),
        ("SHELL_PORT", "0"),
        ("SHELL_PORT", "65536"),
        ("SHELL_HOST", "not-an-ip"),
        ("SHELL_ENVIRONMENT", "invalid-sensitive-value"),
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


def test_server_uses_factory_and_disables_proxy_trust(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = Mock()
    monkeypatch.setattr("shell_api.main.uvicorn.run", run)
    serve()
    run.assert_called_once_with(
        "shell_api.main:create_app",
        factory=True,
        host="127.0.0.1",
        port=8000,
        proxy_headers=False,
        server_header=False,
        access_log=False,
    )


def test_dotenv_cannot_select_environment() -> None:
    Path(".env").write_text("SHELL_ENVIRONMENT=production\nSHELL_PORT=8123\n")
    assert load_settings().environment == "development"
