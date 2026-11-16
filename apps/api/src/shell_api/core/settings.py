"""Validated development/server settings; dotenv is development-only."""

import os
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Literal

from pydantic import Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "production"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SHELL_",
        extra="ignore",
        hide_input_in_errors=True,
    )

    env: Environment
    host: IPv4Address | IPv6Address = IPv4Address("127.0.0.1")
    port: int = Field(default=8000, ge=1, le=65535)


def load_settings() -> Settings:
    environment = os.environ.get("SHELL_ENV")
    if environment not in ("development", "production"):
        raise ValueError("Invalid Shell settings")
    # BaseSettings accepts dotenv overrides via **values at this typed boundary.
    values: dict[str, Any] = {
        "env": environment,
        "_env_file": ".env" if environment == "development" else None,
        "_env_file_encoding": "utf-8",
    }
    try:
        return Settings(**values)
    except ValidationError:
        raise ValueError("Invalid Shell settings") from None
