"""Validated development/server settings; dotenv is development-only."""

import os
from ipaddress import IPv4Address, IPv6Address
from typing import Literal, cast

from pydantic import Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "production"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SHELL_",
        extra="ignore",
        hide_input_in_errors=True,
    )

    environment: Environment = "development"
    host: IPv4Address | IPv6Address = IPv4Address("127.0.0.1")
    port: int = Field(default=8000, ge=1, le=65535)


class DevelopmentSettings(Settings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


def load_settings() -> Settings:
    environment = os.environ.get("SHELL_ENVIRONMENT", "development")
    try:
        settings_class = (
            DevelopmentSettings if environment == "development" else Settings
        )
        return settings_class(
            environment=cast(Environment, environment),
        )
    except ValidationError:
        raise ValueError("Invalid Shell settings") from None
