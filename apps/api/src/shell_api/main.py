"""API factory and Uvicorn entry point: python -m shell_api.main."""

import uvicorn

from shell_api.core.app import create_app
from shell_api.core.settings import load_settings

__all__ = ["create_app"]


def serve() -> None:
    settings = load_settings()
    uvicorn.run(
        "shell_api.main:create_app",
        factory=True,
        host=str(settings.host),
        port=settings.port,
        proxy_headers=False,
        server_header=False,
        access_log=False,
    )


if __name__ == "__main__":
    serve()
