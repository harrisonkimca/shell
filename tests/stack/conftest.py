"""Real supply-chain execution shared by the stack assertions; no skips."""

from pathlib import Path
from typing import Any

import pytest

from scripts import images


@pytest.fixture(scope="session")
def supply_chain(scanner_database: Path) -> dict[str, Any]:
    return images.run_pipeline(
        Path(__file__).resolve().parents[2], database=scanner_database
    )


@pytest.fixture(scope="session")
def scanner_database(tmp_path_factory: pytest.TempPathFactory) -> Path:
    # Per-run, never restored or persisted by Actions cache.
    return tmp_path_factory.mktemp("grype-database")


@pytest.fixture(scope="session")
def scanner_image() -> dict[str, Any]:
    # Existing linux/amd64 CPython rejection fixture, resolved to its child.
    # Scanner execution succeeds on this image before every database mutation.
    reference = (
        "docker.io/library/python@sha256:"
        "b0c5cb8792bf58879f532c1e10f44e1af02d72735758374198f9717d67a7ae52"
    )
    images.command("docker", "pull", "--platform", images.PLATFORM, reference)
    return images.local_identity(reference)
