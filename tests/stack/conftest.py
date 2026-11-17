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
