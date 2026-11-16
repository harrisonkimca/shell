"""Real supply-chain execution shared by the stack assertions; no skips."""

from pathlib import Path
from typing import Any

import pytest

from scripts import images


@pytest.fixture(scope="session")
def supply_chain() -> dict[str, Any]:
    return images.run_pipeline(Path(__file__).resolve().parents[2])
