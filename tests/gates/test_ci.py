"""Workflow aggregate enforcement (AGENTS.md, approved slice 1)."""

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.check_ci import validate

ROOT = Path(__file__).resolve().parents[2]


def workflow() -> dict[str, Any]:
    return yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())


def test_actual_workflow() -> None:
    validate(workflow())


@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", None])
def test_unsuccessful_or_missing_result(result: str | None) -> None:
    with pytest.raises(ValueError):
        validate(workflow(), {"quality": {"result": result}})


def test_successful_results() -> None:
    validate(workflow(), {"quality": {"result": "success"}})


@pytest.mark.parametrize("mutation", ["dependency", "new-job", "pin", "filter"])
def test_invalid_workflow(mutation: str) -> None:
    data = deepcopy(workflow())
    if mutation == "dependency":
        data["jobs"]["ci"]["needs"] = []
    elif mutation == "new-job":
        data["jobs"]["extra"] = {
            "runs-on": "ubuntu-latest",
            "steps": [{"run": "false"}],
        }
    elif mutation == "pin":
        data["jobs"]["quality"]["steps"][0]["uses"] = "actions/checkout@v4"
    else:
        data["on"]["push"] = {"paths": ["apps/**"]}
    with pytest.raises(ValueError):
        validate(data)


@pytest.mark.parametrize("results", [{}, {"extra": {"result": "success"}}])
def test_missing_required_results(results: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        validate(workflow(), results)


def test_aggregate_always_runs() -> None:
    data = workflow()
    data["jobs"]["ci"].pop("if")
    with pytest.raises(ValueError):
        validate(data)
