"""Validate aggregate coverage, immutable Actions and job results."""

import json
import os
import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]


def validate(workflow: dict[str, Any], results: dict[str, Any] | None = None) -> None:
    jobs = workflow["jobs"]
    required = set(jobs) - {"ci"}
    aggregate = jobs["ci"]
    if set(aggregate.get("needs", [])) != required or not required:
        raise ValueError("Aggregate must depend on every check")
    if aggregate.get("if") != "${{ always() }}":
        raise ValueError("Aggregate must always run")
    events = workflow.get("on", {})
    if not {"push", "pull_request", "workflow_dispatch"} <= set(events):
        raise ValueError("Missing required event")
    for event in ("push", "pull_request"):
        if events[event]:
            raise ValueError("Scheduling filters are prohibited")
    for job in jobs.values():
        for step in job.get("steps", []):
            if "uses" in step and not re.fullmatch(r"[^@]+@[0-9a-f]{40}", step["uses"]):
                raise ValueError("Action must use an immutable commit")
    if results is not None:
        if set(results) != required or any(
            result.get("result") != "success" for result in results.values()
        ):
            raise ValueError("Every required job must succeed")


def main() -> None:
    workflows = list((ROOT / ".github/workflows").glob("*.y*ml"))
    if workflows != [ROOT / ".github/workflows/ci.yml"]:
        raise ValueError("All check jobs must be in the aggregate workflow")
    results = json.loads(os.environ["CI_NEEDS"]) if "CI_NEEDS" in os.environ else None
    validate(yaml.safe_load(workflows[0].read_text()), results)


if __name__ == "__main__":
    main()
