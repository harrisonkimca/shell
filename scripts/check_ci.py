"""Validate aggregate coverage, immutable Actions and job results."""

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, cast

import yaml

ROOT = Path(__file__).resolve().parents[1]


def require_command(job: dict[str, Any], command: str) -> dict[str, Any]:
    matches = [s for s in job.get("steps", []) if s.get("run") == command]
    if len(matches) != 1 or "if" in matches[0]:
        raise ValueError(f"Required command must execute unconditionally: {command}")
    step = matches[0]
    if step.get("shell", "bash") != "bash":
        raise ValueError("Required commands must use the fail-closed bash shell")
    return step


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
    for subject in [workflow, *jobs.values()]:
        if "shell" in subject.get("defaults", {}).get("run", {}):
            raise ValueError("defaults.run.shell is prohibited")
    for job in jobs.values():
        if "uses" in job:
            raise ValueError("Reusable workflows must not escape aggregate inspection")
        for subject in [job, *job.get("steps", [])]:
            if "continue-on-error" in subject:
                raise ValueError("continue-on-error is prohibited")
            if "uses" in subject and not re.fullmatch(
                r"[^@]+@[0-9a-f]{40}", subject["uses"]
            ):
                raise ValueError("Action must use an immutable commit")
            if subject.get("uses", "").startswith("astral-sh/setup-uv@"):
                if not re.fullmatch(
                    r"[0-9a-f]{64}", subject.get("with", {}).get("checksum", "")
                ):
                    raise ValueError("uv download requires a SHA-256 checksum")
    if "if" in jobs["quality"]:
        raise ValueError("Quality must execute on every run")
    require_command(jobs["quality"], "uv run --locked python scripts/check.py")
    if "stack" not in jobs or "if" in jobs["stack"]:
        raise ValueError("Stack must execute on every run")
    require_command(jobs["stack"], "uv run --locked python scripts/images.py")
    if "requirements" not in jobs:
        raise ValueError("Missing requirements job")
    requirements = jobs["requirements"]
    producers = required - {"requirements"}
    if requirements.get("if") != "${{ always() }}":
        raise ValueError("Requirements must always run")
    if set(requirements.get("needs", [])) != producers:
        raise ValueError("Requirements must consume every producer")
    checkouts = [
        s
        for s in requirements["steps"]
        if s.get("uses", "").startswith("actions/checkout@")
    ]
    if (
        len(checkouts) != 1
        or checkouts[0].get("with", {}).get("fetch-depth") != 0
        or "if" in checkouts[0]
    ):
        raise ValueError("Requirements need complete checkout history")
    downloads = [
        s
        for s in requirements["steps"]
        if s.get("uses", "").startswith("actions/download-artifact@")
    ]
    if (
        len(downloads) != len(producers)
        or any("if" in s for s in downloads)
        or {s.get("with", {}).get("name") for s in downloads}
        != {f"{name}-reports" for name in producers}
        or any(s.get("with", {}).get("path") != "reports" for s in downloads)
    ):
        raise ValueError("Requirements must download every producer report")
    require_command(
        requirements, "uv run --locked python scripts/check_requirements.py"
    )
    dispatch = cast(dict[str, Any], events.get("workflow_dispatch") or {})
    inputs = cast(dict[str, Any], dispatch.get("inputs", {}))
    if set(inputs) != {"stage", "expected_main_sha"} or any(
        value.get("required") is not True or value.get("type") != "string"
        for value in inputs.values()
    ):
        raise ValueError("Exact completion dispatch inputs are required")
    gate = require_command(
        aggregate, "uv run --locked python scripts/check_ci.py --aggregate"
    )
    if gate.get("env", {}).get("CI_NEEDS") != "${{ toJSON(needs) }}":
        raise ValueError("Aggregate must receive CI_NEEDS from needs")
    if results is not None:
        if set(results) != required or any(
            not isinstance(result, dict)
            or cast(dict[str, Any], result).get("result") != "success"
            for result in results.values()
        ):
            raise ValueError("Every required job must succeed")


def main(root: Path = ROOT, aggregate: bool = False) -> None:
    workflows = sorted((root / ".github/workflows").glob("*.y*ml"))
    if workflows != [root / ".github/workflows/ci.yml"]:
        raise ValueError("All check jobs must be in the aggregate workflow")
    results: dict[str, Any] | None = None
    if aggregate:
        if not os.environ.get("CI_NEEDS"):
            raise ValueError("Aggregate requires CI_NEEDS")
        results = json.loads(os.environ["CI_NEEDS"])
        if not isinstance(results, dict):
            raise ValueError("CI_NEEDS must be a result mapping")
    validate(yaml.safe_load(workflows[0].read_text()), results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aggregate", action="store_true")
    main(aggregate=parser.parse_args().aggregate)
