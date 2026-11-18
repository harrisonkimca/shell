"""Workflow aggregate enforcement (AGENTS.md, approved slice 1)."""

import json
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


@pytest.mark.parametrize("job", ["quality", "requirements", "stack"])
@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", None])
def test_unsuccessful_or_missing_result(job: str, result: str | None) -> None:
    results: dict[str, Any] = {
        name: {"result": "success"} for name in workflow()["jobs"] if name != "ci"
    }
    results[job] = {"result": result}
    with pytest.raises(ValueError):
        validate(workflow(), results)


def test_successful_results() -> None:
    validate(
        workflow(),
        {job: {"result": "success"} for job in workflow()["jobs"] if job != "ci"},
    )


@pytest.mark.parametrize(
    "scope", ["workflow", "quality", "stack", "requirements", "ci"]
)
@pytest.mark.parametrize("shell", ["true {0}", "bash"])
@pytest.mark.parametrize(
    "results",
    [None, {job: {"result": "success"} for job in workflow()["jobs"] if job != "ci"}],
)
def test_default_run_shell_rejected(
    scope: str, shell: str, results: dict[str, Any] | None
) -> None:
    data = workflow()
    subject = data if scope == "workflow" else data["jobs"][scope]
    subject["defaults"] = {"run": {"shell": shell}}
    with pytest.raises(ValueError, match=r"defaults\.run\.shell"):
        validate(data, results)


@pytest.mark.parametrize("job", ["quality", "stack", "requirements", "ci"])
@pytest.mark.parametrize("shell", ["true {0}", "bash"])
def test_required_step_shell_validation(job: str, shell: str) -> None:
    data = workflow()
    command = next(
        s
        for s in data["jobs"][job]["steps"]
        if any(name in s.get("run", "") for name in ("scripts/check", "scripts/images"))
    )
    command["shell"] = shell
    if shell == "bash":
        validate(data)
    else:
        with pytest.raises(ValueError, match="fail-closed bash shell"):
            validate(data)


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


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-env",
        "noop-ci",
        "omitted-quality",
        "job-continue",
        "step-continue",
        "conditional-quality",
        "conditional-command",
        "masked-command",
        "reusable-workflow",
        "missing-checksum",
    ],
)
def test_reported_execution_bypasses(mutation: str) -> None:
    data = workflow()
    quality = data["jobs"]["quality"]
    aggregate = data["jobs"]["ci"]
    command = next(
        s for s in quality["steps"] if "scripts/check.py" in s.get("run", "")
    )
    gate = aggregate["steps"][-1]
    if mutation == "missing-env":
        gate.pop("env")
    elif mutation == "noop-ci":
        gate["run"] = "true"
    elif mutation == "omitted-quality":
        quality["steps"].remove(command)
    elif mutation == "job-continue":
        quality["continue-on-error"] = True
    elif mutation == "step-continue":
        command["continue-on-error"] = True
    elif mutation == "conditional-quality":
        quality["if"] = "${{ false }}"
    elif mutation == "conditional-command":
        command["if"] = "${{ false }}"
    elif mutation == "masked-command":
        command["run"] += " || true"
    elif mutation == "reusable-workflow":
        data["jobs"]["extra"] = {"uses": "org/repo/.github/workflows/w.yml@main"}
        aggregate["needs"].append("extra")
    elif mutation == "missing-checksum":
        quality["steps"][1]["with"].pop("checksum", None)
    with pytest.raises(ValueError):
        validate(data)


def test_aggregate_cli_requires_results() -> None:
    import os
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "scripts/check_ci.py", "--aggregate"],
        cwd=ROOT,
        env={k: v for k, v in os.environ.items() if k != "CI_NEEDS"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "CI_NEEDS" in result.stderr


@pytest.mark.parametrize("extension", ["yml", "yaml"])
def test_additional_workflow_rejected(tmp_path: Path, extension: str) -> None:
    from scripts.check_ci import main

    directory = tmp_path / ".github/workflows"
    directory.mkdir(parents=True)
    (directory / "ci.yml").write_text(yaml.safe_dump(workflow()))
    (directory / f"extra.{extension}").write_text("jobs: {}\n")
    with pytest.raises(ValueError, match="aggregate workflow"):
        main(root=tmp_path)


def test_verified_uv_release() -> None:
    # Compared with upstream v6.8.0's commit ref and uv 0.13.8's published
    # linux/amd64 archive SHA-256 (also independently hashed during remediation).
    for job in workflow()["jobs"].values():
        setup = next(
            s
            for s in job["steps"]
            if s.get("uses", "").startswith("astral-sh/setup-uv@")
        )
        assert (
            setup["uses"]
            == "astral-sh/setup-uv@d0cc045d04ccac9d8b7881df0226f9e82c39688e"
        )
        assert setup["with"]["version"] == "0.13.8"
        assert setup["with"]["checksum"] == (
            "5acfd9177cfecf0bf87578f059728215ccc884388988f55f7a65041b57387d91"
        )


@pytest.mark.parametrize(
    "value", ["", "null", "[]", "{}", '{"quality":{"result":"skipped"}}']
)
def test_aggregate_cli_rejects_invalid_results(value: str) -> None:
    import os
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "scripts/check_ci.py", "--aggregate"],
        cwd=ROOT,
        env={**os.environ, "CI_NEEDS": value},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0


def test_aggregate_cli_accepts_successful_results() -> None:
    import os
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "scripts/check_ci.py", "--aggregate"],
        cwd=ROOT,
        env={
            **os.environ,
            "CI_NEEDS": json.dumps(
                {
                    job: {"result": "success"}
                    for job in workflow()["jobs"]
                    if job != "ci"
                }
            ),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-job",
        "not-always",
        "missing-producer",
        "missing-report",
        "filtered-download",
        "shallow",
        "missing-dispatch",
        "conditional-verifier",
    ],
)
def test_requirements_execution_enforced(mutation: str) -> None:
    data = workflow()
    requirements = data["jobs"]["requirements"]
    if mutation == "missing-job":
        del data["jobs"]["requirements"]
        data["jobs"]["ci"]["needs"].remove("requirements")
    elif mutation == "not-always":
        requirements.pop("if")
    elif mutation == "missing-producer":
        requirements["needs"] = []
    elif mutation == "shallow":
        requirements["steps"][0]["with"]["fetch-depth"] = 1
    elif mutation == "missing-dispatch":
        data["on"]["workflow_dispatch"] = None
    elif mutation == "missing-report":
        requirements["steps"] = [
            s
            for s in requirements["steps"]
            if not s.get("uses", "").startswith("actions/download-artifact@")
        ]
    elif mutation == "filtered-download":
        download = next(
            s
            for s in requirements["steps"]
            if s.get("uses", "").startswith("actions/download-artifact@")
        )
        download["if"] = "${{ success() }}"
    else:
        command = next(
            s
            for s in requirements["steps"]
            if "scripts/check_requirements.py" in s.get("run", "")
        )
        command["if"] = "${{ false }}"
    with pytest.raises(ValueError):
        validate(data)
