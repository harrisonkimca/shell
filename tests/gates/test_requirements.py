"""Requirement trace and completion gates (roadmap Stage 0, approved slice 3)."""

import json
import subprocess
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import pytest

from scripts import check_requirements as gate

ROOT = Path(__file__).resolve().parents[2]
SHA = "a" * 40
CONTEXT = {"tested_revision": SHA, "run_id": "123", "run_attempt": "2"}
ASSOCIATION = ("NFR-011", "configuration check", "dependency-locks")


def collection() -> dict[str, list[tuple[str, str, str]]]:
    return {"tests/test_example.py::test_lock[one]": [ASSOCIATION]}


def report(tmp_path: Path) -> Path:
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite", tests="1", errors="0", failures="0")
    case = ET.SubElement(suite, "testcase", name="test_lock[one]")
    props = ET.SubElement(case, "properties")
    values = {
        **CONTEXT,
        "test_nodeid": next(iter(collection())),
        "requirement_associations": json.dumps([ASSOCIATION]),
    }
    for name, value in values.items():
        ET.SubElement(props, "property", name=name, value=value)
    path = tmp_path / "quality.xml"
    ET.ElementTree(root).write(path)
    return path


def test_normative_catalogue_and_deadlines() -> None:
    catalogue, parts = gate.load_requirements(ROOT)
    assert len(catalogue) == 173
    assert catalogue["AUTH-ERROR-001"] == (0, {"unit test"})
    assert catalogue["AUTH-IDP-012"][0] == 1
    assert "AUTH-ERROR-002" not in catalogue
    assert ("NFR-013", "configuration check", "keys", 2, False) in parts
    assert ("NFR-013", "configuration check", "deployment-isolation", 7, True) in parts
    assert gate.due_parts(parts, 0) == {
        ("AUTH-ERROR-001", "unit test", "problem-details"),
        ASSOCIATION,
        ("NFR-011", "configuration check", "image-pins"),
        ("NFR-011", "configuration check", "build-scans"),
        ("NFR-013", "configuration check", "database"),
        ("NFR-013", "configuration check", "schema"),
        ("NFR-013", "configuration check", "internal-probes"),
        ("NFR-024", "configuration check", "trusted-sources"),
        ("NFR-024", "configuration check", "image-sbom"),
    }
    assert ("NFR-013", "configuration check", "keys") in gate.due_parts(parts, 2)
    assert ("NFR-013", "configuration check", "deployment-isolation") not in (
        gate.due_parts(parts, 8)
    )


def test_complete_execution(tmp_path: Path) -> None:
    assert gate.read_reports([report(tmp_path)], collection(), CONTEXT) == {ASSOCIATION}


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "malformed",
        "empty",
        "omitted",
        "uncollected",
        "duplicate",
        "skip",
        "failure",
        "error",
        "xfail",
        "xpass",
        "collection-error",
        "wrong-revision",
        "wrong-run",
        "wrong-attempt",
        "missing-identity",
        "wrong-association",
        "duplicate-property",
        "suite-count",
    ],
)
def test_incomplete_execution_rejected(tmp_path: Path, mutation: str) -> None:
    path = report(tmp_path)
    tree = ET.parse(path)
    suite = tree.getroot()[0]
    case = suite[0]
    props = case[0]
    if mutation == "missing":
        path.unlink()
    elif mutation == "malformed":
        path.write_text("<broken")
    elif mutation == "empty":
        suite.remove(case)
    elif mutation == "omitted":
        expected = {**collection(), "tests/test_example.py::test_lock[two]": []}
        with pytest.raises(ValueError):
            gate.read_reports([path], expected, CONTEXT)
        return
    elif mutation == "uncollected":
        next(p for p in props if p.get("name") == "test_nodeid").set("value", "unknown")
    elif mutation == "duplicate":
        suite.append(case)
    elif mutation in {"skip", "xfail"}:
        ET.SubElement(case, "skipped", type=mutation)
    elif mutation in {"failure", "xpass"}:
        ET.SubElement(case, "failure", message=mutation)
    elif mutation in {"error", "collection-error"}:
        ET.SubElement(suite if mutation == "collection-error" else case, "error")
    elif mutation.startswith("wrong-"):
        key = {
            "wrong-revision": "tested_revision",
            "wrong-run": "run_id",
            "wrong-attempt": "run_attempt",
            "wrong-association": "requirement_associations",
        }[mutation]
        next(p for p in props if p.get("name") == key).set("value", "wrong")
    elif mutation == "missing-identity":
        props.remove(next(p for p in props if p.get("name") == "test_nodeid"))
    elif mutation == "duplicate-property":
        props.append(props[0])
    elif mutation == "suite-count":
        suite.set("tests", "2")
    if mutation not in {"missing", "malformed"}:
        tree.write(path)
    with pytest.raises(ValueError):
        gate.read_reports([path], collection(), CONTEXT)


@pytest.mark.parametrize(
    "association",
    [
        ("UNKNOWN-001", "unit test", ""),
        ("AUTH-ERROR-002", "unit test", ""),
        ("NFR-011", "unit test", "dependency-locks"),
        ("NFR-011", "configuration check", "unknown"),
        ("NFR-013", "configuration check", "deployment-isolation"),
    ],
)
def test_invalid_association_rejected(association: tuple[str, str, str]) -> None:
    catalogue, parts = gate.load_requirements(ROOT)
    with pytest.raises(ValueError):
        gate.validate_associations({"test": [association]}, catalogue, parts)


def test_premature_completion_fails_but_ordinary_slice_passes() -> None:
    _, parts = gate.load_requirements(ROOT)
    implemented = {ASSOCIATION, ("AUTH-ERROR-001", "unit test", "problem-details")}
    gate.require_due(implemented, parts, -1)
    with pytest.raises(ValueError, match="image-pins"):
        gate.require_due(implemented, parts, 0)


@pytest.mark.parametrize(
    ("event", "ref", "head", "inputs", "expected"),
    [
        ("push", "refs/heads/stage-0/requirement-verification", "", {}, None),
        ("push", "refs/heads/main", "", {}, None),
        ("push", "refs/heads/stage-0/exit", "", {}, 0),
        ("pull_request", "refs/pull/9/merge", "stage-2/exit", {}, 2),
        ("push", "refs/tags/stage-0", "", {}, 0),
        ("push", "refs/tags/stage-2-r2", "", {}, 2),
        ("push", "refs/tags/stage-2-r12", "", {}, 2),
        (
            "workflow_dispatch",
            "refs/heads/main",
            "",
            {"stage": "0", "expected_main_sha": SHA},
            0,
        ),
    ],
)
def test_completion_selectors(
    event: str, ref: str, head: str, inputs: dict[str, str], expected: int | None
) -> None:
    assert gate.select_stage(event, ref, head, inputs, set(range(9))) == expected


@pytest.mark.parametrize(
    ("event", "ref", "head", "inputs"),
    [
        ("push", "refs/tags/stage-0-r1", "", {}),
        ("push", "refs/tags/stage-0-r02", "", {}),
        ("push", "refs/tags/stage-9", "", {}),
        ("push", "refs/heads/stage-x/exit", "", {}),
        ("pull_request", "refs/tags/stage-1", "stage-2/exit", {}),
        (
            "workflow_dispatch",
            "refs/heads/other",
            "",
            {"stage": "0", "expected_main_sha": SHA},
        ),
        ("workflow_dispatch", "refs/heads/main", "", {}),
        (
            "workflow_dispatch",
            "refs/heads/main",
            "",
            {"stage": "00", "expected_main_sha": SHA},
        ),
        ("push", "refs/heads/main", "", {"stage": "0", "expected_main_sha": SHA}),
    ],
)
def test_invalid_or_conflicting_selection(
    event: str, ref: str, head: str, inputs: dict[str, str]
) -> None:
    with pytest.raises(ValueError):
        gate.select_stage(event, ref, head, inputs, set(range(9)))


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


@pytest.fixture
def history(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-b", "main")
    git(tmp_path, "config", "user.email", "test@example.invalid")
    git(tmp_path, "config", "user.name", "Test")
    git(tmp_path, "commit", "--allow-empty", "-m", "initial")
    return tmp_path


def test_reachable_tags_set_highest_floor(history: Path) -> None:
    git(history, "tag", "stage-0")
    git(history, "tag", "stage-2-r2")
    git(history, "tag", "unrelated")
    git(history, "checkout", "--orphan", "unreachable")
    git(history, "commit", "--allow-empty", "-m", "other")
    git(history, "tag", "stage-8")
    git(history, "checkout", "main")
    assert gate.tag_floor(history, set(range(9))) == 2


def test_incomplete_history_rejected(history: Path) -> None:
    (history / ".git/shallow").write_text(git(history, "rev-parse", "HEAD") + "\n")
    with pytest.raises(ValueError, match="history"):
        gate.tag_floor(history, set(range(9)))


@pytest.mark.parametrize("mutation", ["workflow", "expected", "remote", "event"])
def test_exact_revision_mismatches(history: Path, mutation: str) -> None:
    sha = git(history, "rev-parse", "HEAD")
    event: dict[str, Any] = {"after": sha}
    with pytest.raises(ValueError):
        gate.verify_revision(
            history,
            "workflow_dispatch" if mutation != "event" else "push",
            "refs/heads/main",
            "b" * 40 if mutation == "workflow" else sha,
            "b" * 40 if mutation == "expected" else sha,
            {"after": "b" * 40} if mutation == "event" else event,
            "b" * 40 if mutation == "remote" else sha,
        )


def test_exact_main_revision(history: Path) -> None:
    sha = git(history, "rev-parse", "HEAD")
    gate.verify_revision(
        history, "workflow_dispatch", "refs/heads/main", sha, sha, {}, sha
    )


def test_canonical_collection_rejects_errors_and_ignores_filters(history: Path) -> None:
    tmp_path = history
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/test_cases.py").write_text(
        "import pytest\n@pytest.mark.parametrize('value', [1, 2])\n"
        "def test_values(value): pass\n"
    )
    (tmp_path / "tests/conftest.py").write_text(
        (ROOT / "tests/conftest.py").read_text()
    )
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\ntestpaths = ["tests"]\naddopts = "-k absent"\n'
    )
    assert len(gate.collect_tests(tmp_path)) == 2
    (tmp_path / "tests/test_broken.py").write_text("syntax error!\n")
    with pytest.raises(ValueError, match="collection"):
        gate.collect_tests(tmp_path)


@pytest.mark.parametrize("mode", ["pass", "skip", "xfail", "xpass", "deselect", "omit"])
def test_real_pytest_reports(history: Path, mode: str) -> None:
    import os
    import sys

    directory = history / "tests"
    directory.mkdir()
    (directory / "conftest.py").write_text((ROOT / "tests/conftest.py").read_text())
    (history / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n'
        'junit_family = "legacy"\n'
        'markers = ["req(*ids, kind, part): requirement association"]\n'
    )
    marker = ""
    body = "pass"
    if mode == "skip":
        marker = "@pytest.mark.skip(reason='fixture')\n"
    if mode in {"xfail", "xpass"}:
        marker = "@pytest.mark.xfail(reason='fixture', strict=False)\n"
    if mode == "xfail":
        body = "assert False"
    (directory / "test_cases.py").write_text(
        "import pytest\n"
        "@pytest.mark.req('NFR-011', kind='configuration check', "
        "part='dependency-locks')\n"
        "@pytest.mark.parametrize('value', [1, 2])\n"
        f"{marker}def test_values(value): {body}\n"
        "def test_other(): pass\n"
    )
    expected = gate.collect_tests(history)
    path = history / "report.xml"
    args = [sys.executable, "-m", "pytest", f"--junitxml={path}"]
    if mode == "deselect":
        args += ["-k", "other"]
    if mode == "omit":
        args += [
            "tests/test_cases.py::test_values[1]",
            "tests/test_cases.py::test_other",
        ]
    subprocess.run(args, cwd=history, capture_output=True, check=True)
    context = {
        "tested_revision": git(history, "rev-parse", "HEAD"),
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "local"),
    }
    if mode == "pass":
        assert gate.read_reports([path], expected, context) == {ASSOCIATION}
    else:
        with pytest.raises(ValueError):
            gate.read_reports([path], expected, context)


@pytest.mark.parametrize("stage", [0, 1, 2, 7, 8])
def test_cumulative_deadlines_never_drop_earlier_parts(stage: int) -> None:
    _, parts = gate.load_requirements(ROOT)
    due = gate.due_parts(parts, stage)
    assert ASSOCIATION in due
    gate.require_due(due, parts, stage)
    with pytest.raises(ValueError, match="dependency-locks"):
        gate.require_due(due - {ASSOCIATION}, parts, stage)


def test_second_report_cannot_conceal_failure_or_missing_execution(
    tmp_path: Path,
) -> None:
    path = report(tmp_path)
    with pytest.raises(ValueError):
        gate.read_reports([path, tmp_path / "missing.xml"], collection(), CONTEXT)
    with pytest.raises(ValueError):
        gate.read_reports([path, path], collection(), CONTEXT)


@pytest.mark.parametrize("event", ["push", "pull_request", "tag"])
def test_ref_revision_is_checked(history: Path, event: str) -> None:
    sha = git(history, "rev-parse", "HEAD")
    ref = "refs/heads/stage-0/exit"
    payload: dict[str, Any] = {"after": sha}
    actual_event = event
    if event == "pull_request":
        ref = "refs/pull/1/merge"
        base = sha
        git(history, "checkout", "-b", "topic")
        git(history, "commit", "--allow-empty", "-m", "topic")
        head = git(history, "rev-parse", "HEAD")
        git(history, "checkout", "main")
        git(history, "merge", "--no-ff", "topic", "-m", "fixture merge")
        sha = git(history, "rev-parse", "HEAD")
        payload = {
            "pull_request": {
                "merge_commit_sha": sha,
                "base": {"sha": base},
                "head": {"sha": head},
            }
        }
    elif event == "tag":
        git(history, "tag", "-a", "stage-0-r2", "-m", "fixture correction")
        ref = "refs/tags/stage-0-r2"
        actual_event = "push"
    gate.verify_revision(history, actual_event, ref, sha, "", payload, "")
    with pytest.raises(ValueError):
        gate.verify_revision(history, actual_event, ref, "b" * 40, "", payload, "")


@pytest.mark.parametrize("merge_field", [None, "b" * 40])
def test_pr_event_merge_field_does_not_identify_tested_merge(
    history: Path, merge_field: str | None
) -> None:
    base = git(history, "rev-parse", "HEAD")
    git(history, "checkout", "-b", "topic")
    git(history, "commit", "--allow-empty", "-m", "topic")
    head = git(history, "rev-parse", "HEAD")
    git(history, "checkout", "main")
    git(history, "merge", "--no-ff", "topic", "-m", "fixture merge")
    sha = git(history, "rev-parse", "HEAD")
    payload = {
        "pull_request": {
            "merge_commit_sha": merge_field,
            "base": {"sha": base},
            "head": {"sha": head},
        }
    }
    gate.verify_revision(
        history, "pull_request", "refs/pull/7/merge", sha, "", payload, ""
    )
    for field in ("base", "head"):
        broken = {"pull_request": {**payload["pull_request"], field: {"sha": "c" * 40}}}
        with pytest.raises(ValueError):
            gate.verify_revision(
                history, "pull_request", "refs/pull/7/merge", sha, "", broken, ""
            )
