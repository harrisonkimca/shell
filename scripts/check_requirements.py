"""Verify canonical pytest collection, JUnit evidence and cumulative deadlines."""

import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any, cast
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
KINDS = {
    "unit test",
    "integration suite",
    "configuration check",
    "hands-on check",
    "load test",
}
OWNER_KINDS = {"hands-on check", "load test"}
ID = r"(?:AUTH-[A-Z]+|NFR)-\d{3}"
TAG = r"stage-(0|[1-9]\d*)(?:-r([2-9]|[1-9]\d+))?"
type Association = tuple[str, str, str]
type Part = tuple[str, str, str, int, bool]
type Catalogue = dict[str, tuple[int, set[str]]]
type Collection = dict[str, list[Association]]


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def load_requirements(root: Path) -> tuple[Catalogue, list[Part]]:
    kinds: dict[str, set[str]] = {}
    for line in (root / "docs/spec/auth.md").read_text().splitlines():
        cells = [s.strip() for s in line.split("|")[1:-1]]
        if cells and re.fullmatch(ID, cells[0]):
            if len(cells) != 6 or cells[0] in kinds:
                raise ValueError("Malformed or duplicate requirement row")
            verification = {s.strip().lower() for s in cells[3].split(";")}
            if not verification or not verification <= KINDS:
                raise ValueError(f"Unknown verification kinds: {cells[0]}")
            kinds[cells[0]] = verification
    stages: dict[str, int] = {}
    roadmap = (root / "docs/roadmap.md").read_text()
    for section in re.split(r"(?m)^## Stage ", roadmap)[1:]:
        stage = int(section.split(".", 1)[0])
        match = re.search(r"\*\*Requirements\.\*\*(.*?)\n\n", section, re.S)
        if not match:
            raise ValueError("Missing stage requirements")
        for token in re.finditer(rf"({ID})(?:[–](\d{{3}}))?", match[1]):
            first, last = token.groups()
            prefix, number = first.rsplit("-", 1)
            for n in range(int(number), int(last or number) + 1):
                requirement = f"{prefix}-{n:03}"
                if requirement in stages:
                    raise ValueError(f"Duplicate stage assignment: {requirement}")
                stages[requirement] = stage
    if not kinds or kinds.keys() != stages.keys():
        raise ValueError("Spec IDs and roadmap stage assignments disagree")
    catalogue = {key: (stages[key], value) for key, value in kinds.items()}
    metadata = tomllib.loads((root / "tests/requirements.toml").read_text())
    if set(metadata) != {"parts"}:
        raise ValueError("Only supplemental parts belong in requirements metadata")
    parts: list[Part] = []
    names: set[Association] = set()
    overridden: set[tuple[str, str]] = set()
    for entry in metadata["parts"]:
        if not {"id", "kind", "part", "due"} <= entry.keys() or not set(entry) <= {
            "id",
            "kind",
            "part",
            "due",
            "owner",
        }:
            raise ValueError("Malformed supplemental part")
        key, kind, name, due = (entry[k] for k in ("id", "kind", "part", "due"))
        owner = entry.get("owner", kind in OWNER_KINDS)
        if (
            key not in catalogue
            or kind not in catalogue[key][1]
            or not isinstance(name, str)
            or not re.fullmatch(r"[a-z][a-z0-9-]*", name)
            or type(due) is not int
            or due not in set(stages.values())
            or due < stages[key]
            or type(owner) is not bool
            or (kind in OWNER_KINDS and not owner)
            or (key, kind, name) in names
        ):
            raise ValueError(f"Invalid supplemental part: {entry}")
        names.add((key, kind, name))
        overridden.add((key, kind))
        parts.append((key, kind, name, due, owner))
    for key, (stage, verification) in catalogue.items():
        for kind in verification:
            if (key, kind) not in overridden:
                parts.append((key, kind, "", stage, kind in OWNER_KINDS))
    return catalogue, parts


def due_parts(parts: list[Part], stage: int) -> set[Association]:
    return {
        (key, kind, name)
        for key, kind, name, due, owner in parts
        if due <= stage and not owner
    }


def require_due(passed: set[Association], parts: list[Part], stage: int) -> None:
    missing = due_parts(parts, stage) - passed
    if missing:
        raise ValueError(
            f"Missing automated verification through Stage {stage}: {sorted(missing)}"
        )


def validate_associations(
    collection: Collection, catalogue: Catalogue, parts: list[Part]
) -> None:
    allowed = {(key, kind, name) for key, kind, name, _, owner in parts if not owner}
    for nodeid, associations in collection.items():
        if len(associations) != len(set(associations)):
            raise ValueError(f"Duplicate requirement association: {nodeid}")
        for association in associations:
            if association[0] not in catalogue or association not in allowed:
                raise ValueError(
                    f"Invalid automated association: {nodeid}: {association}"
                )


def collect_tests(root: Path) -> Collection:
    config = tomllib.loads((root / "pyproject.toml").read_text())
    roots = config["tool"]["pytest"]["ini_options"]["testpaths"]
    if not roots or any(not (root / path).is_dir() for path in roots):
        raise ValueError("Missing canonical test roots")
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "collection.json"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                *roots,
                "--collect-only",
                "-q",
                "-o",
                "addopts=--strict-markers --strict-config",
                f"--requirements-collection={output}",
            ],
            cwd=root,
            env={k: v for k, v in os.environ.items() if k != "PYTEST_ADDOPTS"},
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode or not output.is_file():
            raise ValueError(
                f"Canonical collection failed:\n{result.stdout}{result.stderr}"
            )
        raw: Any = json.loads(output.read_text())
    if not isinstance(raw, dict) or not raw:
        raise ValueError("Empty canonical collection")
    data = cast(dict[str, list[list[str]]], raw)
    return {
        key: [(a[0], a[1], a[2]) for a in associations]
        for key, associations in data.items()
    }


def read_reports(
    paths: list[Path], collection: Collection, context: dict[str, str]
) -> set[Association]:
    executed: set[str] = set()
    passed: set[Association] = set()
    if not paths:
        raise ValueError("Missing execution reports")
    for path in paths:
        try:
            root = ET.parse(path).getroot()
        except (OSError, ET.ParseError) as error:
            raise ValueError(f"Missing or malformed report: {path}") from error
        suites = [root] if root.tag == "testsuite" else list(root)
        if root.tag not in {"testsuite", "testsuites"} or not suites:
            raise ValueError("Malformed JUnit suites")
        for suite in suites:
            cases = suite.findall("testcase")
            if suite.tag != "testsuite" or not cases or suite.find("error") is not None:
                raise ValueError("Empty or invalid JUnit suite")
            if int(suite.get("tests", "-1")) != len(cases):
                raise ValueError("Incomplete JUnit suite")
            for case in cases:
                if any(
                    case.find(tag) is not None
                    for tag in ("skipped", "failure", "error")
                ):
                    raise ValueError(f"Required test did not pass: {case.get('name')}")
                properties = case.findall("properties/property")
                props = {p.get("name", ""): p.get("value", "") for p in properties}
                if len(props) != len(properties):
                    raise ValueError("Duplicate JUnit properties")
                nodeid = props.get("test_nodeid", "")
                if nodeid not in collection or nodeid in executed:
                    raise ValueError(f"Uncollected or duplicate execution: {nodeid}")
                if any(props.get(key) != value for key, value in context.items()):
                    raise ValueError(f"Report revision/run/attempt mismatch: {nodeid}")
                try:
                    associations = json.loads(props["requirement_associations"])
                except (KeyError, json.JSONDecodeError) as error:
                    raise ValueError("Missing requirement metadata") from error
                if associations != [list(a) for a in collection[nodeid]]:
                    raise ValueError(
                        f"Collection/report association mismatch: {nodeid}"
                    )
                # Pytest represents non-strict XPASS as a successful testcase.
                if "xfail" in props:
                    raise ValueError(
                        f"Unexpected pass cannot verify a requirement: {nodeid}"
                    )
                executed.add(nodeid)
                passed.update(collection[nodeid])
    if executed != collection.keys():
        raise ValueError(
            f"Unexecuted canonical tests: {sorted(collection.keys() - executed)}"
        )
    return passed


def parse_tag(name: str, stages: set[int]) -> int | None:
    match = re.fullmatch(TAG, name)
    if match:
        stage = int(match[1])
        if stage not in stages:
            raise ValueError(f"Unknown completion stage: {name}")
        return stage
    return None


def select_stage(
    event: str, ref: str, head: str, inputs: dict[str, str], stages: set[int]
) -> int | None:
    if event not in {"push", "pull_request", "workflow_dispatch"}:
        raise ValueError("Unsupported verification event")
    selected: list[int] = []
    if ref.startswith("refs/tags/stage-"):
        stage = parse_tag(ref.removeprefix("refs/tags/"), stages)
        if stage is None:
            raise ValueError("Invalid completion tag")
        selected.append(stage)
    for branch in (ref.removeprefix("refs/heads/"), head):
        if branch.startswith("stage-") and branch.endswith("/exit"):
            match = re.fullmatch(r"stage-(0|[1-9]\d*)/exit", branch)
            if not match or int(match[1]) not in stages:
                raise ValueError("Invalid completion branch")
            selected.append(int(match[1]))
    if event == "workflow_dispatch":
        if ref != "refs/heads/main" or set(inputs) != {"stage", "expected_main_sha"}:
            raise ValueError(
                "Completion dispatch requires main, stage and expected_main_sha"
            )
        if not re.fullmatch(r"0|[1-9]\d*", inputs["stage"]):
            raise ValueError("Invalid dispatched stage")
        stage = int(inputs["stage"])
        if stage not in stages or not re.fullmatch(
            r"[0-9a-f]{40}", inputs["expected_main_sha"]
        ):
            raise ValueError("Invalid dispatch stage or exact main SHA")
        selected.append(stage)
    elif inputs:
        raise ValueError("Dispatch inputs conflict with event")
    if len(set(selected)) > 1:
        raise ValueError("Conflicting completion selection")
    return selected[0] if selected else None


def tag_floor(root: Path, stages: set[int]) -> int:
    if git(root, "rev-parse", "--is-shallow-repository") != "false":
        raise ValueError("Complete history is required")
    floor = -1
    for tag in git(root, "tag", "--list").splitlines():
        stage = parse_tag(tag, stages)
        if stage is None:
            continue
        commit = git(root, "rev-parse", f"refs/tags/{tag}^{{commit}}")
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit, "HEAD"],
            cwd=root,
            check=False,
        )
        if result.returncode not in {0, 1}:
            raise ValueError("Incomplete tag ancestry history")
        if result.returncode == 0:
            floor = max(floor, stage)
    return floor


def verify_revision(
    root: Path,
    event: str,
    ref: str,
    workflow_sha: str,
    expected: str,
    payload: dict[str, Any],
    remote_main: str,
) -> None:
    actual = git(root, "rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", workflow_sha) or actual != workflow_sha:
        raise ValueError("Workflow and checkout revisions disagree")
    if event == "workflow_dispatch":
        if ref != "refs/heads/main" or expected != actual or remote_main != actual:
            raise ValueError("Exact-main completion revision mismatch or main race")
    elif ref.startswith("refs/tags/"):
        if git(root, "rev-parse", f"{ref}^{{commit}}") != actual:
            raise ValueError("Completion tag and checkout disagree")
    elif event == "push":
        if payload.get("after") != actual:
            raise ValueError("Push and checkout revisions disagree")
    elif event == "pull_request":
        if payload.get("pull_request", {}).get("merge_commit_sha") != actual:
            raise ValueError("PR merge and checkout revisions disagree")


def main() -> None:
    catalogue, parts = load_requirements(ROOT)
    stages = {stage for stage, _ in catalogue.values()}
    actual = git(ROOT, "rev-parse", "HEAD")
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    selected = None
    if event:
        if os.environ["GITHUB_WORKFLOW_SHA"] != os.environ["GITHUB_SHA"]:
            raise ValueError("Workflow source and event revisions disagree")
        payload = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        inputs = payload.get("inputs", {})
        ref = os.environ["GITHUB_REF"]
        selected = select_stage(
            event, ref, os.environ.get("GITHUB_HEAD_REF", ""), inputs, stages
        )
        # checkout has full history; explicitly fetch repository tags as well.
        subprocess.run(["git", "fetch", "origin", "--tags"], cwd=ROOT, check=True)
        remote_main = ""
        if event == "workflow_dispatch":
            remote_main = git(ROOT, "ls-remote", "origin", "refs/heads/main").split()[0]
        verify_revision(
            ROOT,
            event,
            ref,
            os.environ["GITHUB_SHA"],
            inputs.get("expected_main_sha", ""),
            payload,
            remote_main,
        )
    elif os.environ.get("GITHUB_ACTIONS"):
        raise ValueError("Missing GitHub event context")
    floor = tag_floor(ROOT, stages)
    collection = collect_tests(ROOT)
    validate_associations(collection, catalogue, parts)
    context = {
        "tested_revision": actual,
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "local"),
    }
    # Each producer has one report. No glob can silently omit an absent producer.
    import yaml

    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    producers = set(workflow["jobs"]) - {"ci", "requirements"}
    passed = read_reports(
        [ROOT / f"reports/{name}.xml" for name in sorted(producers)],
        collection,
        context,
    )
    require_due(passed, parts, max(floor, selected if selected is not None else -1))
    if event == "workflow_dispatch":
        if git(ROOT, "ls-remote", "origin", "refs/heads/main").split()[0] != actual:
            raise ValueError("Remote main changed during verification")
    print(
        f"Verified {len(collection)} tests; cumulative floor={floor}; "
        f"selected stage={selected}. Owner checks remain separate."
    )


if __name__ == "__main__":
    main()
