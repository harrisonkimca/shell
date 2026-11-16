"""Minimal collection and requirement metadata alongside standard JUnit reports."""

import inspect
import json
import os
import subprocess
import sys
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest


def pytest_plugin_registered(
    plugin: object, manager: pytest.PytestPluginManager
) -> None:
    root = Path(__file__).resolve()
    # Historic registration covers earlier conftests as well as late helper
    # modules and instances. Hook ownership follows the implementation code,
    # including specname aliases and both wrapper protocols.
    sources: list[tuple[Any, bool]] = [
        (plugin if inspect.ismodule(plugin) else type(plugin), False)
    ]
    sources.extend(
        (impl.function, True)
        for caller in manager.get_hookcallers(plugin) or []
        for impl in caller.get_hookimpls()
        if impl.plugin is plugin
    )
    for source, is_hook in sources:
        try:
            path = Path(inspect.getfile(source)).resolve()
        except TypeError:
            continue
        if not path.is_relative_to(root.parents[1]) or path.is_relative_to(
            Path(sys.prefix).resolve()
        ):
            continue
        if not is_hook and any(
            hasattr(plugin, name) for name in ("collect_ignore", "collect_ignore_glob")
        ):
            manager.unregister(plugin)
            raise pytest.UsageError("Conftest collection ignore lists are forbidden")
        if path != root and (is_hook or hasattr(plugin, "pytest_plugins")):
            manager.unregister(plugin)
            raise pytest.UsageError(
                f"Repository pytest hooks and plugin declarations are forbidden "
                f"outside the root conftest: {path}"
            )


def pytest_pycollect_makeitem(name: str) -> None:
    if name == "pytest_plugins":
        raise pytest.UsageError(
            "Test module plugin declarations are forbidden; "
            "use the root conftest or central pytest configuration"
        )


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--requirements-collection", help="Write canonical collection metadata"
    )


def associations(item: pytest.Item) -> list[tuple[str, str, str]]:
    values: list[tuple[str, str, str]] = []
    for marker in item.iter_markers("req"):
        if (
            not marker.args
            or not all(isinstance(arg, str) for arg in marker.args)
            or set(marker.kwargs) != {"kind", "part"}
            or not all(isinstance(value, str) for value in marker.kwargs.values())
        ):
            raise pytest.UsageError(f"Malformed req marker: {item.nodeid}")
        values.extend(
            (arg, marker.kwargs["kind"], marker.kwargs["part"]) for arg in marker.args
        )
    return values


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> Generator[None]:
    original = set(items)
    yield
    if set(items) != original or len(items) != len(original):
        raise pytest.UsageError("Collection filtering is forbidden")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    for item in items:
        item.user_properties.extend(
            [
                ("test_nodeid", item.nodeid),
                ("requirement_associations", json.dumps(associations(item))),
                ("tested_revision", revision),
                ("run_id", os.environ.get("GITHUB_RUN_ID", "local")),
                ("run_attempt", os.environ.get("GITHUB_RUN_ATTEMPT", "local")),
            ]
        )


def pytest_collection_finish(session: pytest.Session) -> None:
    output = session.config.getoption("requirements_collection")
    if output:
        collection = {item.nodeid: associations(item) for item in session.items}
        if len(collection) != len(session.items):
            raise pytest.UsageError("Duplicate canonical test identities")
        Path(output).write_text(json.dumps(collection))


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item,
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    report = yield
    if hasattr(report, "wasxfail"):
        item.user_properties.append(("xfail", "true"))
    return report
