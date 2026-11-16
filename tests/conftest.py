"""Minimal collection and requirement metadata alongside standard JUnit reports."""

import json
import os
import subprocess
from collections.abc import Generator
from pathlib import Path

import pytest


def pytest_plugin_registered(
    plugin: object, manager: pytest.PytestPluginManager
) -> None:
    path = Path(getattr(plugin, "__file__", ""))
    if path.name != "conftest.py":
        return
    if any(hasattr(plugin, name) for name in ("collect_ignore", "collect_ignore_glob")):
        raise pytest.UsageError("Conftest collection ignore lists are forbidden")
    if path.resolve() == Path(__file__).resolve():
        return
    # Registration precedes collection, including first-result hooks that can
    # bypass modifyitems entirely. Inspect registered names to include specname
    # aliases, independently of hook ordering and either wrapper protocol.
    for hook in manager.get_hookcallers(plugin) or []:
        if hook.name in {
            "pytest_ignore_collect",
            "pytest_collect_file",
            "pytest_collect_directory",
            "pytest_pycollect_makemodule",
            "pytest_pycollect_makeitem",
            "pytest_make_collect_report",
            "pytest_collectreport",
            "pytest_collection",
            "pytest_collection_modifyitems",
            "pytest_collection_finish",
        }:
            raise pytest.UsageError(
                f"Nested conftest collection hooks are forbidden: {path}: {hook.name}"
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
    for plugin in config.pluginmanager.get_plugins():
        if Path(getattr(plugin, "__file__", "")).name == "conftest.py" and any(
            hasattr(plugin, name) for name in ("collect_ignore", "collect_ignore_glob")
        ):
            raise pytest.UsageError("Conftest collection ignore lists are forbidden")
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
