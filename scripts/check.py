"""Common quality command; every command must succeed."""

import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

from grimp import ImportGraph
from importlinter.contracts.independence import IndependenceContract
from importlinter.contracts.layers import LayersContract
from importlinter.domain.contract import ContractCheck

ROOT = Path(__file__).resolve().parents[1]


def check_locks(root: Path) -> None:
    lock = root / "uv.lock"
    if not lock.is_file():
        raise ValueError("Missing uv.lock")
    data = tomllib.loads(lock.read_text())
    for package in data["package"]:
        if "registry" in package["source"]:
            artifacts = [
                *package.get("wheels", []),
                *([package["sdist"]] if "sdist" in package else []),
            ]
            if not artifacts or any(
                not re.fullmatch(r"sha256:[0-9a-f]{64}", a.get("hash", ""))
                for a in artifacts
            ):
                raise ValueError("Missing distribution hashes")
    result = subprocess.run(
        ["uv", "lock", "--check", "--offline"], cwd=root, check=False
    )
    if result.returncode:
        raise RuntimeError("Missing or stale dependency lock")


def main() -> None:
    check_locks(ROOT)
    commands = [
        ["ruff", "check", "."],
        ["ruff", "format", "--check", "."],
        ["pyright"],
        ["lint-imports"],
        [sys.executable, "scripts/check_ci.py"],
        ["pytest", "--junitxml=reports/quality.xml"],
    ]
    env = {**os.environ, "PYTHONPATH": str(ROOT / "apps/api/src")}
    failed = False
    for command in commands:
        failed |= (
            subprocess.run(command, cwd=ROOT, env=env, check=False).returncode != 0
        )
    if failed:
        raise SystemExit(1)


# Built-in layer/independence contracts also follow indirect routes. Architecture
# section 14 requires direct edges for these two rules; retain their validation
# and diagnostics after removing edges that cannot themselves breach the rule.


def package_layer(module: str) -> tuple[str, str]:
    parts = module.split(".")
    boundary = 3 if parts[:2] == ["shell_api", "contexts"] else 2
    return ".".join(parts[:boundary]), parts[boundary] if len(parts) > boundary else ""


class DirectLayers(LayersContract):
    @classmethod
    def _get_field_names(cls) -> list[str]:
        return LayersContract._get_field_names()

    def check(self, graph: ImportGraph, verbose: bool) -> ContractCheck:
        ranks = {"domain": 0, "application": 1, "infrastructure": 2, "presentation": 2}
        for source in graph.modules:
            a, layer_a = package_layer(source)
            for target in graph.find_modules_directly_imported_by(source):
                b, layer_b = package_layer(target)
                breach = (
                    a == b
                    and layer_a in ranks
                    and layer_b in ranks
                    and (
                        ranks[layer_a] < ranks[layer_b]
                        or (
                            ranks[layer_a] == ranks[layer_b] == 2 and layer_a != layer_b
                        )
                    )
                )
                if not breach:
                    graph.remove_import(importer=source, imported=target)
        return super().check(graph, verbose)


class DirectContexts(IndependenceContract):
    @classmethod
    def _get_field_names(cls) -> list[str]:
        return IndependenceContract._get_field_names()

    def check(self, graph: ImportGraph, verbose: bool) -> ContractCheck:
        for source in graph.modules:
            for target in graph.find_modules_directly_imported_by(source):
                if not (
                    source.startswith("shell_api.contexts.")
                    and target.startswith("shell_api.contexts.")
                    and package_layer(source)[0] != package_layer(target)[0]
                ):
                    graph.remove_import(importer=source, imported=target)
        return super().check(graph, verbose)


if __name__ == "__main__":
    main()
