"""Real Buildx/Trivy evidence, including the pinned vulnerable fixture."""

import hashlib
import json
import subprocess
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from scripts import images

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.req("NFR-026", kind="configuration check", part="image-pins")
def test_all_index_pins_support_both_platforms(supply_chain: dict[str, Any]) -> None:
    pins = images.check_configuration(ROOT)
    images.check_coverage(set(pins), supply_chain["inputs"])
    for item in supply_chain["inputs"].values():
        assert item["platform"] == "linux/amd64"
        assert images.platform_digest(item["index"]) == item["child_digest"]
        assert item["index_digest"] in item["index_reference"]


@pytest.mark.req("NFR-026", kind="configuration check", part="build-scans")
def test_every_input_and_built_image_passed_real_scanning(
    supply_chain: dict[str, Any],
) -> None:
    for item in [*supply_chain["effective"].values(), supply_chain["application"]]:
        report = json.loads((ROOT / item["scan"]).read_text())
        images.check_scan(report, item["image_id"], 0)
    application = supply_chain["application"]
    assert (
        application["image_id"] == images.local_identity(application["reference"])["Id"]
    )
    assert application["image_id"] == supply_chain["builds"]["application"]["image_id"]


@pytest.mark.req("NFR-026", kind="configuration check", part="build-scans")
def test_real_scanner_rejects_fixable_high_and_critical(
    supply_chain: dict[str, Any],
) -> None:
    fixture = supply_chain["fixture"]
    assert fixture["scanner_status"] == 42
    report = json.loads((ROOT / fixture["scan"]).read_text())
    with pytest.raises(images.VulnerableImage) as error:
        images.check_scan(report, fixture["image_id"], fixture["scanner_status"])
    assert {"HIGH", "CRITICAL"} <= {v["Severity"] for v in error.value.findings}


@pytest.mark.req("NFR-024", kind="configuration check", part="image-sbom")
def test_inventory_matches_installed_python_and_os_packages(
    supply_chain: dict[str, Any],
) -> None:
    application = supply_chain["application"]
    components = images.check_sbom(ROOT / application["sbom"], application["image_id"])
    installed = images.installed_packages(application["image_id"])
    assert installed["python"] and installed["os"]
    for name, version in [*installed["python"].items(), *installed["os"].items()]:
        assert (name.lower().replace("_", "-"), version) in components, (name, version)


@pytest.mark.req("NFR-026", kind="configuration check", part="build-scans")
def test_upstreams_remain_diagnostics_only_and_build_order_is_gated(
    supply_chain: dict[str, Any],
) -> None:
    for name, item in supply_chain["inputs"].items():
        images.check_upstream(
            name,
            json.loads((ROOT / item["scan"]).read_text()),
            item["image_id"],
            item["scanner_status"],
        )
    events = supply_chain["events"]
    assert events.count("build:application") == 1
    assert events.index("pass:python") < events.index("build:application")
    for name in ("caddy", "postgres"):
        if "build:" + name in events:
            assert events.index("pass:builder") < events.index("build:" + name)
    for name, item in supply_chain["effective"].items():
        packages = images.check_sbom(ROOT / item["sbom"], item["image_id"])
        for group in item["installed"].values():
            assert {
                (k.lower().replace("_", "-"), v) for k, v in group.items()
            } <= packages


@contextmanager
def running(reference: str, *options: str) -> Iterator[str]:
    name = "shell-supply-chain-" + uuid.uuid4().hex[:12]
    images.command("docker", "run", "-d", "--name", name, *options, reference)
    try:
        yield name
    finally:
        subprocess.run(["docker", "logs", name], check=False, capture_output=True)
        subprocess.run(["docker", "rm", "-fv", name], check=True, capture_output=True)


def wait_command(name: str, *args: str) -> str:
    for _ in range(100):
        result = subprocess.run(
            ["docker", "exec", name, *args], capture_output=True, text=True, check=False
        )
        if result.returncode == 0:
            return result.stdout.strip()
        time.sleep(0.2)
    raise AssertionError(f"Container did not become available: {name}")


def assert_container_identity(name: str, item: dict[str, Any]) -> None:
    info = json.loads(images.command("docker", "inspect", name))[0]
    assert info["Image"] == item["image_id"]


@pytest.mark.req("NFR-026", kind="configuration check", part="build-scans")
def test_prepared_python_and_scanned_application_start_without_pip(
    supply_chain: dict[str, Any],
) -> None:
    item = supply_chain["application"]
    code = (
        "import sys,importlib.util,hashlib,pathlib,json,subprocess; "
        "assert sys.version_info[:2]==(3,13); "
        "assert not importlib.util.find_spec('pip'); "
        "assert not importlib.util.find_spec('ensurepip'); "
        "assert not list(pathlib.Path('/usr/local').rglob('*.whl')); "
        "assert subprocess.check_output(['uv','--version'],text=True)"
        ".startswith('uv 0.13.8 '); "
        "print(hashlib.sha256(pathlib.Path('/app/uv.lock').read_bytes()).hexdigest())"
    )
    assert (
        images.command("docker", "run", "--rm", item["image_id"], "python", "-c", code)
        == hashlib.sha256((ROOT / "uv.lock").read_bytes()).hexdigest()
    )
    request = (
        "import urllib.request,urllib.error,json\n"
        "try: urllib.request.urlopen('http://127.0.0.1:8000/supply-chain-probe',timeout=2)\n"
        "except urllib.error.HTTPError as e:\n"
        " assert e.code==404\n"
        " assert e.headers['Content-Type'].startswith('application/problem+json')\n"
        " assert json.load(e)['code']=='request.not_found'\n"
    )
    with running(
        item["image_id"], "-e", "SHELL_ENV=production", "-e", "SHELL_HOST=0.0.0.0"
    ) as name:
        wait_command(name, "python", "-c", request)
        assert_container_identity(name, item)
        info = json.loads(images.command("docker", "inspect", name))[0]
        assert info["Config"]["User"] == "65532:65532"
        assert not info["Mounts"]


@pytest.mark.req("NFR-026", kind="configuration check", part="build-scans")
def test_services_preserve_modules_entrypoint_and_privilege_behavior(
    supply_chain: dict[str, Any], tmp_path: Path
) -> None:
    caddy = supply_chain["effective"]["caddy"]
    original = supply_chain["inputs"]["CADDY_IMAGE"]
    # Inspect the rejected source only as part of the isolated remediation check.
    args = ["caddy", "list-modules", "--versions"]
    expected = images.command("docker", "run", "--rm", original["image_id"], *args)
    assert images.command("docker", "run", "--rm", caddy["image_id"], *args) == expected
    assert "http.handlers.rate_limit" not in expected
    with running(caddy["image_id"]) as name:
        assert "Caddy" in wait_command(name, "wget", "-qO-", "http://127.0.0.1/")
        assert_container_identity(name, caddy)
    pg = supply_chain["effective"]["postgres"]
    original = supply_chain["inputs"]["POSTGRES_IMAGE"]
    entrypoint = "/usr/local/bin/docker-entrypoint.sh"

    def read_entrypoint(identity: str) -> str:
        return images.command(
            "docker", "run", "--rm", "--entrypoint", "sha256sum", identity, entrypoint
        )

    assert read_entrypoint(pg["image_id"]) == read_entrypoint(original["image_id"])
    for key in ("Entrypoint", "Cmd"):
        assert pg["docker"]["Config"][key] == original["docker"]["Config"][key]
    dropped = images.command(
        "docker",
        "run",
        "--rm",
        "--entrypoint",
        "gosu",
        pg["image_id"],
        "postgres",
        "id",
        "-u",
    )
    assert dropped == "70"
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--user",
            "70:70",
            "--entrypoint",
            "gosu",
            pg["image_id"],
            "root",
            "id",
        ],
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    script = tmp_path / "probe.sql"
    script.write_text(
        "CREATE TABLE image_probe (id integer); INSERT INTO image_probe VALUES (42);\n"
    )
    with running(
        pg["image_id"],
        "-e",
        "POSTGRES_PASSWORD=synthetic-image-probe-password",
        "-e",
        "POSTGRES_USER=probe",
        "-e",
        "POSTGRES_DB=probe",
        "--mount",
        f"type=bind,src={script},dst=/docker-entrypoint-initdb.d/probe.sql,readonly",
    ) as name:
        # The initialization server can already answer SQL while PID 1 is still
        # the root entrypoint. Wait for its final privilege drop before probing.
        wait_command(
            name,
            "sh",
            "-c",
            "grep -q '^Uid:[[:space:]]*70[[:space:]]' /proc/1/status",
        )
        query = [
            "psql",
            "-U",
            "probe",
            "-d",
            "probe",
            "-Atqc",
            "SELECT id FROM image_probe",
        ]
        assert wait_command(name, *query) == "42"
        assert_container_identity(name, pg)
        status = images.command("docker", "exec", name, "cat", "/proc/1/status")
        assert (
            next(
                line for line in status.splitlines() if line.startswith("Uid:")
            ).split()[1:]
            == ["70"] * 4
        )
        images.command("docker", "restart", name)
        assert wait_command(name, *query) == "42"
        images.command("docker", "stop", "--time", "10", name)
        assert (
            images.command("docker", "inspect", "--format", "{{.State.ExitCode}}", name)
            == "0"
        )
    for item in (caddy, pg, supply_chain["application"]):
        images.command(
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "sh",
            item["image_id"],
            "-c",
            "test ! -e /usr/local/go && ! command -v go",
        )


@pytest.mark.req("NFR-026", kind="configuration check", part="dependency-locks")
@pytest.mark.parametrize("language", ["python", "go"])
def test_real_installers_reject_corrupted_dependency_hashes(
    supply_chain: dict[str, Any], tmp_path: Path, language: str
) -> None:
    import os
    import re
    import shutil

    if language == "python":
        item = supply_chain["effective"]["python"]
        for name in ("pyproject.toml", "uv.lock", ".python-version"):
            shutil.copy2(ROOT / name, tmp_path / name)
        path = tmp_path / "uv.lock"
        pattern = (
            r'(?ms)(\[\[package\]\]\nname = "fastapi"\n.*?)(?=\n\[\[package\]\]|\Z)'
        )
        path.write_text(
            re.sub(
                pattern,
                lambda m: re.sub(
                    r"sha256:[0-9a-f]{64}", "sha256:" + "0" * 64, m.group()
                ),
                path.read_text(),
            )
        )
        command = [
            "uv",
            "sync",
            "--python",
            "/usr/local/bin/python",
            "--locked",
            "--no-dev",
            "--no-cache",
        ]
        expected = "Hash mismatch"
    else:
        item = supply_chain["effective"]["builder"]
        for name in ("go.mod", "go.sum"):
            shutil.copy2(ROOT / "docker/go" / name, tmp_path / name)
        path = tmp_path / "go.sum"
        path.write_text(
            re.sub(
                r"(?m)^(github.com/caddyserver/xcaddy v0.4.7 )h1:[^\n]+$",
                r"\g<1>h1:" + "A" * 43 + "=",
                path.read_text(),
            )
        )
        command = ["go", "mod", "download"]
        expected = "checksum mismatch"
    images.require_effective(ROOT, item)
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "-e",
            "GOPATH=/tmp/go",
            "--mount",
            f"type=bind,src={tmp_path},dst=/probe",
            "--workdir",
            "/probe",
            "--entrypoint",
            command[0],
            item["image_id"],
            *command[1:],
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert expected in result.stderr


@pytest.mark.req("NFR-026", kind="configuration check", part="build-scans")
def test_real_scanner_errors_cannot_satisfy_vulnerability_verification(
    supply_chain: dict[str, Any],
) -> None:
    identity = "sha256:" + "f" * 64
    status = images.scanner(
        ROOT,
        "image",
        "--config",
        "docker/trivy.yaml",
        "--image-src",
        "docker",
        identity,
    )
    assert status not in {0, 42}
    with pytest.raises(ValueError, match="Scanner error"):
        images.check_scan({}, identity, status)
