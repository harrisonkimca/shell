"""Real Buildx/Trivy evidence, including the pinned vulnerable fixture."""

import copy
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
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
    components = images.check_grype_sbom(
        ROOT / application["sbom"], application["image_id"]
    )
    installed = images.installed_packages(application["image_id"])
    assert installed["python"] and installed["os"]
    for name, version in [*installed["python"].items(), *installed["os"].items()]:
        assert (name.lower().replace("_", "-"), version) in components, (name, version)


@pytest.mark.req("NFR-024", kind="configuration check", part="image-sbom")
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
        packages = images.check_grype_sbom(ROOT / item["sbom"], item["image_id"])
        for group in item["installed"].values():
            assert {
                (k.lower().replace("_", "-"), v) for k, v in group.items()
            } <= packages


def extracted(identity: str, path: str) -> bytes:
    container = images.command(
        "docker", "create", "--platform", images.PLATFORM, identity
    )
    try:
        return subprocess.check_output(["docker", "cp", container + ":" + path, "-"])
    finally:
        images.command("docker", "rm", "-v", container)


@contextmanager
def running(
    reference: str, *options: str, command: tuple[str, ...] = ()
) -> Iterator[str]:
    name = "shell-supply-chain-" + uuid.uuid4().hex[:12]
    images.command("docker", "run", "-d", "--name", name, *options, reference, *command)
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
    # Extract the upstream binary without starting its rejected image. Execute
    # only that parity probe in the already-scanned effective image.
    archive = extracted(original["image_id"], "/usr/bin/caddy")
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        member = tar.getmembers()[0]
        assert (member.uid, member.gid) == (1001, 1001)
        expected_capability = member.pax_headers["SCHILY.xattr.security.capability"]
        data = tar.extractfile(member)
        assert data is not None
        binary = tmp_path / "upstream-caddy"
        binary.write_bytes(data.read())
        binary.chmod(0o755)
    with tarfile.open(
        fileobj=io.BytesIO(extracted(caddy["image_id"], "/usr/bin/caddy"))
    ) as tar:
        assert (
            tar.getmembers()[0].pax_headers["SCHILY.xattr.security.capability"]
            == expected_capability
        )
    args = ["list-modules", "--versions"]
    expected = images.command(
        "docker",
        "run",
        "--rm",
        "-v",
        f"{binary}:/original-caddy:ro",
        "--network",
        "none",
        "--read-only",
        "--user",
        "1001:1001",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--entrypoint",
        "/original-caddy",
        caddy["image_id"],
        *args,
    )
    assert (
        images.command("docker", "run", "--rm", caddy["image_id"], "caddy", *args)
        == expected
    )
    assert (
        images.command(
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "stat",
            caddy["image_id"],
            "-c",
            "%u:%g",
            "/usr/bin/caddy",
        )
        == "1001:1001"
    )
    assert "cap_net_bind_service" in images.command(
        "docker",
        "run",
        "--rm",
        "--entrypoint",
        "getcap",
        caddy["image_id"],
        "/usr/bin/caddy",
    )
    assert "http.handlers.rate_limit" not in expected
    with running(caddy["image_id"]) as name:
        assert "Caddy" in wait_command(name, "wget", "-qO-", "http://127.0.0.1/")
        assert_container_identity(name, caddy)
    pg = supply_chain["effective"]["postgres"]
    original = supply_chain["inputs"]["POSTGRES_IMAGE"]
    entrypoint = "/usr/local/bin/docker-entrypoint.sh"

    def read_entrypoint(identity: str) -> str:
        with tarfile.open(fileobj=io.BytesIO(extracted(identity, entrypoint))) as tar:
            data = tar.extractfile(tar.getmembers()[0])
            assert data is not None
            return hashlib.sha256(data.read()).hexdigest()

    assert read_entrypoint(pg["image_id"]) == read_entrypoint(original["image_id"])
    assert "GOSU_VERSION=1.20" in pg["docker"]["Config"]["Env"]
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


@pytest.mark.req("NFR-026", kind="configuration check", part="database-rejection")
@pytest.mark.parametrize("failure", ["missing", "unusable", "update"])
def test_real_trivy_missing_database_is_fatal(
    tmp_path: Path,
    failure: str,
    capfd: pytest.CaptureFixture[str],
    scanner_image: dict[str, Any],
) -> None:
    identity = scanner_image["Id"]
    status = images.scanner(
        ROOT,
        "image",
        "--config",
        "docker/trivy.yaml",
        "--image-src",
        "docker",
        "--format",
        "json",
        "--output",
        "reports/images/db-baseline.json",
        identity,
    )
    assert status == 42
    with pytest.raises(images.VulnerableImage):
        images.check_scan(
            json.loads((ROOT / "reports/images/db-baseline.json").read_text()),
            identity,
            status,
        )
    capfd.readouterr()
    for name in ("trivy", "grype"):
        (tmp_path / "docker").mkdir(exist_ok=True)
        shutil.copy(ROOT / f"docker/{name}.yaml", tmp_path / f"docker/{name}.yaml")
    database = tmp_path / "db"
    if failure == "update":
        shutil.copytree(images.trivy_database(), database)
        metadata = database / "db/metadata.json"
        data = json.loads(metadata.read_text())
        data["NextUpdate"] = "2000-01-01T00:00:00Z"
        # Trivy also permits one hour of same-run reuse after a download.
        # Expire that interval so this fixture requires a successful update.
        data["DownloadedAt"] = "2000-01-01T00:00:00Z"
        metadata.write_text(json.dumps(data))
    elif failure == "unusable":
        (database / "db").mkdir(parents=True)
        shutil.copy(
            images.trivy_database() / "db/metadata.json", database / "db/metadata.json"
        )
        (database / "db/trivy.db").write_text("unusable vulnerability database")
    status = images.scanner(
        tmp_path,
        "image",
        "--config",
        "docker/trivy.yaml",
        *(["--skip-db-update"] if failure != "update" else []),
        "--image-src",
        "docker",
        identity,
        offline=True,
        database=database,
    )
    captured = capfd.readouterr()
    diagnostic = captured.out + captured.err
    assert status not in {0, 42}
    assert "database" in diagnostic.lower() or "db error" in diagnostic.lower(), (
        diagnostic
    )
    expected = {
        "missing": "first run",
        "unusable": "invalid database",
        "update": "failed to download",
    }[failure]
    assert expected in diagnostic.lower(), diagnostic
    (ROOT / "reports/images" / f"trivy-db-{failure}.log").write_text(diagnostic)


@pytest.mark.req("NFR-024", kind="configuration check", part="coverage-rejection")
def test_pipeline_evidence_is_independently_complete(
    supply_chain: dict[str, Any],
) -> None:

    broken = copy.deepcopy(supply_chain)
    broken["effective"].pop("caddy")
    with pytest.raises(ValueError, match="coverage"):
        images.check_effective_coverage(ROOT, broken)
    references = images.prepared_references(ROOT, supply_chain, scanned=True)
    assert references["caddy"] == supply_chain["effective"]["caddy"]["image_id"]
    assert references["postgres"] == supply_chain["effective"]["postgres"]["image_id"]


@pytest.mark.req("NFR-026", kind="configuration check", part="build-scans")
def test_caddy_nonroot_binds_privileged_port(
    supply_chain: dict[str, Any], tmp_path: Path
) -> None:
    config = tmp_path / "Caddyfile"
    config.write_text(
        '{\n admin off\n}\nhttp://:80 {\n respond "capability works"\n}\n'
    )
    with running(
        supply_chain["effective"]["caddy"]["image_id"],
        "--user",
        "1001:1001",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "NET_BIND_SERVICE",
        "--sysctl",
        "net.ipv4.ip_unprivileged_port_start=1024",
        "-v",
        f"{config}:/etc/caddy/Caddyfile:ro",
    ) as name:
        assert "capability works" in wait_command(
            name, "wget", "-qO-", "http://127.0.0.1/"
        )


@pytest.mark.req("NFR-024", kind="configuration check", part="image-sbom")
@pytest.mark.req("NFR-026", kind="configuration check", part="build-scans")
def test_caddy_migration_matches_binary_and_both_inventories(
    supply_chain: dict[str, Any],
) -> None:
    item = supply_chain["effective"]["caddy"]
    installed = item["installed"]["go"]
    for module, version in {
        "github.com/caddyserver/caddy/v2": "v2.11.9",
        "github.com/smallstep/certificates": "v0.30.3-0.20261105213751-6d5a251fbe01",
        "go.step.sm/crypto": "v0.92.0",
        "github.com/smallstep/cli-utils": "v0.13.0",
        "github.com/go-jose/go-jose/v4": "v4.1.9",
        "golang.org/x/crypto": "v0.59.0",
    }.items():
        assert installed[module] == version
    assert "github.com/go-jose/go-jose/v3" not in installed
    for packages in (
        images.check_grype_sbom(ROOT / item["sbom"], item["image_id"]),
        images.check_sbom(ROOT / item["trivy_sbom"], item["image_id"]),
    ):
        assert ("github.com/go-jose/go-jose/v4", "v4.1.9") in packages
        assert not any(name == "github.com/go-jose/go-jose/v3" for name, _ in packages)


@pytest.mark.req("NFR-026", kind="configuration check", part="build-scans")
def test_caddy_migrated_internal_ca_serves_verified_https(
    supply_chain: dict[str, Any], tmp_path: Path
) -> None:
    caddy = supply_chain["effective"]["caddy"]
    application = supply_chain["effective"]["application"]
    config: dict[str, Any] = {
        "admin": {"disabled": True},
        "apps": {
            "pki": {"certificate_authorities": {"local": {"install_trust": False}}},
            "tls": {
                "automation": {
                    "policies": [
                        {
                            "subjects": ["localhost"],
                            "issuers": [{"module": "internal", "ca": "local"}],
                        }
                    ]
                }
            },
            "http": {
                "servers": {
                    "https": {
                        "listen": [":8443"],
                        "routes": [
                            {
                                "match": [{"host": ["localhost"]}],
                                "handle": [
                                    {"handler": "static_response", "body": "compat-tls"}
                                ],
                            }
                        ],
                        "tls_connection_policies": [{}],
                        "automatic_https": {"disable_redirects": True},
                    },
                    "plain": {
                        "listen": [":80"],
                        "routes": [
                            {
                                "handle": [
                                    {
                                        "handler": "static_response",
                                        "body": "compat-http",
                                    }
                                ]
                            }
                        ],
                    },
                }
            },
        },
    }
    path = tmp_path / "caddy.json"
    path.write_text(json.dumps(config))
    with running(
        caddy["image_id"],
        "--network",
        "none",
        "--read-only",
        "--user",
        "1001:1001",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "NET_BIND_SERVICE",
        "--security-opt",
        "no-new-privileges",
        "--sysctl",
        "net.ipv4.ip_unprivileged_port_start=1024",
        "--tmpfs",
        "/data:uid=1001,gid=1001,mode=0700",
        "--tmpfs",
        "/config:uid=1001,gid=1001,mode=0700",
        "-v",
        f"{path}:/runtime.json:ro",
        command=("caddy", "run", "--config", "/runtime.json"),
    ) as name:
        assert_container_identity(name, caddy)
        assert wait_command(name, "wget", "-qO-", "http://127.0.0.1/") == "compat-http"
        cert = tmp_path / "root.crt"
        cert.write_text(
            wait_command(name, "cat", "/data/caddy/pki/authorities/local/root.crt")
            + "\n"
        )
        code = (
            "import ssl,urllib.request,urllib.error\n"
            "url='https://localhost:8443/'\n"
            "try: urllib.request.urlopen(url,timeout=5)\n"
            "except urllib.error.URLError as e:\n"
            " assert isinstance(e.reason,ssl.SSLCertVerificationError)\n"
            "else: raise AssertionError('Untrusted CA was accepted')\n"
            "context=ssl.create_default_context(cafile='/root.crt')\n"
            "assert context.check_hostname and context.verify_mode==ssl.CERT_REQUIRED\n"
            "response=urllib.request.urlopen(url,context=context,timeout=5)\n"
            "assert response.read()==b'compat-tls'\n"
            "print('Verified internal-CA HTTPS')\n"
        )
        assert (
            images.command(
                "docker",
                "run",
                "--rm",
                "--network",
                "container:" + name,
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "-v",
                f"{cert}:/root.crt:ro",
                application["image_id"],
                "python",
                "-c",
                code,
            )
            == "Verified internal-CA HTTPS"
        )
        (ROOT / "reports/images/caddy-https.json").write_text(
            json.dumps(
                {
                    "caddy": caddy["image_id"],
                    "client": application["image_id"],
                    "untrusted_ca_rejected": True,
                    "trusted_ca_verified": True,
                    "port_80_nonroot": True,
                }
            )
            + "\n"
        )
