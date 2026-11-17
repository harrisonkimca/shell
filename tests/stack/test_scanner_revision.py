"""Real scanner regressions independent of candidate preparation success."""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts import images

ROOT = Path(__file__).resolve().parents[2]
PRINCIPALS = [
    pytest.param(
        "python",
        "docker.io/library/python@sha256:b0c5cb8792bf58879f532c1e10f44e1af02d72735758374198f9717d67a7ae52",
        {"High", "Critical"},
        marks=pytest.mark.req(
            "NFR-026", kind="configuration check", part="principal-python-rejection"
        ),
    ),
    pytest.param(
        "postgresql",
        "docker.io/library/postgres@sha256:ec68817297c5984a00c85c9e3bbd88079d0217284f1a3f0525603a6f9b883916",
        {"High"},
        marks=pytest.mark.req(
            "NFR-026", kind="configuration check", part="principal-postgres-rejection"
        ),
    ),
    pytest.param(
        "redis",
        "docker.io/library/redis@sha256:f887e6dacdcfa8e14af2f625fdf4474ff8c37dc36ce13b9e89e6e9a901f155ad",
        {"High", "Critical"},
        marks=pytest.mark.req(
            "NFR-026", kind="configuration check", part="principal-redis-rejection"
        ),
    ),
]


@pytest.mark.req("NFR-026", kind="configuration check", part="build-scans")
@pytest.mark.parametrize(
    "name,reference,severities", PRINCIPALS, ids=["python", "postgresql", "redis"]
)
def test_real_principal_vulnerabilities_rejected(
    name: str, reference: str, severities: set[str], scanner_database: Path
) -> None:
    images.command("docker", "pull", "--platform", images.PLATFORM, reference)
    identity = images.local_identity(reference)
    output = ROOT / "reports/images"
    output.mkdir(parents=True, exist_ok=True)
    report, bom = (
        output / f"fixture-{name}.grype.json",
        output / f"fixture-{name}.cdx.json",
    )
    status = images.grype(ROOT, identity["Id"], report, bom, scanner_database)
    data = json.loads(report.read_text())
    assert (
        status == 0
    )  # Raw scanner execution succeeds; the independent JSON gate rejects.
    with pytest.raises(images.VulnerableImage):
        images.check_grype(data, identity, status)
    findings = [
        m
        for m in data["matches"]
        if m["artifact"]["name"] == name
        and m["artifact"]["type"] == "binary"
        and m["vulnerability"]["fix"]["state"] == "fixed"
    ]
    assert severities <= {m["vulnerability"]["severity"] for m in findings}
    assert any(n == name for n, _ in images.check_grype_sbom(bom, identity["Id"]))


@pytest.mark.req("NFR-026", kind="configuration check", part="scanner-policy-rejection")
@pytest.mark.parametrize("bypass", ["ambient", "environment"])
def test_real_grype_ambient_bypasses_cannot_suppress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner_database: Path, bypass: str
) -> None:
    (tmp_path / "docker").mkdir()
    for tool in ("trivy", "grype"):
        shutil.copy(ROOT / f"docker/{tool}.yaml", tmp_path / f"docker/{tool}.yaml")
    if bypass == "ambient":
        (tmp_path / ".grype.yaml").write_text(
            'ignore:\n  - package:\n      name: ".*"\n'
        )
    else:
        monkeypatch.setenv("GRYPE_IGNORE_WONTFIX", "fixed,unknown")
        monkeypatch.setenv("GRYPE_IGNORE_STATES", "fixed,unknown")
        monkeypatch.setenv("GRYPE_DB_AUTO_UPDATE", "false")
        monkeypatch.setenv("SYFT_SELECT_CATALOGERS", "os")
    tool = images.verified_tool("grype", ROOT)

    def selected_tool(name: str, root: Path) -> Path:
        return tool

    monkeypatch.setattr(images, "verified_tool", selected_tool)
    ref = (
        "docker.io/library/redis@sha256:"
        "f887e6dacdcfa8e14af2f625fdf4474ff8c37dc36ce13b9e89e6e9a901f155ad"
    )
    images.command("docker", "pull", "--platform", images.PLATFORM, ref)
    identity = images.local_identity(ref)
    # Reproduce Fable's original vulnerability before checking the wrapper.
    before = ROOT / "reports/images" / ("bypass-" + bypass + ".before.json")
    before.parent.mkdir(parents=True, exist_ok=True)
    unsafe_env = dict(os.environ)
    unsafe_env["GRYPE_DB_CACHE_DIR"] = str(scanner_database)
    baseline = subprocess.run(
        [
            str(tool),
            identity["Id"],
            "--from",
            "docker",
            "--platform",
            images.PLATFORM,
            *(
                ["-c", str(ROOT / "docker/grype.yaml")]
                if bypass == "environment"
                else []
            ),
            "--fail-on",
            "high",
            "-o",
            "json",
            "--file",
            str(before),
        ],
        cwd=tmp_path,
        env=unsafe_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert baseline.returncode == 0, baseline.stderr
    assert json.loads(before.read_text()).get("ignoredMatches")
    report, bom = tmp_path / "report.json", tmp_path / "bom.json"
    status = images.grype(tmp_path, identity["Id"], report, bom, scanner_database)
    with pytest.raises(images.VulnerableImage):
        images.check_grype(json.loads(report.read_text()), identity, status)
    assert not json.loads(report.read_text()).get("ignoredMatches")
    shutil.copy2(report, ROOT / "reports/images" / ("bypass-" + bypass + ".after.json"))


@pytest.mark.req("NFR-026", kind="configuration check", part="database-rejection")
@pytest.mark.parametrize("failure", ["missing", "unusable", "update"])
def test_real_grype_database_update_failures_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scanner_database: Path,
    failure: str,
) -> None:
    if failure == "update":
        database = scanner_database
    else:
        database = tmp_path / "db"
        if failure == "unusable":
            (database / "6").mkdir(parents=True)
            (database / "6/vulnerability.db").write_text("unusable database")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    report, bom = tmp_path / "r.json", tmp_path / "b.json"
    status = images.grype(ROOT, "sha256:" + "f" * 64, report, bom, database)
    assert status != 0
    with pytest.raises(ValueError, match="Grype scanner error"):
        images.check_grype({}, {}, status)


@pytest.mark.req("NFR-026", kind="configuration check", part="database-rejection")
def test_real_grype_stale_database_is_not_accepted(
    tmp_path: Path, scanner_database: Path
) -> None:
    # The scanner's actual age validator, with a deliberately expired limit.
    policy = tmp_path / "expired.yaml"
    policy.write_text((ROOT / "docker/grype.yaml").read_text() + "\n# expiry test\n")

    value: dict[str, Any] = yaml.safe_load(policy.read_text())
    value["db"]["max-allowed-built-age"] = "1ns"
    value["db"]["auto-update"] = False
    policy.write_text(yaml.safe_dump(value))
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GRYPE_", "SYFT_"))}
    env["GRYPE_DB_CACHE_DIR"] = str(scanner_database)
    result = subprocess.run(
        [str(images.verified_tool("grype")), "db", "status", "-c", str(policy)],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "old" in result.stderr.lower() or "age" in result.stderr.lower()
