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
    capfd: pytest.CaptureFixture[str],
    scanner_image: dict[str, Any],
) -> None:
    identity = scanner_image
    report, bom = tmp_path / "r.json", tmp_path / "b.json"
    status = images.grype(ROOT, identity["Id"], report, bom, scanner_database)
    assert status == 0
    assert json.loads(report.read_text())["source"]["target"]["layers"]
    shutil.copy2(report, ROOT / "reports/images" / f"grype-db-{failure}.baseline.json")
    capfd.readouterr()
    if failure == "update":
        database = scanner_database
    else:
        database = tmp_path / "db"
        if failure == "unusable":
            (database / "6").mkdir(parents=True)
            (database / "6/vulnerability.db").write_text("unusable database")
    if failure == "missing":
        assert not (database / "6/vulnerability.db").exists()
    if failure == "update":
        assert (database / "6/vulnerability.db").is_file()
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    report, bom = tmp_path / "r.json", tmp_path / "b.json"
    status = images.grype(ROOT, identity["Id"], report, bom, database)
    captured = capfd.readouterr()
    diagnostic = captured.out + captured.err
    assert "database" in diagnostic.lower(), diagnostic
    assert "update" in diagnostic.lower() or "does not exist" in diagnostic.lower(), (
        diagnostic
    )
    assert "connection refused" in diagnostic.lower(), diagnostic
    if failure == "unusable":
        assert "file is not a database" in diagnostic.lower(), diagnostic
    (ROOT / "reports/images" / f"grype-db-{failure}.log").write_text(diagnostic)
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


@pytest.mark.req("NFR-026", kind="configuration check", part="scanner-policy-rejection")
@pytest.mark.parametrize("state", ["fixed", "unknown"])
def test_real_trivy_preserves_and_rejects_unrated_findings(state: str) -> None:
    # Controlled native-report fixture exercises the pinned scanner's actual
    # filtering. It does not claim discovery of a real UNKNOWN advisory.
    output = ROOT / "reports/images"
    output.mkdir(parents=True, exist_ok=True)
    identity = "sha256:" + "a" * 64
    source = output / f"unrated-{state}.fixture.json"
    converted = output / f"unrated-{state}.filtered.json"
    report: dict[str, Any] = {
        "SchemaVersion": 2,
        "ArtifactName": "controlled-unrated-fixture",
        "ArtifactType": "container_image",
        "Metadata": {"ImageID": identity},
        "Results": [
            {"Target": "controlled-fixture", "Class": "lang-pkgs", "Type": "gobinary"}
        ],
    }

    def convert() -> dict[str, Any]:
        status = images.scanner(
            ROOT,
            "convert",
            "--config",
            "docker/trivy.yaml",
            "--ignorefile",
            "/dev/null",
            "--severity",
            "UNKNOWN",
            "--exit-code",
            "0",
            "--format",
            "json",
            "--output",
            str(converted.relative_to(ROOT)),
            str(source.relative_to(ROOT)),
        )
        assert status == 0
        return json.loads(converted.read_text())

    source.write_text(json.dumps(report))
    images.check_scan(convert(), identity, 0)
    shutil.copy2(converted, output / f"unrated-{state}.baseline.json")
    finding = {
        "VulnerabilityID": "TEST-UNRATED",
        "PkgName": "controlled-fixture",
        "InstalledVersion": "1",
        "Severity": "UNKNOWN",
        "Status": state,
        "FixedVersion": "2" if state == "fixed" else "",
    }
    report["Results"] = [{"Target": "controlled-fixture", "Vulnerabilities": [finding]}]
    source.write_text(json.dumps(report))
    filtered = convert()
    assert filtered["Results"][0]["Vulnerabilities"][0]["Severity"] == "UNKNOWN"
    with pytest.raises(images.VulnerableImage, match="Blocking vulnerabilities"):
        images.check_scan(filtered, identity, 0)
