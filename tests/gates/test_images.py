"""Image/source rejection checks for the approved Stage 0 slice 4."""

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from scripts import images

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.req("NFR-024", kind="configuration check", part="trusted-sources")
def test_actual_sources_and_effective_build_inputs() -> None:
    pins = images.check_configuration(ROOT)
    assert set(images.build_inputs(ROOT, pins)) <= set(pins.values())


@pytest.fixture
def configured(tmp_path: Path) -> Path:
    for name in (
        "docker/images.env",
        "docker/api/Dockerfile",
        "docker/trivy.yaml",
        "config/trusted-sources.toml",
        "pyproject.toml",
        "uv.lock",
        ".python-version",
    ):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / name, target)
    for name in ("go", "python", "caddy", "postgres"):
        shutil.copytree(ROOT / "docker" / name, tmp_path / "docker" / name)
    return tmp_path


@pytest.mark.parametrize(
    "mutation",
    [
        "mutable",
        "repository",
        "registry-lookalike",
        "index",
        "artifact",
        "artifact-lookalike",
        "direct-source",
        "extra-index",
        "build-arg",
        "copy-image",
    ],
)
def test_unapproved_or_unpinned_inputs_rejected(
    configured: Path, mutation: str
) -> None:
    path = configured / "docker/images.env"
    if mutation == "mutable":
        path.write_text(
            path.read_text().split("\n", 1)[0] + "\nBAD_IMAGE=python:3.13\n"
        )
    elif mutation in {"repository", "registry-lookalike"}:
        text = path.read_text().replace(
            "docker.io/library/python",
            "docker.io/unapproved/python"
            if mutation == "repository"
            else "docker.io.evil/library/python",
        )
        path.write_text(text)
    elif mutation in {"index", "artifact", "artifact-lookalike", "direct-source"}:
        path = configured / "uv.lock"
        text = path.read_text()
        if mutation == "index":
            text = text.replace(
                "https://pypi.org/simple", "https://evil.example/simple"
            )
        elif mutation == "direct-source":
            text = text.replace(
                'registry = "https://pypi.org/simple"',
                'url = "https://evil.example/pkg.whl"',
            )
        else:
            text = text.replace(
                "https://files.pythonhosted.org/packages/",
                "https://"
                + (
                    "files.pythonhosted.org.evil"
                    if mutation == "artifact-lookalike"
                    else "evil.example"
                )
                + "/packages/",
            )
        path.write_text(text)
    elif mutation == "extra-index":
        path = configured / "pyproject.toml"
        path.write_text(
            path.read_text()
            + '\n[[tool.uv.index]]\nurl = "https://evil.example/simple"\n'
        )
    else:
        path = configured / "docker/api/Dockerfile"
        path.write_text(
            path.read_text()
            + (
                "\nFROM ${UNPINNED_IMAGE}\n"
                if mutation == "build-arg"
                else "\nCOPY --from=evil/image:latest /x /x\n"
            )
        )
    with pytest.raises((ValueError, RuntimeError)):
        images.check_configuration(configured)


def test_repository_normalization_is_exact() -> None:
    assert (
        images.repository("python:3.13@sha256:" + "a" * 64)
        == "docker.io/library/python"
    )
    assert (
        images.repository("docker.io/axllent/mailpit@sha256:" + "a" * 64)
        == "docker.io/axllent/mailpit"
    )
    with pytest.raises(ValueError):
        images.repository("https://docker.io/library/python:latest")


@pytest.mark.parametrize("mutation", ["arm64", "amd64", "duplicate", "child-pin"])
def test_index_requires_both_platforms(mutation: str) -> None:
    manifest: dict[str, Any] = {
        "manifests": [
            {
                "digest": "sha256:" + "a" * 64,
                "platform": {"os": "linux", "architecture": arch},
            }
            for arch in ("amd64", "arm64")
        ]
    }
    if mutation in {"amd64", "arm64"}:
        manifest["manifests"] = [
            m
            for m in manifest["manifests"]
            if m["platform"]["architecture"] != mutation
        ]
    elif mutation == "duplicate":
        manifest["manifests"].append(manifest["manifests"][0])
    else:
        manifest = {"config": {"digest": "sha256:" + "b" * 64}}
    with pytest.raises(ValueError):
        images.platform_digest(manifest)


@pytest.mark.parametrize(
    "mutation", ["missing", "invalid", "wrong-image", "empty", "missing-version"]
)
def test_sbom_rejection(tmp_path: Path, mutation: str) -> None:
    identity = "sha256:" + "a" * 64
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "container",
                "properties": [
                    {"name": "aquasecurity:trivy:ImageID", "value": identity},
                ],
            }
        },
        "components": [{"name": "libc", "version": "1", "type": "library"}],
    }
    path = tmp_path / "bom.json"
    if mutation == "invalid":
        path.write_text("not json")
    elif mutation != "missing":
        if mutation == "wrong-image":
            bom["metadata"]["component"]["properties"][0]["value"] = (
                "sha256:" + "b" * 64
            )
        elif mutation == "empty":
            bom["components"] = []
        else:
            del bom["components"][0]["version"]
        path.write_text(json.dumps(bom))
    with pytest.raises((ValueError, OSError)):
        images.check_sbom(path, identity)


@pytest.mark.parametrize("status", [1, 2, 42])
def test_scanner_errors_and_unsubstantiated_rejection_fail(status: int) -> None:
    with pytest.raises(ValueError):
        images.check_scan(
            {"Metadata": {"ImageID": "wrong"}}, "sha256:" + "a" * 64, status
        )


@pytest.mark.parametrize("severity", ["HIGH", "CRITICAL"])
def test_fixable_findings_are_never_exempted(severity: str) -> None:
    identity = "sha256:" + "a" * 64
    report = {
        "SchemaVersion": 2,
        "Metadata": {"ImageID": identity},
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "Severity": severity,
                        "FixedVersion": "2",
                        "VulnerabilityID": "synthetic",
                    }
                ]
            },
        ],
    }
    with pytest.raises(images.VulnerableImage):
        images.check_scan(report, identity, 42)


def test_missing_image_evidence_fails() -> None:
    with pytest.raises(ValueError, match="coverage"):
        images.check_coverage({"one", "two"}, {"one": {}})


def test_cyclonedx_17_keeps_versions_and_grouping_nodes(tmp_path: Path) -> None:
    identity = "sha256:" + "a" * 64
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {
            "component": {
                "properties": [
                    {"name": "aquasecurity:trivy:ImageID", "value": identity},
                ]
            }
        },
        "components": [
            {
                "type": "application",
                "name": "usr/local/bin/uv",
                "properties": [
                    {"name": "aquasecurity:trivy:Class", "value": "lang-pkgs"},
                    {"name": "aquasecurity:trivy:Type", "value": "rustbinary"},
                ],
            },
            {"type": "library", "name": "libc", "version": "1"},
        ],
    }
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(bom))
    assert ("libc", "1") in images.check_sbom(path, identity)
    del bom["components"][1]["version"]
    path.write_text(json.dumps(bom))
    with pytest.raises(ValueError):
        images.check_sbom(path, identity)


@pytest.mark.parametrize(
    "name", ["REDIS_IMAGE", "MAILPIT_IMAGE", "GO_IMAGE", "UNKNOWN_IMAGE"]
)
def test_upstream_rejection_cannot_authorize_unapproved_remediation(name: str) -> None:
    report = {
        "SchemaVersion": 2,
        "Metadata": {"ImageID": "sha256:" + "a" * 64},
        "Results": [{"Vulnerabilities": [{"Severity": "HIGH", "FixedVersion": "2"}]}],
    }
    with pytest.raises(ValueError):
        images.check_upstream(name, report, "sha256:" + "a" * 64, 42)


@pytest.mark.parametrize("name", ["PYTHON_IMAGE", "CADDY_IMAGE", "POSTGRES_IMAGE"])
def test_only_approved_upstreams_may_enter_preparation(name: str) -> None:
    identity = "sha256:" + "a" * 64
    report = {
        "SchemaVersion": 2,
        "Metadata": {"ImageID": identity},
        "Results": [{"Vulnerabilities": [{"Severity": "HIGH", "FixedVersion": "2"}]}],
    }
    images.check_upstream(name, report, identity, 42)
    with pytest.raises(ValueError):
        images.check_upstream(name, report, identity, 1)
    with pytest.raises(images.VulnerableImage):
        images.check_scan(report, identity, 42)


def test_loaded_build_identity_rejects_a_different_image() -> None:
    with pytest.raises(ValueError, match="identity"):
        images.check_build_identity(
            {"containerimage.digest": "sha256:" + "a" * 64}, "sha256:" + "b" * 64
        )


def test_os_inventory_retains_distribution_epoch_and_release() -> None:
    assert (
        images.package_version({"Epoch": 1, "Version": "1.3.1", "Release": "1+deb13u1"})
        == "1:1.3.1-1+deb13u1"
    )
    assert images.package_version({"Version": "3.24.4-r0"}) == "3.24.4-r0"


def test_vulnerable_effective_input_stops_before_dependent_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = "sha256:" + "a" * 64
    report = {
        "SchemaVersion": 2,
        "Metadata": {"ImageID": identity},
        "Results": [
            {"Vulnerabilities": [{"Severity": "CRITICAL", "FixedVersion": "2"}]}
        ],
    }
    (tmp_path / "scan.json").write_text(json.dumps(report))

    def unexpected_inspection(reference: str) -> dict[str, Any]:
        raise AssertionError("Rejected effective image reached dependent use")

    monkeypatch.setattr(images, "local_identity", unexpected_inspection)
    with pytest.raises(images.VulnerableImage):
        images.require_effective(
            tmp_path,
            {
                "scan": "scan.json",
                "image_id": identity,
                "scanner_status": 42,
                "reference": "prepared",
            },
        )


@pytest.mark.parametrize(
    "mutation", ["go-source", "go-version", "debian", "toolchain", "raw-app"]
)
def test_additional_sources_and_boundaries_are_enforced(
    configured: Path, mutation: str
) -> None:
    if mutation == "go-source":
        path = configured / "docker/go/go.mod"
        text = path.read_text().replace(
            "github.com/caddyserver/xcaddy", "evil.example/xcaddy"
        )
    elif mutation == "go-version":
        path = configured / "docker/go/go.mod"
        text = path.read_text().replace("v0.4.7", "v99.0.0")
    elif mutation == "debian":
        path = configured / "docker/python/debian.sources"
        text = path.read_text().replace("http://deb.debian.org", "http://evil.example")
    elif mutation == "toolchain":
        path = configured / "docker/go/Dockerfile"
        text = path.read_text().replace("GOTOOLCHAIN=local", "GOTOOLCHAIN=auto")
    else:
        path = configured / "docker/api/Dockerfile"
        text = path.read_text().replace("PREPARED_IMAGE", "PYTHON_IMAGE")
    path.write_text(text)
    with pytest.raises((ValueError, KeyError)):
        images.check_configuration(configured)


@pytest.mark.parametrize("architecture", ["amd64", "arm64"])
def test_identity_inspection_works_with_ci_docker_cli(
    monkeypatch: pytest.MonkeyPatch, architecture: str
) -> None:
    def inspect(*args: str) -> str:
        assert args == ("docker", "image", "inspect", "sha256:" + "a" * 64)
        return json.dumps([{"Os": "linux", "Architecture": architecture}])

    monkeypatch.setattr(images, "command", inspect)
    if architecture == "amd64":
        assert images.local_identity("sha256:" + "a" * 64)["Architecture"] == "amd64"
    else:
        with pytest.raises(ValueError, match="platform"):
            images.local_identity("sha256:" + "a" * 64)


def test_xcaddy_local_main_wrapper_still_requires_versioned_caddy_library(
    tmp_path: Path,
) -> None:
    identity = "sha256:" + "a" * 64
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {
            "component": {
                "properties": [
                    {"name": "aquasecurity:trivy:ImageID", "value": identity}
                ]
            }
        },
        "components": [
            {
                "type": "library",
                "name": "caddy",
                "purl": "pkg:golang/caddy",
                "properties": [
                    {"name": "aquasecurity:trivy:PkgID", "value": "caddy"},
                    {"name": "aquasecurity:trivy:PkgType", "value": "gobinary"},
                ],
            },
            {
                "type": "library",
                "name": "github.com/caddyserver/caddy/v2",
                "version": "v2.11.9",
            },
        ],
    }
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(bom))
    assert ("github.com/caddyserver/caddy/v2", "v2.11.9") in images.check_sbom(
        path, identity
    )
    del bom["components"][1]["version"]
    path.write_text(json.dumps(bom))
    with pytest.raises(ValueError):
        images.check_sbom(path, identity)
