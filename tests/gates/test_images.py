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
