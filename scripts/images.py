"""Single CI Buildx/Trivy path; local development does not invoke this command."""

import json
import os
import re
import subprocess
import sys
import tomllib
import uuid
from pathlib import Path
from string import Template
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PLATFORM = "linux/amd64"
TRIVY = (
    "docker.io/aquasec/trivy:0.76.2@"
    "sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb"
)
# Deliberately vulnerable historical image, never a build/service candidate.
FIXTURE = (
    "docker.io/library/python:3.13.0-slim-bookworm@"
    "sha256:0de818129b26ed8f46fd772f540c80e277b67a28229531a1ba0fdacfaed19bcb"
)
DIGEST = r"sha256:[0-9a-f]{64}"


def command(*args: str, root: Path = ROOT) -> str:
    return subprocess.check_output(args, cwd=root, text=True).strip()


def repository(reference: str) -> str:
    if "://" in reference:
        raise ValueError("Image references cannot be URLs")
    if not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*(?:@sha256:[0-9a-f]{64})?", reference):
        raise ValueError(f"Invalid image reference: {reference}")
    name = reference.split("@", 1)[0]
    name = re.sub(r":[^/]+$", "", name)
    first = name.split("/", 1)[0]
    if "/" not in name or not ("." in first or ":" in first or first == "localhost"):
        name = "docker.io/" + name
    name = name.replace("index.docker.io/", "docker.io/", 1)
    if name.startswith("docker.io/") and name.count("/") == 1:
        name = name.replace("docker.io/", "docker.io/library/", 1)
    return name


def build_inputs(root: Path, arguments: dict[str, str]) -> list[str]:
    """Resolve FROM/external COPY with the very arguments passed to Buildx."""
    stages: set[str] = set()
    inputs: list[str] = []
    for line in (root / "docker/api/Dockerfile").read_text().splitlines():
        tokens = line.split()
        if not tokens or tokens[0].startswith("#"):
            continue
        if tokens[0].upper() == "ARG":
            # Defaults/overrides cannot silently replace the supplied pins.
            if len(tokens) != 2 or tokens[1] not in arguments:
                raise ValueError("Unknown or overridden image build argument")
        if tokens[0].upper() == "FROM":
            try:
                reference = Template(tokens[1]).substitute(arguments)
            except KeyError as error:
                raise ValueError("Missing effective build argument") from error
            if reference not in stages:
                inputs.append(reference)
            if len(tokens) == 4 and tokens[2].upper() == "AS":
                stages.add(tokens[3])
        if tokens[0].upper() == "COPY":
            for token in tokens[1:]:
                if token.startswith("--from="):
                    reference = Template(token[7:]).substitute(arguments)
                    if reference not in stages:
                        inputs.append(reference)
    if not inputs:
        raise ValueError("Missing Dockerfile inputs")
    return inputs


def check_configuration(root: Path) -> dict[str, str]:
    trusted = tomllib.loads((root / "config/trusted-sources.toml").read_text())
    pins: dict[str, str] = {}
    for line in (root / "docker/images.env").read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        name, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z_]*_IMAGE", name) or name in pins:
            raise ValueError("Invalid/duplicate image pin")
        pins[name] = value
    for reference in [*pins.values(), *build_inputs(root, pins)]:
        if not re.fullmatch(rf"[^@]+@{DIGEST}", reference):
            raise ValueError("Images require digest pins")
        if repository(reference) not in trusted["image-repositories"]:
            raise ValueError(f"Unapproved image repository: {reference}")
        if reference not in pins.values():
            raise ValueError("Dockerfile input absent from pinned configuration")
    project = tomllib.loads((root / "pyproject.toml").read_text())
    uv = project.get("tool", {}).get("uv", {})
    for index in uv.get("index", []):
        if index["url"] not in trusted["package-indexes"]:
            raise ValueError("Unapproved package index")
    if any(
        key in uv for key in ("sources", "index-url", "extra-index-url", "find-links")
    ):
        raise ValueError("Unexpected dependency source override")
    lock = tomllib.loads((root / "uv.lock").read_text())
    for package in lock["package"]:
        source = package["source"]
        if package["name"] == "shell" and source in (
            {"virtual": "."},
            {"editable": "."},
        ):
            continue
        if (
            set(source) != {"registry"}
            or source["registry"] not in trusted["package-indexes"]
        ):
            raise ValueError("Unapproved resolved dependency source")
        artifacts = [
            *package.get("wheels", []),
            *([package["sdist"]] if "sdist" in package else []),
        ]
        if not artifacts or any(
            not any(a["url"].startswith(p) for p in trusted["distribution-prefixes"])
            for a in artifacts
        ):
            raise ValueError("Unapproved distribution source")
    return pins


def platform_digest(index: dict[str, Any]) -> str:
    selected: dict[str, str] = {}
    for architecture in ("amd64", "arm64"):
        manifests = [
            m
            for m in index.get("manifests", [])
            if m.get("platform", {}).get("os") == "linux"
            and m["platform"].get("architecture") == architecture
        ]
        if len(manifests) != 1 or not re.fullmatch(
            DIGEST, manifests[0].get("digest", "")
        ):
            raise ValueError(
                f"Index must contain exactly one linux/{architecture} manifest"
            )
        selected[architecture] = manifests[0]["digest"]
    return selected["amd64"]


class VulnerableImage(ValueError):
    def __init__(self, findings: list[dict[str, Any]]) -> None:
        self.findings = findings
        super().__init__(f"Fixable HIGH/CRITICAL vulnerabilities: {findings}")


def check_scan(report: dict[str, Any], identity: str, status: int) -> None:
    if status not in (0, 42):
        raise ValueError(f"Scanner error: exit {status}")
    if (
        report.get("SchemaVersion") != 2
        or report.get("Metadata", {}).get("ImageID") != identity
        or not isinstance(report.get("Results"), list)
    ):
        raise ValueError("Invalid scan or wrong-image association")
    findings = [
        v
        for result in report["Results"]
        for v in result.get("Vulnerabilities", [])
        if v.get("FixedVersion") and v.get("Severity") in {"HIGH", "CRITICAL"}
    ]
    if findings:
        raise VulnerableImage(findings)
    if status != 0:
        raise ValueError("Scanner rejected image without vulnerability evidence")


def check_sbom(path: Path, identity: str) -> set[tuple[str, str]]:
    bom = json.loads(path.read_text())
    if (
        bom.get("bomFormat") != "CycloneDX"
        or bom.get("specVersion") not in {"1.4", "1.5", "1.6"}
        or bom.get("version") != 1
    ):
        raise ValueError("Invalid CycloneDX inventory")
    props = bom.get("metadata", {}).get("component", {}).get("properties", [])
    if not any(
        p["name"] == "aquasecurity:trivy:ImageID" and p["value"] == identity
        for p in props
    ):
        raise ValueError("SBOM image identity mismatch")
    components = bom.get("components", [])
    if not components or any(
        not c.get("name") or not c.get("version") for c in components
    ):
        raise ValueError("Missing package names/versions in SBOM")
    return {(c["name"].lower().replace("_", "-"), c["version"]) for c in components}


def check_coverage(expected: set[str], actual: dict[str, Any]) -> None:
    if set(actual) != expected:
        raise ValueError("Incomplete image coverage")


def local_identity(reference: str) -> dict[str, Any]:
    result = json.loads(
        command("docker", "image", "inspect", "--platform", PLATFORM, reference)
    )[0]
    if result["Os"] + "/" + result["Architecture"] != PLATFORM:
        raise ValueError("Wrong image platform")
    return result


def scanner(root: Path, *args: str) -> int:
    cache = root / ".cache/trivy"
    cache.mkdir(parents=True, exist_ok=True)
    # Use a pinned tool container and its normal DB update semantics. No inherited
    # TRIVY_* variables, ignore files or user configuration enter the container.
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock",
            "-v",
            f"{root}:/work",
            "-v",
            f"{cache}:/root/.cache/trivy",
            "-w",
            "/work",
            TRIVY,
            *args,
        ],
        cwd=root,
        check=False,
    ).returncode


def installed_packages(identity: str) -> dict[str, dict[str, str]]:
    code = (
        "import importlib.metadata,json,subprocess; "
        "print(json.dumps({'python':{d.metadata['Name']:d.version "
        "for d in importlib.metadata.distributions()},"
        "'os':dict(line.split('\\t') for line in subprocess.check_output("
        "['dpkg-query','-W','-f=${Package}\\t${Version}\\n'],"
        "text=True).splitlines())}))"
    )
    return json.loads(
        command(
            "docker",
            "run",
            "--rm",
            "--platform",
            PLATFORM,
            identity,
            "python",
            "-c",
            code,
        )
    )


def run_pipeline(root: Path) -> dict[str, Any]:
    pins = check_configuration(root)
    output = root / "reports/images"
    output.mkdir(parents=True, exist_ok=True)
    evidence: dict[str, Any] = {"inputs": {}}

    def save() -> None:
        (output / "identities.json").write_text(json.dumps(evidence, indent=2) + "\n")

    def scan(name: str, reference: str) -> dict[str, Any]:
        command("docker", "pull", "--platform", PLATFORM, reference, root=root)
        identity = local_identity(reference)
        path = Path("reports/images") / f"{name}.scan.json"
        path_on_host = root / path
        path_on_host.unlink(missing_ok=True)
        status = scanner(
            root,
            "image",
            "--config",
            "docker/trivy.yaml",
            "--image-src",
            "docker",
            "--platform",
            PLATFORM,
            "--format",
            "json",
            "--output",
            str(path),
            reference,
        )
        item = {
            "reference": reference,
            "image_id": identity["Id"],
            "docker": identity,
            "scan": str(path_on_host),
            "scanner_status": status,
        }
        evidence[name] = item
        save()
        if status not in (0, 42):
            raise ValueError(f"Scanner failed for {reference}: {status}")
        check_scan(json.loads(path_on_host.read_text()), identity["Id"], status)
        return item

    # Negative control uses the exact production scan path, before candidates.
    fixture_index = json.loads(
        command(
            "docker",
            "buildx",
            "imagetools",
            "inspect",
            FIXTURE,
            "--format",
            "{{json .Manifest}}",
            root=root,
        )
    )
    fixture_reference = repository(FIXTURE) + "@" + platform_digest(fixture_index)
    try:
        scan("fixture", fixture_reference)
    except VulnerableImage as error:
        if not {"HIGH", "CRITICAL"} <= {v["Severity"] for v in error.findings}:
            raise ValueError(
                "Fixture must demonstrate both HIGH and CRITICAL"
            ) from error
    else:
        raise ValueError("Pinned vulnerable fixture unexpectedly passed")
    for name, reference in pins.items():
        index = json.loads(
            command(
                "docker",
                "buildx",
                "imagetools",
                "inspect",
                reference,
                "--format",
                "{{json .Manifest}}",
                root=root,
            )
        )
        if index.get("digest") != reference.split("@")[1]:
            raise ValueError("Resolved index digest mismatch")
        child = platform_digest(index)
        item = scan(name, repository(reference) + "@" + child)
        item.update(
            reference=reference,
            index=index,
            index_digest=index["digest"],
            child_digest=child,
            platform=PLATFORM,
        )
        evidence["inputs"][name] = item
        del evidence[name]
        save()
    check_coverage(set(pins), evidence["inputs"])
    reference = (
        "shell-ci:"
        + os.environ.get("GITHUB_RUN_ID", "local")
        + "-"
        + os.environ.get("GITHUB_RUN_ATTEMPT", "1")
        + "-"
        + uuid.uuid4().hex
    )
    args = [
        argument
        for key, value in pins.items()
        for argument in ("--build-arg", f"{key}={value}")
    ]
    command(
        "docker",
        "buildx",
        "build",
        "--platform",
        PLATFORM,
        "--load",
        "--provenance=false",
        "--metadata-file",
        str(output / "build.json"),
        "--iidfile",
        str(output / "image.id"),
        "-f",
        "docker/api/Dockerfile",
        "-t",
        reference,
        *args,
        ".",
        root=root,
    )
    identity = local_identity(reference)
    build = json.loads((output / "build.json").read_text())
    if identity["Id"] != build["containerimage.config.digest"]:
        raise ValueError("Loaded image differs from Buildx output")
    evidence["build"] = build
    # Local unique application reference must not be pulled or replaced.
    path = Path("reports/images/application.scan.json")
    status = scanner(
        root,
        "image",
        "--config",
        "docker/trivy.yaml",
        "--image-src",
        "docker",
        "--platform",
        PLATFORM,
        "--format",
        "json",
        "--output",
        str(path),
        identity["Id"],
    )
    application = {
        "reference": reference,
        "image_id": identity["Id"],
        "docker": identity,
        "scan": str(root / path),
        "scanner_status": status,
    }
    evidence["application"] = application
    save()
    check_scan(json.loads((root / path).read_text()), identity["Id"], status)
    sbom = Path("reports/images/application.cdx.json")
    if scanner(
        root, "convert", "--format", "cyclonedx", "--output", str(sbom), str(path)
    ):
        raise ValueError("SBOM generation failed")
    check_sbom(root / sbom, identity["Id"])
    application["sbom"] = str(root / sbom)
    save()
    return evidence


def main() -> None:
    (ROOT / "reports/stack.xml").unlink(missing_ok=True)
    raise SystemExit(
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/stack",
                "--junitxml=reports/stack.xml",
            ],
            cwd=ROOT,
            check=False,
        ).returncode
    )


if __name__ == "__main__":
    main()
