"""Single CI Buildx/Trivy path; local development does not invoke this command."""

import hashlib
import io
import json
import os
import platform
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request
import uuid
from pathlib import Path
from string import Template
from typing import Any

import yaml

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


TRIVY_POLICY = {
    "scan": {"scanners": ["vuln"], "list-all-pkgs": True},
    "severity": ["HIGH", "CRITICAL"],
    "vulnerability": {"ignore-unfixed": True},
    "exit-code": 42,
    "timeout": "10m",
}
GRYPE_POLICY = {
    "check-for-app-update": False,
    "db": {
        "auto-update": True,
        "require-update-check": True,
        "validate-age": True,
        "validate-by-hash-on-start": True,
        "max-update-check-frequency": "0s",
    },
}
TOOL_PINS = {
    "grype": {
        "linux-amd64": (
            "grype_0.122.0_linux_amd64.tar.gz",
            "e697e6f7224637df87e267e4318cc027feae99a8e1b80280241d32b9ee5d4920",
        ),
        "darwin-arm64": (
            "grype_0.122.0_darwin_arm64.tar.gz",
            "ca8907493c82181b0ceb6fe782ebdcb98b30dcd477319aaad7be89aa7590461b",
        ),
    },
    "buildx": {
        "linux-amd64": (
            "buildx-v0.39.0.linux-amd64",
            "5fb31a097304fbf6dd4038649a0decf32c2b9510e4047acd7d68b9d700c46194",
        ),
        "darwin-arm64": (
            "buildx-v0.39.0.darwin-arm64",
            "0190e4b9c85510974290f9a597e86c4d8200be782aeaa3df7d756ab4423d6b2d",
        ),
    },
}


def check_scanner_policy(root: Path) -> None:
    for name, expected in (("trivy", TRIVY_POLICY), ("grype", GRYPE_POLICY)):
        path = root / f"docker/{name}.yaml"
        if not path.is_file() or yaml.safe_load(path.read_text()) != expected:
            raise ValueError(f"Unapproved {name} scanner policy")


def verified_tool(name: str, root: Path = ROOT) -> Path:
    arch = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[platform.machine()]
    asset, checksum = TOOL_PINS[name][sys.platform + "-" + arch]
    cache = root / ".cache/tools"
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / asset
    if not archive.exists():
        repo, version = (
            ("anchore/grype", "v0.122.0")
            if name == "grype"
            else ("docker/buildx", "v0.39.0")
        )
        with urllib.request.urlopen(
            f"https://github.com/{repo}/releases/download/{version}/{asset}"
        ) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != checksum:
            raise ValueError(f"{name} download integrity failure")
        archive.write_bytes(data)
    data = archive.read_bytes()
    if hashlib.sha256(data).hexdigest() != checksum:
        raise ValueError(f"{name} cached tool integrity failure")
    if name == "buildx":
        archive.chmod(0o755)
        return archive
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        member = tar.extractfile("grype")
        if member is None:
            raise ValueError("Missing Grype executable")
        binary = member.read()
    executable = cache / "grype"
    if executable.exists() and executable.read_bytes() != binary:
        raise ValueError("Grype cached executable integrity failure")
    if not executable.exists():
        executable.write_bytes(binary)
        executable.chmod(0o755)
    return executable


def grype(root: Path, identity: str, report: Path, sbom: Path, database: Path) -> int:
    check_scanner_policy(root)
    # An explicit file defeats cwd/home config discovery. No inherited scanner
    # setting survives, including the legacy GRYPE_IGNORE_WONTFIX bypass.
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GRYPE_", "SYFT_"))}
    env["GRYPE_DB_CACHE_DIR"] = str(database.resolve())
    for path in (report, sbom):
        path.unlink(missing_ok=True)
    return subprocess.run(
        [
            str(verified_tool("grype", root)),
            identity,
            "--from",
            "docker",
            "--platform",
            PLATFORM,
            "-c",
            str((root / "docker/grype.yaml").resolve()),
            "-o",
            "json=" + str(report.resolve()),
            "-o",
            "cyclonedx-json=" + str(sbom.resolve()),
        ],
        cwd=root,
        env=env,
        check=False,
    ).returncode


def check_grype(report: dict[str, Any], identity: dict[str, Any], status: int) -> None:
    if status != 0:
        raise ValueError(f"Grype scanner error: {status}")
    target = report.get("source", {}).get("target", {})
    layers = [layer.get("digest") for layer in target.get("layers", [])]
    if (
        report.get("source", {}).get("type") != "image"
        or target.get("architecture") != identity["Architecture"]
        or target.get("os") != identity["Os"]
        or layers != identity["RootFS"]["Layers"]
        or not layers
        or not re.fullmatch(DIGEST, target.get("imageID", ""))
        or not isinstance(report.get("matches"), list)
    ):
        raise ValueError("Grype wrong-image association or invalid report")
    if report.get("ignoredMatches"):
        raise ValueError("Grype ignored matches are forbidden")
    findings = [
        m
        for m in report["matches"]
        if m.get("vulnerability", {}).get("severity") in {"High", "Critical"}
        and m["vulnerability"].get("fix", {}).get("state")
        not in {"not-fixed", "wont-fix"}
    ]
    if findings:
        raise VulnerableImage(findings)


def check_grype_sbom(path: Path, identity: str) -> set[tuple[str, str]]:
    bom = json.loads(path.read_text())
    if (
        bom.get("bomFormat") != "CycloneDX"
        or bom.get("specVersion") != "1.7"
        or bom.get("version") != 1
        or not bom.get("components")
    ):
        raise ValueError("Invalid Grype CycloneDX inventory")
    # This is supplemental to check_grype's scanner-derived layer/architecture
    # binding; the caller-supplied SBOM name alone never authenticates an image.
    if bom.get("metadata", {}).get("component", {}).get(
        "version"
    ) != identity.removeprefix("sha256:"):
        raise ValueError("Grype SBOM image association mismatch")
    packages: set[tuple[str, str]] = set()
    for component in bom["components"]:
        if component.get("type") == "file":
            continue
        if not component.get("name") or not component.get("version"):
            raise ValueError("Missing installed package name/version")
        version = component["version"]
        if component.get("purl", "").startswith("pkg:golang/"):
            version = "v" + version.removeprefix("go").removeprefix("v")
        packages.add((component["name"].lower().replace("_", "-"), version))
    if not packages:
        raise ValueError("Empty Grype package inventory")
    return packages


def command(*args: str, root: Path = ROOT) -> str:
    effective = (
        (str(verified_tool("buildx", root)), *args[2:])
        if args[:2] == ("docker", "buildx")
        else args
    )
    return subprocess.check_output(effective, cwd=root, text=True).strip()


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


# Local inputs can only enter the specific dependent Dockerfiles below.
RECIPES = {
    "go": ("GO_IMAGE",),
    "python": ("UV_IMAGE", "PYTHON_IMAGE"),
    "caddy": ("BUILDER_IMAGE", "CADDY_IMAGE"),
    "postgres": ("BUILDER_IMAGE", "POSTGRES_IMAGE"),
    "api": ("PREPARED_IMAGE",),
    "redis": ("REDIS_IMAGE",),
}
LOCAL = {"BUILDER_IMAGE": "local:builder", "PREPARED_IMAGE": "local:python"}
REMEDIATIONS = {
    "PYTHON_IMAGE": "docker.io/library/python",
    "CADDY_IMAGE": "docker.io/library/caddy",
    "POSTGRES_IMAGE": "docker.io/library/postgres",
    "REDIS_IMAGE": "docker.io/library/redis",
    "GO_IMAGE": "docker.io/library/golang",
}


def instructions(path: Path) -> list[tuple[str, list[str]]]:
    # A deliberately small Dockerfile subset, not a general Dockerfile parser.
    text = path.read_text()
    if re.search(r"(?m)^\s*#\s*(?:syntax|escape|check)\s*=", text, re.I):
        raise ValueError("Unsupported Docker parser directive")
    text = re.sub(r"\\\r?\n[ \t]*", " ", text)
    result: list[tuple[str, list[str]]] = []
    for line in text.splitlines():
        tokens = shlex.split(line, comments=True)
        if not tokens:
            continue
        op = tokens.pop(0).upper()
        if op not in {"ARG", "FROM", "ENV", "WORKDIR", "COPY", "RUN", "USER", "CMD"}:
            raise ValueError("Unsupported Docker instruction")
        if (
            any(t.startswith("--mount") or "from=" in t for t in tokens)
            and op != "COPY"
        ):
            raise ValueError("Unsupported source-bearing Docker option")
        result.append((op, tokens))
    return result


def check_run(tokens: list[str]) -> None:
    # Only the simple &&-joined commands used by these recipes are supported.
    # Arbitrary shell interpreters, source installers and alternate Go commands
    # require an explicit reviewed extension, not another denylist entry.
    commands: list[list[str]] = [[]]
    for token in tokens:
        if token == "&&":
            commands.append([])
        else:
            commands[-1].append(token)
    for fields in commands:
        while fields and re.fullmatch(r"[A-Z_]+=[^ ]+", fields[0]):
            fields = fields[1:]
        if not fields or fields[0] not in {
            "uv",
            "python",
            "rm",
            "mkdir",
            "sort",
            "sha256sum",
            "cmp",
            "go",
            "xcaddy",
            "printf",
            "apt-get",
            "apk",
            "gosu",
            "setcap",
        }:
            raise ValueError("Unsupported RUN command")
        if fields[0] == "go":
            if fields[1:] not in (
                ["mod", "download"],
                ["mod", "download", "all"],
                ["mod", "verify"],
                ["clean", "-modcache"],
                [
                    "version",
                    "-m",
                    "/usr/local/bin/xcaddy",
                    ">",
                    "/usr/share/shell-build/xcaddy.txt",
                ],
            ):
                if fields[1:3] != ["build", "-mod=readonly"] or any(
                    arg.startswith(("-modfile", "-overlay", "-toolexec", "-compiler"))
                    for arg in fields
                ):
                    raise ValueError("Unsupported Go build/download form")
        if fields[0] == "uv" and fields != [
            "uv",
            "sync",
            "--python",
            "/usr/local/bin/python",
            "--locked",
            "--no-dev",
            "--no-cache",
            "--index-url",
            "https://pypi.org/simple",
        ]:
            raise ValueError("Unsupported Python dependency source")
        if fields[0] == "apk" and fields != ["apk", "upgrade", "--no-cache"]:
            raise ValueError("Unsupported or unauthenticated Alpine update")
        if fields[0] == "apt-get" and fields[1:] not in (
            ["update", "--error-on=any"],
            ["upgrade", "-y", "--no-install-recommends"],
        ):
            raise ValueError("Unsupported Debian update")
        if fields[0] == "xcaddy" and fields != [
            "xcaddy",
            "build",
            "v2.11.9",
            "--replace",
            "golang.org/x/net=golang.org/x/net@v0.62.0",
            "--replace",
            "github.com/klauspost/compress=github.com/klauspost/compress@v1.20.2",
            "--output",
            "/out/caddy",
        ]:
            raise ValueError("Unapproved xcaddy source arguments")


def build_inputs(root: Path, arguments: dict[str, str]) -> list[str]:
    # Discover actual build files, including alternate Dockerfile spellings.
    paths = sorted(
        p
        for p in root.rglob("*Dockerfile*")
        if not any(
            part.startswith(".") or part in {"reports", "__pycache__"}
            for part in p.relative_to(root).parts
        )
    )
    expected = sorted(root / f"docker/{name}/Dockerfile" for name in RECIPES)
    if paths != expected or any(
        (root / n).exists()
        for n in (
            "compose.yaml",
            "compose.yml",
            "docker-compose.yaml",
            "docker-compose.yml",
        )
    ):
        raise ValueError("Every build configuration needs an enforced build/scan path")
    external: list[str] = []
    controls = {
        "GOTOOLCHAIN": "local",
        "GOPROXY": "https://proxy.golang.org",
        "GOSUMDB": "sum.golang.org",
        "CGO_ENABLED": "0",
    }
    for name, keys in RECIPES.items():
        bindings = {key: LOCAL[key] if key in LOCAL else arguments[key] for key in keys}
        stages: set[str] = set()
        inputs: list[str] = []
        environment: dict[str, str] = {}
        for op, tokens in instructions(root / f"docker/{name}/Dockerfile"):
            if not tokens:
                raise ValueError("Empty Docker instruction")
            if op == "ARG" and (
                len(tokens) != 1 or tokens[0] not in {*keys, "TARGETARCH"}
            ):
                raise ValueError("Unknown or overridden build argument")
            if op == "FROM":
                if len(tokens) not in {1, 3} or (
                    len(tokens) == 3 and tokens[1].upper() != "AS"
                ):
                    raise ValueError("Unsupported FROM form")
                try:
                    reference = Template(tokens[0]).substitute(bindings)
                except (KeyError, ValueError) as error:
                    raise ValueError("Missing effective build argument") from error
                if reference not in stages:
                    inputs.append(reference)
                if len(tokens) == 3:
                    stages.add(tokens[2])
            if op == "COPY":
                for token in tokens:
                    if token.startswith("--") and not (
                        token.startswith("--from=") or token.startswith("--chown=")
                    ):
                        raise ValueError("Unsupported COPY option")
                    if token.startswith("--from=") and token[7:] not in stages:
                        raise ValueError("Unresolved external COPY input")
                    if "://" in token:
                        raise ValueError("Unsupported remote COPY source")
            if op == "RUN":
                check_run(tokens)
            if op in {"ENV", "RUN"}:
                if op == "ENV" and any("=" not in t for t in tokens):
                    raise ValueError("Only assignment ENV syntax is supported")
                for token in tokens:
                    if "=" not in token:
                        continue
                    key, value = token.split("=", 1)
                    if (
                        key.startswith("GO") and key != "GOSU_VERSION"
                    ) or key == "CGO_ENABLED":
                        allowed = controls.get(key)
                        if key in {"GOOS", "GOARCH"} and op == "RUN":
                            allowed = "linux" if key == "GOOS" else "${TARGETARCH}"
                        if key == "GOPROXY" and op == "RUN" and value == "off":
                            allowed = "off"
                        if value != allowed:
                            raise ValueError("Uncontrolled Go downloads or toolchain")
                    if op == "ENV":
                        environment[key] = value
                if op == "RUN" and (
                    tokens[0].startswith("--")
                    or any(
                        t in {"curl", "wget", "git", "ADD", "ONBUILD"} for t in tokens
                    )
                    or "go env" in " ".join(tokens)
                    or "<<" in " ".join(tokens)
                ):
                    raise ValueError("Unsupported source-bearing RUN form")
        if name == "go" and any(environment.get(k) != v for k, v in controls.items()):
            raise ValueError("Uncontrolled Go downloads")
        if inputs != [bindings[key] for key in keys]:
            raise ValueError("Unapproved Dockerfile input or remediation boundary")
        external.extend(r for r in inputs if r not in LOCAL.values())
    return external


def check_source_files(root: Path, trusted: dict[str, Any]) -> None:
    for name in ("go", "caddy", "postgres"):
        module = (root / f"docker/{name}/go.mod").read_text()
        sums = (root / f"docker/{name}/go.sum").read_text().splitlines()
        direct = {
            "go": ("github.com/caddyserver/xcaddy", "v0.4.7"),
            "caddy": ("github.com/caddyserver/caddy/v2", "v2.11.9"),
            "postgres": (
                "github.com/tianon/gosu",
                "v0.0.0-20261025094355-29b939aa5bd4",
            ),
        }[name]
        if not re.search(
            r"(?m)^\s*(?:require\s+)?"
            + re.escape(direct[0])
            + r"\s+"
            + re.escape(direct[1])
            + r"(?:\s|$)",
            module,
        ):
            raise ValueError("Unapproved direct Go source identity")
        if re.findall(r"(?m)^\s*go\s+(\S+)\s*$", module) != ["1.27.3"] or re.search(
            r"(?m)^\s*toolchain\b", module
        ):
            raise ValueError("Unapproved Go toolchain")
        for line in sums:
            fields = line.split()
            if (
                len(fields) != 3
                or not re.fullmatch(r"v[^ ]+", fields[1])
                or not re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", fields[2])
            ):
                raise ValueError("Unapproved or unhashed Go source")
        for path, version in re.findall(
            r"(?m)^\s*(?:require\s+)?([\w./-]+)\s+(v[^\s]+)", module
        ):
            if name == "caddy" and path in {
                "golang.org/x/net",
                "github.com/klauspost/compress",
            }:
                version = {
                    "golang.org/x/net": "v0.62.0",
                    "github.com/klauspost/compress": "v1.20.2",
                }[path]
            if not any(line.startswith(f"{path} {version} h1:") for line in sums):
                raise ValueError("Go dependency missing locked checksum")
        replacements = [
            " ".join(line.split())
            for line in module.splitlines()
            if re.match(r"^\s*replace\b", line)
        ]
        allowed = (
            [
                "replace golang.org/x/net => golang.org/x/net v0.62.0",
                "replace github.com/klauspost/compress => "
                "github.com/klauspost/compress v1.20.2",
            ]
            if name == "caddy"
            else []
        )
        if sorted(replacements) != sorted(allowed):
            raise ValueError("Unapproved Go source replacement")
    if trusted["go"] != {
        "proxy": "https://proxy.golang.org",
        "sumdb": "sum.golang.org",
    }:
        raise ValueError("Unapproved Go proxy policy")
    for name in ("go", "caddy", "postgres"):
        recipe = (root / f"docker/{name}/Dockerfile").read_text()
        if (
            "go mod verify" not in recipe
            or "sha256sum -c /tmp/locks.sha256" not in recipe
        ):
            raise ValueError("Missing Go lock verification")
        if name != "caddy" and "go build -mod=readonly" not in recipe:
            raise ValueError("Go build must be readonly")
    for name in ("go", "caddy", "postgres", "redis"):
        recipe = (root / f"docker/{name}/Dockerfile").read_text()
        if "apk upgrade --no-cache" not in recipe:
            raise ValueError("Missing approved Alpine preparation")
        urls = re.findall(r"https?://[^\s'\\]+", recipe)
        if any(
            url not in [*trusted["alpine"]["repositories"], trusted["go"]["proxy"]]
            for url in urls
        ):
            raise ValueError("Unapproved Alpine repository")
    source = (root / "docker/python/debian.sources").read_text()
    for block in source.strip().split("\n\n"):
        fields = dict(line.split(": ", 1) for line in block.splitlines())
        if (
            set(fields) != {"Types", "URIs", "Suites", "Components", "Signed-By"}
            or fields["Types"] != "deb"
            or fields["Components"] != "main"
            or fields["URIs"] not in trusted["debian"]["repositories"]
            or not set(fields["Suites"].split()) <= set(trusted["debian"]["suites"])
            or fields["Signed-By"] != trusted["debian"]["signed-by"]
        ):
            raise ValueError("Unapproved or unauthenticated Debian source")


def check_configuration(root: Path) -> dict[str, str]:
    check_scanner_policy(root)
    trusted = tomllib.loads((root / "config/trusted-sources.toml").read_text())
    pins: dict[str, str] = {}
    for line in (root / "docker/images.env").read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        name, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z_]*_IMAGE", name) or name in pins:
            raise ValueError("Invalid/duplicate image pin")
        pins[name] = value
    expected = {key for keys in RECIPES.values() for key in keys if key not in LOCAL}
    if set(pins) != expected | {"REDIS_IMAGE", "MAILPIT_IMAGE"}:
        raise ValueError("Missing or unknown image role")
    for reference in [*pins.values(), *build_inputs(root, pins)]:
        if not re.fullmatch(rf"[^@]+@{DIGEST}", reference):
            raise ValueError("Images require digest pins")
        if repository(reference) not in trusted["image-repositories"]:
            raise ValueError(f"Unapproved image repository: {reference}")
        if reference not in pins.values():
            raise ValueError("Dockerfile input absent from pinned configuration")
    for name, repo in REMEDIATIONS.items():
        if repository(pins[name]) != repo:
            raise ValueError("Unauthorized remediation source")
    check_source_files(root, trusted)
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


def platform_digest(index: dict[str, Any], architecture: str = "amd64") -> str:
    requested = architecture
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
    return selected[requested]


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


def check_upstream(
    name: str, report: dict[str, Any], identity: str, status: int
) -> None:
    try:
        check_scan(report, identity, status)
    except VulnerableImage:
        if name not in REMEDIATIONS:
            raise


def check_build_identity(metadata: dict[str, Any], identity: str) -> None:
    accepted = {
        metadata.get("containerimage.digest"),
        metadata.get("containerimage.config.digest"),
    }
    if identity not in accepted or not re.fullmatch(DIGEST, identity):
        raise ValueError("Build/image identity mismatch")


def require_effective(root: Path, item: dict[str, Any]) -> None:
    check_scan(
        json.loads((root / item["scan"]).read_text()),
        item["image_id"],
        item["scanner_status"],
    )
    check_grype(
        json.loads((root / item["grype_scan"]).read_text()),
        item["docker"],
        item["grype_status"],
    )
    if local_identity(item["reference"])["Id"] != item["image_id"]:
        raise ValueError("Effective input identity changed before dependent use")


def check_sbom(path: Path, identity: str) -> set[tuple[str, str]]:
    bom = json.loads(path.read_text())
    if (
        bom.get("bomFormat") != "CycloneDX"
        or bom.get("specVersion") not in {"1.4", "1.5", "1.6", "1.7"}
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
    if not components:
        raise ValueError("Missing SBOM components")
    packages: set[tuple[str, str]] = set()
    wrapper = False
    for component in components:
        if not component.get("name"):
            raise ValueError("Missing package name")
        if not component.get("version"):
            props = {p["name"]: p["value"] for p in component.get("properties", [])}
            if (
                component.get("type") == "library"
                and component["name"] == "caddy"
                and component.get("purl") == "pkg:golang/caddy"
                and props.get("aquasecurity:trivy:PkgID") == "caddy"
                and props.get("aquasecurity:trivy:PkgType") == "gobinary"
            ):
                # xcaddy's generated main module is local (devel), not a
                # dependency. Its actual Caddy library must still be versioned.
                wrapper = True
                packages.add(("caddy", ""))
                continue
            if (
                component.get("type") != "application"
                or props.get("aquasecurity:trivy:Class") != "lang-pkgs"
                or props.get("aquasecurity:trivy:Type")
                not in {"gobinary", "rustbinary", "python-pkg"}
            ):
                raise ValueError("Missing package version")
        else:
            packages.add(
                (component["name"].lower().replace("_", "-"), component["version"])
            )
    if not packages or (
        wrapper
        and not any(
            name == "github.com/caddyserver/caddy/v2" and version
            for name, version in packages
        )
    ):
        raise ValueError("Empty package inventory")
    return packages


def check_installed(
    packages: set[tuple[str, str]], actual: dict[str, dict[str, str]]
) -> None:
    for group in actual.values():
        for package, version in group.items():
            if (package.lower().replace("_", "-"), version) not in packages:
                raise ValueError(
                    f"Missing installed Grype component: {package} {version}"
                )


def check_coverage(expected: set[str], actual: dict[str, Any]) -> None:
    if set(actual) != expected:
        raise ValueError("Incomplete image coverage")


def local_identity(reference: str, target: str = PLATFORM) -> dict[str, Any]:
    # Callers use a selected child digest or the unique loaded application ref.
    # Inspect then verifies the platform without requiring newer CLI flags.
    result = json.loads(command("docker", "image", "inspect", reference))[0]
    if result["Os"] + "/" + result["Architecture"] != target:
        raise ValueError("Wrong image platform")
    return result


def scanner(root: Path, *args: str, offline: bool = False) -> int:
    check_scanner_policy(root)
    cache = root / ".cache/trivy"
    cache.mkdir(parents=True, exist_ok=True)
    socket = Path("/var/run/docker.sock")
    socket_group = str(socket.stat().st_gid) if socket.exists() else "0"
    # Use a pinned tool container and its normal DB update semantics. No inherited
    # TRIVY_* variables, ignore files or user configuration enter the container.
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--group-add",
            socket_group,
            *(["--network", "none"] if offline else []),
            "--env",
            "TRIVY_CACHE_DIR=/trivy-cache",
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock",
            "-v",
            f"{root}:/work",
            "-v",
            f"{cache}:/trivy-cache",
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


def go_packages(text: str) -> dict[str, str]:
    lines = text.splitlines()
    result = {"stdlib": "v" + lines[0].split(": go", 1)[1]}
    previous = ""
    for line in lines[1:]:
        fields = line.split()
        if len(fields) >= 3 and fields[0] in {"mod", "dep"}:
            previous = fields[1]
            if fields[2].startswith("v"):
                result[previous] = fields[2]
        elif len(fields) >= 3 and fields[0] == "=>":
            result.pop(previous, None)
            result[fields[1]] = fields[2]
    return result


def package_version(package: dict[str, Any]) -> str:
    if (
        not package.get("Version")
        and package.get("Name") == package.get("ID") == "caddy"
        and package.get("AnalyzedBy") == "gobinary"
        and package.get("Identifier", {}).get("PURL") == "pkg:golang/caddy"
    ):
        # Same generated local wrapper checked by check_sbom, not a dependency.
        return ""
    # Trivy's native OS report splits epochs/releases; CycloneDX uses the
    # complete installed distribution version (as do dpkg/apk queries).
    epoch = f"{package['Epoch']}:" if package.get("Epoch") else ""
    release = f"-{package['Release']}" if package.get("Release") else ""
    return epoch + package["Version"] + release


def actual_inventory(
    root: Path, item: dict[str, Any], family: str, builder: dict[str, Any] | None
) -> dict[str, dict[str, str]]:
    identity = item["image_id"]
    if family in {"python", "application"}:
        inventory = installed_packages(identity)
        inventory["principal"] = {
            "python": command(
                "docker", "run", "--rm", "--entrypoint", "python", identity, "--version"
            ).split()[1]
        }
        return inventory
    shell = """awk -F: '/^P:/{p=$2} /^V:/{print p "\\t" $2}' /lib/apk/db/installed"""
    os_packages = dict(
        line.split("\t")
        for line in command(
            "docker", "run", "--rm", "--entrypoint", "sh", identity, "-c", shell
        ).splitlines()
    )
    inventory = {"os": os_packages}
    if family == "postgres":
        inventory["principal"] = {
            "postgresql": command(
                "docker",
                "run",
                "--rm",
                "--entrypoint",
                "postgres",
                identity,
                "--version",
            ).split()[-1]
        }
    if family == "redis":
        banner = command(
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "redis-server",
            identity,
            "--version",
        )
        match = re.search(r"\bv=([0-9.]+)\b", banner)
        if match is None:
            raise ValueError("Unknown installed Redis version")
        inventory["principal"] = {"redis": match[1]}
    binary = {
        "builder": "/usr/local/bin/xcaddy",
        "caddy": "/usr/bin/caddy",
        "postgres": "/usr/local/bin/gosu",
    }.get(family)
    if binary and builder is not None:
        with tempfile.TemporaryDirectory(dir=root) as directory:
            relative = Path(directory) / "binary"
            relative.write_bytes(
                subprocess.check_output(
                    ["docker", "run", "--rm", "--entrypoint", "cat", identity, binary],
                    cwd=root,
                )
            )
            info = command(
                "docker",
                "run",
                "--rm",
                "-v",
                f"{relative}:/binary:ro",
                "--entrypoint",
                "go",
                builder["image_id"],
                "version",
                "-m",
                "/binary",
            )
        (root / "reports/images" / (family + ".binary")).unlink(missing_ok=True)
        (root / "reports/images" / (family + ".buildinfo.txt")).write_text(info + "\n")
        inventory["go"] = go_packages(info)
    return inventory


def run_pipeline(
    root: Path,
    *,
    verify: bool = True,
    database: Path | None = None,
    target: str = PLATFORM,
) -> dict[str, Any]:
    if target not in {"linux/amd64", "linux/arm64"} or (verify and target != PLATFORM):
        raise ValueError("Unsupported preparation/scanning platform")
    pins = check_configuration(root)
    output = root / "reports/images"
    output.mkdir(parents=True, exist_ok=True)
    evidence: dict[str, Any] = {
        "inputs": {},
        "effective": {},
        "builds": {},
        "events": [],
        "verified": verify,
        "platform": target,
    }
    namespace = (
        "shell-ci:" + os.environ.get("GITHUB_RUN_ID", "local") + "-" + uuid.uuid4().hex
    )

    database = database or (
        Path(tempfile.mkdtemp(prefix="shell-grype-")) if verify else Path()
    )

    def save() -> None:
        (output / "identities.json").write_text(json.dumps(evidence, indent=2) + "\n")

    def resolve(reference: str) -> dict[str, Any]:
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
        child = platform_digest(index, target.split("/")[1])
        selected = repository(reference) + "@" + child
        command("docker", "pull", "--platform", target, selected, root=root)
        return {
            "index_reference": reference,
            "index": index,
            "index_digest": index["digest"],
            "child_digest": child,
            "platform": target,
            "selected": selected,
        }

    def scan(name: str, reference: str, upstream: str | None = None) -> dict[str, Any]:
        identity = local_identity(reference, target)
        path = Path("reports/images") / (name + ".scan.json")
        (root / path).unlink(missing_ok=True)
        status = (
            scanner(
                root,
                "image",
                "--config",
                "docker/trivy.yaml",
                "--ignorefile",
                "/dev/null",
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
            if verify
            else 0
        )
        item = {
            "reference": reference,
            "image_id": identity["Id"],
            "docker": identity,
            "scan": str(path),
            "scanner_status": status,
        }
        evidence[name] = item
        save()
        if not verify:
            return item
        grype_path = output / (name + ".grype.json")
        bom = output / (name + ".cdx.json")
        grype_status = grype(root, identity["Id"], grype_path, bom, database)
        item.update(
            grype_scan=str(grype_path.relative_to(root)),
            grype_status=grype_status,
            sbom=str(bom.relative_to(root)),
        )
        save()
        if status not in {0, 42}:
            raise ValueError(f"Scanner failed: {name}: {status}")
        report = json.loads((root / path).read_text())
        if grype_status != 0:
            raise ValueError(f"Grype scanner error: {grype_status}")
        grype_accepted = True
        try:
            check_grype(json.loads(grype_path.read_text()), identity, grype_status)
        except VulnerableImage:
            grype_accepted = False
            if upstream not in REMEDIATIONS and name != "fixture":
                raise
        if upstream:
            check_upstream(upstream, report, identity["Id"], status)
        else:
            check_scan(report, identity["Id"], status)
        if status == 0 and grype_accepted:
            evidence["events"].append("pass:" + name)
        save()
        return item

    def inventory(
        name: str,
        item: dict[str, Any],
        family: str,
        builder: dict[str, Any] | None = None,
    ) -> None:
        if not verify:
            return
        bom = Path("reports/images") / (name + ".trivy.cdx.json")
        if scanner(
            root, "convert", "--format", "cyclonedx", "--output", str(bom), item["scan"]
        ):
            raise ValueError("SBOM generation failed")
        packages = check_sbom(root / bom, item["image_id"])
        report = json.loads((root / item["scan"]).read_text())
        for result in report["Results"]:
            for package in result.get("Packages", []):
                pair = (
                    package["Name"].lower().replace("_", "-"),
                    package_version(package),
                )
                if pair not in packages:
                    raise ValueError(f"Incomplete SBOM: {pair}")
        actual = actual_inventory(root, item, family, builder)
        for key, group in actual.items():
            if key == "principal":
                continue
            for package, version in group.items():
                if (package.lower().replace("_", "-"), version) not in packages:
                    raise ValueError(
                        f"Missing installed component: {package} {version}"
                    )
        item["trivy_sbom"] = str(bom)
        grype_packages = check_grype_sbom(root / item["sbom"], item["image_id"])
        check_installed(grype_packages, actual)
        item["installed"] = actual
        save()

    def build(
        name: str,
        recipe: str,
        bindings: dict[str, str],
        dependencies: list[dict[str, Any]],
    ) -> dict[str, Any]:
        for dependency in dependencies:
            if verify:
                require_effective(root, dependency)
        evidence["events"].append("build:" + name)
        save()
        reference = namespace + "-" + name
        metadata = output / (name + ".build.json")
        args = [
            value
            for key, value in bindings.items()
            for value in ("--build-arg", f"{key}={value}")
        ]
        with (output / (name + ".build.log")).open("w") as log:
            subprocess.run(
                [
                    str(verified_tool("buildx", root)),
                    "build",
                    "--platform",
                    target,
                    "--load",
                    "--no-cache",
                    "--provenance=false",
                    "--metadata-file",
                    str(metadata),
                    "--iidfile",
                    str(output / (name + ".id")),
                    "-f",
                    f"docker/{recipe}/Dockerfile",
                    "-t",
                    reference,
                    *args,
                    ".",
                ],
                cwd=root,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
            )
        result = json.loads(metadata.read_text())
        identity = local_identity(reference, target)
        check_build_identity(result, identity["Id"])
        check_build_identity(result, (output / (name + ".id")).read_text().strip())
        evidence["builds"][name] = {
            "metadata": result,
            "arguments": bindings,
            "image_id": identity["Id"],
            "recipe": recipe,
        }
        save()
        return scan(name, reference)

    fixture = resolve(FIXTURE) if verify else {}
    if verify:
        try:
            scan("fixture", fixture["selected"])
        except VulnerableImage as error:
            if not {"HIGH", "CRITICAL"} <= {v["Severity"] for v in error.findings}:
                raise ValueError(
                    "Fixture must demonstrate both HIGH and CRITICAL"
                ) from error
        else:
            raise ValueError("Vulnerable fixture unexpectedly passed")
        evidence["fixture"].update(fixture)
    for name, reference in pins.items():
        resolution = resolve(reference)
        item = scan(name, resolution["selected"], name)
        item.update(resolution)
        # The build consumes the platform-selected reference, never a mutable tag.
        evidence["inputs"][name] = item
        del evidence[name]
        save()
    check_coverage(set(pins), evidence["inputs"])
    inputs = evidence["inputs"]
    builder = build(
        "builder",
        "go",
        {"GO_IMAGE": inputs["GO_IMAGE"]["selected"]},
        [],
    )
    inventory("builder", builder, "builder", builder)
    evidence["effective"]["builder"] = builder
    python = build(
        "python",
        "python",
        {
            "PYTHON_IMAGE": inputs["PYTHON_IMAGE"]["selected"],
            "UV_IMAGE": inputs["UV_IMAGE"]["selected"],
        },
        [inputs["UV_IMAGE"]],
    )
    inventory("python", python, "python")
    evidence["effective"]["python"] = python
    for name, recipe in (("CADDY_IMAGE", "caddy"), ("POSTGRES_IMAGE", "postgres")):
        if (
            verify
            and inputs[name]["scanner_status"] == 0
            and grype_passes(root, inputs[name])
        ):
            item = inputs[name]
        else:
            item = build(
                recipe,
                recipe,
                {
                    "BUILDER_IMAGE": builder["reference"],
                    name: inputs[name]["selected"],
                },
                [builder],
            )
        inventory(recipe, item, recipe, builder)
        evidence["effective"][recipe] = item
    for name in ("REDIS_IMAGE", "MAILPIT_IMAGE"):
        item = inputs[name]
        if name == "REDIS_IMAGE" and (
            not verify or item["scanner_status"] != 0 or not grype_passes(root, item)
        ):
            item = build("redis", "redis", {name: item["selected"]}, [])
        inventory(name, item, "redis" if name == "REDIS_IMAGE" else "service")
        evidence["effective"][name] = item
    application = build(
        "application", "api", {"PREPARED_IMAGE": python["reference"]}, [python]
    )
    inventory("application", application, "application")
    evidence["application"] = application
    evidence["effective"]["application"] = application
    # Verify the loaded prepared image's layers are the application's actual base.
    if (
        application["docker"]["RootFS"]["Layers"][
            : len(python["docker"]["RootFS"]["Layers"])
        ]
        != python["docker"]["RootFS"]["Layers"]
    ):
        raise ValueError("Application did not use the scanned prepared base")
    save()
    if verify:
        check_effective_coverage(root, evidence)
    return evidence


def grype_passes(root: Path, item: dict[str, Any]) -> bool:
    try:
        check_grype(
            json.loads((root / item["grype_scan"]).read_text()),
            item["docker"],
            item["grype_status"],
        )
    except VulnerableImage:
        return False
    return True


def expected_effective(root: Path = ROOT) -> set[str]:
    pins = check_configuration(root)
    consumed = {k for keys in RECIPES.values() for k in keys}
    return {
        "builder"
        if name == "go"
        else "application"
        if name == "api"
        else "REDIS_IMAGE"
        if name == "redis"
        else name
        for name in RECIPES
    } | (pins.keys() - consumed)


def check_effective_coverage(root: Path, evidence: dict[str, Any]) -> None:
    check_coverage(expected_effective(root), evidence["effective"])
    for item in evidence["effective"].values():
        require_effective(root, item)
        check_grype_sbom(root / item["sbom"], item["image_id"])
        check_sbom(root / item["trivy_sbom"], item["image_id"])
        if not item.get("installed"):
            raise ValueError("Incomplete installed image coverage")


def prepared_images(root: Path = ROOT, *, target: str = PLATFORM) -> dict[str, Any]:
    """Slice 5 interface: prepare locally without scanners; return exact IDs.

    CI instead passes run_pipeline's verified evidence into prepared_references,
    then uses those loaded images without building or pulling replacements.
    """
    return run_pipeline(root, verify=False, target=target)


def prepared_references(
    root: Path, evidence: dict[str, Any], *, scanned: bool
) -> dict[str, str]:
    if scanned:
        if evidence.get("verified") is not True:
            raise ValueError("Prepared evidence is not scanned")
        check_effective_coverage(root, evidence)
    references: dict[str, str] = {}
    for role in ("application", "caddy", "postgres", "REDIS_IMAGE", "MAILPIT_IMAGE"):
        item = evidence["effective"][role]
        if local_identity(item["reference"])["Id"] != item["image_id"]:
            raise ValueError("Prepared image identity changed")
        references[role] = item["image_id"]
    return references


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
