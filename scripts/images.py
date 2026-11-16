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


# Local inputs can only enter the specific dependent Dockerfiles below.
RECIPES = {
    "go": ("GO_IMAGE",),
    "python": ("UV_IMAGE", "PYTHON_IMAGE"),
    "caddy": ("BUILDER_IMAGE", "CADDY_IMAGE"),
    "postgres": ("BUILDER_IMAGE", "POSTGRES_IMAGE"),
    "api": ("PREPARED_IMAGE",),
}
LOCAL = {"BUILDER_IMAGE": "local:builder", "PREPARED_IMAGE": "local:python"}
REMEDIATIONS = {
    "PYTHON_IMAGE": "docker.io/library/python",
    "CADDY_IMAGE": "docker.io/library/caddy",
    "POSTGRES_IMAGE": "docker.io/library/postgres",
}


def build_inputs(root: Path, arguments: dict[str, str]) -> list[str]:
    paths = sorted((root / "docker").glob("**/Dockerfile"))
    expected = sorted(root / f"docker/{name}/Dockerfile" for name in RECIPES)
    if paths != expected:
        raise ValueError("Every Dockerfile needs an enforced build/scan path")
    external: list[str] = []
    for name, keys in RECIPES.items():
        bindings = {key: LOCAL[key] if key in LOCAL else arguments[key] for key in keys}
        stages: set[str] = set()
        inputs: list[str] = []
        for line in (root / f"docker/{name}/Dockerfile").read_text().splitlines():
            tokens = line.split()
            if not tokens or tokens[0].startswith("#"):
                continue
            tokens[0] = tokens[0].upper()
            if tokens[0] == "ARG" and tokens[1] not in {*keys, "TARGETARCH"}:
                raise ValueError("Unknown or overridden build argument")
            if tokens[0] == "FROM":
                try:
                    reference = Template(tokens[1]).substitute(bindings)
                except KeyError as error:
                    raise ValueError("Missing effective build argument") from error
                if reference not in stages:
                    inputs.append(reference)
                if len(tokens) == 4 and tokens[2].upper() == "AS":
                    stages.add(tokens[3])
            if tokens[0] == "COPY":
                for token in tokens[1:]:
                    if token.startswith("--from=") and token[7:] not in stages:
                        raise ValueError("Unresolved external COPY input")
        if inputs != [bindings[key] for key in keys]:
            raise ValueError("Unapproved Dockerfile input or remediation boundary")
        external.extend(
            reference for reference in inputs if reference not in LOCAL.values()
        )
    return external


def check_source_files(root: Path, trusted: dict[str, Any]) -> None:
    for name in ("go", "caddy", "postgres"):
        module = (root / f"docker/{name}/go.mod").read_text()
        sums = (root / f"docker/{name}/go.sum").read_text().splitlines()
        if "go 1.27.3" not in module or "toolchain " in module:
            raise ValueError("Unapproved Go toolchain")
        for line in sums:
            fields = line.split()
            if (
                len(fields) != 3
                or fields[0] not in trusted["go-module-repositories"]
                or not re.fullmatch(r"v[^ ]+", fields[1])
                or not re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", fields[2])
            ):
                raise ValueError("Unapproved or unhashed Go source")
        for path, version in re.findall(
            r"(?m)^\s*(?:require )?([\w./-]+) (v[^\s]+)", module
        ):
            if name == "caddy" and path == "golang.org/x/net":
                version = "v0.62.0"
            if not any(line.startswith(f"{path} {version} h1:") for line in sums):
                raise ValueError("Go dependency missing locked checksum")
        replacements = [
            line for line in module.splitlines() if line.startswith("replace ")
        ]
        allowed = (
            ["replace golang.org/x/net => golang.org/x/net v0.62.0"]
            if name == "caddy"
            else []
        )
        if replacements != allowed:
            raise ValueError("Unapproved Go source replacement")
    go_recipe = (root / "docker/go/Dockerfile").read_text()
    if (
        "GOTOOLCHAIN=local" not in go_recipe
        or f"GOPROXY={trusted['go']['proxy']}" not in go_recipe
        or f"GOSUMDB={trusted['go']['sumdb']}" not in go_recipe
    ):
        raise ValueError("Uncontrolled Go downloads")
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


def check_coverage(expected: set[str], actual: dict[str, Any]) -> None:
    if set(actual) != expected:
        raise ValueError("Incomplete image coverage")


def local_identity(reference: str) -> dict[str, Any]:
    # Callers use a selected child digest or the unique loaded application ref.
    # Inspect then verifies the platform without requiring newer CLI flags.
    result = json.loads(command("docker", "image", "inspect", reference))[0]
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
        return installed_packages(identity)
    shell = """awk -F: '/^P:/{p=$2} /^V:/{print p "\\t" $2}' /lib/apk/db/installed"""
    os_packages = dict(
        line.split("\t")
        for line in command(
            "docker", "run", "--rm", "--entrypoint", "sh", identity, "-c", shell
        ).splitlines()
    )
    inventory = {"os": os_packages}
    binary = {
        "builder": "/usr/local/bin/xcaddy",
        "caddy": "/usr/bin/caddy",
        "postgres": "/usr/local/bin/gosu",
    }.get(family)
    if binary and builder is not None:
        relative = Path("reports/images") / (family + ".binary")
        data = subprocess.check_output(
            ["docker", "run", "--rm", "--entrypoint", "cat", identity, binary], cwd=root
        )
        (root / relative).write_bytes(data)
        info = command(
            "docker",
            "run",
            "--rm",
            "-v",
            f"{root / relative}:/binary:ro",
            "--entrypoint",
            "go",
            builder["image_id"],
            "version",
            "-m",
            "/binary",
        )
        (root / "reports/images" / (family + ".buildinfo.txt")).write_text(info + "\n")
        inventory["go"] = go_packages(info)
    return inventory


def run_pipeline(root: Path) -> dict[str, Any]:
    pins = check_configuration(root)
    output = root / "reports/images"
    output.mkdir(parents=True, exist_ok=True)
    evidence: dict[str, Any] = {
        "inputs": {},
        "effective": {},
        "builds": {},
        "events": [],
    }
    namespace = (
        "shell-ci:" + os.environ.get("GITHUB_RUN_ID", "local") + "-" + uuid.uuid4().hex
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
        child = platform_digest(index)
        selected = repository(reference) + "@" + child
        command("docker", "pull", "--platform", PLATFORM, selected, root=root)
        return {
            "index_reference": reference,
            "index": index,
            "index_digest": index["digest"],
            "child_digest": child,
            "platform": PLATFORM,
            "selected": selected,
        }

    def scan(name: str, reference: str, upstream: str | None = None) -> dict[str, Any]:
        identity = local_identity(reference)
        path = Path("reports/images") / (name + ".scan.json")
        (root / path).unlink(missing_ok=True)
        status = scanner(
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
        item = {
            "reference": reference,
            "image_id": identity["Id"],
            "docker": identity,
            "scan": str(path),
            "scanner_status": status,
        }
        evidence[name] = item
        save()
        if status not in {0, 42}:
            raise ValueError(f"Scanner failed: {name}: {status}")
        report = json.loads((root / path).read_text())
        if upstream:
            check_upstream(upstream, report, identity["Id"], status)
        else:
            check_scan(report, identity["Id"], status)
        if status == 0:
            evidence["events"].append("pass:" + name)
        save()
        return item

    def inventory(
        name: str,
        item: dict[str, Any],
        family: str,
        builder: dict[str, Any] | None = None,
    ) -> None:
        bom = Path("reports/images") / (name + ".cdx.json")
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
        for group in actual.values():
            for package, version in group.items():
                if (package.lower().replace("_", "-"), version) not in packages:
                    raise ValueError(
                        f"Missing installed component: {package} {version}"
                    )
        item["sbom"] = str(bom)
        item["installed"] = actual
        save()

    def build(
        name: str,
        recipe: str,
        bindings: dict[str, str],
        dependencies: list[dict[str, Any]],
    ) -> dict[str, Any]:
        for dependency in dependencies:
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
                    "docker",
                    "buildx",
                    "build",
                    "--platform",
                    PLATFORM,
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
        identity = local_identity(reference)
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

    fixture = resolve(FIXTURE)
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
    for name in ("UV_IMAGE", "GO_IMAGE", "REDIS_IMAGE", "MAILPIT_IMAGE"):
        check_scan(
            json.loads((root / inputs[name]["scan"]).read_text()),
            inputs[name]["image_id"],
            inputs[name]["scanner_status"],
        )
    builder = build(
        "builder",
        "go",
        {"GO_IMAGE": inputs["GO_IMAGE"]["selected"]},
        [inputs["GO_IMAGE"]],
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
        if inputs[name]["scanner_status"] == 0:
            item = inputs[name]
        else:
            item = build(
                recipe,
                recipe,
                {
                    "BUILDER_IMAGE": builder["reference"],
                    name: inputs[name]["selected"],
                    "TARGETARCH": "amd64",
                },
                [builder],
            )
        inventory(recipe, item, recipe, builder)
        evidence["effective"][recipe] = item
    for name in ("REDIS_IMAGE", "MAILPIT_IMAGE"):
        item = inputs[name]
        inventory(name, item, "service")
        evidence["effective"][name] = item
    application = build(
        "application", "api", {"PREPARED_IMAGE": python["reference"]}, [python]
    )
    inventory("application", application, "application")
    evidence["application"] = application
    # Verify the loaded prepared image's layers are the application's actual base.
    if (
        application["docker"]["RootFS"]["Layers"][
            : len(python["docker"]["RootFS"]["Layers"])
        ]
        != python["docker"]["RootFS"]["Layers"]
    ):
        raise ValueError("Application did not use the scanned prepared base")
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
