"""Real Buildx/Trivy evidence, including the pinned vulnerable fixture."""

import json
from pathlib import Path
from typing import Any

import pytest

from scripts import images

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.req("NFR-011", kind="configuration check", part="image-pins")
def test_all_index_pins_support_both_platforms(supply_chain: dict[str, Any]) -> None:
    pins = images.check_configuration(ROOT)
    images.check_coverage(set(pins), supply_chain["inputs"])
    for item in supply_chain["inputs"].values():
        assert item["platform"] == "linux/amd64"
        assert images.platform_digest(item["index"]) == item["child_digest"]
        assert item["index_digest"] in item["reference"]


@pytest.mark.req("NFR-011", kind="configuration check", part="build-scans")
def test_every_input_and_built_image_passed_real_scanning(
    supply_chain: dict[str, Any],
) -> None:
    for item in [*supply_chain["inputs"].values(), supply_chain["application"]]:
        report = json.loads(Path(item["scan"]).read_text())
        images.check_scan(report, item["image_id"], 0)
    application = supply_chain["application"]
    assert (
        application["image_id"] == images.local_identity(application["reference"])["Id"]
    )
    assert (
        application["image_id"] == supply_chain["build"]["containerimage.config.digest"]
    )


@pytest.mark.req("NFR-011", kind="configuration check", part="build-scans")
def test_real_scanner_rejects_fixable_high_and_critical(
    supply_chain: dict[str, Any],
) -> None:
    fixture = supply_chain["fixture"]
    assert fixture["scanner_status"] == 42
    report = json.loads(Path(fixture["scan"]).read_text())
    with pytest.raises(images.VulnerableImage) as error:
        images.check_scan(report, fixture["image_id"], fixture["scanner_status"])
    assert {"HIGH", "CRITICAL"} <= {v["Severity"] for v in error.value.findings}


@pytest.mark.req("NFR-024", kind="configuration check", part="image-sbom")
def test_inventory_matches_installed_python_and_os_packages(
    supply_chain: dict[str, Any],
) -> None:
    application = supply_chain["application"]
    components = images.check_sbom(Path(application["sbom"]), application["image_id"])
    installed = images.installed_packages(application["image_id"])
    assert installed["python"] and installed["os"]
    for name, version in [*installed["python"].items(), *installed["os"].items()]:
        assert (name.lower().replace("_", "-"), version) in components, (name, version)
