"""Native Debian unfixed states need verified scanner/package provenance."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from scripts import images
from tests.gates.test_image_revision import grype_report
from tests.gates.test_images import configured as configured
from tests.gates.test_trivy_unrated import report_for


def debian_report(identity: str) -> dict[str, Any]:
    purl = "pkg:deb/debian/sample@1.0?arch=amd64&distro=debian-13.7"
    return {
        "SchemaVersion": 2,
        "Metadata": {"ImageID": identity, "OS": {"Family": "debian", "Name": "13.7"}},
        "Results": [
            {
                "Class": "os-pkgs",
                "Type": "debian",
                "Target": "controlled-debian",
                "Packages": [
                    {
                        "ID": "sample@1.0",
                        "Name": "sample",
                        "Version": "1.0",
                        "Identifier": {"PURL": purl},
                    }
                ],
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "TEST-UNFIXED",
                        "PkgID": "sample@1.0",
                        "PkgName": "sample",
                        "InstalledVersion": "1.0",
                        "PkgIdentifier": {"PURL": purl},
                        "Severity": "UNKNOWN",
                        "Status": "affected",
                        "DataSource": {
                            "ID": "debian",
                            "Name": "Debian Security Tracker",
                            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker",
                        },
                    }
                ],
            }
        ],
    }


@pytest.mark.req("NFR-026", kind="configuration check", part="build-scans")
@pytest.mark.parametrize("severity", ["UNKNOWN", "", "Unrated", None])
@pytest.mark.parametrize("fixed", ["absent", ""])
def test_verified_debian_unfixed_findings_remain_visible(
    severity: str | None, fixed: str
) -> None:
    identity = "sha256:" + "a" * 64
    report = debian_report(identity)
    finding = report["Results"][0]["Vulnerabilities"][0]
    if severity is None:
        del finding["Severity"]
    else:
        finding["Severity"] = severity
    if fixed != "absent":
        finding["FixedVersion"] = fixed
    before = copy.deepcopy(report)
    images.check_scan(report, identity, 0)
    assert report == before
    assert report["Results"][0]["Vulnerabilities"]


@pytest.mark.req("NFR-026", kind="configuration check", part="scanner-policy-rejection")
@pytest.mark.parametrize(
    "mutation",
    [
        "os-family",
        "missing-os",
        "os-release",
        "missing-release",
        "result-type",
        "class",
        "source-id",
        "source-url",
        "source-name",
        "missing-source",
        "purl-type",
        "purl-release",
        "missing-purl",
        "package-id",
        "package-name",
        "package-version",
        "missing-packages",
        "catalog-version",
        "catalog-purl",
        "fixed",
        "null-fixed",
        "invalid-fixed",
        "unknown",
        "missing-status",
        "empty-status",
        "fixed-status",
        "investigating",
        "deferred",
        "unfamiliar",
        "case-status",
    ],
)
def test_debian_unfixed_rejects_unverified_or_unresolved_evidence(
    mutation: str,
) -> None:
    identity = "sha256:" + "a" * 64
    report = debian_report(identity)
    images.check_scan(report, identity, 0)
    result = report["Results"][0]
    v = result["Vulnerabilities"][0]
    if mutation == "os-family":
        report["Metadata"]["OS"]["Family"] = "alpine"
    elif mutation == "missing-os":
        del report["Metadata"]["OS"]
    elif mutation == "os-release":
        report["Metadata"]["OS"]["Name"] = "12.1"
    elif mutation == "missing-release":
        del report["Metadata"]["OS"]["Name"]
    elif mutation == "result-type":
        result["Type"] = "alpine"
    elif mutation == "class":
        result["Class"] = "lang-pkgs"
    elif mutation.startswith("source-"):
        v["DataSource"][
            {"source-id": "ID", "source-url": "URL", "source-name": "Name"}[mutation]
        ] = "unverified"
    elif mutation == "missing-source":
        del v["DataSource"]
    elif mutation == "purl-type":
        v["PkgIdentifier"]["PURL"] = v["PkgIdentifier"]["PURL"].replace(
            "deb/debian/", "golang/"
        )
    elif mutation == "purl-release":
        v["PkgIdentifier"]["PURL"] = v["PkgIdentifier"]["PURL"].replace("13.7", "12.1")
    elif mutation == "missing-purl":
        del v["PkgIdentifier"]
    elif mutation == "package-id":
        v["PkgID"] = "other"
    elif mutation == "package-name":
        v["PkgName"] = "other"
    elif mutation == "package-version":
        v["InstalledVersion"] = "other"
    elif mutation == "missing-packages":
        del result["Packages"]
    elif mutation == "catalog-version":
        result["Packages"][0]["Version"] = "other"
    elif mutation == "catalog-purl":
        result["Packages"][0]["Identifier"]["PURL"] = "other"
    elif mutation in {"fixed", "null-fixed", "invalid-fixed"}:
        v["FixedVersion"] = {"fixed": "2", "null-fixed": None, "invalid-fixed": False}[
            mutation
        ]
    elif mutation == "missing-status":
        del v["Status"]
    else:
        v["Status"] = {
            "unknown": "unknown",
            "empty-status": "",
            "fixed-status": "fixed",
            "investigating": "under_investigation",
            "deferred": "fix_deferred",
            "unfamiliar": "future",
            "case-status": "Affected",
        }[mutation]
    with pytest.raises(
        images.VulnerableImage, match="Blocking vulnerabilities"
    ) as error:
        images.check_scan(report, identity, 0)
    assert error.value.findings == [v]


@pytest.mark.req("NFR-026", kind="configuration check", part="scanner-policy-rejection")
@pytest.mark.parametrize("severity", ["HIGH", "CRITICAL", "UNKNOWN"])
@pytest.mark.parametrize("state", ["affected", "unknown", "fixed", "will_not_fix"])
def test_available_fix_always_blocks_independent_of_debian_status(
    severity: str, state: str
) -> None:
    identity = "sha256:" + "a" * 64
    report = debian_report(identity)
    v = report["Results"][0]["Vulnerabilities"][0]
    v.update(Severity=severity, Status=state, FixedVersion="2")
    with pytest.raises(images.VulnerableImage, match="Blocking vulnerabilities"):
        images.check_scan(report, identity, 0)


@pytest.mark.req("NFR-026", kind="configuration check", part="build-scans")
def test_debian_unfixed_acceptance_never_overrides_grype(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity, grype = grype_report()
    (configured / "primary.json").write_text(json.dumps(report_for(identity["Id"])))
    (configured / "unrated.json").write_text(json.dumps(debian_report(identity["Id"])))
    (configured / "grype.json").write_text(json.dumps(grype))
    item = {
        "image_id": identity["Id"],
        "docker": identity,
        "reference": "test",
        "scan": "primary.json",
        "scanner_status": 0,
        "unrated_scan": "unrated.json",
        "unrated_status": 0,
        "grype_scan": "grype.json",
        "grype_status": 0,
    }

    def inspect(reference: str) -> dict[str, Any]:
        return identity

    monkeypatch.setattr(images, "local_identity", inspect)
    images.require_effective(configured, item)
    grype["matches"] = [
        {"vulnerability": {"severity": "High", "fix": {"state": "fixed"}}}
    ]
    (configured / "grype.json").write_text(json.dumps(grype))
    with pytest.raises(images.VulnerableImage, match="Blocking vulnerabilities"):
        images.require_effective(configured, item)
