"""Trivy independently rejects unrated findings before dependent use."""

import json
from pathlib import Path
from typing import Any

import pytest

from scripts import images
from tests.gates.test_image_revision import grype_report
from tests.gates.test_images import configured as configured


def report_for(identity: str) -> dict[str, Any]:
    return {"SchemaVersion": 2, "Metadata": {"ImageID": identity}, "Results": []}


@pytest.mark.req("NFR-026", kind="configuration check", part="scanner-policy-rejection")
@pytest.mark.parametrize("severity", ["UNKNOWN", "", "Unrated", None])
@pytest.mark.parametrize(
    "state",
    ["fixed", "unknown", "under_investigation", "fix_deferred", "affected", "", None],
)
@pytest.mark.parametrize("fixed", ["2", ""])
def test_trivy_unrated_available_or_unresolved_fix_rejected(
    severity: str | None, state: str | None, fixed: str
) -> None:
    identity = "sha256:" + "a" * 64
    report = report_for(identity)
    images.check_scan(report, identity, 0)
    finding: dict[str, Any] = {"FixedVersion": fixed}
    if severity is not None:
        finding["Severity"] = severity
    if state is not None:
        finding["Status"] = state
    report["Results"] = [{"Vulnerabilities": [finding]}]
    with pytest.raises(
        images.VulnerableImage, match="Blocking vulnerabilities"
    ) as error:
        images.check_scan(report, identity, 0)
    assert error.value.findings == [finding]


@pytest.mark.req("NFR-026", kind="configuration check", part="build-scans")
@pytest.mark.parametrize("severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"])
@pytest.mark.parametrize("state", ["will_not_fix", "end_of_life", "not_affected"])
def test_trivy_existing_fixed_severity_policy_and_confirmed_unavailable_fixes_retained(
    severity: str, state: str
) -> None:
    identity = "sha256:" + "a" * 64
    report = report_for(identity)
    report["Results"] = [{"Vulnerabilities": [{"Severity": severity, "Status": state}]}]
    images.check_scan(report, identity, 0)


@pytest.mark.req("NFR-026", kind="configuration check", part="build-scans")
@pytest.mark.parametrize(
    "mutation", ["fixable", "unresolved", "missing", "wrong-image", "scanner-error"]
)
def test_trivy_unrated_report_required_before_dependent_use(
    configured: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    identity, grype = grype_report()
    trivy = report_for(identity["Id"])
    (configured / "t.json").write_text(json.dumps(trivy))
    (configured / "u.json").write_text(json.dumps(trivy))
    (configured / "g.json").write_text(json.dumps(grype))
    item = {
        "image_id": identity["Id"],
        "docker": identity,
        "reference": "test",
        "scan": "t.json",
        "scanner_status": 0,
        "unrated_scan": "u.json",
        "unrated_status": 0,
        "grype_scan": "g.json",
        "grype_status": 0,
    }

    def inspect(reference: str) -> dict[str, Any]:
        return identity

    monkeypatch.setattr(images, "local_identity", inspect)
    images.require_effective(configured, item)
    if mutation in {"fixable", "unresolved"}:
        trivy["Results"] = [
            {
                "Vulnerabilities": [
                    {
                        "Severity": "UNKNOWN",
                        "Status": "unknown",
                        "FixedVersion": "2" if mutation == "fixable" else "",
                    }
                ]
            }
        ]
        expected = "Blocking vulnerabilities"
    elif mutation == "wrong-image":
        trivy["Metadata"]["ImageID"] = "wrong"
        expected = "wrong-image association"
    elif mutation == "scanner-error":
        item["unrated_status"] = 1
        expected = "Scanner error"
    else:
        (configured / "u.json").unlink()
        expected = "u.json"
    if mutation != "missing":
        (configured / "u.json").write_text(json.dumps(trivy))
    with pytest.raises((ValueError, OSError), match=expected):
        images.require_effective(configured, item)
