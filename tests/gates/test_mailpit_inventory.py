"""Mailpit's actual banner must agree with its binary build metadata."""

import subprocess
from pathlib import Path

import pytest

from scripts import images


@pytest.mark.req("NFR-024", kind="configuration check", part="image-sbom")
@pytest.mark.parametrize(
    "banner",
    [
        "Mailpit v1.33.0 compiled with go1.27.4 on linux/amd64",
        "Mailpit v1.34.0 compiled with go1.27.3 on linux/amd64",
        "invalid banner",
    ],
)
def test_mailpit_banner_and_build_metadata_must_agree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, banner: str
) -> None:
    (tmp_path / "reports/images").mkdir(parents=True)
    current_banner = "Mailpit v1.34.0 compiled with go1.27.4 on linux/amd64"

    def command(*args: str) -> str:
        if args[-1] == "/binary":
            return (
                "/binary: go1.27.4\n\tpath\tgithub.com/axllent/mailpit\n"
                "\tmod\tgithub.com/axllent/mailpit\tv1.34.0+dirty\th1:test\n"
            )
        if args[-1] == "--no-release-check":
            return current_banner
        assert args[-2] == "-c"
        return "musl\t1.2.5"

    def binary(*args: object, **kwargs: object) -> bytes:
        return b"test binary"

    monkeypatch.setattr(images, "command", command)
    monkeypatch.setattr(subprocess, "check_output", binary)
    inventory = images.actual_inventory(
        tmp_path, {"image_id": "mailpit"}, "mailpit", {"image_id": "go"}
    )
    assert inventory["principal"] == {"github.com/axllent/mailpit": "v1.34.0+dirty"}
    current_banner = banner
    with pytest.raises(ValueError, match="disagree"):
        images.actual_inventory(
            tmp_path, {"image_id": "mailpit"}, "mailpit", {"image_id": "go"}
        )
