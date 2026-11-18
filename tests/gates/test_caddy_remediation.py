"""Owner-approved released-x/crypto experiment and effective binary identity."""

import hashlib
from pathlib import Path

import pytest

from scripts import images

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.req("NFR-024", kind="configuration check", part="trusted-sources")
@pytest.mark.parametrize(
    "file,sha256",
    [
        ("go.mod", "35d117667a7a44794cd906ba47a45a786e561ae719aaf9ed0232793e6f0618b5"),
        ("go.sum", "3a5d901e52e628a6387c87d25be7173efea87cfd468518f35ee20f3ca9feff29"),
    ],
)
def test_caddy_complete_graph_matches_approved_experiment(
    file: str, sha256: str
) -> None:
    assert (
        hashlib.sha256((ROOT / "docker/caddy" / file).read_bytes()).hexdigest()
        == sha256
    )


@pytest.mark.req("NFR-024", kind="configuration check", part="source-rejection")
def test_caddy_binary_cannot_reintroduce_go_jose_v3() -> None:
    info = (
        "/binary: go1.27.4\n\tpath\tcaddy\n\tmod\tcaddy\t(devel)\n"
        "\tdep\tgithub.com/caddyserver/caddy/v2\tv2.11.9\th1:test\n"
    )
    images.check_go_identity(info, "caddy")
    with pytest.raises(ValueError, match="go-jose v3"):
        images.check_go_identity(
            info + "\tdep\tgithub.com/go-jose/go-jose/v3\tv3.0.5\th1:test\n", "caddy"
        )
