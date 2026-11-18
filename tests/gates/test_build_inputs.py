"""Build input binding and restricted Dockerfile continuation syntax."""

import shutil
from pathlib import Path

import pytest

from scripts import images
from tests.gates.test_images import ROOT
from tests.gates.test_images import configured as configured


@pytest.mark.req("NFR-024", kind="configuration check", part="source-rejection")
@pytest.mark.parametrize(
    "path",
    [
        *(
            f"docker/{name}/{file}"
            for name in ("go", "caddy", "postgres")
            for file in ("go.mod", "go.sum", "Dockerfile")
        ),
        "docker/go",
        "docker/caddy",
        "docker/postgres",
        "docker/python",
        "docker/python/debian.sources",
        "docker/api/Dockerfile",
        "pyproject.toml",
        "uv.lock",
        ".python-version",
        "apps/api/src",
        "apps/api/src/shell_api/main.py",
        "apps/api/src/.assets",
        "apps/api/src/.assets/input",
        "apps/api/src/shell_api",
        "apps/api",
        "apps",
        "docker",
        ".dockerignore",
    ],
)
def test_symbolic_build_inputs_rejected(
    configured: Path, tmp_path: Path, path: str
) -> None:
    shutil.copytree(ROOT / "apps/api/src", configured / "apps/api/src")
    (configured / "apps/api/src/.assets").mkdir()
    (configured / "apps/api/src/.assets/input").write_text("asset")
    shutil.copy(ROOT / ".dockerignore", configured / ".dockerignore")
    images.check_configuration(configured)
    source = configured / path
    target = tmp_path / "original"
    source.rename(target)
    source.symlink_to(target, target_is_directory=target.is_dir())
    with pytest.raises(ValueError, match="symbolic build input"):
        images.check_configuration(configured)


@pytest.mark.req("NFR-024", kind="configuration check", part="source-rejection")
@pytest.mark.parametrize("recipe", images.RECIPES)
@pytest.mark.parametrize(
    "continuation",
    [" \\\n\n", " \\\n \n", "\\\n", " \\\t\n ", " \\ \n ", "\t\\\n ", " \\\n\t"],
)
def test_ambiguous_continuations_rejected(
    configured: Path, recipe: str, continuation: str
) -> None:
    images.check_configuration(configured)
    path = configured / f"docker/{recipe}/Dockerfile"
    original = path.read_text()
    # Splitting an existing space normalized to the same pinned instruction in
    # the old gate, though BuildKit concatenates or skips the blank differently.
    before = original.splitlines()[0]
    assert " " in before
    after = before.replace(" ", continuation, 1)
    path.write_text(original.replace(before, after, 1))
    with pytest.raises(ValueError, match="Unsupported Docker continuation"):
        images.check_configuration(configured)
