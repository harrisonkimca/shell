"""Carry requirement associations in standard pytest JUnit properties."""

import pytest


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        for marker in item.iter_markers("req"):
            item.user_properties.extend(
                [
                    ("requirement", ",".join(str(arg) for arg in marker.args)),
                    ("verification_kind", str(marker.kwargs["kind"])),
                    ("verification_part", str(marker.kwargs["part"])),
                ]
            )
