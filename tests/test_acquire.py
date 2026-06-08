"""Tests for the Syft-based SBOM acquisition wrapper (runner injected)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sbom_counsel.acquire import sbom_from_syft
from sbom_counsel.errors import EnvironmentToolError

SYFT_CYCLONEDX = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "left-pad",
                "version": "1.3.0",
                "licenses": [{"license": {"id": "WTFPL"}}],
            },
            {
                "type": "library",
                "name": "lodash",
                "version": "4.17.21",
                "licenses": [{"license": {"id": "MIT"}}],
            },
        ],
    }
)


def test_sbom_from_syft_parses_output(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()

    def fake_runner(args: list[str], cwd: Path) -> str:
        assert args[0] == "syft"
        assert "cyclonedx-json" in args
        return SYFT_CYCLONEDX

    sbom = sbom_from_syft(project, runner=fake_runner)
    assert sbom.sbom_format == "cyclonedx"
    assert {c.name for c in sbom.components} == {"left-pad", "lodash"}


def test_missing_target_raises(tmp_path: Path) -> None:
    with pytest.raises(EnvironmentToolError, match="not found"):
        sbom_from_syft(tmp_path / "nope", runner=lambda a, c: SYFT_CYCLONEDX)


def test_bad_json_from_syft_raises(tmp_path: Path) -> None:
    with pytest.raises(EnvironmentToolError, match="parse Syft output"):
        sbom_from_syft(tmp_path, runner=lambda a, c: "not json")


def test_non_sbom_output_raises(tmp_path: Path) -> None:
    with pytest.raises(EnvironmentToolError, match="could not read"):
        sbom_from_syft(tmp_path, runner=lambda a, c: json.dumps({"unrelated": True}))
