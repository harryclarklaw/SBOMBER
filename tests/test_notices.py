"""Tests for the third-party attribution notices file."""

from __future__ import annotations

from pathlib import Path

import pytest

from sbom_counsel.classify import analyze
from sbom_counsel.ingest import load_sbom
from sbom_counsel.policy import load_default_policy
from sbom_counsel.report.notices import (
    bundled_license_text,
    render_notices_markdown,
    render_notices_text,
)


@pytest.fixture
def cdx_result(cyclonedx_hardcases_path: Path):
    return analyze(load_sbom(cyclonedx_hardcases_path), load_default_policy())


@pytest.fixture
def spdx_result(spdx_hardcases_path: Path):
    return analyze(load_sbom(spdx_hardcases_path), load_default_policy())


def test_bundled_text_available_for_common_licences() -> None:
    assert "MIT License" in (bundled_license_text("MIT") or "")
    assert "Apache License" in (bundled_license_text("Apache-2.0") or "")
    assert bundled_license_text("Totally-Unknown") is None


def test_text_notices_list_components_and_licences(cdx_result) -> None:
    text = render_notices_text(cdx_result)
    assert "THIRD-PARTY SOFTWARE NOTICES" in text
    assert "mit-lib 1.0.0" in text
    assert "Copyright (c) 2024 MIT Authors" in text
    # Bundled MIT text is reproduced verbatim.
    assert "Permission is hereby granted, free of charge" in text


def test_text_notices_include_bundled_apache_text(cdx_result) -> None:
    text = render_notices_text(cdx_result)
    assert "---- Apache-2.0" in text
    assert "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION" in text


def test_text_notices_embedded_sbom_text(cdx_result) -> None:
    text = render_notices_text(cdx_result)
    # apache-lib carried an embedded text in the fixture.
    assert "LICENCE TEXTS PROVIDED IN THE SBOM" in text
    assert "embedded test text" in text


def test_pointer_for_unbundled_recognised_licence(cdx_result) -> None:
    # AGPL-3.0-only is recognised but not bundled -> pointer, never invented text.
    text = render_notices_text(cdx_result)
    assert "spdx.org/licenses/AGPL-3.0-only.html" in text


def test_markdown_notices(spdx_result) -> None:
    md = render_notices_markdown(spdx_result)
    assert md.startswith("# Third-party software notices")
    assert "## Components" in md
    assert "## Licence texts" in md
    # SPDX fixture has an extracted custom licence text.
    assert "Acme Custom License" in md


def test_notices_deterministic(cdx_result) -> None:
    assert render_notices_text(cdx_result) == render_notices_text(cdx_result)
    assert render_notices_markdown(cdx_result) == render_notices_markdown(cdx_result)
