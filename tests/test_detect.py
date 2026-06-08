"""Tests for SBOM format auto-detection."""

from __future__ import annotations

import pytest

from sbom_counsel.errors import UnsupportedFormatError
from sbom_counsel.ingest import detect_format


def test_detects_cyclonedx_by_marker() -> None:
    assert detect_format({"bomFormat": "CycloneDX", "specVersion": "1.5"}) == "cyclonedx"


def test_detects_spdx_by_version_key() -> None:
    assert detect_format({"spdxVersion": "SPDX-2.3"}) == "spdx"


def test_detects_cyclonedx_by_structure() -> None:
    assert detect_format({"specVersion": "1.4", "components": []}) == "cyclonedx"


def test_detects_spdx_by_structure() -> None:
    assert detect_format({"SPDXID": "SPDXRef-DOCUMENT", "packages": []}) == "spdx"


def test_unrecognised_raises() -> None:
    with pytest.raises(UnsupportedFormatError):
        detect_format({"foo": "bar"})


def test_non_object_raises() -> None:
    with pytest.raises(UnsupportedFormatError):
        detect_format(["not", "an", "object"])
