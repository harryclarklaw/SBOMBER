"""Tests for SPDX ingestion."""

from __future__ import annotations

from pathlib import Path

from sbom_counsel.ingest import load_sbom


def _by_name(sbom):
    return {c.name: c for c in sbom.components}


def test_basic_metadata(spdx_hardcases_path: Path) -> None:
    sbom = load_sbom(spdx_hardcases_path)
    assert sbom.sbom_format == "spdx"
    assert sbom.spec_version == "SPDX-2.3"
    assert sbom.document_name == "acme-service-sbom"
    assert sbom.metadata_timestamp == "2026-02-01T12:00:00Z"


def test_root_package_excluded(spdx_hardcases_path: Path) -> None:
    # The DESCRIBES-related package (the product) is not a dependency.
    assert "acme-service" not in _by_name(load_sbom(spdx_hardcases_path))


def test_concluded_and_declared_findings(spdx_hardcases_path: Path) -> None:
    c = _by_name(load_sbom(spdx_hardcases_path))["mit-pkg"]
    sources = {f.source: f.raw for f in c.licenses}
    assert sources["concluded"] == "MIT"
    assert sources["declared"] == "MIT"


def test_purl_supplier_originator_checksums(spdx_hardcases_path: Path) -> None:
    c = _by_name(load_sbom(spdx_hardcases_path))["mit-pkg"]
    assert c.purl == "pkg:pypi/mit-pkg@1.2.3"
    assert c.supplier == "MIT Pkg Authors"  # "Organization:" prefix stripped
    assert c.author == "Jane Doe"  # "Person:" prefix stripped
    assert c.homepage == "https://example.com/mit-pkg"
    assert c.hashes[0].algorithm == "SHA256"


def test_noassertion_supplier_becomes_none(spdx_hardcases_path: Path) -> None:
    c = _by_name(load_sbom(spdx_hardcases_path))["gpl-pkg"]
    assert c.supplier is None
    assert c.version == "4.0"


def test_fallback_only_keeps_declared_when_concluded_noassertion(
    spdx_hardcases_path: Path,
) -> None:
    c = _by_name(load_sbom(spdx_hardcases_path))["fallback-pkg"]
    # NOASSERTION concluded is dropped at ingestion; only the declared remains.
    assert [f.source for f in c.licenses] == ["declared"]
    assert c.licenses[0].raw == "BSD-3-Clause"


def test_none_and_noassertion_drop_to_no_findings(spdx_hardcases_path: Path) -> None:
    c = _by_name(load_sbom(spdx_hardcases_path))["none-pkg"]
    assert c.licenses == ()


def test_extracted_license_text_attached(spdx_hardcases_path: Path) -> None:
    c = _by_name(load_sbom(spdx_hardcases_path))["custom-pkg"]
    assert c.embedded_texts
    assert c.embedded_texts[0].license_id == "LicenseRef-AcmeCustom"
    assert "Acme Custom License" in c.embedded_texts[0].text


def test_package_with_no_licence(spdx_hardcases_path: Path) -> None:
    c = _by_name(load_sbom(spdx_hardcases_path))["nolicense-pkg"]
    assert c.licenses == ()
