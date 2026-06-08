"""Tests for CycloneDX ingestion."""

from __future__ import annotations

from pathlib import Path

from sbom_counsel.ingest import load_sbom


def _by_name(sbom):  # type: ignore[no-untyped-def]
    return {c.name: c for c in sbom.components}


def test_basic_metadata(cyclonedx_hardcases_path: Path) -> None:
    sbom = load_sbom(cyclonedx_hardcases_path)
    assert sbom.sbom_format == "cyclonedx"
    assert sbom.spec_version == "1.5"
    assert sbom.metadata_timestamp == "2026-01-15T10:00:00Z"
    assert sbom.document_name == "acme-game 1.0.0"


def test_metadata_component_is_excluded(cyclonedx_hardcases_path: Path) -> None:
    sbom = load_sbom(cyclonedx_hardcases_path)
    # The product itself (metadata.component) must not appear as a dependency.
    assert "acme-game" not in _by_name(sbom)


def test_nested_components_are_flattened(cyclonedx_hardcases_path: Path) -> None:
    comps = _by_name(load_sbom(cyclonedx_hardcases_path))
    assert "parent-lib" in comps
    assert "gpl-nested" in comps  # nested under parent-lib


def test_component_fields(cyclonedx_hardcases_path: Path) -> None:
    c = _by_name(load_sbom(cyclonedx_hardcases_path))["mit-lib"]
    assert c.version == "1.0.0"
    assert c.supplier == "MIT Authors"
    assert c.purl == "pkg:cargo/mit-lib@1.0.0"
    assert c.copyright == "Copyright (c) 2024 MIT Authors"
    assert c.hashes[0].algorithm == "SHA-256"
    assert c.hashes[0].value == "aaaa1111"
    assert [lic.raw for lic in c.licenses] == ["MIT"]
    assert c.licenses[0].source == "declared"


def test_expression_license(cyclonedx_hardcases_path: Path) -> None:
    c = _by_name(load_sbom(cyclonedx_hardcases_path))["dual-lib"]
    assert c.licenses[0].kind == "expression"
    assert c.licenses[0].raw == "MIT OR Apache-2.0"


def test_embedded_license_text_and_homepage(cyclonedx_hardcases_path: Path) -> None:
    c = _by_name(load_sbom(cyclonedx_hardcases_path))["apache-lib"]
    assert c.homepage == "https://example.com/apache-lib"
    assert c.embedded_texts
    assert "Apache License" in c.embedded_texts[0].text


def test_acknowledgement_marks_concluded(cyclonedx_hardcases_path: Path) -> None:
    c = _by_name(load_sbom(cyclonedx_hardcases_path))["concluded-lib"]
    sources = {lic.raw: lic.source for lic in c.licenses}
    assert sources["MIT"] == "concluded"
    assert sources["GPL-3.0-only"] == "declared"


def test_license_name_kind(cyclonedx_hardcases_path: Path) -> None:
    c = _by_name(load_sbom(cyclonedx_hardcases_path))["proprietary-lib"]
    assert c.licenses[0].kind == "name"
    assert c.licenses[0].raw == "MyCorp Proprietary License v3"


def test_component_with_no_licence(cyclonedx_hardcases_path: Path) -> None:
    c = _by_name(load_sbom(cyclonedx_hardcases_path))["nolicense-lib"]
    assert c.licenses == ()


def test_vulnerability_attached(cyclonedx_hardcases_path: Path) -> None:
    c = _by_name(load_sbom(cyclonedx_hardcases_path))["mit-lib"]
    assert c.vulnerabilities
    assert c.vulnerabilities[0].id == "CVE-2024-0001"
    assert c.vulnerabilities[0].severity == "high"
    assert c.vulnerabilities[0].source == "NVD"


def test_base64_text_is_decoded(tmp_path: Path) -> None:
    import base64
    import json

    encoded = base64.b64encode(b"Decoded MIT text").decode("ascii")
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "b64",
                "version": "1.0.0",
                "licenses": [
                    {"license": {"id": "MIT", "text": {"encoding": "base64", "content": encoded}}}
                ],
            }
        ],
    }
    path = tmp_path / "b64.cdx.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    c = load_sbom(path).components[0]
    assert c.embedded_texts[0].text == "Decoded MIT text"
