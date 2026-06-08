"""Parse CycloneDX JSON SBOMs into the normalised model.

Targets CycloneDX 1.4 to 1.6 (the current major line and its recent predecessors),
reading only the fields the analysis needs. CycloneDX licence entries may be an
SPDX id, a free-text name, or an SPDX ``expression``; from 1.5 each entry may
carry an ``acknowledgement`` of ``declared`` or ``concluded``.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

from ..models import (
    Component,
    EmbeddedLicenseText,
    Hash,
    LicenseFinding,
    LicenseSource,
    Sbom,
    Vulnerability,
)


def _acknowledgement_source(*candidates: Any) -> LicenseSource:
    for value in candidates:
        if isinstance(value, str) and value.strip().lower() == "concluded":
            return "concluded"
    return "declared"


def _decode_text(text_obj: Any) -> str | None:
    if not isinstance(text_obj, dict):
        return None
    content = text_obj.get("content")
    if not isinstance(content, str):
        return None
    if str(text_obj.get("encoding", "")).lower() == "base64":
        try:
            return base64.b64decode(content).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            return content
    return content


def _parse_licenses(
    entries: Any,
) -> tuple[tuple[LicenseFinding, ...], tuple[EmbeddedLicenseText, ...]]:
    findings: list[LicenseFinding] = []
    texts: list[EmbeddedLicenseText] = []
    if not isinstance(entries, list):
        return (), ()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if "expression" in entry:
            expression = entry.get("expression")
            if isinstance(expression, str) and expression.strip():
                source = _acknowledgement_source(entry.get("acknowledgement"))
                findings.append(
                    LicenseFinding(raw=expression.strip(), kind="expression", source=source)
                )
            continue

        lic = entry.get("license")
        if not isinstance(lic, dict):
            continue
        source = _acknowledgement_source(lic.get("acknowledgement"), entry.get("acknowledgement"))
        license_id = lic.get("id")
        name = lic.get("name")
        if isinstance(license_id, str) and license_id.strip():
            findings.append(LicenseFinding(raw=license_id.strip(), kind="id", source=source))
        elif isinstance(name, str) and name.strip():
            findings.append(LicenseFinding(raw=name.strip(), kind="name", source=source))

        text = _decode_text(lic.get("text"))
        if text:
            texts.append(
                EmbeddedLicenseText(
                    license_id=license_id if isinstance(license_id, str) else None,
                    name=name if isinstance(name, str) else None,
                    text=text,
                )
            )
    return tuple(findings), tuple(texts)


def _parse_hashes(entries: Any) -> tuple[Hash, ...]:
    if not isinstance(entries, list):
        return ()
    hashes: list[Hash] = []
    for entry in entries:
        if isinstance(entry, dict):
            alg = entry.get("alg")
            value = entry.get("content")
            if isinstance(alg, str) and isinstance(value, str):
                hashes.append(Hash(algorithm=alg, value=value))
    return tuple(hashes)


def _homepage(component: dict[str, Any]) -> str | None:
    refs = component.get("externalReferences")
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, dict) and ref.get("type") == "website":
                url = ref.get("url")
                if isinstance(url, str):
                    return url
    return None


def _supplier(component: dict[str, Any]) -> str | None:
    supplier = component.get("supplier")
    if isinstance(supplier, dict):
        name = supplier.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
    publisher = component.get("publisher")
    if isinstance(publisher, str) and publisher.strip():
        return publisher.strip()
    return None


def _author(component: dict[str, Any]) -> str | None:
    author = component.get("author")
    if isinstance(author, str) and author.strip():
        return author.strip()
    authors = component.get("authors")
    if isinstance(authors, list):
        raw_names = [a.get("name") for a in authors if isinstance(a, dict)]
        clean_names = [n.strip() for n in raw_names if isinstance(n, str) and n.strip()]
        if clean_names:
            return ", ".join(clean_names)
    return None


def _flatten_components(items: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(items, list):
        return out
    for item in items:
        if not isinstance(item, dict):
            continue
        out.append(item)
        nested = item.get("components")
        if isinstance(nested, list):
            out.extend(_flatten_components(nested))
    return out


def _parse_vulnerabilities(data: dict[str, Any]) -> dict[str, list[Vulnerability]]:
    """Map component bom-ref/purl to any vulnerabilities the SBOM already lists."""
    by_ref: dict[str, list[Vulnerability]] = {}
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        return by_ref
    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        vid = vuln.get("id")
        if not isinstance(vid, str):
            continue
        source_obj = vuln.get("source")
        source = source_obj.get("name") if isinstance(source_obj, dict) else None
        severity = None
        ratings = vuln.get("ratings")
        if isinstance(ratings, list):
            for rating in ratings:
                if isinstance(rating, dict) and isinstance(rating.get("severity"), str):
                    severity = rating["severity"]
                    break
        record = Vulnerability(
            id=vid,
            source=source if isinstance(source, str) else None,
            severity=severity,
            description=(
                vuln.get("description") if isinstance(vuln.get("description"), str) else None
            ),
        )
        affects = vuln.get("affects")
        if isinstance(affects, list):
            for affected in affects:
                if isinstance(affected, dict) and isinstance(affected.get("ref"), str):
                    by_ref.setdefault(affected["ref"], []).append(record)
    return by_ref


def parse(data: dict[str, Any], source_path: str | None = None) -> Sbom:
    """Parse a CycloneDX JSON document into a :class:`Sbom`."""
    spec_version = str(data.get("specVersion", "unknown"))
    metadata_raw = data.get("metadata")
    metadata = metadata_raw if isinstance(metadata_raw, dict) else {}
    timestamp = metadata.get("timestamp") if isinstance(metadata.get("timestamp"), str) else None

    document_name = None
    meta_component = metadata.get("component")
    if isinstance(meta_component, dict):
        name = meta_component.get("name")
        version = meta_component.get("version")
        if isinstance(name, str):
            document_name = f"{name} {version}".strip() if isinstance(version, str) else name

    vulns_by_ref = _parse_vulnerabilities(data)

    components: list[Component] = []
    for raw in _flatten_components(data.get("components")):
        name = raw.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        version = raw.get("version")
        bom_ref = raw.get("bom-ref")
        purl = raw.get("purl")
        findings, texts = _parse_licenses(raw.get("licenses"))

        vulns: tuple[Vulnerability, ...] = ()
        for key in (bom_ref, purl):
            if isinstance(key, str) and key in vulns_by_ref:
                vulns = vulns + tuple(vulns_by_ref[key])

        components.append(
            Component(
                name=name.strip(),
                version=version.strip() if isinstance(version, str) and version.strip() else None,
                supplier=_supplier(raw),
                author=_author(raw),
                purl=purl.strip() if isinstance(purl, str) and purl.strip() else None,
                bom_ref=bom_ref if isinstance(bom_ref, str) else None,
                copyright=raw.get("copyright") if isinstance(raw.get("copyright"), str) else None,
                homepage=_homepage(raw),
                licenses=findings,
                embedded_texts=texts,
                hashes=_parse_hashes(raw.get("hashes")),
                vulnerabilities=vulns,
            )
        )

    return Sbom(
        sbom_format="cyclonedx",
        spec_version=spec_version,
        components=tuple(components),
        document_name=document_name,
        metadata_timestamp=timestamp,
        source_path=source_path,
    )
