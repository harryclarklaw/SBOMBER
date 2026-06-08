"""Parse SPDX JSON SBOMs into the normalised model.

Targets SPDX 2.2 and 2.3 (the current 2.x line, the dominant JSON form in the
field). Licence information comes from ``licenseConcluded`` and
``licenseDeclared`` on each package; custom licence texts are collected from the
document-level ``hasExtractedLicensingInfos`` and attached to the packages that
reference them.
"""

from __future__ import annotations

from typing import Any

from ..models import (
    Component,
    EmbeddedLicenseText,
    Hash,
    LicenseFinding,
    Sbom,
)

# SPDX uses these tokens for "no value"; treat them as absent.
_ABSENT = {"NOASSERTION", "NONE", ""}


def _clean(value: Any) -> str | None:
    if isinstance(value, str) and value.strip() and value.strip().upper() not in _ABSENT:
        return value.strip()
    return None


def _strip_actor_prefix(value: str | None) -> str | None:
    if value is None:
        return None
    for prefix in ("Organization:", "Person:", "Tool:"):
        if value.startswith(prefix):
            return value[len(prefix) :].strip() or None
    return value


def _purl(package: dict[str, Any]) -> str | None:
    refs = package.get("externalRefs")
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                locator = ref.get("referenceLocator")
                if isinstance(locator, str) and locator.strip():
                    return locator.strip()
    return None


def _hashes(package: dict[str, Any]) -> tuple[Hash, ...]:
    checksums = package.get("checksums")
    if not isinstance(checksums, list):
        return ()
    out: list[Hash] = []
    for checksum in checksums:
        if isinstance(checksum, dict):
            alg = checksum.get("algorithm")
            value = checksum.get("checksumValue")
            if isinstance(alg, str) and isinstance(value, str):
                out.append(Hash(algorithm=alg, value=value))
    return tuple(out)


def _licenses(package: dict[str, Any]) -> tuple[LicenseFinding, ...]:
    findings: list[LicenseFinding] = []
    concluded = _clean(package.get("licenseConcluded"))
    if concluded is not None:
        findings.append(LicenseFinding(raw=concluded, kind="expression", source="concluded"))
    declared = _clean(package.get("licenseDeclared"))
    if declared is not None:
        findings.append(LicenseFinding(raw=declared, kind="expression", source="declared"))
    return tuple(findings)


def _extracted_license_texts(data: dict[str, Any]) -> dict[str, EmbeddedLicenseText]:
    result: dict[str, EmbeddedLicenseText] = {}
    infos = data.get("hasExtractedLicensingInfos")
    if not isinstance(infos, list):
        return result
    for info in infos:
        if not isinstance(info, dict):
            continue
        license_id = info.get("licenseId")
        text = info.get("extractedText")
        if isinstance(license_id, str) and isinstance(text, str) and text.strip():
            name = info.get("name")
            result[license_id] = EmbeddedLicenseText(
                license_id=license_id,
                name=name if isinstance(name, str) else None,
                text=text,
            )
    return result


def _root_spdx_ids(data: dict[str, Any]) -> set[str]:
    """SPDXIDs that the document DESCRIBES (i.e. the product itself, not a dep)."""
    roots: set[str] = set()
    describes = data.get("documentDescribes")
    if isinstance(describes, list):
        roots.update(item for item in describes if isinstance(item, str))
    relationships = data.get("relationships")
    document_id = data.get("SPDXID")
    if isinstance(relationships, list):
        for rel in relationships:
            if not isinstance(rel, dict):
                continue
            if rel.get("relationshipType") == "DESCRIBES" and rel.get("spdxElementId") == document_id:
                related = rel.get("relatedSpdxElement")
                if isinstance(related, str):
                    roots.add(related)
    return roots


def parse(data: dict[str, Any], source_path: str | None = None) -> Sbom:
    """Parse an SPDX JSON document into a :class:`Sbom`."""
    spec_version = str(data.get("spdxVersion", "unknown"))
    document_name = data.get("name") if isinstance(data.get("name"), str) else None
    creation_info = data.get("creationInfo") if isinstance(data.get("creationInfo"), dict) else {}
    timestamp = creation_info.get("created") if isinstance(creation_info.get("created"), str) else None

    extracted = _extracted_license_texts(data)
    roots = _root_spdx_ids(data)

    components: list[Component] = []
    packages = data.get("packages")
    if not isinstance(packages, list):
        packages = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        spdx_id = package.get("SPDXID")
        # Skip the package the document describes — that is the product itself.
        if isinstance(spdx_id, str) and spdx_id in roots:
            continue

        findings = _licenses(package)

        # Attach any extracted (custom) licence texts referenced by this package.
        texts: list[EmbeddedLicenseText] = []
        if extracted:
            referenced = " ".join(f.raw for f in findings)
            for license_id, embedded in extracted.items():
                if license_id in referenced:
                    texts.append(embedded)

        components.append(
            Component(
                name=name.strip(),
                version=_clean(package.get("versionInfo")),
                supplier=_strip_actor_prefix(_clean(package.get("supplier"))),
                author=_strip_actor_prefix(_clean(package.get("originator"))),
                purl=_purl(package),
                bom_ref=spdx_id if isinstance(spdx_id, str) else None,
                copyright=_clean(package.get("copyrightText")),
                homepage=_clean(package.get("homepage")),
                licenses=findings,
                embedded_texts=tuple(texts),
                hashes=_hashes(package),
            )
        )

    return Sbom(
        sbom_format="spdx",
        spec_version=spec_version,
        components=tuple(components),
        document_name=document_name,
        metadata_timestamp=timestamp,
        source_path=source_path,
    )
