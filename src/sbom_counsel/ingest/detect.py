"""Auto-detect the SBOM format from a parsed JSON document."""

from __future__ import annotations

from typing import Any

from ..errors import UnsupportedFormatError
from ..models import SbomFormat


def detect_format(data: Any) -> SbomFormat:
    """Return the SBOM format of a parsed JSON document.

    Detection relies on format-defining keys: CycloneDX documents carry
    ``bomFormat: "CycloneDX"`` (and/or ``specVersion``); SPDX documents carry
    ``spdxVersion``. Raises :class:`UnsupportedFormatError` for anything else.
    """
    if not isinstance(data, dict):
        raise UnsupportedFormatError(
            "The input is not a JSON object, so it is not a recognised SBOM.",
            hint="Provide a CycloneDX or SPDX SBOM in JSON form.",
        )

    bom_format = data.get("bomFormat")
    if isinstance(bom_format, str) and bom_format.strip().lower() == "cyclonedx":
        return "cyclonedx"

    if "spdxVersion" in data:
        return "spdx"

    # Fall back to structural hints for documents that omit the marker key.
    schema = str(data.get("$schema", "")).lower()
    if "cyclonedx" in schema or ("specVersion" in data and "components" in data):
        return "cyclonedx"
    if "spdx" in schema or ("SPDXID" in data and "packages" in data):
        return "spdx"

    raise UnsupportedFormatError(
        "Could not recognise the input as a CycloneDX or SPDX SBOM.",
        hint=(
            "CycloneDX JSON has a 'bomFormat' field; SPDX JSON has a 'spdxVersion' field. "
            "Check that the file is one of these formats in JSON."
        ),
    )
