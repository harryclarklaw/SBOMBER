"""SBOM ingestion: read a file, detect its format, normalise to the model."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..errors import InputError
from ..models import Sbom
from . import cyclonedx, spdx
from .detect import detect_format

__all__ = ["detect_format", "load_sbom", "parse_sbom"]


def parse_sbom(data: Any, source_path: str | None = None) -> Sbom:
    """Normalise an already-parsed JSON SBOM document into a :class:`Sbom`."""
    sbom_format = detect_format(data)
    if sbom_format == "cyclonedx":
        return cyclonedx.parse(data, source_path)
    return spdx.parse(data, source_path)


def load_sbom(path: str | Path) -> Sbom:
    """Read, parse, detect, and normalise an SBOM file.

    Raises :class:`InputError` (never an unhandled exception) for a missing file,
    invalid JSON, or an unrecognised format.
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise InputError(
            f"SBOM file not found: {p}",
            hint="Check the path to the SBOM file.",
        ) from exc
    except IsADirectoryError as exc:
        raise InputError(f"Expected an SBOM file but got a directory: {p}") from exc
    except OSError as exc:
        raise InputError(f"Could not read SBOM file {p}: {exc}") from exc

    if not text.strip():
        raise InputError(f"SBOM file is empty: {p}")

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(
            f"SBOM file {p} is not valid JSON: {exc}",
            hint="Only JSON CycloneDX and SPDX SBOMs are supported in this version.",
        ) from exc

    return parse_sbom(data, str(p))
