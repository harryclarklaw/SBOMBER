"""Licence resolution: turn raw SBOM licence statements into SPDX expressions."""

from __future__ import annotations

from .resolver import Resolution, ResolvedSymbol, is_known, normalize_key, resolve

__all__ = ["Resolution", "ResolvedSymbol", "is_known", "normalize_key", "resolve"]
