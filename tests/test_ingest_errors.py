"""Tests that bad input fails gracefully with InputError, never a raw traceback."""

from __future__ import annotations

from pathlib import Path

import pytest

from sbom_counsel.errors import InputError, UnsupportedFormatError
from sbom_counsel.ingest import load_sbom


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="not found"):
        load_sbom(tmp_path / "nope.json")


def test_empty_file(tmp_path: Path) -> None:
    p = tmp_path / "empty.json"
    p.write_text("", encoding="utf-8")
    with pytest.raises(InputError, match="empty"):
        load_sbom(p)


def test_invalid_json(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(InputError, match="not valid JSON"):
        load_sbom(p)


def test_unrecognised_format(tmp_path: Path) -> None:
    p = tmp_path / "unknown.json"
    p.write_text('{"hello": "world"}', encoding="utf-8")
    with pytest.raises(UnsupportedFormatError):
        load_sbom(p)


def test_directory_input(tmp_path: Path) -> None:
    with pytest.raises(InputError):
        load_sbom(tmp_path)
