"""Shared test fixtures and helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


def load_fixture(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return data


@pytest.fixture
def cyclonedx_hardcases_path() -> Path:
    return FIXTURES / "cyclonedx_hardcases.json"


@pytest.fixture
def spdx_hardcases_path() -> Path:
    return FIXTURES / "spdx_hardcases.json"
