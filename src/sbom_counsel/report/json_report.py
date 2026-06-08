"""Render the report data as deterministic JSON."""

from __future__ import annotations

import json
from typing import Any


def render_json(data: dict[str, Any]) -> str:
    """Serialise the report data to indented, UTF-8, deterministic JSON.

    Key order follows the canonical structure (insertion order is stable in
    Python), so repeated runs on the same input produce byte-identical output.
    """
    return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False) + "\n"
