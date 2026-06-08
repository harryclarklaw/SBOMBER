"""Render the report data as a self-contained HTML document."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from jinja2 import Environment, PackageLoader


@lru_cache(maxsize=1)
def _environment() -> Environment:
    # Force autoescaping: the report renders untrusted values (component names,
    # suppliers, etc.) from the SBOM into HTML, and the template file extension
    # (.html.j2) would otherwise defeat extension-based autoescape selection.
    env = Environment(
        loader=PackageLoader("sbom_counsel.report", "templates"),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["posture_label"] = _posture_label
    return env


_POSTURE_LABEL = {"allowed": "Allowed", "review": "Review", "blocked": "Blocked"}


def _posture_label(value: str) -> str:
    return _POSTURE_LABEL.get(value, value)


def render_html(data: dict[str, Any]) -> str:
    """Render a single, self-contained HTML file (inline CSS, no network use)."""
    template = _environment().get_template("report.html.j2")
    return template.render(**data) + "\n"
