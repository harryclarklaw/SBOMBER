"""Reporting layer: build report data and render it in each output format."""

from __future__ import annotations

from ..models import AnalysisResult
from .builder import build_report_data
from .html import render_html
from .json_report import render_json
from .markdown import render_markdown
from .notices import render_notices_markdown, render_notices_text

__all__ = [
    "build_report_data",
    "render_all",
    "render_html",
    "render_json",
    "render_markdown",
    "render_notices_markdown",
    "render_notices_text",
]


def render_all(
    result: AnalysisResult, *, include_vulnerabilities: bool = False
) -> dict[str, str]:
    """Render every output format and return a mapping of suffix -> content.

    Keys are: ``report.json``, ``report.md``, ``report.html``, ``notices.txt``,
    ``notices.md``.
    """
    data = build_report_data(result, include_vulnerabilities=include_vulnerabilities)
    return {
        "report.json": render_json(data),
        "report.md": render_markdown(data),
        "report.html": render_html(data),
        "notices.txt": render_notices_text(result),
        "notices.md": render_notices_markdown(result),
    }
