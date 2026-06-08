"""Single-call entry point for embeddings (the in-browser web app, notebooks, etc.).

The browser app runs the *same* analysis engine as the CLI, compiled to
WebAssembly via Pyodide, so the web verdict is identical to the CLI and CI
verdict — one auditable source of truth. This module gives that app (and any
other embedding) one function that takes SBOM text plus optional policy and
exceptions text and returns everything needed to render a report, with errors
returned as data rather than raised, so a UI never has to catch exceptions.

Nothing here performs any I/O or network access: callers pass text in and get
data out. In the browser this means the user's SBOM never leaves their machine.
"""

from __future__ import annotations

import json
from typing import Any

from . import APP_NAME, APP_TAGLINE, __version__
from .classify import analyze
from .errors import SbomCounselError
from .ingest import parse_sbom
from .models import Posture
from .policy import (
    empty_exception_set,
    load_default_policy,
    load_exceptions_from_text,
    load_policy_from_text,
)
from .report import (
    build_report_data,
    render_html,
    render_json,
    render_markdown,
    render_notices_markdown,
    render_notices_text,
)

_FAIL_ON: dict[str, tuple[Posture, ...]] = {
    "none": (),
    "blocked": ("blocked",),
    "review": ("review", "blocked"),
}


def _error(kind: str, message: str) -> dict[str, Any]:
    return {"ok": False, "error": {"kind": kind, "message": message}}


def about() -> dict[str, str]:
    """Identifying metadata for the UI header."""
    return {"name": APP_NAME, "version": __version__, "tagline": APP_TAGLINE}


def default_policy_yaml() -> str:
    """The default policy text, for pre-filling an in-app policy editor."""
    from .policy import default_policy_text

    return default_policy_text()


def analyze_text(
    sbom_text: str,
    *,
    policy_text: str | None = None,
    exceptions_text: str | None = None,
    strict_unresolved: bool = False,
    fail_on: str = "blocked",
    filename: str | None = None,
    include_vulnerabilities: bool = True,
) -> dict[str, Any]:
    """Analyse SBOM text and return report data plus every rendered format.

    Returns ``{"ok": True, "report": <data>, "renders": {...}}`` on success, or
    ``{"ok": False, "error": {"kind": ..., "message": ...}}`` on any failure.
    Never raises for expected error conditions (bad JSON, unsupported format,
    invalid policy/exceptions).
    """
    if not sbom_text or not sbom_text.strip():
        return _error("input", "The file is empty.")

    try:
        data = json.loads(sbom_text)
    except json.JSONDecodeError as exc:
        return _error(
            "input",
            f"The file is not valid JSON ({exc}). This tool reads CycloneDX or SPDX "
            f"SBOMs in JSON form.",
        )

    try:
        sbom = parse_sbom(data, filename)
        if policy_text and policy_text.strip():
            policy = load_policy_from_text(policy_text, "<custom policy>")
        else:
            policy = load_default_policy()
        if strict_unresolved:
            policy = policy.with_unresolved_posture("blocked")
        if exceptions_text and exceptions_text.strip():
            exceptions = load_exceptions_from_text(exceptions_text, "<custom exceptions>")
        else:
            exceptions = empty_exception_set()

        result = analyze(
            sbom,
            policy,
            exceptions,
            tool_name=APP_NAME,
            tool_version=__version__,
            gate_fail_on=_FAIL_ON.get(fail_on, ("blocked",)),
        )
        report = build_report_data(result, include_vulnerabilities=include_vulnerabilities)
        return {
            "ok": True,
            "report": report,
            "renders": {
                "report.json": render_json(report),
                "report.md": render_markdown(report),
                "report.html": render_html(report),
                "notices.txt": render_notices_text(result),
                "notices.md": render_notices_markdown(result),
            },
        }
    except SbomCounselError as exc:
        return _error(exc.exit_code.name.lower(), str(exc))
    except Exception as exc:
        return _error("internal", f"Unexpected error: {type(exc).__name__}: {exc}")


def analyze_text_json(sbom_text: str, **kwargs: Any) -> str:
    """Like :func:`analyze_text`, but returns a JSON string.

    Convenient for the browser: the JavaScript side can ``JSON.parse`` the result
    instead of converting a Python object across the Pyodide boundary.
    """
    return json.dumps(analyze_text(sbom_text, **kwargs), ensure_ascii=False)
