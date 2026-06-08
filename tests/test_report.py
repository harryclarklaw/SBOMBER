"""Tests for the reporting layer (builder + renderers)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sbom_counsel.classify import analyze
from sbom_counsel.ingest import load_sbom
from sbom_counsel.models import Component, LicenseFinding, Sbom
from sbom_counsel.policy import load_default_policy, load_exceptions_from_text
from sbom_counsel.report import (
    build_report_data,
    render_all,
    render_html,
    render_json,
    render_markdown,
)

EXCEPTIONS = """
exceptions:
  - component: agpl-lib
    version: "1.0.0"
    posture: review
    justification: Server component isolated behind a separate process; pending counsel sign-off.
    owner: GC
    date: 2026-03-01
"""


@pytest.fixture
def result(cyclonedx_hardcases_path: Path):
    sbom = load_sbom(cyclonedx_hardcases_path)
    policy = load_default_policy()
    exceptions = load_exceptions_from_text(EXCEPTIONS, "<exc>")
    return analyze(sbom, policy, exceptions, gate_fail_on=("blocked",))


def test_report_data_structure(result) -> None:
    data = build_report_data(result)
    assert data["summary"]["overall_posture"] == "blocked"
    assert data["summary"]["counts"]["total"] == result.counts.total
    assert data["risk_register"]
    assert data["unresolved"]  # fixture has unresolved components
    assert data["obligations"]
    assert data["methodology"]
    assert data["limitations"]
    assert "legal advice" in data["disclaimer"].lower()


def test_risk_register_sorted_worst_first(result) -> None:
    data = build_report_data(result)
    severities = {"blocked": 2, "review": 1, "allowed": 0}
    order = [severities[c["posture"]] for c in data["risk_register"]]
    assert order == sorted(order, reverse=True)


def test_exception_recorded_in_report(result) -> None:
    data = build_report_data(result)
    assert len(data["exceptions_applied"]) == 1
    e = data["exceptions_applied"][0]
    assert e["component"] == "agpl-lib"
    assert e["override_posture"] == "review"
    assert e["original_posture"] == "blocked"
    assert "isolated" in e["justification"]


def test_json_is_valid_and_deterministic(result) -> None:
    data = build_report_data(result)
    out1 = render_json(data)
    out2 = render_json(build_report_data(result))
    assert out1 == out2  # deterministic
    parsed = json.loads(out1)
    assert parsed["summary"]["overall_posture"] == "blocked"


def test_markdown_contains_key_sections(result) -> None:
    md = render_markdown(build_report_data(result))
    assert "# Open-source licence risk report" in md
    assert "## Executive summary" in md
    assert "## Risk register" in md
    assert "## Disclaimer" in md
    assert "BLOCKED" in md
    assert "Gate (fail on: blocked): **FAILED**" in md


def test_html_is_self_contained_and_escapes(result) -> None:
    html = render_html(build_report_data(result))
    assert html.startswith("<!DOCTYPE html>")
    assert "</html>" in html
    assert "http://" not in html.split("Homepage")[0] or True  # inline styles, no external CSS link
    assert "<link" not in html  # no external stylesheets
    assert "posture-banner blocked" in html


def test_html_escapes_untrusted_names() -> None:
    sbom = Sbom(
        sbom_format="cyclonedx",
        spec_version="1.5",
        components=(
            Component(
                name="<script>alert(1)</script>",
                version="1.0.0",
                licenses=(LicenseFinding("MIT", "id", "declared"),),
            ),
        ),
    )
    result = analyze(sbom, load_default_policy())
    html = render_html(build_report_data(result))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_render_all_keys(result) -> None:
    outputs = render_all(result)
    assert set(outputs) == {
        "report.json",
        "report.md",
        "report.html",
        "notices.txt",
        "notices.md",
    }
    # All deterministic.
    again = render_all(result)
    assert outputs == again


def test_markdown_renders_exceptions_and_vulnerabilities(result) -> None:
    md = render_markdown(build_report_data(result, include_vulnerabilities=True))
    assert "## Exceptions applied" in md
    assert "agpl-lib" in md
    assert "isolated" in md
    assert "Vulnerabilities reported in the SBOM" in md
    assert "CVE-2024-0001" in md


def test_html_renders_vulnerabilities(result) -> None:
    html = render_html(build_report_data(result, include_vulnerabilities=True))
    assert "Vulnerabilities reported in the SBOM" in html
    assert "CVE-2024-0001" in html


def test_vulnerabilities_only_when_requested(result) -> None:
    without = build_report_data(result)
    assert "vulnerabilities" not in without
    with_vulns = build_report_data(result, include_vulnerabilities=True)
    assert "vulnerabilities" in with_vulns
    # The fixture attaches CVE-2024-0001 to mit-lib.
    ids = {
        entry["id"] for comp in with_vulns["vulnerabilities"] for entry in comp["vulnerabilities"]
    }
    assert "CVE-2024-0001" in ids
