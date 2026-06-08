"""Tests for the embedding/browser entry point."""

from __future__ import annotations

import json
from pathlib import Path

from sbom_counsel.webapi import (
    about,
    analyze_text,
    analyze_text_json,
    default_policy_yaml,
)

CLEAN = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "a",
                "version": "1.0.0",
                "licenses": [{"license": {"id": "MIT"}}],
            }
        ],
    }
)

BLOCKED = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "g",
                "version": "1.0.0",
                "licenses": [{"expression": "GPL-3.0-only"}],
            }
        ],
    }
)


def test_analyze_text_success() -> None:
    out = analyze_text(CLEAN, filename="a.json")
    assert out["ok"] is True
    assert out["report"]["summary"]["overall_posture"] == "allowed"
    assert set(out["renders"]) == {
        "report.json",
        "report.md",
        "report.html",
        "notices.txt",
        "notices.md",
    }
    assert out["renders"]["report.html"].startswith("<!DOCTYPE html>")


def test_analyze_text_blocked() -> None:
    out = analyze_text(BLOCKED)
    assert out["ok"] is True
    assert out["report"]["summary"]["overall_posture"] == "blocked"


def test_empty_input_is_error() -> None:
    out = analyze_text("   ")
    assert out["ok"] is False
    assert out["error"]["kind"] == "input"


def test_invalid_json_is_error() -> None:
    out = analyze_text("{not json")
    assert out["ok"] is False
    assert "JSON" in out["error"]["message"]


def test_unsupported_format_is_error() -> None:
    out = analyze_text(json.dumps({"hello": "world"}))
    assert out["ok"] is False
    assert out["error"]["kind"] == "input_error"


def test_invalid_policy_is_error() -> None:
    out = analyze_text(CLEAN, policy_text="categories: {permissive: {posture: nope}}")
    assert out["ok"] is False
    assert out["error"]["kind"] == "config_error"


def test_strict_unresolved_blocks_unknown() -> None:
    unknown = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{"type": "library", "name": "x", "version": "1.0.0"}],
        }
    )
    normal = analyze_text(unknown)
    strict = analyze_text(unknown, strict_unresolved=True)
    assert normal["report"]["summary"]["overall_posture"] == "review"
    assert strict["report"]["summary"]["overall_posture"] == "blocked"


def test_exceptions_text_applied() -> None:
    exceptions = (
        "exceptions:\n"
        "  - component: g\n"
        "    version: '1.0.0'\n"
        "    posture: allowed\n"
        "    justification: Build-time only.\n"
        "    owner: GC\n"
        "    date: 2026-01-01\n"
    )
    out = analyze_text(BLOCKED, exceptions_text=exceptions)
    assert out["report"]["summary"]["counts"]["exceptions_applied"] == 1
    assert out["report"]["summary"]["overall_posture"] == "allowed"


def test_analyze_text_json_roundtrips() -> None:
    parsed = json.loads(analyze_text_json(CLEAN))
    assert parsed["ok"] is True
    assert parsed["report"]["summary"]["overall_posture"] == "allowed"


def test_about_and_default_policy() -> None:
    info = about()
    assert info["name"] == "sbom-counsel"
    assert "categories:" in default_policy_yaml()


def test_example_files_analyse(tmp_path: Path) -> None:
    # The shipped examples should analyse cleanly through the web path too.
    root = Path(__file__).resolve().parent.parent
    clean = (root / "examples" / "clean-project.cdx.json").read_text(encoding="utf-8")
    mixed = (root / "examples" / "mixed-project.spdx.json").read_text(encoding="utf-8")
    assert analyze_text(clean)["report"]["summary"]["overall_posture"] == "allowed"
    assert analyze_text(mixed)["report"]["summary"]["overall_posture"] == "blocked"
