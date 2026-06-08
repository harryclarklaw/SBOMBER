"""Tests for the cargo convenience wrapper (parsers + injected runner)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sbom_counsel.cargo import (
    collect_sbom,
    components_from_cargo_deny,
    components_from_cargo_metadata,
)
from sbom_counsel.errors import EnvironmentToolError

CARGO_METADATA = {
    "workspace_members": ["my-app 0.1.0 (path+file:///proj)"],
    "packages": [
        {
            "id": "my-app 0.1.0 (path+file:///proj)",
            "name": "my-app",
            "version": "0.1.0",
            "license": "MIT",
        },
        {
            "id": "serde 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
            "name": "serde",
            "version": "1.0.0",
            "license": "MIT OR Apache-2.0",
            "authors": ["Serde Authors"],
            "repository": "https://github.com/serde-rs/serde",
        },
        {
            "id": "openssl 0.10.0 (registry+...)",
            "name": "openssl",
            "version": "0.10.0",
            "license": "Apache-2.0",
        },
        {
            "id": "legacy 0.1.0 (registry+...)",
            "name": "legacy",
            "version": "0.1.0",
            "license": "MIT/Apache-2.0",
        },
    ],
}


def test_metadata_excludes_workspace_members() -> None:
    comps = components_from_cargo_metadata(CARGO_METADATA)
    names = {c.name for c in comps}
    assert "my-app" not in names
    assert {"serde", "openssl", "legacy"} <= names


def test_metadata_extracts_fields() -> None:
    comps = {c.name: c for c in components_from_cargo_metadata(CARGO_METADATA)}
    serde = comps["serde"]
    assert serde.version == "1.0.0"
    assert serde.author == "Serde Authors"
    assert serde.homepage == "https://github.com/serde-rs/serde"
    assert serde.purl == "pkg:cargo/serde@1.0.0"
    assert serde.licenses[0].raw == "MIT OR Apache-2.0"


def test_metadata_normalises_slash_separator() -> None:
    comps = {c.name: c for c in components_from_cargo_metadata(CARGO_METADATA)}
    assert comps["legacy"].licenses[0].raw == "MIT OR Apache-2.0"


def test_cargo_deny_list_shape() -> None:
    data = [
        {"name": "foo", "version": "1.2.3", "license": "MIT"},
        {"name": "bar", "version": "0.1.0", "license": "GPL-3.0-only"},
    ]
    comps = {c.name: c for c in components_from_cargo_deny(data)}
    assert comps["foo"].licenses[0].raw == "MIT"
    assert comps["bar"].version == "0.1.0"


def test_cargo_deny_dict_shape() -> None:
    data = {"foo 1.2.3": {"license": "MIT"}}
    comps = components_from_cargo_deny(data)
    assert comps[0].name == "foo"
    assert comps[0].version == "1.2.3"
    assert comps[0].licenses[0].raw == "MIT"


def test_collect_sbom_with_injected_runner(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text("[package]\nname='x'\n", encoding="utf-8")

    def fake_runner(args: list[str], cwd: Path) -> str:
        assert args[0] == "cargo"
        return json.dumps(CARGO_METADATA)

    sbom = collect_sbom(tmp_path, tool="cargo-metadata", runner=fake_runner)
    assert sbom.sbom_format == "cargo-metadata"
    assert {c.name for c in sbom.components} == {"serde", "openssl", "legacy"}


def test_collect_sbom_requires_cargo_toml(tmp_path: Path) -> None:
    with pytest.raises(EnvironmentToolError, match=r"Cargo\.toml"):
        collect_sbom(tmp_path, tool="cargo-metadata", runner=lambda a, c: "{}")


def test_collect_sbom_missing_directory() -> None:
    with pytest.raises(EnvironmentToolError, match="not found"):
        collect_sbom("/nonexistent/dir/xyz", tool="cargo-metadata")
