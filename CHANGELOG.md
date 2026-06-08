# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-08

Initial release.

### Added

- SBOM ingestion for CycloneDX (JSON, 1.4–1.6) and SPDX (JSON, 2.2–2.3) with
  automatic format detection and normalisation into a single component model.
- SPDX licence resolution via the `license-expression` library: normalisation of
  deprecated identifiers, parsing of `AND`/`OR`/`WITH` and compound expressions,
  and conservative handling of NOASSERTION, NONE, non-SPDX identifiers,
  unparseable expressions, and missing licences.
- A data-driven, external YAML licence policy (the "lawyer's lever") mapping
  licences to categories, ship-postures (`allowed`/`review`/`blocked`), and
  obligations, shipped with a conservative default policy. Recognised-but-unmapped
  and unresolved licences are treated conservatively.
- A classification engine that combines expression operators legally: `OR`
  selects the most permissive option (dual licensing), `AND` takes the most
  restrictive and accumulates obligations, and `WITH` never silently improves the
  posture. Every result is traceable to a policy rule.
- A project exceptions (allowlist) file requiring justification, owner, and date;
  applied exceptions are audited in the report.
- Reports in Markdown, self-contained HTML, and JSON, all built from one
  canonical data structure, plus a third-party attribution notices file (plain
  text and Markdown) that reproduces SBOM-embedded text, bundled verbatim SPDX
  text, or an explicit pointer — never invented text.
- A command-line interface (`analyze`, `cargo`, `init-policy`,
  `init-exceptions`) serving both a legal reader and a CI gate, with deterministic
  exit codes.
- A Rust convenience wrapper sourcing components from `cargo metadata` (default)
  or `cargo-deny` (best-effort).
- An importable library API.
- Documentation, example SBOMs and reports, a default policy, an example
  exceptions file, tests, type checking, linting, and CI.

[Unreleased]: https://github.com/harryclarklaw/sbomber/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/harryclarklaw/sbomber/releases/tag/v0.1.0
