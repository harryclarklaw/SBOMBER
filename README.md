# sbom-counsel

Open-source licence-risk analysis for software bills of materials (SBOMs).

`sbom-counsel` reads an SBOM for a software project and produces a
lawyer-readable open-source licence risk report, plus a third-party attribution
notices file. It is built around one question:

> Can this set of components be shipped inside a proprietary, commercially
> distributed product?

It runs fully offline and produces deterministic output. It is a command-line
tool and an importable Python library.

> **This tool does not give legal advice.** Its classifications are automated and
> indicative, depend entirely on the policy in force, and must be reviewed by
> qualified legal counsel before any distribution decision. See
> [Disclaimer](#disclaimer).

## Why it exists

The EU Cyber Resilience Act will require manufacturers of products with digital
elements placed on the EU market to produce a machine-readable SBOM (covering at
least top-level dependencies) as part of full compliance from 11 December 2027.
That SBOM is a **security**-transparency artefact. It does not answer the
**intellectual-property** question of whether the licences in that component set
are compatible with shipping a closed-source product.

`sbom-counsel` consumes the SBOM a studio will already have to generate and adds
the IP/licence interpretation layer on top: it resolves each component's licence,
classifies it against an editable policy, applies your project exceptions, and
explains every result so counsel can audit it. That interpretation layer is the
point of the tool.

## What it does

1. **Ingests** a CycloneDX (JSON) or SPDX (JSON) SBOM, auto-detecting the format
   and normalising both into one component model.
2. **Resolves** each component's licence to a normalised SPDX expression
   (preferring concluded over declared information), using the
   [`license-expression`](https://github.com/aboutcode-org/license-expression)
   library for SPDX parsing and validation.
3. **Classifies** every component against an external, editable **policy**,
   resolving each licence or expression to a category, a ship-posture, and the
   obligations it triggers.
4. **Handles the unresolved cases** conservatively. NOASSERTION, non-SPDX or
   unrecognised identifiers, and components with no licence are surfaced as
   unresolved and given the policy's conservative default — never silently
   treated as acceptable.
5. **Applies project exceptions** after classification, recording each override
   with its justification.
6. **Reports** a per-component risk register and an overall release posture, in
   Markdown, self-contained HTML, and JSON, plus a third-party notices file.

## Installation

Requires Python 3.11 or later.

Install as an isolated CLI with [pipx](https://pypa.github.io/pipx/):

```
pipx install sbom-counsel
```

Or install into the current environment with pip:

```
pip install sbom-counsel
```

From a checkout of this repository:

```
pip install .
# or, for development, with the test and lint tooling:
pip install -e ".[dev]"
```

The console command is `sbom-counsel`. You can also run it as
`python -m sbom_counsel`.

## Quick start

```
# Analyse an SBOM; writes the report set to ./sbom-counsel-report/
sbom-counsel analyze path/to/sbom.json

# Use a custom policy and project exceptions
sbom-counsel analyze sbom.json --policy policy.yaml --exceptions exceptions.yaml

# CI gate: exit non-zero if any component is blocked
sbom-counsel analyze sbom.json --gate

# Print the JSON report to stdout instead of writing files
sbom-counsel analyze sbom.json --print json
```

A worked example lives in [`examples/`](examples/). To reproduce it:

```
sbom-counsel analyze examples/mixed-project.spdx.json \
    --exceptions examples/exceptions.yaml -o examples/reports
```

The generated [`examples/reports/report.md`](examples/reports/report.md) and
`report.html` show the output for a project that mixes permissive, copyleft,
custom, and unresolved components, with one audited exception.

## Web app (no terminal required)

For non-technical users — the lawyer or general counsel who will read the report —
there is a browser front-end in [`web/`](web/): drag in an SBOM, get the same
report with an interactive, filterable table and one-click downloads.

It runs the **same engine entirely in the browser** (compiled to WebAssembly via
Pyodide), so **the SBOM is never uploaded** — it is read and analysed locally on
the user's machine. That matters for a confidential dependency manifest, and it
means the web verdict is identical to the CLI and CI verdict (one auditable
engine, not a re-implementation).

Preview it locally:

```
./web/build.sh                       # builds the engine into web/
python -m http.server -d web 8000    # serve over http (not file://)
# open http://localhost:8000/
```

It deploys to GitHub Pages automatically on push to `main` (see
`.github/workflows/pages.yml`); enable Pages for the repository to host it. See
[`web/README.md`](web/README.md) for details.

## Generating an SBOM

If you don't already have an SBOM, generate one from a project with
[Syft](https://github.com/anchore/syft) and let the tool drive it in one step:

```
sbom-counsel scan path/to/project        # requires Syft on PATH
```

`scan` runs Syft to produce the SBOM, then analyses it with the same pipeline as
`analyze`. This is an optional convenience; the SBOM path remains primary. For
Rust specifically, `sbom-counsel cargo path/to/project` uses cargo directly (see
[Rust convenience path](#rust-convenience-path)).

## Outputs

By default, `analyze` writes five files to the output directory:

| File | Audience | Contents |
| --- | --- | --- |
| `report.md` | Lawyer / GC | Readable risk report in Markdown |
| `report.html` | Lawyer / GC | The same report as a self-contained HTML file |
| `report.json` | Pipelines | The same data, machine-readable |
| `notices.txt` | Distribution | Third-party attribution notices (plain text) |
| `notices.md` | Distribution | Third-party attribution notices (Markdown) |

Use `--format` to select a subset, for example `--format json --format notices`.
Every output is deterministic: the same inputs produce byte-identical files
(there is no wall-clock timestamp in the reports).

The report contains an executive summary with the overall release posture and
counts; a risk register table (component, version, licence, category, posture,
rule applied, obligations); a dedicated list of unresolved components; the
aggregated obligations to satisfy before distribution; any exceptions applied;
an optional vulnerability section (only when present in the SBOM and requested
with `--include-vulnerabilities`); and clearly separated methodology and
disclaimer sections.

## Postures and how expressions combine

Every licence resolves to one of three postures:

| Posture | Meaning for a proprietary, distributed product |
| --- | --- |
| `allowed` | No concern beyond the stated obligations (e.g. attribution). |
| `review` | A human must assess this before distribution. |
| `blocked` | Not suitable as-is. |

SPDX expressions are combined the way the law works:

- **`A OR B`** — you may choose the most permissive option, so the **best**
  posture wins. This is how dual licensing such as `MIT OR GPL-3.0-only` is
  handled (you may take MIT, so it is `allowed`).
- **`A AND B`** — you must satisfy every licence, so the **most restrictive**
  posture wins and obligations accumulate.
- **`A WITH exception`** — the base licence's posture is used **unless** the
  policy has an explicit rule for the whole expression. An exception never
  silently improves the posture; it is flagged for review.

Uncertainty always resolves towards `review` or `blocked`, never towards
`allowed`.

## The policy file (the lawyer's lever)

All classification logic lives in an external YAML policy file, not in code. A
lawyer can edit it without touching the source. Write a starting copy with:

```
sbom-counsel init-policy -o policy.yaml
```

The policy maps licence categories to a description, a ship-posture, and the
obligations they trigger, and maps SPDX licence ids to categories:

```yaml
categories:
  permissive:
    description: Permissive licences ...
    posture: allowed
    obligations:
      - "Retain all copyright notices and licence text ..."
  strong_copyleft:
    posture: blocked
    obligations: [ ... ]

licenses:
  MIT: permissive
  Apache-2.0: permissive
  GPL-3.0-only: strong_copyleft
  AGPL-3.0-only: network_copyleft
```

To change how a licence is treated, move it between categories or change a
category's `posture`. To make the tool stricter about unknown licences, set the
`unknown` category's `posture` to `blocked` (or pass `--strict-unresolved`).
Full-expression rules (for `WITH` exceptions) and per-licence notes are
supported; see the comments at the top of the generated file. Deprecated SPDX ids
(e.g. `GPL-2.0`) are accepted and normalised automatically.

The shipped default policy encodes **conservative defaults** intended to be
reviewed by qualified counsel for your product and jurisdiction. Read the header
of the generated file before relying on it.

## The exceptions file

A project exception grants a specific component and version an overriding
posture. Every exception must carry a justification, an owner, and a date;
exceptions without a justification are rejected. Applied exceptions appear in the
report. Write a starting copy with `sbom-counsel init-exceptions -o exceptions.yaml`:

```yaml
exceptions:
  - component: media-codec
    version: "5.1.2"          # exact version, or "*" for any version
    posture: allowed
    justification: >-
      Used only at build time; not distributed in the shipped product.
    owner: Jordan Counsel <legal@example.com>
    date: 2026-05-21
```

## CI gate and exit codes

`--gate` turns the analysis into a build gate. `--fail-on` sets the threshold
(`blocked` by default, or `review` to also fail on components needing review).

| Exit code | Meaning |
| --- | --- |
| 0 | Success (and, with `--gate`, the gate passed). |
| 1 | The gate failed (a component's posture is in the fail set). |
| 2 | Command-line usage error. |
| 3 | Input error (SBOM missing, unreadable, malformed, or unsupported). |
| 4 | Configuration error (policy or exceptions file invalid). |
| 5 | Environment error (a required external tool is missing or failed). |

Example pre-release check:

```
sbom-counsel analyze sbom.json --gate --fail-on blocked
```

## Rust convenience path

For Rust projects you can derive components directly from the source tree instead
of supplying an SBOM:

```
sbom-counsel cargo path/to/rust/project
```

By default this uses `cargo metadata` (part of cargo, always available), which
reports each crate's SPDX licence. `--tool cargo-deny` is also supported
(best-effort) when that tool is installed. This is a convenience wrapper; the SBOM
path is the primary, ecosystem-agnostic route.

## Using it as a library

```python
from sbom_counsel import analyze, load_sbom, load_default_policy, build_report_data

sbom = load_sbom("sbom.json")
policy = load_default_policy()
result = analyze(sbom, policy, gate_fail_on=("blocked",))

print(result.overall_posture)          # "allowed" | "review" | "blocked"
print(result.counts.blocked)
data = build_report_data(result)       # the canonical report structure
```

The layers (ingestion, resolution, classification, policy, reporting) are
independently importable and testable.

## Known limitations

- The tool analyses the component set described by the SBOM only; it is no better
  than the SBOM it is given, and it does not detect missing components.
- It does **not** perform static or dynamic linkage analysis. This particularly
  affects weak-copyleft (LGPL, MPL, EPL) assessment, which is therefore surfaced
  for review rather than decided.
- It is **not** a vulnerability scanner. Vulnerability data is surfaced only if
  the SBOM already carries it and `--include-vulnerabilities` is passed; it is
  never generated.
- It does not perform automated remediation or modify dependencies.
- It does **not** assert CRA compliance or any certification. It is a readiness
  and analysis aid.
- Licence resolution covers SPDX identifiers and expressions. Free-text licence
  names that are not valid SPDX are treated as unresolved rather than guessed.
- Exceptions match a component name with an exact version (or `*`); version
  ranges are not supported in this version.
- Input is JSON CycloneDX (1.4–1.6) and SPDX (2.2–2.3). XML and tag-value forms
  are out of scope for this version.

## Disclaimer

`sbom-counsel` does not provide legal advice and must not be relied on as a
substitute for it. The classifications it produces are automated and indicative,
depend entirely on the policy in force, and may be incomplete or incorrect for
your specific facts. Licence interpretation depends on how a component is used —
including linking, modification, and the distribution model — which this tool
does not determine. Do not make a distribution decision on the basis of its
output alone. Have the results, including any component marked `allowed`,
reviewed by qualified legal counsel before distributing your product.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: `pip install -e ".[dev]"`, then
`ruff check`, `black --check`, `mypy`, and `pytest` must pass. The policy and
exceptions are external data and must never be hardcoded.

## Licence

`sbom-counsel` is licensed under the Apache License 2.0 — permissive, with an
express patent grant, which is the prudent choice for a publicly released tool.
See [LICENSE](LICENSE).
