# Contributing to sbom-counsel

Thank you for considering a contribution. This document covers how to set up a
development environment and the standards a change must meet.

## Development setup

Requires Python 3.11 or later.

```
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

## Checks

All of the following must pass before a change is merged. CI runs them on every
push and pull request.

```
ruff check src tests        # lint
black --check src tests     # formatting
mypy                        # type checking (strict for the package)
pytest                      # tests
```

To auto-fix formatting and the lint issues that are safe to fix automatically:

```
ruff check --fix src tests
black src tests
```

## Standards

- **The legal-interpretation layer is the product.** Keep it cohesive,
  conservative, and explainable. Every classification must be traceable to a
  policy rule; never introduce an opaque judgement.
- **Policy and exceptions are external data.** Classification logic belongs in
  the YAML policy, never hardcoded in Python. If you add a default mapping, add
  it to `src/sbom_counsel/data/default_policy.yaml`.
- **Conservative on uncertainty.** Anything unresolved must resolve towards
  `review` or `blocked`, never `allowed`.
- **Never fabricate.** Do not invent obligations or licence texts. The notices
  file reproduces only text from the SBOM or the bundled verbatim store; anything
  else is an explicit pointer.
- **Determinism.** Output must be byte-identical across runs on the same input.
  Do not introduce wall-clock timestamps or unordered iteration into outputs.
- **Offline by default.** The tool must not make network calls in its core paths.
- **Errors are actionable.** User-facing failures raise an `SbomCounselError`
  subclass with a clear message and the right exit code — never a raw traceback.
- **Tests alongside code.** Add unit tests for new behaviour and, for
  user-visible changes, an end-to-end test. Include fixtures for hard cases
  (compound SPDX expressions, dual licensing, NOASSERTION, non-SPDX identifiers,
  missing licences, applied exceptions).

## Adding or changing a licence classification

1. Edit `default_policy.yaml` (mapping, category, note, or expression rule).
2. If the change concerns resolution behaviour, update
   `src/sbom_counsel/licensing/`.
3. Add or update tests in `tests/test_policy.py` or `tests/test_classify.py`.
4. If the default mapping changes a posture, note it in `CHANGELOG.md`.

## Commit and PR conventions

- Keep commits focused and write a clear message explaining the *why*.
- Use [Semantic Versioning](https://semver.org/). User-visible changes go in
  `CHANGELOG.md` under "Unreleased".
- A change to a default posture or category is a behaviour change and should be
  called out prominently, since it affects users' gate results.

## Reporting issues

Please include the tool version, the (sanitised) SBOM snippet that reproduces the
problem, the policy in use if not the default, and the exact command and output.
