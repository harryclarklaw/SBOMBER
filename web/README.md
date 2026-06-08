# sbom-counsel web app

A browser front-end for non-technical users (the lawyer / general counsel). Drag
in a CycloneDX or SPDX SBOM and get the same risk report the command-line tool
produces — with an interactive, filterable table and one-click downloads.

## The key property: nothing is uploaded

The analysis runs **entirely in the visitor's browser**. The page loads the real
`sbom-counsel` Python engine compiled to WebAssembly (via
[Pyodide](https://pyodide.org)) and runs it locally; the SBOM file is read in the
browser and never sent to any server. This matters for a legal tool: a general
counsel can analyse a confidential dependency manifest without it leaving their
machine, and there is no server to operate or to trust.

Because it's the *same* engine as the CLI, the web verdict is identical to the
command-line and CI verdict — one auditable source of truth, not a re-implementation.

## Files

- `index.html` — the page.
- `style.css` — styling.
- `app.js` — loads Pyodide, runs the engine, renders the interactive report.
- `samples.js` — two built-in sample SBOMs for the "Try a sample" buttons.
- `build.sh` — builds the engine wheel into this folder.

The engine is a Python wheel (`sbom_counsel-<version>-py3-none-any.whl`) that sits
next to `index.html`. It is **not** committed; it is produced by `build.sh` or by
CI, so it always matches the source.

## Preview locally

```
./web/build.sh                       # builds the wheel into web/
python -m http.server -d web 8000    # serve it (do NOT just double-click index.html)
# open http://localhost:8000/
```

It must be served over `http://` (Pyodide cannot load from a `file://` page). The
first load downloads the Python runtime and the engine's dependencies from public
CDNs (jsDelivr / PyPI) and is cached afterwards, so the first analysis takes a few
seconds and later ones are instant.

## Deploy (GitHub Pages)

The workflow `.github/workflows/pages.yml` builds the wheel into `web/` and
publishes the folder to GitHub Pages on every push to `main`. Enable Pages for the
repository (Settings → Pages → Source: GitHub Actions) and it will be served at
your Pages URL. Any static host works equally well — it's just static files plus
public CDN scripts.

## Notes and limits

- Generating an SBOM from a project folder (the `scan` / Syft path) is a desktop
  step, not a browser one: browsers cannot read a whole project directory. Users
  without an SBOM should generate one with Syft or `sbom-counsel scan` and then
  drop the result here.
- The Pyodide version is pinned in `index.html`; the engine version is pinned in
  `app.js` (`PKG_VERSION`). Keep them in step with the package version.
- This page carries the same disclaimer as every report: it is not legal advice.
