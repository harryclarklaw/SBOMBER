#!/usr/bin/env bash
# Build the sbom-counsel wheel and place it next to index.html, so the page can
# load the analysis engine. Run this once before previewing the page locally.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"

cd "$root"
python -m pip install --quiet --upgrade build
rm -f "$here"/sbom_counsel-*.whl
python -m build --wheel --outdir "$here"

echo
echo "Wheel built into: $here"
echo "Preview locally (must be served over http, not opened as a file):"
echo "    python -m http.server -d \"$here\" 8000"
echo "Then open http://localhost:8000/"
