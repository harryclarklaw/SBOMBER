# Examples

Sample inputs and generated outputs for sbom-counsel. These double as a
demonstration and as fixtures you can run against.

## Inputs

- `clean-project.cdx.json` — a CycloneDX SBOM for a small application with an
  all-permissive dependency set. It passes the gate cleanly.
- `mixed-project.spdx.json` — an SPDX SBOM that contains a network-copyleft
  component (`realtime-sync`, AGPL-3.0), a strong-copyleft component
  (`media-codec`, GPL-2.0), a weak-copyleft component (`ui-toolkit`, MPL-2.0), a
  custom-licensed component carrying its own licence text (`crash-reporter`), and
  an unresolved component (`telemetry-core`, NOASSERTION).
- `exceptions.yaml` — grants `media-codec` an audited exception (build-time only,
  not distributed).
- `policy.yaml` — a copy of the built-in default policy, ready to edit. Generated
  with `sbom-counsel init-policy`.

## Generated reports

`reports/` holds the output of:

```
sbom-counsel analyze examples/mixed-project.spdx.json \
    --exceptions examples/exceptions.yaml \
    -o examples/reports
```

It contains `report.md`, `report.html`, `report.json`, `notices.txt`, and
`notices.md`. Open `report.html` in a browser for the most readable view.

## Reproduce

```
# Clean project — exits 0 under the gate.
sbom-counsel analyze examples/clean-project.cdx.json --gate

# Mixed project — exits 1 under the gate (a blocked component remains).
sbom-counsel analyze examples/mixed-project.spdx.json \
    --exceptions examples/exceptions.yaml --gate
```
