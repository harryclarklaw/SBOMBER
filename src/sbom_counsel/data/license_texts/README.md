# Bundled licence texts

These files contain the canonical, verbatim licence texts published by SPDX/OSI
for a small set of common licences, used to assemble the third-party attribution
notices file when the SBOM does not embed the text itself.

The texts include the standard placeholder fields (for example `<year>` and
`<copyright holders>`); the actual copyright line for a given component, when
recorded in the SBOM, is shown alongside in the notices file.

sbom-counsel never invents or paraphrases licence text. If a component's licence
is not embedded in the SBOM and is not in this store, the notices file emits an
explicit pointer to the SPDX page instead of any text.

To add a licence, drop a file named `<SPDX-ID>.txt` here containing the verbatim
official text.
