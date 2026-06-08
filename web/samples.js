"use strict";
/* Two small, self-contained sample SBOMs for the "Try a sample" buttons. */
const SAMPLES = {
  clean: JSON.stringify({
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    metadata: { component: { type: "application", name: "starlight-runtime", version: "1.0.0" } },
    components: [
      { type: "library", name: "serde", version: "1.0.203", licenses: [{ expression: "MIT OR Apache-2.0" }] },
      { type: "library", name: "glam", version: "0.27.0", licenses: [{ expression: "MIT OR Apache-2.0" }] },
      { type: "library", name: "bytes", version: "1.6.0", copyright: "Copyright (c) 2018 Carl Lerche", licenses: [{ license: { id: "MIT" } }] },
      { type: "library", name: "miniz_oxide", version: "0.7.3", licenses: [{ expression: "MIT OR Zlib OR Apache-2.0" }] }
    ]
  }, null, 2),

  mixed: JSON.stringify({
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: "nebula-server",
    documentDescribes: ["SPDXRef-root"],
    relationships: [{ spdxElementId: "SPDXRef-DOCUMENT", relationshipType: "DESCRIBES", relatedSpdxElement: "SPDXRef-root" }],
    packages: [
      { name: "nebula-server", SPDXID: "SPDXRef-root", versionInfo: "1.0.0", licenseConcluded: "Apache-2.0", licenseDeclared: "Apache-2.0" },
      { name: "realtime-sync", SPDXID: "SPDXRef-1", versionInfo: "3.2.0", supplier: "Organization: Sync Systems Ltd", licenseConcluded: "AGPL-3.0-only", licenseDeclared: "AGPL-3.0-only" },
      { name: "media-codec", SPDXID: "SPDXRef-2", versionInfo: "5.1.2", licenseConcluded: "GPL-2.0-only", licenseDeclared: "GPL-2.0-only" },
      { name: "ui-toolkit", SPDXID: "SPDXRef-3", versionInfo: "2.0.0", licenseConcluded: "MPL-2.0", licenseDeclared: "MPL-2.0" },
      { name: "telemetry-core", SPDXID: "SPDXRef-4", versionInfo: "0.9.7", licenseConcluded: "NOASSERTION", licenseDeclared: "NOASSERTION" },
      { name: "fast-json", SPDXID: "SPDXRef-5", versionInfo: "1.8.0", copyrightText: "Copyright (c) 2022 A. Developer", licenseConcluded: "MIT", licenseDeclared: "MIT" }
    ]
  }, null, 2)
};
