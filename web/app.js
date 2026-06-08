"use strict";
/*
 * sbom-counsel browser app.
 *
 * Loads the real Python analysis engine (the same code as the CLI) into the
 * browser via Pyodide, then runs it entirely client-side. The user's SBOM is
 * read with the FileReader API and passed straight to Python in memory; nothing
 * is uploaded anywhere.
 */

const PKG_VERSION = "0.1.0";
const WHEEL_NAME = `sbom_counsel-${PKG_VERSION}-py3-none-any.whl`;

const POSTURE_LABEL = { allowed: "Allowed", review: "Review", blocked: "Blocked" };
const POSTURE_LIGHT = { allowed: "🟢", review: "🟡", blocked: "🔴" };

let pyodide = null;
let engineReady = false;
let lastSbomText = null; // remembered so the strict toggle can re-run
let lastFilename = null;

// ---- tiny DOM helpers (use textContent for anything untrusted) -------------
const $ = (sel) => document.querySelector(sel);
function el(tag, opts = {}) {
  const node = document.createElement(tag);
  if (opts.class) node.className = opts.class;
  if (opts.text != null) node.textContent = opts.text;
  if (opts.html != null) node.innerHTML = opts.html;
  if (opts.attrs) for (const [k, v] of Object.entries(opts.attrs)) node.setAttribute(k, v);
  return node;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

function status(message, kind) {
  const box = $("#status");
  box.className = "show" + (kind ? " " + kind : "");
  clear(box);
  if (kind === "loading") box.appendChild(el("span", { class: "spinner" }));
  box.appendChild(document.createTextNode(message));
}
function hideStatus() { $("#status").className = ""; }

// ---- engine bootstrap ------------------------------------------------------
async function bootEngine() {
  try {
    status("Loading the Python runtime… (first load can take ~20 seconds; it is cached afterwards)", "loading");
    pyodide = await loadPyodide();

    status("Loading the analysis engine…", "loading");
    await pyodide.loadPackage("micropip");
    const micropip = pyodide.pyimport("micropip");

    const wheelUrl = new URL("./" + WHEEL_NAME, location.href).href;
    try {
      await micropip.install(wheelUrl);
    } catch (e) {
      // Fall back to PyPI if the local wheel is not present (e.g. once published).
      await micropip.install("sbom-counsel==" + PKG_VERSION);
    }
    await pyodide.runPythonAsync("import sbom_counsel.webapi as _w");

    engineReady = true;
    hideStatus();
    enableControls();
  } catch (err) {
    status(
      "Could not load the analysis engine. If you are previewing locally, make sure you built the " +
      "wheel into this folder (see web/README.md) and are serving over http (not opening the file " +
      "directly). Details: " + err,
      "error"
    );
  }
}

function enableControls() {
  $("#pickBtn").disabled = false;
  $("#sampleClean").disabled = false;
  $("#sampleMixed").disabled = false;
}

// ---- run the analysis ------------------------------------------------------
async function analyze(text, filename) {
  if (!engineReady) { status("The engine is still loading; one moment…", "loading"); return; }
  lastSbomText = text;
  lastFilename = filename || null;
  status("Analysing…", "loading");
  try {
    const strict = $("#strict").checked;
    // Pyodide passes JS objects as positional args, so use callKwargs() to send
    // the options through as Python keyword arguments (not a 2nd positional arg).
    const resultJson = pyodide.globals.get("_w").analyze_text_json.callKwargs(text, {
      strict_unresolved: strict,
      filename: filename || null,
      include_vulnerabilities: true,
    });
    const result = JSON.parse(resultJson);
    if (!result.ok) {
      status("Could not analyse this file: " + result.error.message, "error");
      $("#results").classList.add("hidden");
      return;
    }
    hideStatus();
    render(result);
  } catch (err) {
    status("Unexpected error while analysing: " + err, "error");
  }
}

// ---- rendering -------------------------------------------------------------
function render(result) {
  const report = result.report;
  const summary = report.summary;
  const posture = summary.overall_posture;

  const verdict = $("#verdict");
  verdict.className = "verdict " + posture;
  clear(verdict);
  verdict.appendChild(el("span", { class: "light", text: POSTURE_LIGHT[posture] }));
  const vbox = el("div");
  vbox.appendChild(el("div", { class: "big", text: "Overall: " + POSTURE_LABEL[posture].toUpperCase() }));
  vbox.appendChild(el("div", { class: "interp", text: summary.interpretation }));
  verdict.appendChild(vbox);
  $("#interp").textContent = "";

  const chips = $("#chips");
  clear(chips);
  const c = summary.counts;
  chips.appendChild(chip("blocked", "Blocked", c.blocked));
  chips.appendChild(chip("review", "Review", c.review));
  chips.appendChild(chip("allowed", "Allowed", c.allowed));
  chips.appendChild(chip("", "Unresolved", c.unresolved));
  chips.appendChild(chip("", "Exceptions", c.exceptions_applied));
  chips.appendChild(chip("", "Total", c.total));

  renderDownloads(result.renders);
  renderRegister(report.risk_register);
  renderUnresolved(report.unresolved);
  renderObligations(report.obligations);
  renderExceptions(report.exceptions_applied);
  renderVulnerabilities(report.vulnerabilities || []);
  renderList($("#methodology"), report.methodology);
  renderList($("#limitations"), report.limitations);
  $("#disclaimer").textContent = report.disclaimer;
  $("#footerNote").textContent =
    `Policy: ${report.policy.name} (v${report.policy.version}). ` +
    `Engine: ${report.tool.name} ${report.tool.version}, running locally via Pyodide.`;

  $("#results").classList.remove("hidden");
  applyFilters();
  $("#results").scrollIntoView({ behavior: "smooth", block: "start" });
}

function chip(kind, label, n) {
  return el("span", { class: "chip " + kind, html: `${label}: <b>${n}</b>` });
}

function badge(posture) {
  return el("span", { class: "badge " + posture, text: POSTURE_LABEL[posture] });
}

function renderDownloads(renders) {
  const wrap = $("#downloads");
  clear(wrap);
  const files = [
    ["report.html", "HTML report"],
    ["report.md", "Markdown report"],
    ["report.json", "JSON report"],
    ["notices.txt", "Notices (text)"],
    ["notices.md", "Notices (Markdown)"],
  ];
  for (const [name, label] of files) {
    if (!(name in renders)) continue;
    const blob = new Blob([renders[name]], { type: "text/plain;charset=utf-8" });
    const a = el("a", { class: "button secondary", text: "Download " + label });
    a.href = URL.createObjectURL(blob);
    a.download = name;
    wrap.appendChild(a);
  }
}

function renderRegister(rows) {
  const body = $("#registerBody");
  clear(body);
  rows.forEach((row, i) => {
    const tr = el("tr", { class: "row" });
    tr.dataset.posture = row.posture;
    tr.dataset.text = (row.name + " " + (row.version || "") + " " + (row.license_expression || "")).toLowerCase();
    tr.appendChild(el("td", { text: row.name }));
    tr.appendChild(el("td", { text: row.version || "—" }));
    tr.appendChild(el("td", { class: "mono", text: row.license_expression || "(unresolved)" }));
    tr.appendChild(el("td", { text: row.categories.length ? row.categories.join(", ") : "—" }));
    const ptd = el("td");
    ptd.appendChild(badge(row.posture));
    if (row.exception) ptd.appendChild(el("div", { class: "small muted", text: "exception (was " + POSTURE_LABEL[row.base_posture] + ")" }));
    tr.appendChild(ptd);

    const detail = el("tr", { class: "detail hidden" });
    const dtd = el("td", { attrs: { colspan: "5" } });
    dtd.appendChild(el("p", { class: "why", text: row.explanation }));
    if (row.obligations.length) {
      dtd.appendChild(el("div", { class: "small", html: "<b>Obligations:</b>" }));
      const ul = el("ul");
      row.obligations.forEach((o) => ul.appendChild(el("li", { class: "small", text: o })));
      dtd.appendChild(ul);
    }
    if (row.exception) {
      dtd.appendChild(el("p", { class: "small", html: `<b>Exception:</b> ${escapeHtml(row.exception.justification)} — ${escapeHtml(row.exception.owner)}, ${escapeHtml(row.exception.date)}` }));
    }
    dtd.appendChild(el("p", { class: "small muted", text: "Rule(s) applied: " + (row.rules_applied.join("; ") || "—") }));
    detail.appendChild(dtd);

    tr.addEventListener("click", () => detail.classList.toggle("hidden"));
    body.appendChild(tr);
    body.appendChild(detail);
  });
}

function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s == null ? "" : String(s);
  return d.innerHTML;
}

function sectionTable(wrapId, title, headers, rows, cellFns) {
  const wrap = $(wrapId);
  clear(wrap);
  if (!rows.length) return;
  wrap.appendChild(el("h2", { text: title }));
  const table = el("table");
  const thead = el("tr");
  headers.forEach((h) => thead.appendChild(el("th", { text: h })));
  const theadWrap = el("thead"); theadWrap.appendChild(thead); table.appendChild(theadWrap);
  const tbody = el("tbody");
  rows.forEach((r) => {
    const tr = el("tr");
    cellFns.forEach((fn) => tr.appendChild(fn(r)));
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  wrap.appendChild(table);
}

function renderUnresolved(rows) {
  sectionTable("#unresolvedWrap", "Unresolved and unknown components",
    ["Component", "Version", "Posture", "Reason"], rows,
    [
      (r) => el("td", { text: r.name }),
      (r) => el("td", { text: r.version || "—" }),
      (r) => { const t = el("td"); t.appendChild(badge(r.posture)); return t; },
      (r) => el("td", { text: r.reason || "" }),
    ]);
}

function renderObligations(items) {
  const wrap = $("#obligationsWrap");
  clear(wrap);
  if (!items.length) return;
  wrap.appendChild(el("h2", { text: "Obligations to satisfy before distribution" }));
  const ul = el("ul");
  items.forEach((it) => {
    const li = el("li");
    li.appendChild(document.createTextNode(it.obligation));
    li.appendChild(el("div", { class: "small muted", text: "Applies to: " + it.components.join(", ") }));
    ul.appendChild(li);
  });
  wrap.appendChild(ul);
}

function renderExceptions(rows) {
  sectionTable("#exceptionsWrap", "Exceptions applied",
    ["Component", "Version", "Override", "Was", "Justification", "Owner", "Date"], rows,
    [
      (r) => el("td", { text: r.component }),
      (r) => el("td", { text: r.version }),
      (r) => { const t = el("td"); t.appendChild(badge(r.override_posture)); return t; },
      (r) => { const t = el("td"); t.appendChild(badge(r.original_posture)); return t; },
      (r) => el("td", { text: r.justification }),
      (r) => el("td", { text: r.owner }),
      (r) => el("td", { text: r.date }),
    ]);
}

function renderVulnerabilities(comps) {
  const wrap = $("#vulnWrap");
  clear(wrap);
  if (!comps.length) return;
  wrap.appendChild(el("h2", { text: "Vulnerabilities reported in the SBOM (informational)" }));
  wrap.appendChild(el("p", { class: "small muted", text: "Reproduced from the SBOM as-is; not generated or verified by this tool, and separate from licence analysis." }));
  const rows = [];
  comps.forEach((c) => c.vulnerabilities.forEach((v) => rows.push({ name: c.name, version: c.version, ...v })));
  const table = el("table");
  const head = el("thead"); const hr = el("tr");
  ["Component", "Version", "ID", "Severity", "Source"].forEach((h) => hr.appendChild(el("th", { text: h })));
  head.appendChild(hr); table.appendChild(head);
  const tb = el("tbody");
  rows.forEach((r) => {
    const tr = el("tr");
    tr.appendChild(el("td", { text: r.name }));
    tr.appendChild(el("td", { text: r.version || "—" }));
    tr.appendChild(el("td", { class: "mono", text: r.id }));
    tr.appendChild(el("td", { text: r.severity || "—" }));
    tr.appendChild(el("td", { text: r.source || "—" }));
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  wrap.appendChild(table);
}

function renderList(node, items) {
  clear(node);
  const ul = el("ul");
  items.forEach((it) => ul.appendChild(el("li", { class: "small", text: it })));
  node.appendChild(ul);
}

// ---- filtering -------------------------------------------------------------
let activePosture = "all";
function applyFilters() {
  const q = $("#search").value.trim().toLowerCase();
  const rows = document.querySelectorAll("#registerBody tr.row");
  rows.forEach((tr) => {
    const matchesPosture = activePosture === "all" || tr.dataset.posture === activePosture;
    const matchesText = !q || tr.dataset.text.includes(q);
    const show = matchesPosture && matchesText;
    tr.classList.toggle("hidden", !show);
    const detail = tr.nextElementSibling;
    if (detail && detail.classList.contains("detail")) {
      detail.classList.add("hidden"); // collapse when filtering
    }
  });
}

// ---- wiring ----------------------------------------------------------------
function readFile(file) {
  const reader = new FileReader();
  reader.onload = () => analyze(String(reader.result), file.name);
  reader.onerror = () => status("Could not read that file.", "error");
  reader.readAsText(file);
}

function wire() {
  const dz = $("#dropzone");
  const input = $("#fileInput");
  $("#pickBtn").addEventListener("click", () => input.click());
  dz.addEventListener("click", (e) => { if (e.target.id !== "pickBtn") input.click(); });
  dz.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") input.click(); });
  input.addEventListener("change", () => { if (input.files[0]) readFile(input.files[0]); });

  ["dragenter", "dragover"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("drag"); }));
  ["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("drag"); }));
  dz.addEventListener("drop", (e) => { if (e.dataTransfer.files[0]) readFile(e.dataTransfer.files[0]); });

  $("#strict").addEventListener("change", () => { if (lastSbomText) analyze(lastSbomText, lastFilename); });
  $("#search").addEventListener("input", applyFilters);
  document.querySelectorAll(".pill").forEach((p) => p.addEventListener("click", () => {
    document.querySelectorAll(".pill").forEach((x) => x.classList.remove("active"));
    p.classList.add("active");
    activePosture = p.dataset.posture;
    applyFilters();
  }));

  $("#sampleClean").addEventListener("click", () => analyze(SAMPLES.clean, "clean-project.cdx.json"));
  $("#sampleMixed").addEventListener("click", () => analyze(SAMPLES.mixed, "mixed-project.spdx.json"));
}

wire();
bootEngine();
