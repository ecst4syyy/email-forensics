// Email Forensics web UI.
//
// Safety rules for this file: every value that comes from an analysed message is inserted with
// textContent (never innerHTML), URLs are shown defanged and are never links, and the page talks
// only to the local API (the CSP allows nothing else).
"use strict";

(() => {
  const VERDICT_ORDER = ["clean", "caution", "suspicious", "malicious"];
  const SEVERITIES = ["high", "medium", "low", "info"];
  const ICONS = {
    copy: "M9 9h11v11H9zM5 15H4V4h11v1",
    download: "M12 4v11m0 0-4-4m4 4 4-4M5 20h14",
    file: "M14 3H6v18h12V7zM14 3v4h4",
    code: "m8 8-5 4 5 4m8-8 5 4-5 4",
    chev: "m9 6 6 6-6 6",
  };

  const state = {
    entries: [],          // {id, file, name, status: pending|done|error, reports, error, elapsed}
    selected: null,       // {entry, index, path: [nested indices]}
    tab: "findings",
    findingFilter: "all",
    findingQuery: "",
    token: "",
    health: null,
  };
  let nextId = 1;

  // ------------------------------------------------------------------ DOM helpers

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else if (k === "text") el.textContent = v;
      else if (k === "style") Object.assign(el.style, v);   // CSSOM: allowed by the CSP, unlike style attributes
      else el.setAttribute(k, v === true ? "" : v);
    }
    append(el, children);
    return el;
  }

  function append(el, children) {
    for (const c of children.flat(Infinity)) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  function svgIcon(name, cls) {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    if (cls) svg.setAttribute("class", cls);
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", ICONS[name]);
    svg.append(p);
    return svg;
  }

  const $ = (id) => document.getElementById(id);

  // replaceChildren would print null/false children as text; skip them like h() does.
  function fill(el, ...children) {
    el.replaceChildren();
    return append(el, children);
  }

  function toast(msg) {
    const t = $("toast");
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => t.classList.remove("show"), 2600);
  }

  // Values from evidence may contain control or bidi characters; make them visible instead of
  // letting them reorder or hide text.
  function safe(text) {
    if (text === null || text === undefined) return "";
    return String(text).replace(/[\u0000-\u0008\u000b-\u001f\u007f​-‏‪-‮⁠-⁤⁦-⁩﻿]/g,
      (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
  }

  function oneLine(text) {
    return safe(text).replace(/[\r\n\t]+/g, " ");
  }

  function defang(value) {
    if (!value) return "";
    let v = oneLine(value);
    const m = v.match(/^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(.*)$/i);
    if (m) {
      const scheme = m[1].toLowerCase().replace(/^http/, "hxxp").replace(/^ftp/, "fxp");
      return `${scheme}://${m[2].replace(/\./g, "[.]")}${m[3]}`;
    }
    return v.replace(/\./g, "[.]");
  }

  function fmtDate(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    if (isNaN(d)) return iso;
    return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  function fmtBytes(n) {
    if (n === null || n === undefined) return "—";
    const u = ["B", "KB", "MB", "GB"];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return `${i ? n.toFixed(1) : n} ${u[i]}`;
  }

  function copyBtn(value, label) {
    return h("button", {
      class: "copy", type: "button", title: `Copy ${label || ""}`.trim(), "aria-label": `Copy ${label || "value"}`,
      onclick: async (e) => {
        e.preventDefault(); e.stopPropagation();
        try { await navigator.clipboard.writeText(value); toast("Copied"); } catch { toast("Copy not available"); }
      },
    }, svgIcon("copy"));
  }

  function sevPill(sev) { return h("span", { class: `sev sev-${sev}`, text: sev }); }
  function resPill(res) { return h("span", { class: `res res-${String(res || "unknown").toLowerCase()}`, text: res || "—" }); }
  function tag(text, kind) { return h("span", { class: `tag${kind ? " " + kind : ""}`, text: oneLine(text) }); }

  function kv(rows) {
    const dl = h("dl", { class: "kv" });
    for (const [k, v] of rows) {
      if (v === null || v === undefined || v === "" || (Array.isArray(v) && !v.length)) continue;
      dl.append(h("dt", { text: k }), h("dd", {}, v instanceof Node ? v : oneLine(Array.isArray(v) ? v.join(", ") : v)));
    }
    return dl;
  }

  function table(headers, rows) {
    return h("div", { class: "table-wrap" },
      h("table", {},
        h("thead", {}, h("tr", {}, headers.map((x) => h("th", { text: x })))),
        h("tbody", {}, rows.map((r) => h("tr", {}, r.map((c) =>
          c instanceof Node && c.tagName === "TD" ? c : h("td", { class: "wrap" }, c instanceof Node ? c : oneLine(c))))))));
  }

  function code(text) { return h("pre", { class: "code" }, safe(text)); }

  function card(title, count, ...body) {
    return h("section", { class: "card fade-in" },
      h("h2", {}, title, count !== null && count !== undefined ? h("span", { class: "count", text: `· ${count}` }) : null), body);
  }

  function empty(text) { return h("div", { class: "empty", text }); }

  function download(name, data, type) {
    const blob = data instanceof Blob ? data : new Blob([data], { type });
    const url = URL.createObjectURL(blob);
    const a = h("a", { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  // ------------------------------------------------------------------ API

  async function api(path, body, filename) {
    const headers = {};
    if (state.token) headers.Authorization = `Bearer ${state.token}`;
    // Header values must be Latin-1; file names often are not ("Invoice – May.eml", emoji, accents).
    if (filename) headers["X-Filename"] = encodeURIComponent(filename);
    const resp = await fetch(path, { method: body ? "POST" : "GET", headers, body, cache: "no-store" });
    if (!resp.ok) {
      let msg = `${resp.status} ${resp.statusText}`;
      try { msg = (await resp.json()).error || msg; } catch { /* not JSON */ }
      const err = new Error(msg);
      err.status = resp.status;
      throw err;
    }
    return resp;
  }

  async function loadHealth() {
    try {
      const health = await (await api("/api/v1/health")).json();
      state.health = health;
      $("version").textContent = `v${health.version} · local analysis`;
      const f = health.features || {};
      const chips = $("features");
      fill(chips, 
        h("span", { class: `chip${f.dns ? " on" : ""}`, title: "Live DNS re-verification of DKIM/SPF/DMARC/ARC", text: f.dns ? "DNS checks on" : "Offline" }),
        f.enrichment ? h("span", { class: "chip on", text: "Enrichment on" }) : null,
        f.yara ? h("span", { class: "chip on", text: "YARA" }) : null,
        f.custom_rules ? h("span", { class: "chip on", text: `${f.custom_rules} custom rule${f.custom_rules > 1 ? "s" : ""}` }) : null,
      );
      if (health.auth_required) $("token-box").hidden = false;
    } catch (e) {
      $("version").textContent = "server not reachable";
    }
  }

  // ------------------------------------------------------------------ uploads

  // After a drop, show the first message that finishes; after that only the user's clicks change
  // what is on screen, so a slow file finishing later never pulls them away from what they read.
  function addFiles(files) {
    state.follow = true;
    for (const file of files) {
      const max = state.health && state.health.max_upload;
      const entry = { id: nextId++, file, name: file.name || "message", status: "pending", reports: [], error: null };
      state.entries.unshift(entry);
      if (max && file.size > max) {
        entry.status = "error";
        entry.error = `File is larger than this server accepts (${fmtBytes(max)}).`;
        entry.retryable = false;
        if (!state.selected) show(entry);
        continue;
      }
      analyze(entry);
    }
    renderHistory();
  }

  async function analyze(entry) {
    renderHistory();
    try {
      const resp = await api("/api/v1/analyze?format=bundle", entry.file, entry.name);
      const data = await resp.json();
      entry.reports = data.reports || [];
      entry.elapsed = data.elapsed_ms;
      entry.status = "done";
      if (state.follow || !state.selected || state.selected.entry === entry
          || state.selected.entry.status !== "done") show(entry);
    } catch (e) {
      entry.status = "error";
      entry.error = e.message;
      if (e.status === 401) {
        $("token-box").hidden = false;
        $("token-input").focus();
        toast("This server needs an API token");
      } else {
        toast(`${entry.name}: ${e.message}`);
      }
      if (!state.selected || state.selected.entry === entry) show(entry);
    }
    renderHistory();
  }

  function show(entry) {
    state.follow = false;
    select(entry, 0);
  }

  function select(entry, index, path) {
    state.follow = false;
    state.selected = { entry, index, path: path || [] };
    state.tab = "findings";
    state.findingFilter = "all";
    state.findingQuery = "";
    renderHistory();
    renderReport();
    if (window.matchMedia("(max-width: 860px)").matches) $("main").scrollIntoView({ behavior: "smooth" });
  }

  function currentReport() {
    const sel = state.selected;
    if (!sel || sel.entry.status !== "done") return null;
    let r = sel.entry.reports[sel.index];
    for (const i of sel.path) r = r && r.nested[i] && r.nested[i].report;
    return r;
  }

  // ------------------------------------------------------------------ history

  function verdictOf(r) { return (r.assessment && r.assessment.verdict) || "unknown"; }
  function scoreOf(r) { return r.assessment ? r.assessment.score : "?"; }

  function renderHistory() {
    const list = $("history");
    fill(list);
    $("clear-history").hidden = !state.entries.length;
    if (!state.entries.length) {
      list.append(h("li", { class: "history-empty", text: "Analysed messages appear here." }));
      return;
    }
    for (const entry of state.entries) {
      if (entry.status === "pending") {
        list.append(h("li", {}, h("div", { class: "history-item pending" },
          h("div", { class: "mini-score" }, h("div", { class: "spinner" })),
          h("div", { class: "hi-text" }, h("div", { class: "hi-subject", text: oneLine(entry.name) }),
            h("div", { class: "hi-meta", text: "Analysing…" })))));
        continue;
      }
      if (entry.status === "error") {
        list.append(h("li", {}, h("button", {
          class: `history-item failed${state.selected && state.selected.entry === entry ? " active" : ""}`, type: "button",
          onclick: () => select(entry, 0),
        }, h("div", { class: "mini-score", text: "!" }),
        h("div", { class: "hi-text" }, h("div", { class: "hi-subject", text: oneLine(entry.name) }),
          h("div", { class: "hi-meta", text: entry.error })))));
        continue;
      }
      entry.reports.forEach((r, i) => {
        const active = state.selected && state.selected.entry === entry && state.selected.index === i;
        const label = entry.reports.length > 1 ? `${entry.name} · #${i + 1}` : entry.name;
        list.append(h("li", {}, h("button", {
          class: `history-item${active ? " active" : ""}`, type: "button", onclick: () => select(entry, i),
          title: oneLine(r.headers.subject || label),
        }, h("div", { class: `mini-score v-${verdictOf(r)}`, text: scoreOf(r) }),
        h("div", { class: "hi-text" },
          h("div", { class: "hi-subject", text: oneLine(r.headers.subject || "(no subject)") }),
          h("div", { class: "hi-meta", text: `${oneLine(r.headers.from_address || "unknown sender")} · ${label}` })))));
      });
    }
  }

  // ------------------------------------------------------------------ report

  function renderReport() {
    const root = $("report");
    const sel = state.selected;
    $("welcome").hidden = !!sel;
    root.hidden = !sel;
    if (!sel) return;
    if (sel.entry.status === "pending") {
      fill(root, h("section", { class: "card fade-in", "aria-busy": "true" },
        h("h2", { text: `Analysing ${oneLine(sel.entry.name)}…` }), [1, 2, 3, 4].map(() => h("div", { class: "skeleton" }))));
      return;
    }
    if (sel.entry.status === "error") {
      fill(root, h("div", { class: "notice error fade-in" },
        h("b", { text: `Could not analyse ${oneLine(sel.entry.name)}` }), h("div", { text: sel.entry.error }),
        sel.entry.retryable === false ? null : h("div", { class: "hero-actions" }, h("button", {
          class: "btn primary", type: "button", text: "Retry",
          onclick: () => { sel.entry.status = "pending"; sel.entry.error = null; renderReport(); analyze(sel.entry); },
        }))));
      return;
    }
    const r = currentReport();
    if (!r) return;
    fill(root, 
      crumbs(sel),
      notices(r),
      hero(r, sel),
      h("div", { class: "grid-2 gap-below" }, reasonsCard(r), overviewCard(r)),
      tabs(r),
      h("div", { id: "tab-body" }, tabBody(r)),
    );
    animateGauge();
  }

  function crumbs(sel) {
    if (!sel.path.length) return null;
    const parts = [h("button", { type: "button", text: "Original message", onclick: () => select(sel.entry, sel.index, []) })];
    let r = sel.entry.reports[sel.index];
    sel.path.forEach((idx, depth) => {
      const n = r.nested[idx];
      r = n.report;
      parts.push(h("span", { text: "›" }));
      const name = oneLine(n.filename || `part ${n.part}`);
      parts.push(depth === sel.path.length - 1 ? h("span", { text: name })
        : h("button", { type: "button", text: name, onclick: () => select(sel.entry, sel.index, sel.path.slice(0, depth + 1)) }));
    });
    return h("nav", { class: "crumbs", "aria-label": "Attached message path" }, parts);
  }

  function notices(r) {
    const out = [];
    const codes = new Set(r.findings.map((f) => f.code));
    if (codes.has("ANALYSIS_TIMEOUT")) out.push(h("div", { class: "notice warn", text: "Analysis ran out of time; this report is incomplete." }));
    if (codes.has("ANALYZER_ERROR")) out.push(h("div", { class: "notice warn", text: "Part of the analysis failed; this report may be incomplete." }));
    if (r.evidence.converted) out.push(h("div", { class: "notice", text: "This message was converted from Outlook .msg; its body was rebuilt, so DKIM cannot be verified." }));
    for (const n of r.evidence.notes || []) out.push(h("div", { class: "notice", text: oneLine(n) }));
    return out;
  }

  function hero(r, sel) {
    const v = verdictOf(r);
    const score = r.assessment ? r.assessment.score : 0;
    const h_ = r.headers;
    const from = h_.from_display_name ? `${oneLine(h_.from_display_name)} <${oneLine(h_.from_address || "")}>` : oneLine(h_.from_address || "—");
    const C = 2 * Math.PI * 52;
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 120 120");
    for (const [cls, extra] of [["track", {}], ["value", { "stroke-dasharray": C, "stroke-dashoffset": C, "data-target": C * (1 - score / 100) }]]) {
      const c = document.createElementNS(ns, "circle");
      c.setAttribute("cx", 60); c.setAttribute("cy", 60); c.setAttribute("r", 52); c.setAttribute("class", cls);
      for (const [k, val] of Object.entries(extra)) c.setAttribute(k, val);
      svg.append(c);
    }
    const replyTo = (h_.reply_to || []).map(oneLine).join(", ");
    return h("section", { class: `card hero v-${v} fade-in` },
      h("div", { class: "gauge", role: "img", "aria-label": `Risk score ${score} of 100` }, svg,
        h("div", { class: "gauge-label" }, h("div", { class: "gauge-score", text: score }), h("div", { class: "gauge-max", text: "/ 100 risk" }))),
      h("div", {},
        h("span", { class: "verdict-pill", text: v }),
        h("div", { class: "hero-subject", text: oneLine(h_.subject || "(no subject)") }),
        h("dl", { class: "hero-meta" },
          h("dt", { text: "From" }), h("dd", { text: from }),
          replyTo ? [h("dt", { text: "Reply-To" }), h("dd", { text: replyTo })] : null,
          h("dt", { text: "To" }), h("dd", { text: (h_.to || []).map(oneLine).join(", ") || "—" }),
          h("dt", { text: "Date" }), h("dd", { text: fmtDate(h_.date) }),
          h("dt", { text: "Evidence" }), h("dd", {}, h("span", { class: "hash", text: `SHA-256 ${r.evidence.sha256}` }), copyBtn(r.evidence.sha256, "SHA-256"))),
        heroActions(r, sel)));
  }

  function animateGauge() {
    const c = document.querySelector(".gauge .value");
    if (c) requestAnimationFrame(() => requestAnimationFrame(() => c.setAttribute("stroke-dashoffset", c.dataset.target)));
  }

  function baseName(sel) { return (sel.entry.name || "message").replace(/\.[^.]+$/, "").replace(/[^\w.-]+/g, "_").slice(0, 60) || "message"; }

  function heroActions(r, sel) {
    const whole = sel.entry.reports.length > 1 || sel.path.length;
    const note = whole ? "covers the whole uploaded file" : null;
    const busy = async (btn, fn) => {
      btn.disabled = true;
      try { await fn(); } catch (e) { toast(e.message); } finally { btn.disabled = false; }
    };
    const htmlBtn = h("button", { class: "btn primary", type: "button", title: note || "Self-contained, safe-to-open HTML report" },
      svgIcon("file"), "HTML report");
    htmlBtn.addEventListener("click", () => busy(htmlBtn, async () => {
      const resp = await api("/api/v1/analyze?format=html", sel.entry.file, sel.entry.name);
      download(`${baseName(sel)}-report.html`, await resp.blob());
    }));
    const menu = h("div", { class: "menu" });
    const list = h("div", { class: "menu-list", hidden: true });
    const iocBtn = h("button", { class: "btn", type: "button", "aria-haspopup": "true" }, svgIcon("download"), "Export indicators");
    iocBtn.addEventListener("click", (e) => { e.stopPropagation(); list.hidden = !list.hidden; });
    for (const [fmt, label, desc, ext] of [["stix", "STIX 2.1", "Threat-intel platforms", "json"], ["misp", "MISP event", "Import into MISP", "json"], ["csv", "CSV", "Spreadsheets, blocklists", "csv"]]) {
      list.append(h("button", { type: "button", onclick: () => busy(iocBtn, async () => {
        list.hidden = true;
        const resp = await api(`/api/v1/iocs?format=${fmt}`, sel.entry.file, sel.entry.name);
        download(`${baseName(sel)}-iocs-${fmt}.${ext}`, await resp.blob());
      }) }, label, h("small", { text: desc })));
    }
    document.addEventListener("click", () => { list.hidden = true; });
    menu.append(iocBtn, list);
    const jsonBtn = h("button", { class: "btn", type: "button", title: "This report as JSON",
      onclick: () => download(`${baseName(sel)}-report.json`, JSON.stringify(r, null, 2), "application/json") }, svgIcon("code"), "JSON");
    return h("div", { class: "hero-actions" }, htmlBtn, menu, jsonBtn,
      sel.entry.elapsed !== undefined ? h("span", { class: "faint", text: `analysed in ${sel.entry.elapsed} ms` }) : null);
  }

  function reasonsCard(r) {
    const a = r.assessment;
    if (!a) return card("Why this verdict", null, empty("No assessment."));
    const reasons = a.reasons.filter((x) => x.points > 0);
    const body = reasons.length ? reasons.slice(0, 8).map((x) => h("div", { class: `reason rs-${x.severity}` },
      h("div", { class: "pts", text: `+${Math.round(x.points)}` }),
      h("div", {}, h("div", { class: "reason-msg", text: oneLine(x.message) }), h("div", { class: "reason-code", text: x.code }))))
      : [empty("Nothing raised the score. No finding pointed to a threat.")];
    if (reasons.length > 8) body.push(h("div", { class: "faint", text: `+ ${reasons.length - 8} more in Findings` }));
    if (a.floor) body.push(h("div", { class: "floor-note", text: `${a.floor} is near-conclusive on its own, so it sets a minimum score.` }));
    if (a.nested_score) body.push(h("div", { class: "floor-note", text: `An attached email scored ${a.nested_score}; it counts towards this message.` }));
    return card("Why this verdict", null, body);
  }

  function overviewCard(r) {
    const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
    r.findings.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
    const cats = Object.entries((r.assessment && r.assessment.categories) || {}).sort((x, y) => y[1] - x[1]);
    const max = Math.max(60, ...cats.map((c) => c[1]));
    const urls = allUrls(r);
    return card("At a glance", null,
      h("div", { class: "stat-grid" },
        ["high", "medium", "low"].map((s) => h("div", { class: `stat ${s}` }, h("b", { text: counts[s] }), h("span", { text: `${s} findings` }))),
        h("div", { class: "stat" }, h("b", { text: r.attachments.length }), h("span", { text: "attachments" }))),
      h("h3", { text: "Risk by category" }),
      cats.length ? cats.map(([name, pts]) => h("div", { class: "bar-row" },
        h("span", { text: name }), h("div", { class: "bar" }, h("i", { style: { width: `${Math.min(100, pts / max * 100)}%` } })),
        h("span", { class: "bar-val", text: Math.round(pts) }))) : h("div", { class: "faint", text: "No category scored points." }),
      h("h3", { text: "Message" }),
      kv([["Format", `${r.evidence.format}${r.evidence.container ? " · " + r.evidence.container : ""}`],
        ["Size", fmtBytes(r.evidence.size)], ["Links", String(urls.length)], ["Hops", String(r.headers.hops.length)],
        ["Attached emails", r.nested.length ? String(r.nested.length) : null], ["Mailer", r.headers.x_mailer]]));
  }

  // ------------------------------------------------------------------ tabs

  function allUrls(r) {
    return [...r.body.urls.map((u) => ({ ...u, where: "body" })),
      ...r.attachments.flatMap((a) => (a.urls || []).map((u) => ({ ...u, where: a.filename || `part ${a.part}` })))];
  }

  function tabs(r) {
    const defs = [
      ["findings", "Findings", r.findings.length],
      ["route", "Sender & route", null],
      ["auth", "Authentication", null],
      ["links", "Links & content", allUrls(r).length],
      ["attachments", "Attachments", r.attachments.length],
      ["indicators", "Indicators", (r.indicators || []).length],
      r.nested.length ? ["nested", "Attached emails", r.nested.length] : null,
      ["raw", "Raw JSON", null],
    ].filter(Boolean);
    if (!defs.some((d) => d[0] === state.tab)) state.tab = "findings";
    return h("div", { class: "tabs", role: "tablist" }, defs.map(([id, label, n]) => h("button", {
      class: `tab${state.tab === id ? " active" : ""}`, type: "button", role: "tab", "aria-selected": String(state.tab === id),
      onclick: (e) => {
        state.tab = id;
        document.querySelectorAll(".tab").forEach((t) => {
          t.classList.toggle("active", t === e.currentTarget);
          t.setAttribute("aria-selected", String(t === e.currentTarget));
        });
        fill($("tab-body"), tabBody(currentReport()));
      },
    }, label, n !== null ? h("span", { class: "count", text: ` ${n}` }) : null)));
  }

  function tabBody(r) {
    switch (state.tab) {
      case "route": return routeTab(r);
      case "auth": return authTab(r);
      case "links": return linksTab(r);
      case "attachments": return attachmentsTab(r);
      case "indicators": return indicatorsTab(r);
      case "nested": return nestedTab(r);
      case "raw": return rawTab(r);
      default: return findingsTab(r);
    }
  }

  function findingsTab(r) {
    const list = h("div", {});
    const counts = { all: r.findings.length };
    r.findings.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
    const draw = () => {
      const q = state.findingQuery.toLowerCase();
      const items = r.findings
        .filter((f) => state.findingFilter === "all" || f.severity === state.findingFilter)
        .filter((f) => !q || f.code.toLowerCase().includes(q) || f.message.toLowerCase().includes(q))
        .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
      fill(list, ...(items.length ? items.map(findingItem) : [empty(r.findings.length ? "No findings match." : "No findings for this message.")]));
    };
    const filters = h("div", { class: "toolbar" },
      ["all", ...SEVERITIES].filter((s) => s === "all" || counts[s]).map((s) => h("button", {
        class: `filter${state.findingFilter === s ? " active" : ""}`, type: "button",
        onclick: (e) => {
          state.findingFilter = s;
          filters.querySelectorAll(".filter").forEach((b) => b.classList.toggle("active", b === e.currentTarget));
          draw();
        },
      }, `${s === "all" ? "All" : s[0].toUpperCase() + s.slice(1)} ${counts[s] || 0}`)),
      h("input", { class: "search", type: "search", placeholder: "Search findings…", value: state.findingQuery, "aria-label": "Search findings",
        oninput: (e) => { state.findingQuery = e.target.value; draw(); } }));
    const suppressed = (r.suppressed || []).length
      ? h("details", { class: "more" }, h("summary", { text: `${r.suppressed.length} finding(s) suppressed by custom rules` }),
        table(["Code", "Rule", "Message"], r.suppressed.map((s) => [s.code, s.rule, s.message])))
      : null;
    draw();
    return card("Findings", r.findings.length, filters, list, suppressed);
  }

  function findingItem(f) {
    const ev = f.evidence && Object.keys(f.evidence).length ? f.evidence : null;
    return h("details", { class: "finding" },
      h("summary", {}, sevPill(f.severity),
        h("div", {}, h("div", { class: "f-msg", text: oneLine(f.message) }), h("div", { class: "f-code", text: f.code })),
        ev ? svgIcon("chev", "chev") : h("span", {})),
      ev ? h("div", { class: "finding-body" }, code(JSON.stringify(ev, null, 2))) : null);
  }

  function routeTab(r) {
    const hd = r.headers;
    const id = r.identity || {};
    const origin = hd.hops.find((x) => x.from_ip && x.ip_is_private === false);
    const hops = [...hd.hops].sort((a, b) => b.index - a.index);   // oldest (sender side) first
    const timeline = hops.length ? h("ol", { class: "timeline" }, hops.map((hop) => h("li", { class: hop === origin ? "origin" : "" },
      h("span", { class: "dot" }),
      h("div", { class: "hop-title" }, `${oneLine(hop.from_host || "?")} → ${oneLine(hop.by_host || "?")}`),
      h("div", { class: "hop-meta" },
        hop.from_ip ? tag(hop.from_ip, hop.ip_is_private === false ? "warn" : "") : null,
        hop === origin ? tag("origin IP", "warn") : null,
        hop.protocol ? tag(hop.protocol) : null,
        `${fmtDate(hop.timestamp)}${hop.delay_seconds ? ` · +${hop.delay_seconds}s` : ""}`))))
      : empty("No Received headers.");
    const verdicts = Object.entries(id.provider_verdicts || {});
    return h("div", { class: "grid-2 gap-below" },
      card("Sender identity", null, kv([
        ["From", hd.from_display_name ? `${hd.from_display_name} <${hd.from_address || ""}>` : hd.from_address],
        ["Reply-To", hd.reply_to], ["Return-Path", hd.return_path], ["Sender", hd.sender], ["To", hd.to], ["Cc", hd.cc],
        ["Subject", hd.subject], ["Date", hd.date ? `${fmtDate(hd.date)} (${hd.date})` : null], ["Message-ID", hd.message_id],
        ["Mailer", id.mailer ? `${id.mailer}${id.mailer_category ? ` (${id.mailer_category})` : ""}` : hd.x_mailer],
        ["Originating IP", hd.x_originating_ip], ["PHP script", id.php_script],
        ["Recipient domains", id.recipient_domains], ["Headers", String(hd.header_count)],
      ]), verdicts.length ? [h("h3", { text: "Mail provider verdicts" }), kv(verdicts.map(([k, v]) => [k, typeof v === "object" ? JSON.stringify(v) : String(v)]))] : null),
      card("Delivery route", hd.hops.length, h("p", { class: "muted", text: "Oldest hop first. Hops below your own mail servers can be forged by the sender." }), timeline));
  }

  function authTab(r) {
    const a = r.auth || {};
    const recorded = r.headers.auth_results || [];
    const cards = [];
    for (const d of a.dkim || []) {
      cards.push(h("div", { class: "auth-card" },
        h("div", { class: "auth-head" }, `DKIM · ${oneLine(d.domain || "?")}`, resPill(d.result)),
        h("p", { text: oneLine(d.reason || "") }),
        h("p", { text: `${d.algorithm || ""} · selector ${d.selector || "?"}${d.key_bits ? ` · ${d.key_bits}-bit` : ""} · body hash ${d.body_hash_ok === true ? "matches" : d.body_hash_ok === false ? "DOES NOT MATCH" : "unchecked"}` })));
    }
    if (a.arc) cards.push(h("div", { class: "auth-card" }, h("div", { class: "auth-head" }, `ARC · ${a.arc.instances} hop(s)`, resPill(a.arc.result)),
      h("p", { text: oneLine(a.arc.reason || "") }), h("p", { text: (a.arc.sealers || []).map((s) => `${s.i}: ${s.d} (cv=${s.cv})`).join(" · ") })));
    if (a.spf) cards.push(h("div", { class: "auth-card" }, h("div", { class: "auth-head" }, `SPF · ${oneLine(a.spf.domain || "")}`, resPill(a.spf.result)),
      h("p", { text: oneLine(a.spf.reason || "") }),
      h("p", { text: `IP ${a.spf.ip || "?"}${a.spf_ip_source ? ` (from ${a.spf_ip_source})` : ""}${a.spf.mechanism ? ` · matched ${a.spf.mechanism}` : ""}` })));
    if (a.dmarc) cards.push(h("div", { class: "auth-card" }, h("div", { class: "auth-head" }, `DMARC · ${oneLine(a.dmarc.from_domain || "")}`, resPill(a.dmarc.result)),
      h("p", { text: oneLine(a.dmarc.reason || "") }),
      h("p", { text: `${a.dmarc.policy ? `policy p=${a.dmarc.policy}` : "no policy"} · DKIM aligned: ${(a.dmarc.dkim_aligned || []).join(", ") || "no"} · SPF aligned: ${a.dmarc.spf_aligned ? "yes" : "no"}` })));
    const offline = !a.online;
    return h("div", {},
      offline ? h("div", { class: "notice", text: "Offline mode: DKIM body hashes are checked, but signatures, SPF and DMARC need DNS. Start the server with --online or --doh to re-verify them now." }) : null,
      card("Re-verification", cards.length, cards.length ? h("div", { class: "auth-grid" }, cards) : empty("No DKIM signatures, and no DNS checks were run.")),
      card("Recorded by the receiving server", recorded.length, recorded.length
        ? table(["Method", "Result", "Server", "Details"], recorded.map((x) => [x.method.toUpperCase(), h("td", {}, resPill(x.result)), x.authserv_id || "",
          Object.entries(x.properties || {}).map(([k, v]) => `${k}=${v}`).join(" ")]))
        : empty("No Authentication-Results header.")));
  }

  function linksTab(r) {
    const urls = allUrls(r);
    const flagged = new Set();
    for (const f of r.findings) {
      if (!f.code.startsWith("URL_") && !f.code.startsWith("LOOKALIKE_")) continue;
      const s = JSON.stringify(f.evidence || {});
      urls.forEach((u) => { if (u.host && s.includes(u.host)) flagged.add(u.url); });
    }
    const rows = urls.sort((a, b) => flagged.has(b.url) - flagged.has(a.url)).map((u) => [
      h("td", { class: "wrap" }, h("span", { class: "hash", text: defang(u.url) }), copyBtn(u.url, "URL")),
      h("td", { class: "wrap" }, flagged.has(u.url) ? tag("flagged", "bad") : null, u.org_domain ? tag(u.org_domain) : null),
      (u.anchor_texts || []).map(oneLine).join(" | "),
      `${u.where}: ${(u.sources || []).join(", ")}`,
    ]);
    const html = r.body.html || [];
    return h("div", {},
      card("Links", urls.length, h("p", { class: "muted", text: "Defanged and not clickable. Copy only when you mean to." }),
        urls.length ? table(["URL", "Domain", "Link text", "Found in"], rows) : empty("No links.")),
      card("Text", r.body.text_bodies.length, r.body.text_bodies.length
        ? r.body.text_bodies.map((t) => h("div", {}, h("div", { class: "faint", text: `part ${t.part} · ${t.content_type} · ${t.length} chars` }), code(t.preview)))
        : empty("No plain-text body.")),
      html.length ? card("HTML", html.length, html.map((x) => h("div", {},
        h("div", { class: "faint", text: `part ${x.part}` }),
        x.visible_text ? [h("h3", { text: "What the reader sees" }), code(x.visible_text)] : null,
        (x.hidden_text || []).length ? [h("h3", { text: "Hidden from the reader" }), code(x.hidden_text.join("\n"))] : null))) : null);
  }

  function hashRows(o) {
    return ["sha256", "sha1", "md5"].filter((k) => o[k]).map((k) => [k.toUpperCase(), h("span", {}, h("span", { class: "hash", text: o[k] }), copyBtn(o[k], k))]);
  }

  function attachmentsTab(r) {
    if (!r.attachments.length) return card("Attachments", 0, empty("No attachments."));
    const byPart = {};
    for (const f of r.findings) {
      const part = f.evidence && f.evidence.part;
      if (part) (byPart[part] = byPart[part] || []).push(f);
    }
    return card("Attachments", r.attachments.length, r.attachments.map((a) => {
      const fs = (byPart[a.part] || []).sort((x, y) => SEVERITIES.indexOf(x.severity) - SEVERITIES.indexOf(y.severity));
      const mismatch = a.extension && a.detected_type && a.extension !== a.detected_type;
      return h("div", { class: "att" },
        h("div", { class: "att-head" },
          h("div", { class: "att-name", text: oneLine(a.filename || `part ${a.part}`) }),
          h("div", { class: "att-flags" }, fs.slice(0, 4).map((f) => h("span", { class: `sev sev-${f.severity}`, title: oneLine(f.message), text: f.code })))),
        kv([["Detected type", `${a.detected_description || a.detected_type || "unknown"}${mismatch ? `  (named .${a.extension})` : ""}`],
          ["Declared type", a.content_type], ["Size", fmtBytes(a.size)], ["Part", a.part], ...hashRows(a)]),
        fs.length ? [h("h3", { text: "Findings" }), fs.map(findingItem)] : null,
        a.archive ? archiveView(a.archive) : null,
        a.payload ? payloadView(a.payload) : null);
    }));
  }

  function archiveView(ar) {
    return [h("h3", { text: `Archive contents (${ar.format}, ${ar.members.length} entries${ar.encrypted_members ? `, ${ar.encrypted_members} encrypted` : ""})` }),
      ar.error ? h("div", { class: "notice warn", text: oneLine(ar.error) }) : null,
      table(["Name", "Type", "Size", "SHA-256"], ar.members.slice(0, 200).map((m) => [
        `${m.container ? m.container + "/" : ""}${m.name}${m.encrypted ? " 🔒" : ""}`, m.detected_type || "", fmtBytes(m.size),
        m.sha256 ? h("td", { class: "wrap" }, h("span", { class: "hash", text: m.sha256 })) : ""]))];
  }

  function embeddedTable(list) {
    return table(["Name", "Source", "Type", "SHA-256"], list.map((e) => [e.name || "", e.source || "", e.detected_type || "", e.sha256 || ""]));
  }

  function payloadView(p) {
    const out = [];
    const o = p.office;
    if (o) {
      if (o.metadata && Object.keys(o.metadata).length) out.push(h("h3", { text: "Document metadata" }), kv(Object.entries(o.metadata)));
      for (const m of o.vba || []) {
        out.push(h("h3", { text: `VBA macro · ${m.name}` }),
          h("div", {}, (m.autoexec || []).map((x) => tag(`auto-run: ${x}`, "bad")), (m.suspicious || []).map((x) => tag(x, "warn")), m.stomped ? tag("VBA stomping", "bad") : null),
          (m.iocs || []).length ? kv([["Indicators", (m.iocs || []).map(defang).join("  ")]]) : null,
          m.preview ? code(m.preview) : null);
      }
      if ((o.xlm_macros || []).length) out.push(h("h3", { text: "Excel 4.0 (XLM) macros" }), code(o.xlm_macros.join("\n")));
      if ((o.dde || []).length) out.push(h("h3", { text: "DDE fields" }), code(o.dde.join("\n")));
      if ((o.activex || []).length) out.push(h("h3", { text: "ActiveX controls" }), h("div", {}, o.activex.map((x) => tag(x))));
      if ((o.embedded || []).length) out.push(h("h3", { text: "Embedded objects" }), embeddedTable(o.embedded));
      if ((o.external || []).length) out.push(h("h3", { text: "External references" }),
        table(["Type", "Target", "Part"], o.external.map((x) => [x.type, defang(x.target), x.part])));
    }
    const pdf = p.pdf;
    if (pdf) {
      out.push(h("h3", { text: `PDF${pdf.version ? " " + pdf.version : ""}` }),
        h("div", {}, Object.entries(pdf.keywords || {}).filter(([, n]) => n).map(([k, n]) => tag(`${k} ×${n}`, /JavaScript|JS|Launch|OpenAction|AA|EmbeddedFile/.test(k) ? "warn" : ""))));
      if ((pdf.launch || []).length) out.push(kv([["Launch", pdf.launch]]));
      if ((pdf.uris || []).length) out.push(kv([["Links", pdf.uris.map(defang).join("  ")]]));
      if ((pdf.javascript || []).length) out.push(h("h3", { text: "JavaScript" }), code(pdf.javascript.join("\n\n")));
      if ((pdf.embedded || []).length) out.push(h("h3", { text: "Embedded files" }), embeddedTable(pdf.embedded));
    }
    const l = p.lnk;
    if (l) out.push(h("h3", { text: "Windows shortcut" }), kv([["Target", l.target || l.env_target || l.relative_path], ["Arguments", l.arguments],
      ["Working dir", l.working_dir], ["Icon", l.icon], ["Window", l.show_command], ["Created on machine", l.machine_id], ["Error", l.error]]));
    const s = p.script;
    if (s) {
      out.push(h("h3", { text: "Script behaviour" }), kv(Object.entries(s.indicators || {}).map(([k, v]) => [k, v.join(", ")])));
      if ((s.decoded_commands || []).length) out.push(h("h3", { text: "Decoded PowerShell" }), code(s.decoded_commands.join("\n\n")));
      if ((s.urls || []).length) out.push(kv([["URLs", s.urls.map(defang).join("  ")]]));
    }
    if ((p.embedded || []).length) out.push(h("h3", { text: "Embedded files" }), embeddedTable(p.embedded));
    return out.length ? h("div", {}, out) : null;
  }

  function indicatorsTab(r) {
    const inds = r.indicators || [];
    if (!inds.length) return card("Indicators", 0, empty("No indicators."));
    const byType = {};
    inds.forEach((i) => { (byType[i.type] = byType[i.type] || []).push(i); });
    let filter = "all";
    const wrap = h("div", {});
    const draw = () => fill(wrap, table(["Type", "Value", "Role", "Context"],
      inds.filter((i) => filter === "all" || i.type === filter).map((i) => [i.type,
        h("td", { class: "wrap" }, h("span", { class: "hash", text: ["url", "domain", "ipv4", "ipv6", "email-addr"].includes(i.type) ? defang(i.value) : oneLine(i.value) }), copyBtn(i.value, i.type)),
        i.role, i.context || ""])));
    const bar = h("div", { class: "toolbar" }, ["all", ...Object.keys(byType)].map((t) => h("button", {
      class: `filter${t === "all" ? " active" : ""}`, type: "button",
      onclick: (e) => { filter = t; bar.querySelectorAll(".filter").forEach((b) => b.classList.toggle("active", b === e.currentTarget)); draw(); },
    }, `${t === "all" ? "All" : t} ${t === "all" ? inds.length : byType[t].length}`)));
    draw();
    return card("Indicators", inds.length, h("p", { class: "muted", text: `Each indicator keeps the verdict of its message (${verdictOf(r)}). A clean newsletter's domains are not threats.` }), bar, wrap);
  }

  function nestedTab(r) {
    const sel = state.selected;
    return card("Attached emails", r.nested.length, h("div", { class: "nested-list" }, r.nested.map((n, i) => h("button", {
      class: "nested-item", type: "button", onclick: () => select(sel.entry, sel.index, [...sel.path, i]),
    }, h("div", { class: `mini-score v-${verdictOf(n.report)}`, text: scoreOf(n.report) }),
    h("div", { class: "hi-text" }, h("div", { class: "hi-subject", text: oneLine(n.report.headers.subject || "(no subject)") }),
      h("div", { class: "hi-meta", text: `${oneLine(n.report.headers.from_address || "")} · ${oneLine(n.filename || "part " + n.part)}` }))))));
  }

  function rawTab(r) {
    const text = JSON.stringify(r, null, 2);
    return card("Raw JSON", null,
      h("div", { class: "toolbar" }, h("button", { class: "btn", type: "button", onclick: async () => {
        try { await navigator.clipboard.writeText(text); toast("Copied"); } catch { toast("Copy not available"); }
      } }, svgIcon("copy"), "Copy")), code(text));
  }

  // ------------------------------------------------------------------ wiring

  function setupTheme() {
    let theme = null;
    try { theme = localStorage.getItem("ef-theme"); } catch { /* storage blocked */ }
    if (theme) document.documentElement.dataset.theme = theme;
    $("theme-toggle").addEventListener("click", () => {
      const dark = document.documentElement.dataset.theme
        ? document.documentElement.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
      const next = dark ? "light" : "dark";
      document.documentElement.dataset.theme = next;
      try { localStorage.setItem("ef-theme", next); } catch { /* storage blocked */ }
    });
  }

  function setupUpload() {
    const dz = $("dropzone");
    const input = $("file-input");
    input.addEventListener("change", () => { addFiles([...input.files]); input.value = ""; });
    for (const ev of ["dragenter", "dragover"]) dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("drag"); });
    for (const ev of ["dragleave", "drop"]) dz.addEventListener(ev, () => dz.classList.remove("drag"));
    dz.addEventListener("drop", (e) => { e.preventDefault(); if (e.dataTransfer.files.length) addFiles([...e.dataTransfer.files]); });
    // dropping anywhere on the page works too, and never navigates away to the file
    window.addEventListener("dragover", (e) => e.preventDefault());
    window.addEventListener("drop", (e) => { e.preventDefault(); if (!dz.contains(e.target) && e.dataTransfer.files.length) addFiles([...e.dataTransfer.files]); });
    const tokenInput = $("token-input");
    try { state.token = sessionStorage.getItem("ef-token") || ""; } catch { /* storage blocked */ }
    tokenInput.value = state.token;
    tokenInput.addEventListener("input", () => {
      state.token = tokenInput.value.trim();
      try { sessionStorage.setItem("ef-token", state.token); } catch { /* storage blocked */ }
    });
    $("clear-history").addEventListener("click", () => {
      state.entries = state.entries.filter((e) => e.status === "pending");
      state.selected = null;
      renderHistory();
      renderReport();
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    setupTheme();
    setupUpload();
    loadHealth();
  });
})();
