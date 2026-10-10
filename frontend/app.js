const API = "";  // same-origin, FastAPI serves this file too

// ---------- tab switching ----------
document.getElementById("tabs").addEventListener("click", (e) => {
  const btn = e.target.closest(".tab");
  if (!btn) return;
  document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  btn.classList.add("active");
  document.getElementById(`view-${btn.dataset.view}`).classList.add("active");
  if (btn.dataset.view === "dataset") loadDataset();
});

// ---------- health check ----------
async function checkHealth() {
  const el = document.getElementById("llmStatus");
  try {
    const res = await fetch(`${API}/api/health`);
    const data = await res.json();
    if (data.llm_configured) {
      el.textContent = `${data.llm_provider} · ${data.llm_model} · ready`;
      el.className = "llm-status ready";
    } else {
      el.textContent = `${data.llm_provider} · no API key set`;
      el.className = "llm-status missing";
      el.title = data.note || "";
    }
  } catch (e) {
    el.textContent = "backend unreachable";
    el.className = "llm-status missing";
  }
}
checkHealth();

// ---------- crate inspection ----------
const scanForm = document.getElementById("scanForm");
const scanButton = document.getElementById("scanButton");
const scanResult = document.getElementById("scanResult");

async function doInspect(name, version, condition, prescreen) {
  scanButton.disabled = true;
  scanButton.textContent = "Inspecting…";
  scanResult.classList.remove("hidden");
  scanResult.innerHTML = `<div class="status-msg">Downloading crate, extracting signals, querying LLM…</div>`;

  try {
    const res = await fetch(`${API}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, version, condition, prescreen }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Analysis failed");
    renderScanResult(data);
  } catch (err) {
    scanResult.innerHTML = `<div class="status-msg error">${escapeHtml(err.message)}</div>`;
  } finally {
    scanButton.disabled = false;
    scanButton.textContent = "Inspect";
  }
}

scanForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = document.getElementById("crateName").value.trim();
  const version = document.getElementById("crateVersion").value.trim();
  const condition = document.getElementById("condition").value;
  const prescreen = document.getElementById("prescreen").checked;
  await doInspect(name, version, condition, prescreen);
});

const CONDITION_LABELS = {
  structured: "signals + RAG + LLM",
  structured_norag: "signals + LLM (no RAG)",
  hybrid: "hybrid (signals + windows + LLM)",
  hybrid_norag: "hybrid (no RAG)",
  raw: "raw source + domain prompt",
  naive: "naive prompt",
};

function scoreChip(label, v) {
  if (v === null || v === undefined) return "";
  return `<span class="score-chip">${label} <b>${Number(v).toFixed(2)}</b></span>`;
}

function renderScanResult(data) {
  const c = data.classification;
  const label = c.classification;

  let html = `
    <div class="verdict-strip ${label}">
      <div class="verdict-label ${label}">${label}</div>
      <div class="verdict-meta">
        <b>${escapeHtml(data.crate)}</b> v${escapeHtml(data.version)} &nbsp;·&nbsp;
        confidence: <b>${c.confidence}</b> &nbsp;·&nbsp;
        action: <b>${c.recommended_action}</b> &nbsp;·&nbsp;
        condition: <b>${CONDITION_LABELS[data.condition] || escapeHtml(data.condition)}</b>
      </div>
    </div>
    <div class="score-row">
      ${scoreChip("malware", c.malware_score)}
      ${scoreChip("security risk", c.security_risk_score)}
      ${scoreChip("obfuscation", c.obfuscation_score)}
      ${scoreChip("confidence", c.confidence_score)}
      ${c.reconciled ? `<span class="score-chip warn">verdict escalated from ${c.llm_classification} (score/label mismatch)</span>` : ""}
      ${c.score_label_consistent === false ? `<span class="score-chip warn">score and label disagree</span>` : ""}
    </div>
    ${c.llm_skipped ? `<div class="status-msg">LLM not consulted (static pre-screen): ${escapeHtml(data.prescreen?.reason || "")}</div>` : ""}
    ${data.usage ? `<p class="muted">LLM calls: ${data.usage.calls}</p>` : ""}
    <div class="reasoning-block">${escapeHtml(c.reasoning || "(no reasoning returned)")}</div>
  `;

  if (data.signals) {
    html += `<div class="signal-manifest">${renderSignalManifest(data.signals)}</div>`;
  }

  if (data.retrieved_context && data.retrieved_context.length) {
    html += `<div class="rag-panel">
      <p class="rag-eyebrow">retrieved grounding context (RAG)</p>
      ${data.retrieved_context.map(doc => `
        <div class="rag-doc">
          <div class="rag-doc-head">
            <span class="rag-doc-title">${escapeHtml(doc.title)}</span>
            <span class="rag-doc-sim">similarity ${doc.similarity.toFixed(2)}</span>
          </div>
          <div class="rag-doc-text">${escapeHtml(doc.text)}</div>
          <div class="rag-doc-source">source: ${escapeHtml(doc.source || "unknown")}
            ${c.retrieved_evidence_used && c.retrieved_evidence_used.includes(doc.id)
              ? '<span class="rag-used-flag">cited by LLM</span>' : ''}
          </div>
        </div>
      `).join("")}
    </div>`;
  }

  scanResult.innerHTML = html;
}

function renderSignalManifest(s) {
  const rows = [];

  const br = s.build_rs || {};
  rows.push(row("build.rs", br.has_build_rs
    ? flagList(br.signals) + (br.flagged_snippets?.length
        ? `<div class="signal-value">${br.flagged_snippets.slice(0,3).map(escapeHtml).join("<br>")}</div>` : "")
    : none("no build.rs present")));

  const uf = s.unsafe_ffi || {};
  rows.push(row("unsafe / FFI", `${uf.unsafe_block_count ?? 0} unsafe block(s), `
    + `${uf.unsafe_per_kloc ?? 0} per kLOC`
    + (uf.syscall_usage?.length ? ` — <span class="signal-flag">raw syscall usage</span>` : "")));

  const pm = s.proc_macro || {};
  rows.push(row("proc-macro", pm.is_proc_macro
    ? `declared as proc-macro` + (pm.proc_macro_suspicious_imports?.length
        ? ` — <span class="signal-flag">suspicious imports: ${pm.proc_macro_suspicious_imports.join(", ")}</span>` : "")
    : none("not a proc-macro crate")));

  const ts = s.typosquatting || {};
  rows.push(row("typosquatting", ts.target
    ? `closest to <b>${ts.target}</b>, score ${ts.score}, edit distance ${ts.edit_distance}`
      + (ts.flagged ? ` <span class="signal-flag">flagged</span>` : "")
    : none("no comparison available")));

  const dep = s.dependencies || {};
  rows.push(row("dependencies", `${dep.count ?? 0} direct dependenc${dep.count === 1 ? "y" : "ies"}`
    + (dep.suspicious?.length ? ` — <span class="signal-flag">${dep.suspicious.join(", ")}</span>` : "")));

  const ss = s.source_scan || {};
  rows.push(row("library source scan", (ss.categories?.length)
    ? ss.categories.map(c => `<span class="signal-flag">${c}</span>`).join("")
        + (ss.possible_exfiltration_shape ? ` <span class="signal-flag">exfiltration shape</span>` : "")
    : none("nothing notable in library code")));

  const ver = s.version || {};
  rows.push(row("version", ver.high_major_version
    ? `<span class="signal-flag">major ${ver.major}</span> ${escapeHtml(ver.note || "")}`
    : none(`v${escapeHtml(ver.version || "?")}`)));

  const pi = s.prompt_injection || {};
  rows.push(row("prompt injection", pi.detected
    ? `<span class="signal-flag">detected</span><div class="signal-value">${(pi.matches || []).slice(0,3).map(m => escapeHtml(`${m.file}:${m.line} ${m.snippet}`)).join("<br>")}</div>`
    : none("none detected")));

  return rows.join("");
}
function row(name, valueHtml) {
  return `<div class="signal-row"><div class="signal-name">${name}</div><div class="signal-value">${valueHtml}</div></div>`;
}
function flagList(signals) {
  if (!signals || !signals.length) return none("no suspicious signals in build.rs");
  return signals.map(s => `<span class="signal-flag">${s}</span>`).join("");
}
function none(text) { return `<span class="signal-none">${text}</span>`; }
function escapeHtml(str) {
  const d = document.createElement("div");
  d.textContent = str ?? "";
  return d.innerHTML;
}

// ---------- dataset view ----------
let datasetLoaded = false;
async function loadDataset() {
  if (datasetLoaded) return;
  const summary = document.getElementById("datasetSummary");
  const tbody = document.querySelector("#datasetTable tbody");
  try {
    const res = await fetch(`${API}/api/dataset`);
    const data = await res.json();
    const counts = data.label_counts || {};
    summary.textContent = `${data.total_crates || 0} entries (${data.analyzable_crates ?? "?"} analyzable) — `
      + Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(" · ");

    tbody.innerHTML = (data.crates || []).map(c => `
      <tr>
        <td>${escapeHtml(c.name)}</td>
        <td>${escapeHtml(c.version || "—")}</td>
        <td><span class="label-pill ${c.label}">${c.label}</span></td>
        <td>${escapeHtml(c.label_source || "—")}</td>
        <td>${escapeHtml(c.attack_category || "—")}</td>
        <td title="${escapeHtml(c.note || "")}">${c.analyzable === false ? "no" : (c.analyzable ? "yes" : "?")}</td>
      </tr>
    `).join("") || `<tr><td colspan="6" class="muted">No dataset loaded — add entries to data/dataset.json</td></tr>`;
    datasetLoaded = true;
  } catch (e) {
    summary.textContent = "Failed to load dataset.";
  }
}

// ---------- ablation view ----------
document.getElementById("runAblation").addEventListener("click", async () => {
  const out = document.getElementById("ablationOutput");
  out.innerHTML = `<div class="status-msg">Running every condition over the analyzable dataset entries — this calls the LLM many times (the per-file workflow alone makes several calls per file) and may take a long time…</div>`;
  try {
    const res = await fetch(`${API}/api/ablation`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({}),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Ablation failed");
    renderAblation(data);
  } catch (e) {
    out.innerHTML = `<div class="status-msg error">${escapeHtml(e.message)}</div>`;
  }
});

function renderAblation(metrics) {
  const out = document.getElementById("ablationOutput");
  const labels = {
    structured: "Signals + RAG + LLM",
    structured_norag: "Signals + LLM (no RAG)",
    raw: "Raw source + domain prompt",
    naive: "Naive prompt",
    socketai: "Per-file workflow (SocketAI-style)",
    cargo_audit: "cargo-audit (advisory lookup)",
  };
  const meta = metrics._meta || {};
  const rows = Object.entries(labels).map(([key, label]) => {
    const m = metrics[key];
    if (!m) return "";
    const calls = meta.usage?.[key]?.calls;
    return `
      <tr>
        <td>${label}</td>
        <td>${bar(m.precision)}</td>
        <td>${bar(m.recall)}</td>
        <td>${bar(m.f1)}</td>
        <td>${m.fpr === null || m.fpr === undefined ? "n/a" : (m.fpr * 100).toFixed(1) + "%"}</td>
        <td>${m.tp}/${m.fp}/${m.fn}/${m.tn}</td>
        <td>${calls ?? "—"}</td>
      </tr>`;
  }).join("");

  const warnings = [...new Set(Object.entries(metrics)
    .filter(([k, v]) => k !== "_meta" && v && v.warnings)
    .flatMap(([, v]) => v.warnings))];

  out.innerHTML = `
    <table class="ablation-table">
      <thead><tr><th>Condition</th><th>Precision</th><th>Recall</th><th>F1</th><th>FPR</th><th>TP/FP/FN/TN</th><th>LLM calls</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <p class="muted" style="margin-top:16px">
      ${meta.n_analyzable ?? "?"} of ${meta.n_dataset ?? "?"} dataset entries were analyzable
      (${meta.n_skipped_unanalyzable ?? 0} skipped: crate removed from crates.io or version unknown).
    </p>
    ${warnings.map(w => `<p class="status-msg error">${escapeHtml(w)}</p>`).join("")}`;
}
function bar(value) {
  if (value === null || value === undefined) return "n/a";
  const pct = Math.round((value || 0) * 100);
  return `<div>${value.toFixed(3)}<div class="metric-bar-track"><div class="metric-bar-fill" style="width:${pct}%"></div></div></div>`;
}

function handleDeepLink() {
  const params = new URLSearchParams(window.location.search);
  const hash = window.location.hash.replace("#", "");

  if (hash === "dataset" || params.get("tab") === "dataset") {
    document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.view === "dataset"));
    document.querySelectorAll(".view").forEach(v => v.classList.toggle("active", v.id === "view-dataset"));
    loadDataset();
  } else if (hash === "ablation" || params.get("tab") === "ablation") {
    document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.view === "ablation"));
    document.querySelectorAll(".view").forEach(v => v.classList.toggle("active", v.id === "view-ablation"));
    if (params.get("run") === "1") {
      document.getElementById("runAblation").click();
    }
  }

  const crate = params.get("crate");
  const version = params.get("version");
  const condition = params.get("condition");
  if (crate && version) {
    document.getElementById("crateName").value = crate;
    document.getElementById("crateVersion").value = version;
    if (condition) document.getElementById("condition").value = condition;
    if (params.get("auto") === "1") {
      doInspect(crate, version, condition || "structured", false);
    }
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", handleDeepLink);
} else {
  handleDeepLink();
}
