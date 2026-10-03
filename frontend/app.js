/* CodeAudit Agent demo frontend — vanilla JS, no build step.
 * Talks to the FastAPI backend. All dynamic strings are escaped before
 * being inserted into the DOM (findings carry code evidence).
 */
"use strict";

/* ---------------- settings ---------------- */
const $ = (id) => document.getElementById(id);
const backendInput = $("backendUrl");
const apiKeyInput = $("apiKey");
// When served from the API itself (/ui), same-origin is the right default.
// Otherwise (separate static host) fall back to the local dev backend.
const _sameOriginDefault =
  window.location.pathname.startsWith("/ui") && window.location.origin.startsWith("http")
    ? window.location.origin
    : "http://localhost:8000";
backendInput.value = localStorage.getItem("ca_backend") || _sameOriginDefault;
apiKeyInput.value = localStorage.getItem("ca_key") || "";
backendInput.addEventListener("change", () => {
  localStorage.setItem("ca_backend", backendInput.value.trim());
  checkHealth();
});
apiKeyInput.addEventListener("change", () =>
  localStorage.setItem("ca_key", apiKeyInput.value)
);

const base = () => backendInput.value.trim().replace(/\/+$/, "");
const headers = (json = true) => {
  const h = {};
  if (json) h["Content-Type"] = "application/json";
  const k = apiKeyInput.value.trim();
  if (k) h["X-API-Key"] = k;
  return h;
};

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

/* ---------------- health ---------------- */
async function checkHealth() {
  const dot = $("healthDot");
  try {
    const r = await fetch(base() + "/health", { signal: AbortSignal.timeout(4000) });
    dot.className = "health " + (r.ok ? "ok" : "bad");
    dot.title = r.ok ? "Backend reachable" : "Backend error " + r.status;
  } catch {
    dot.className = "health unknown";
    dot.title = "Backend unreachable";
  }
}
checkHealth();
setInterval(checkHealth, 15000);

/* ---------------- tabs ---------------- */
document.querySelectorAll(".tab").forEach((t) =>
  t.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((x) => x.classList.remove("active"));
    t.classList.add("active");
    $("tab-" + t.dataset.tab).classList.add("active");
    if (t.dataset.tab === "findings" || t.dataset.tab === "retest") loadProjects();
  })
);

function setStatus(el, msg, cls = "") {
  el.className = "status " + cls;
  el.innerHTML = msg;
}
function busy(btn, on) { btn.disabled = on; }

const SEVC = { critical: "#991b1b", high: "#dc2626", medium: "#d97706", low: "#2563eb", info: "#64748b" };
function riskColor(score) {
  if (score >= 8) return "#991b1b";
  if (score >= 6) return "#dc2626";
  if (score >= 4) return "#d97706";
  if (score >= 2) return "#2563eb";
  return "#16a34a";
}

/* ---------------- finding rendering ---------------- */
function findingCard(f, opts = {}) {
  const sev = String(f.severity || "info").toLowerCase();
  const fp = f._fingerprint || "";
  const life = opts.lifecycle || f._lifecycle;
  const lifeBadge = life ? `<span class="badge ${esc(life)}">${esc(life)}</span>` : "";
  const statusBadge = f._status && f._status !== "new"
    ? `<span class="badge ${esc(f._status)}">${esc(f._status)}</span>` : "";
  const loc = f.file ? `File: <code>${esc(f.file)}</code> line ${esc(f.line ?? "?")}`
    : f.url ? `URL: <code>${esc(f.url)}</code>` : "";
  const kb = (f.knowledge_used || []).length
    ? `<p class="kb">Knowledge consulted: ${f.knowledge_used.map((k) => `[${esc(k)}]`).join(" ")}</p>` : "";
  const actions = opts.actions === false ? "" : `
    <div class="actions">
      <button data-act="ack" data-fp="${esc(fp)}">Acknowledge</button>
      <button data-act="fix" data-fp="${esc(fp)}">Mark fixed</button>
    </div>`;
  return `
  <details class="finding" ${opts.open ? "open" : ""}>
    <summary><div class="finding-head">
      <span class="sev ${esc(sev)}">${esc(sev.toUpperCase())}</span>
      <h3>${esc(f.title || "(untitled)")}</h3>
      ${lifeBadge}${statusBadge}
    </div>
    <p class="meta">${loc} · confidence: ${esc(f.confidence ?? "?")} · source: ${esc(f.source ?? "?")}
    ${f.rule_id ? ` · rule <code>${esc(f.rule_id)}</code>` : ""}${(f.cwe_ids || []).length ? ` · ${f.cwe_ids.map(esc).join(", ")}` : ""}</p></summary>
    <pre>${esc(f.evidence || "")}</pre>
    <p class="desc">${esc(f.description || "")}</p>
    ${f.suggested_fix ? `<p><strong>Suggested fix:</strong> ${esc(f.suggested_fix)}</p>` : ""}
    ${kb}${actions}
  </details>`;
}

function wireFindingActions(container, projectId) {
  container.querySelectorAll("button[data-act]").forEach((b) =>
    b.addEventListener("click", async (e) => {
      e.stopPropagation();
      const status = b.dataset.act === "ack" ? "acknowledged" : "fixed";
      b.disabled = true;
      try {
        const r = await fetch(base() + `/projects/${projectId}/findings/status`, {
          method: "POST", headers: headers(), body: JSON.stringify({ fingerprint: b.dataset.fp, status }),
        });
        if (!r.ok) throw new Error("HTTP " + r.status);
        b.textContent = status === "acknowledged" ? "Acknowledged ✓" : "Fixed ✓";
      } catch (err) {
        b.textContent = "Failed — retry";
        b.disabled = false;
      }
    })
  );
}

/* ---------------- job polling ---------------- */
async function pollJob(jobId, statusEl, label) {
  for (;;) {
    await new Promise((r) => setTimeout(r, 1500));
    const r = await fetch(base() + "/jobs/" + jobId, { headers: headers(false) });
    if (!r.ok) throw new Error("Job poll failed: HTTP " + r.status);
    const job = await r.json();
    setStatus(statusEl, `<span class="spinner"></span>${esc(label)} — job ${esc(job.state)}…`);
    if (job.state === "done") return job;
    if (job.state === "failed" || job.state === "cancelled")
      throw new Error("Job " + job.state + (job.error_message ? ": " + job.error_message : ""));
  }
}

/* ---------------- analyze ---------------- */
$("analyzeBtn").addEventListener("click", async () => {
  const btn = $("analyzeBtn"), statusEl = $("analyzeStatus"), out = $("analyzeResult");
  const repoUrl = $("repoUrl").value.trim();
  if (!repoUrl) return setStatus(statusEl, "Enter a repository URL.", "error");
  busy(btn, true); out.innerHTML = "";
  setStatus(statusEl, `<span class="spinner"></span>Analyzing…`);
  try {
    const asyncMode = $("analyzeAsync").checked;
    const body = { repository_url: repoUrl };
    const proj = $("analyzeProject").value;
    if (proj) body.project_id = proj;
    const r = await fetch(base() + "/analyze" + (asyncMode ? "?async=true" : ""), {
      method: "POST", headers: headers(), body: JSON.stringify(body),
    });
    let data;
    if (r.status === 202) {
      const { job_id } = await r.json();
      setStatus(statusEl, `<span class="spinner"></span>Queued as job ${esc(job_id)}…`);
      const job = await pollJob(job_id, statusEl, "Analyzing");
      data = job.result;
    } else {
      if (!r.ok) throw new Error("HTTP " + r.status + ": " + (await r.text()).slice(0, 300));
      data = await r.json();
    }
    renderAnalysis(data, out);
    setStatus(statusEl, `Done — ${data.summary?.findings_total ?? data.findings?.length ?? 0} findings.`, "ok");
  } catch (err) {
    setStatus(statusEl, "Error: " + esc(err.message), "error");
  } finally { busy(btn, false); }
});

function renderAnalysis(data, out) {
  const score = data.risk?.score ?? 0;
  const findings = data.findings || [];
  const ai = data.ai?.status === "enabled"
    ? `AI: ${esc(data.ai.provider || "")} enriched ${data.ai.findings_enriched ?? 0}` : "AI: disabled (deterministic only)";
  out.innerHTML = `
    <div class="riskbar">
      <div class="risk-score" style="background:${riskColor(score)}">${esc(score)}</div>
      <div class="risk-meta"><strong>Risk ${esc(score)}/10 (${esc(data.risk?.level || "?")})</strong><br>
      ${esc(data.summary?.files_scanned ?? "?")} files scanned · ${findings.length} findings<br>${ai}</div>
    </div>
    <div class="toolbar"><span class="count">${findings.length} findings — click to expand evidence</span></div>
    ${findings.map((f) => findingCard(f, { actions: false })).join("")}
    <div class="disclaimer">Absence of findings is <strong>not</strong> proof of security.
    Findings are evidence-grounded observations, not confirmed exploits.</div>`;
}

/* ---------------- website scan ---------------- */
$("scanBtn").addEventListener("click", async () => {
  const btn = $("scanBtn"), statusEl = $("scanStatus"), out = $("scanResult");
  const target = $("targetUrl").value.trim();
  const token = $("scanToken").value;
  if (!target) return setStatus(statusEl, "Enter a target URL.", "error");
  if (!token) return setStatus(statusEl, "A scan authorization token is required.", "error");
  if (!$("scanAuthorize").checked)
    return setStatus(statusEl, "You must confirm you are authorized to scan this target.", "error");
  busy(btn, true); out.innerHTML = "";
  setStatus(statusEl, `<span class="spinner"></span>Scanning ${esc(target)}…`);
  try {
    const r = await fetch(base() + "/scan/website", {
      method: "POST", headers: headers(),
      body: JSON.stringify({
        target_url: target,
        authorization_token: token,
        i_authorize_this_scan: true,
        session_cookie: $("sessionCookie").value || null,
        active_probes: $("scanProbes").checked,
        project_id: $("scanProject").value || null,
      }),
    });
    if (!r.ok) throw new Error("HTTP " + r.status + ": " + (await r.text()).slice(0, 300));
    const data = await r.json();
    renderWebsiteScan(data, out);
    setStatus(statusEl, `Done — ${data.findings?.length ?? 0} findings.`, "ok");
  } catch (err) {
    setStatus(statusEl, "Error: " + esc(err.message), "error");
  } finally { busy(btn, false); }
});

function renderWebsiteScan(data, out) {
  const findings = data.findings || [];
  out.innerHTML = `
    <div class="riskbar"><div class="risk-meta">
      <strong>${esc(data.urls_scanned?.length ?? 0)} URLs scanned</strong> ·
      ${esc(data.checks_run ?? "?")} checks · ${esc(data.requests_made ?? "?")} requests
      ${data.truncated ? " · <strong>truncated (budget)</strong>" : ""}</div></div>
    ${findings.map((f) => findingCard(f, { actions: false })).join("")}
    <div class="disclaimer">${esc(data.disclaimer || "Absence of findings is not proof of security.")}</div>`;
}

/* ---------------- projects + findings ---------------- */
let projectsCache = [];
async function loadProjects() {
  const sels = [$("projectSelect"), $("retestProject"), $("analyzeProject"), $("scanProject")];
  for (const sel of sels) {
    const keep = sel.querySelector("option[value='']");
    sel.innerHTML = "";
    sel.appendChild(keep || Object.assign(document.createElement("option"), { value: "", textContent: "— select project —" }));
  }
  try {
    const r = await fetch(base() + "/projects", { headers: headers(false) });
    if (!r.ok) return;
    projectsCache = await r.json();
    for (const sel of sels) {
      for (const p of projectsCache)
        sel.insertAdjacentHTML("beforeend", `<option value="${esc(p.id)}">${esc(p.name)}</option>`);
    }
  } catch { /* backend may not require auth; ignore */ }
}

$("refreshProjects").addEventListener("click", () => { loadProjects(); loadFindings(); });
$("newProjectBtn").addEventListener("click", async () => {
  const name = prompt("Project name:");
  if (!name) return;
  const r = await fetch(base() + "/projects", {
    method: "POST", headers: headers(), body: JSON.stringify({ name }),
  });
  if (r.ok) { await loadProjects(); }
  else alert("Failed: HTTP " + r.status);
});
$("projectSelect").addEventListener("change", loadFindings);

async function loadFindings() {
  const pid = $("projectSelect").value;
  const out = $("findingsList"), statusEl = $("findingsStatus");
  out.innerHTML = "";
  if (!pid) return;
  setStatus(statusEl, "Loading…");
  try {
    const histR = await fetch(base() + `/projects/${pid}/scans`, { headers: headers(false) });
    if (!histR.ok) throw new Error("HTTP " + histR.status);
    const hist = await histR.json();

    // Pull the latest run of each kind and render its findings with statuses.
    const runs = [
      ...(hist.repo_analyses || []).map((a) => ({ ...a, kind: "analyses" })),
      ...(hist.website_scans || []).map((s) => ({ ...s, kind: "website-scans" })),
    ].sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
    if (!runs.length) return setStatus(statusEl, "No scans recorded for this project yet.", "");

    const latest = runs[0];
    const kind = latest.kind === "analyses" ? "analyses" : "website-scans";
    const [fR, statR2] = await Promise.all([
      fetch(base() + `/${kind}/${latest.id}/findings`, { headers: headers(false) }),
      fetch(base() + `/projects/${pid}/findings/status`, { headers: headers(false) }),
    ]);
    if (!fR.ok) throw new Error("HTTP " + fR.status);
    const items = await fR.json();
    const statusMap = {};
    if (statR2.ok) for (const s of await statR2.json()) statusMap[s.fingerprint] = s.status;
    out.innerHTML = `<div class="toolbar"><span class="count">${items.length} findings from latest ${esc(kind === "analyses" ? "analysis" : "scan")}</span></div>` +
      items.map(({ fingerprint, finding }) =>
        findingCard({ ...finding, _fingerprint: fingerprint, _status: statusMap[fingerprint] || "new" })
      ).join("");
    wireFindingActions(out, pid);
    setStatus(statusEl, `Latest run: ${esc(latest.id.slice(0, 8))}…`, "ok");
  } catch (err) {
    setStatus(statusEl, "Error: " + esc(err.message), "error");
  }
}

/* ---------------- retest ---------------- */
$("retestKind").addEventListener("change", () =>
  $("retestAuth").classList.toggle("hidden", $("retestKind").value !== "website_scan")
);
$("retestBtn").addEventListener("click", async () => {
  const btn = $("retestBtn"), statusEl = $("retestStatus"), out = $("retestResult");
  const pid = $("retestProject").value;
  const kind = $("retestKind").value;
  if (!pid) return setStatus(statusEl, "Select a project.", "error");
  const body = { kind };
  if (kind === "website_scan") {
    body.authorization_token = $("retestToken").value;
    body.i_authorize_this_scan = $("retestAuthorize").checked;
    if (!body.authorization_token || !body.i_authorize_this_scan)
      return setStatus(statusEl, "Website retest needs a fresh token + authorization.", "error");
  }
  busy(btn, true); out.innerHTML = "";
  setStatus(statusEl, `<span class="spinner"></span>Retesting… (this re-runs the full scan)`);
  try {
    const r = await fetch(base() + `/projects/${pid}/retest`, {
      method: "POST", headers: headers(), body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error("HTTP " + r.status + ": " + (await r.text()).slice(0, 300));
    const d = await r.json();
    renderRetest(d, out);
    setStatus(statusEl,
      `Done — ${d.new.length} new, ${d.persisting.length} persisting, ${d.resolved.length} resolved.` +
      (d.risk_before != null ? ` Risk ${d.risk_before} → ${d.risk_after}.` : ""), "ok");
  } catch (err) {
    setStatus(statusEl, "Error: " + esc(err.message), "error");
  } finally { busy(btn, false); }
});

function renderRetest(d, out) {
  const bucket = (name, items, cls) => items.length ? `
    <div class="bucket ${cls}"><h3>${name} (${items.length})</h3>
    ${items.map((f) => findingCard({
      title: f.title, severity: f.severity, file: f.file, url: f.url,
      line: f.line, rule_id: f.rule_id, confidence: "", source: "",
      evidence: "", description: "",
    }, { lifecycle: f.lifecycle, actions: false })).join("")}</div>` : "";
  out.innerHTML =
    bucket("New", d.new, "new") +
    bucket("Persisting", d.persisting, "persisting") +
    bucket("Resolved", d.resolved, "resolved") +
    (!d.new.length && !d.persisting.length && !d.resolved.length
      ? `<div class="card"><p class="hint">No findings in either run — clean.</p></div>` : "");
}

loadProjects();
