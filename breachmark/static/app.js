/* BreachMark front-end. No framework, no build step. All dynamic text goes through textContent. */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

  async function api(url, { method = "GET", body } = {}) {
    const opts = { method, headers: { "X-BreachMark": "1" } };
    if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
    let res;
    try { res = await fetch(url, opts); } catch (e) { throw new Error("Cannot reach the BreachMark server."); }
    let data = null;
    try { data = await res.json(); } catch (e) { /* not JSON */ }
    if (!res.ok) {
      const d = data && data.detail;
      throw new Error((typeof d === "string" ? d : d ? JSON.stringify(d) : "") || `Request failed (HTTP ${res.status}).`);
    }
    return data;
  }

  function el(tag, attrs, ...kids) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") node.className = v; else if (k === "text") node.textContent = v; else node.setAttribute(k, v);
    }
    for (const kid of kids) if (kid != null) node.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    return node;
  }
  function toast(msg, kind = "") {
    const t = el("div", { class: "toast " + kind, text: msg });
    $("#toasts").append(t);
    setTimeout(() => t.remove(), kind === "bad" ? 8000 : 3500);
  }
  const VERDICT = { 1: "YES", 0: "NO", 2: "AMBIGUOUS" };
  const fmtMs = (v) => v == null ? "n/a" : v < 1000 ? `${Math.round(v)} ms` : `${(v / 1000).toFixed(1)} s`;
  function outcomeOf(r) {
    if (r.status !== "done") return r.status === "error" ? "bad" : "amb";
    return r.verdict === 2 ? "amb" : r.correct ? "good" : "bad";
  }
  function verdictChip(r) {
    if (r.status === "error") return el("span", { class: "chip bad", text: "ERROR" });
    if (r.status === "skipped") return el("span", { class: "chip amb", text: "SKIPPED" });
    return el("span", { class: "chip " + outcomeOf(r), text: VERDICT[r.verdict] ?? "?" });
  }

  /* ---------- modal ---------- */
  const modal = $("#modal");
  async function openResult(id) {
    try {
      const r = await api(`/api/results/${id}`);
      $("#modal-title").textContent = `${r.model}, ${r.strategy}, ${r.variant === "vuln" ? "vulnerable" : "patched"} code (${r.cve || "no CVE"}, ${r.cwe || "no CWE"})`;
      const body = $("#modal-body");
      body.replaceChildren();
      const facts = el("dl", { class: "kv" });
      const add = (k, v) => { facts.append(el("dt", { text: k }), el("dd", { text: v })); };
      add("Expected answer", r.expected === 1 ? "YES (code is vulnerable)" : "NO (code is patched)");
      add("Model answer", r.verdict == null ? "none" : VERDICT[r.verdict]);
      add("Parsed from", r.parse_method || "n/a");
      add("Latency", fmtMs(r.latency_ms));
      add("Tokens", `${r.prompt_tokens ?? "n/a"} in, ${r.completion_tokens ?? "n/a"} out`);
      body.append(facts);
      if (r.error) body.append(el("div", { class: "notice bad", text: r.error }));
      body.append(el("h4", { text: "Model response" }), el("pre", { text: r.response || "(empty)" }));
      const details = el("details", {}, el("summary", { text: "Prompt that was sent" }), el("pre", { text: r.prompt }));
      body.append(el("h4", { text: "" }), details);
      modal.showModal();
    } catch (e) { toast(e.message, "bad"); }
  }
  document.addEventListener("click", (ev) => {
    const t = ev.target.closest("[data-result]");
    if (t) { ev.preventDefault(); openResult(t.dataset.result); }
    if (ev.target.closest("[data-close]")) modal.close();
    if (ev.target === modal) modal.close();
  });

  /* ---------- progress watching ---------- */
  function watch(id, status, onUpdate) {
    let current = status;
    const tick = async () => {
      try {
        const p = await api(`/api/runs/${id}`);
        onUpdate(p);
        if (p.status !== current && !["pending", "running"].includes(p.status)) { location.reload(); return; }
        current = p.status;
      } catch (e) { /* keep polling */ }
      setTimeout(tick, 1500);
    };
    setTimeout(tick, 800);
  }
  function paintProgress(root, p) {
    $$("[data-progress-bar]", root).forEach((b) => { b.style.setProperty("--w", p.percent + "%"); });
    $$("[data-progress-text]", root).forEach((t) => {
      const c = p.counts;
      t.textContent = `${p.finished} of ${p.total} (${p.percent}%)` + (c.error ? `, ${c.error} failed` : "") +
        (p.eta_seconds != null ? `, about ${p.eta_seconds < 90 ? p.eta_seconds + "s" : Math.round(p.eta_seconds / 60) + " min"} left` : "");
    });
  }

  /* ---------- run detail ---------- */
  function initRun() {
    const root = $("#run-root");
    if (!root) return;
    const id = root.dataset.runId;
    $$("[data-run-action]").forEach((btn) => btn.addEventListener("click", async () => {
      if (btn.dataset.confirm && !confirm(btn.dataset.confirm)) return;
      const action = btn.dataset.runAction;
      btn.disabled = true;
      try {
        if (action === "delete") { await api(`/api/runs/${id}`, { method: "DELETE" }); location.href = "/runs"; return; }
        await api(`/api/runs/${id}/${action}`, { method: "POST" });
        setTimeout(() => location.reload(), 700);
      } catch (e) { toast(e.message, "bad"); btn.disabled = false; }
    }));
    if (["pending", "running"].includes(root.dataset.status)) watch(id, root.dataset.status, (p) => paintProgress(root, p));
    initResultsBrowser(id);
  }
  function initResultsBrowser(id) {
    const box = $("#results-browser");
    if (!box) return;
    const state = { page: 1 };
    const body = $("#results-body", box), info = $("#results-info", box);
    async function load() {
      const q = new URLSearchParams({ page_no: state.page, per_page: 20 });
      for (const k of ["strategy", "variant", "outcome"]) { const v = $("#rf-" + k).value; if (v) q.set(k, v); }
      try {
        const d = await api(`/api/runs/${id}/results?${q}`);
        body.replaceChildren();
        if (!d.rows.length) body.append(el("tr", {}, el("td", { colspan: 8, class: "muted", text: "No results match these filters." })));
        for (const r of d.rows) {
          const tr = el("tr", { class: "edge-" + outcomeOf(r) },
            el("td", { class: "nowrap" }, el("a", { href: `/samples/${r.sample_id}`, text: r.cve || `#${r.sample_id}` })),
            el("td", { class: "mono", text: r.cwe || "" }), el("td", { text: r.project || "" }),
            el("td", { text: r.strategy }), el("td", { text: r.variant === "vuln" ? "vulnerable" : "patched" }),
            el("td", {}, verdictChip(r), r.truncated ? el("span", { class: "sub", text: " truncated" }) : null),
            el("td", { class: "num", text: fmtMs(r.latency_ms) }),
            el("td", {}, el("button", { class: "btn ghost sm", "data-result": r.id, text: "Details" })));
          body.append(tr);
        }
        info.textContent = `${d.total} result${d.total === 1 ? "" : "s"}, page ${d.page} of ${d.pages}`;
        $("#rp-prev").disabled = d.page <= 1; $("#rp-next").disabled = d.page >= d.pages;
      } catch (e) { toast(e.message, "bad"); }
    }
    $$("select", box).forEach((s) => s.addEventListener("change", () => { state.page = 1; load(); }));
    $("#rp-prev").addEventListener("click", () => { state.page = Math.max(1, state.page - 1); load(); });
    $("#rp-next").addEventListener("click", () => { state.page += 1; load(); });
    load();
  }

  /* ---------- runs list ---------- */
  function initRunsList() {
    $$("[data-live-run]").forEach((row) => watch(row.dataset.liveRun, row.dataset.status, (p) => paintProgress(row, p)));
  }

  /* ---------- demo ---------- */
  function initDemo() {
    $$("[data-demo]").forEach((btn) => btn.addEventListener("click", async () => {
      btn.disabled = true;
      try { await api("/api/demo", { method: "POST" }); location.href = "/runs"; }
      catch (e) { toast(e.message, "bad"); btn.disabled = false; }
    }));
  }

  /* ---------- new run ---------- */
  function initRunNew() {
    const form = $("#run-form");
    if (!form) return;
    const providers = JSON.parse($("#providers-json").textContent);
    const val = (id) => { const n = $("#" + id); return n ? n.value.trim() : ""; };
    const checked = (name) => $$(`input[name="${name}"]:checked`, form).map((c) => c.value);
    const num = (v) => (v === "" ? null : Number(v));

    function spec() {
      const limit = num(val("limit"));
      return {
        name: val("name"), provider: val("provider"), model: val("model"),
        strategies: checked("strategy"), variants: checked("variant"),
        filters: { cwe: val("f-cwe"), project: val("f-project"), granularity: val("f-granularity"),
                   year_min: val("f-year-min"), year_max: val("f-year-max"), max_noise: val("f-max-noise") },
        limit, shuffle_seed: $("#shuffle").checked ? (num(val("seed")) ?? 1) : null,
        options: { temperature: val("o-temperature"), max_tokens: val("o-max-tokens"), num_ctx: val("o-num-ctx"),
                   max_input_chars: val("o-max-input"), input_policy: val("o-policy"), concurrency: val("o-concurrency"),
                   max_retries: val("o-retries"), timeout: val("o-timeout"), judge: $("#o-judge").checked, blind: $("#o-blind").checked,
                   judge_model: val("o-judge-model"), base_url: val("base_url"),
                   price_in: val("o-price-in"), price_out: val("o-price-out") },
      };
    }

    let timer;
    const estimate = () => {
      clearTimeout(timer);
      timer = setTimeout(async () => {
        const out = $("#estimate");
        const s = spec();
        if (!s.model || !s.strategies.length || !s.variants.length) { out.textContent = "Choose a model and at least one strategy to see the size of this run."; return; }
        try {
          const e = await api("/api/estimate", { method: "POST", body: s });
          out.textContent = `${e.samples} samples, ${e.requests.toLocaleString()} model calls, about ${(e.approx_input_tokens / 1e6).toFixed(2)}M input tokens.`;
        } catch (err) { out.textContent = err.message; }
      }, 300);
    };

    const providerSel = $("#provider");
    async function onProvider() {
      const p = providers.find((x) => x.name === providerSel.value);
      $("#base_url").placeholder = p.default_base_url || "(not used)";
      $("#base_url").disabled = p.name === "mock";
      $("#o-concurrency").placeholder = `${p.default_concurrency} (default)`;
      $("#ctx-field").hidden = p.name !== "ollama";
      $("#key-warning").hidden = !(p.needs_key && p.key_source === "missing");
      $("#mock-note").hidden = p.name !== "mock";
      await fetchModels(true);
    }
    async function fetchModels(quiet) {
      const out = $("#model-status");
      out.textContent = "Looking for models...";
      try {
        const r = await api(`/api/providers/${providerSel.value}/ping`, { method: "POST", body: { base_url: val("base_url") } });
        const list = $("#models"); list.replaceChildren();
        r.models.forEach((m) => list.append(el("option", { value: m })));
        out.textContent = r.ok ? `${r.models.length} model(s) found. Pick one or type a name.` : r.message;
        out.className = "hint" + (r.ok ? "" : " err");
        if (r.ok && !val("model") && r.models.length) $("#model").value = r.models[0];
      } catch (e) { out.textContent = e.message; out.className = "hint err"; }
      estimate();
    }
    providerSel.addEventListener("change", onProvider);
    $("#btn-models").addEventListener("click", () => fetchModels(false));
    form.addEventListener("input", estimate); form.addEventListener("change", estimate);

    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const btn = $("#btn-start"); btn.disabled = true;
      try {
        const r = await api("/api/runs", { method: "POST", body: spec() });
        location.href = `/runs/${r.id}`;
      } catch (e) { toast(e.message, "bad"); btn.disabled = false; }
    });
    onProvider();
  }

  /* ---------- settings ---------- */
  function initSettings() {
    $$("[data-ping]").forEach((btn) => btn.addEventListener("click", async () => {
      const name = btn.dataset.ping, out = $(`[data-ping-out="${name}"]`);
      out.textContent = "Testing..."; out.className = "small";
      try {
        const r = await api(`/api/providers/${name}/ping`, { method: "POST", body: { base_url: ($(`[data-base="${name}"]`) || {}).value || "" } });
        out.textContent = r.message; out.className = "small " + (r.ok ? "" : "err");
      } catch (e) { out.textContent = e.message; out.className = "small err"; }
    }));
    $$("[data-save-key]").forEach((btn) => btn.addEventListener("click", async () => {
      const name = btn.dataset.saveKey, input = $(`[data-key="${name}"]`);
      try {
        const r = await api(`/api/providers/${name}/key`, { method: "POST", body: { key: input.value } });
        input.value = "";
        toast(r.key_source === "missing" ? "Key cleared." : "Key saved for this session only.", "good");
        setTimeout(() => location.reload(), 600);
      } catch (e) { toast(e.message, "bad"); }
    }));
    const imp = $("#btn-import");
    if (imp) imp.addEventListener("click", async () => {
      imp.disabled = true;
      try { const r = await api("/api/dataset/import", { method: "POST" }); toast(`Dataset refreshed: ${r.total} samples.`, "good"); setTimeout(() => location.reload(), 700); }
      catch (e) { toast(e.message, "bad"); imp.disabled = false; }
    });
  }

  /* ---------- playground ---------- */
  function initPlayground() {
    const form = $("#pg-form");
    if (!form) return;
    const providers = JSON.parse($("#providers-json").textContent);
    const val = (id) => $("#" + id).value.trim();
    const providerSel = $("#provider");
    async function models() {
      const p = providers.find((x) => x.name === providerSel.value);
      $("#base_url").placeholder = p.default_base_url || "(not used)"; $("#base_url").disabled = p.name === "mock";
      $("#key-warning").hidden = !(p.needs_key && p.key_source === "missing");
      try {
        const r = await api(`/api/providers/${p.name}/ping`, { method: "POST", body: { base_url: val("base_url") } });
        const list = $("#models"); list.replaceChildren(); r.models.forEach((m) => list.append(el("option", { value: m })));
        $("#model-status").textContent = r.ok ? `${r.models.length} model(s) found.` : r.message;
        $("#model-status").className = "hint" + (r.ok ? "" : " err");
        if (r.ok && !val("model") && r.models.length) $("#model").value = r.models[0];
      } catch (e) { $("#model-status").textContent = e.message; }
    }
    providerSel.addEventListener("change", models); models();

    $("#btn-commit").addEventListener("click", async () => {
      const btn = $("#btn-commit"); btn.disabled = true;
      try { const r = await api("/api/playground/commit", { method: "POST", body: { url: val("commit-url") } }); $("#code").value = r.diff; toast("Diff loaded.", "good"); }
      catch (e) { toast(e.message, "bad"); } finally { btn.disabled = false; }
    });

    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const out = $("#pg-results"), btn = $("#btn-run");
      const strategies = $$('input[name="strategy"]:checked', form).map((c) => c.value);
      btn.disabled = true; out.replaceChildren(el("p", { class: "muted" }, el("span", { class: "spin" }), " Asking the model..."));
      try {
        const r = await api("/api/playground", { method: "POST", body: {
          provider: val("provider"), model: val("model"), strategies, code: $("#code").value, cwe: val("cwe"),
          options: { base_url: val("base_url"), temperature: val("temperature"), max_tokens: val("max_tokens"), num_ctx: val("num_ctx") } } });
        out.replaceChildren();
        const s = r.summary;
        out.append(el("div", { class: "notice" + (s.yes && !s.no ? " bad" : s.no && !s.yes ? " good" : "") },
          el("b", { text: `Looking for ${r.cwe}: ` }),
          `${s.yes} strategy(ies) said YES, ${s.no} said NO` + (s.ambiguous ? `, ${s.ambiguous} unclear` : "") + (s.errors ? `, ${s.errors} failed` : "") + ".",
          r.truncated ? el("div", { class: "hint", text: "The input was longer than the size limit and was shortened in the middle before it was sent." }) : null));
        for (const x of r.results) {
          const head = el("div", { class: "row" }, el("h3", { text: x.strategy }),
            x.error ? el("span", { class: "chip bad", text: "ERROR" }) : el("span", { class: "chip " + (x.verdict === 2 ? "amb" : ""), text: x.verdict_text }),
            x.error ? null : el("span", { class: "muted small", text: `${fmtMs(x.latency_ms)}, parsed from ${x.method}` }));
          const block = el("section", { class: "section", style: "margin-top:20px" }, head);
          if (x.error) block.append(el("div", { class: "notice bad", text: x.error }));
          else block.append(el("details", { open: "" }, el("summary", { text: "Model response" }), el("pre", { class: "code", style: "padding:12px;white-space:pre-wrap", text: x.response || "(empty)" })));
          out.append(block);
        }
      } catch (e) { out.replaceChildren(el("div", { class: "notice bad", text: e.message })); }
      finally { btn.disabled = false; }
    });
  }

  /* ---------- prompts ---------- */
  function initPrompts() {
    const form = $("#prompt-form");
    if (!form) return;
    $$("[data-edit]").forEach((btn) => btn.addEventListener("click", () => {
      $("#p-key").value = btn.dataset.edit; $("#p-name").value = btn.dataset.name;
      $("#p-template").value = btn.dataset.template; $("#p-desc").value = btn.dataset.desc || "";
      $("#p-key").readOnly = true; form.scrollIntoView({ behavior: "smooth" });
      $("#p-title").textContent = `New version of "${btn.dataset.name}"`;
    }));
    $("#p-reset").addEventListener("click", () => { form.reset(); $("#p-key").readOnly = false; $("#p-title").textContent = "New prompt"; $("#p-preview").hidden = true; });
    $("#p-preview-btn").addEventListener("click", async () => {
      try {
        const r = await api("/api/prompts/preview", { method: "POST", body: { template: $("#p-template").value } });
        const box = $("#p-preview"); box.hidden = false;
        $("#p-preview-text").textContent = r.rendered;
        $("#p-warnings").replaceChildren(...r.warnings.map((w) => el("div", { class: "notice warn", text: w })));
      } catch (e) { toast(e.message, "bad"); }
    });
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      try {
        const r = await api("/api/prompts", { method: "POST", body: { key: $("#p-key").value || $("#p-name").value, name: $("#p-name").value, description: $("#p-desc").value, template: $("#p-template").value } });
        toast("Prompt saved as a new version.", "good"); setTimeout(() => location.reload(), 600);
      } catch (e) { toast(e.message, "bad"); }
    });
  }

  /* ---------- compare ---------- */
  function initCompare() {
    const form = $("#compare-form");
    if (!form) return;
    const go = () => {
      const ids = $$('input[name="runs"]:checked', form).map((c) => c.value);
      location.href = ids.length ? `/compare?runs=${ids.join(",")}` : "/compare";
    };
    $("#btn-compare").addEventListener("click", go);
    $$("[data-focus-select]").forEach((s) => s.addEventListener("change", () => { location.href = s.value; }));
  }

  document.addEventListener("DOMContentLoaded", () => {
    initDemo(); initRun(); initRunsList(); initRunNew(); initSettings(); initPlayground(); initPrompts(); initCompare();
  });
})();
