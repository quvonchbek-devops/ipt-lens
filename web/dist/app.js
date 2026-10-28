(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const el = (tag, cls = "", text = "") => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text) n.textContent = text;
    return n;
  };

  const TOKEN_KEY = "iptlens_token";
  const PENDING_MSG = "Change applied. Confirm it in the yellow bar, or it is rolled back automatically.";

  const svg = (d) => `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`;
  const ICON = {
    pencil: svg('<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>'),
    trash: svg('<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/>'),
    lock: svg('<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>'),
    chain: svg('<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/>'),
    x: svg('<path d="M18 6 6 18M6 6l12 12"/>'),
  };

  // Descriptions (display only)
  const CHAIN_INFO = {
    INPUT: "Traffic to the server itself (SSH, this panel, local services).",
    OUTPUT: "Traffic leaving the server.",
    FORWARD: "Traffic passing through the server (containers, VPN).",
    "DOCKER-USER": "Traffic forwarded to Docker containers. These rules run before Docker's own rules.",
    PREROUTING: "When a packet arrives, before address translation.",
    POSTROUTING: "When a packet leaves, after address translation.",
  };
  const TABLE_INFO = {
    filter: "Allow and block rules (the main firewall).",
    nat: "Address translation rules (NAT, port forwarding).",
    mangle: "Packet marking rules.",
    raw: "Rules that run before connection tracking.",
  };
  const WHERE_HINT = {
    INPUT: "Affects traffic to the server itself, such as SSH or this panel.",
    "DOCKER-USER": "Affects traffic to Docker containers. Does not affect the server itself.",
  };
  const ACT_LABEL = { ACCEPT: "Allow", DROP: "Block", REJECT: "Reject", RETURN: "Return" };
  const VERDICT = { ACCEPT: "Allowed", DROP: "Dropped", REJECT: "Rejected" };

  // System chains hidden by default: managed (protected) chains plus Tailscale and UFW helpers
  const isSystemChain = (ch) => ch.protected || /^(ts-|UFW-)/.test(ch.name || "");

  let state = null;
  let activeTable = "filter";
  let lastSig = "";
  let remaining = 0;
  let bannerOn = false;
  let tokenPromise = null;
  let modalCancel = null;
  let lastFocus = null;
  let showSystem = false;
  let focusChain = null; // { table, chain, scrolled }

  const kb = (bytes) => (bytes / 1024).toFixed(1) + " KB";
  const ruleSpec = (raw) => String(raw || "").replace(/^\[\d+:\d+\]\s*/, "").replace(/^-A\s+\S+\s*/, "");

  /* ---------- connection status ---------- */
  function setConn(ok) {
    $("conn").className = "pill " + (ok ? "pill-ok" : "pill-err");
    $("conn-text").textContent = ok ? "Live" : "Disconnected";
  }

  /* ---------- toasts ---------- */
  function toast(msg, kind = "info") {
    const t = el("div", "toast " + kind);
    t.append(el("div", "toast-msg", msg));
    const x = el("button", "icon-ghost");
    x.innerHTML = ICON.x;
    x.setAttribute("aria-label", "Dismiss");
    x.addEventListener("click", () => t.remove());
    t.append(x);
    $("toasts").append(t);
    setTimeout(() => t.remove(), 6000);
  }

  /* ---------- modal ---------- */
  function openModal({ title, sub = "", body = [], actions = [], onCancel = null }) {
    lastFocus = document.activeElement;
    modalCancel = onCancel;
    const box = $("modal-box");
    box.innerHTML = "";
    const head = el("div", "modal-h");
    head.append(el("h3", "", title));
    if (sub) head.append(el("p", "modal-sub mono", sub));
    const bodyEl = el("div", "modal-b");
    bodyEl.append(...body);
    const foot = el("div", "modal-f");
    actions.forEach((a) => {
      const b = el("button", "btn " + (a.cls || "btn-ghost"), a.label);
      b.type = "button";
      b.addEventListener("click", a.onClick);
      foot.append(b);
    });
    box.append(head, bodyEl, foot);
    $("modal").hidden = false;
    const first = box.querySelector("input,textarea,button");
    if (first) first.focus();
  }

  function closeModal() {
    modalCancel = null;
    $("modal").hidden = true;
    $("modal-box").innerHTML = "";
    if (lastFocus && lastFocus.focus) lastFocus.focus();
    lastFocus = null;
  }

  function dismissModal() {
    const cancel = modalCancel;
    closeModal();
    if (cancel) cancel();
  }

  function confirmModal({ title, text, okLabel, danger = false, extra = [], onOk }) {
    openModal({
      title,
      body: [el("p", "modal-text", text), ...extra],
      actions: [
        { label: "Cancel", cls: "btn-ghost", onClick: dismissModal },
        { label: okLabel, cls: danger ? "btn-danger" : "btn-primary", onClick: () => { closeModal(); onOk(); } },
      ],
    });
  }

  $("modal-backdrop").addEventListener("click", dismissModal);

  document.addEventListener("keydown", (e) => {
    if ($("modal").hidden) return;
    if (e.key === "Escape") { e.preventDefault(); dismissModal(); return; }
    if (e.key !== "Tab") return;
    const items = [...$("modal-box").querySelectorAll("button,input,textarea,select")].filter((n) => !n.disabled);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  });

  /* ---------- token (401) ---------- */
  function askToken() {
    if (tokenPromise) return tokenPromise;
    tokenPromise = new Promise((resolve) => {
      const inp = el("input", "mono");
      inp.type = "password";
      inp.autocomplete = "off";
      inp.placeholder = "API token";
      const done = (val) => { tokenPromise = null; resolve(val); };
      openModal({
        title: "API token",
        sub: "Enter the server token. It is kept only for this browser session.",
        body: [inp],
        onCancel: () => done(null),
        actions: [
          { label: "Cancel", cls: "btn-ghost", onClick: dismissModal },
          { label: "Use token", cls: "btn-primary", onClick: () => {
            const t = inp.value.trim();
            if (!t) return;
            sessionStorage.setItem(TOKEN_KEY, t);
            closeModal();
            done(t);
          } },
        ],
      });
    });
    return tokenPromise;
  }

  /* ---------- API ---------- */
  async function api(path, opts = {}, retried = false) {
    const headers = { "Content-Type": "application/json" };
    const token = sessionStorage.getItem(TOKEN_KEY);
    if (token) headers.Authorization = "Bearer " + token;

    let res;
    try {
      res = await fetch(path, { method: opts.method || "GET", headers, body: opts.body });
    } catch {
      throw new Error("Cannot reach the server");
    }

    if (res.status === 401 && !retried) {
      const t = await askToken();
      if (!t) throw new Error("No token entered");
      return api(path, opts, true);
    }

    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = text; }

    if (!res.ok) {
      const msg = data && typeof data === "object" && data.error ? data.error
        : (typeof data === "string" && data.trim()) || res.statusText;
      throw new Error(msg);
    }
    return data;
  }

  /* ---------- polling ---------- */
  async function refresh() {
    if (tokenPromise) return;
    try {
      const d = await api("/api/v1/state");
      setConn(true);
      state = d.state;
      $("mock-strip").hidden = !state.is_mock;
      $("ver").textContent = d.version || "";
      bannerOn = !!d.watchdog_pending;
      remaining = d.watchdog_rem_sec || 0;
      $("banner").hidden = !bannerOn;
      $("wd-timer").textContent = remaining;
      const sig = JSON.stringify([state.tables, state.enrich_map]);
      if (sig !== lastSig) {
        lastSig = sig;
        render();
      }
    } catch {
      setConn(false);
    }
  }

  /* ---------- render helpers ---------- */
  function badge(v) {
    if (!v || !state || !state.enrich_map) return "";
    const raw = String(v).replace(/^!/, "");
    const m = state.enrich_map[raw] || state.enrich_map[raw.replace(/\/32$/, "")];
    if (!m) return "";
    const t = ["docker", "vpn", "iface"].includes(m.type) ? m.type : "iface";
    return ` <span class="badge badge-${t}">${esc(m.type)}: ${esc(m.name)}</span>`;
  }

  const ANY = `<span class="tert">any</span>`;
  const ifaceText = (v) => (v ? `${esc(v)}${badge(v)}` : ANY);
  const addrText = (v) => (!v || v === "0.0.0.0/0" ? ANY : `${esc(v)}${badge(v)}`);

  function actionPill(t, to) {
    const label = ACT_LABEL[t] || t;
    const cls = t === "ACCEPT" ? "tg-ok" : (t === "DROP" || t === "REJECT") ? "tg-bad" : "tg-warn";
    return `<span class="tg ${cls}" title="iptables: -j ${esc(t)}">${esc(label)}</span>${to ? `<div class="sub mono">${esc(to)}</div>` : ""}`;
  }

  function ruleRow(r, chain) {
    const locked = r.protected;
    const dis = locked ? "disabled" : "";
    const tip = locked ? "Managed by Docker, Kubernetes, libvirt or ufw. It cannot be changed here." : "";
    const attrs = `data-chain="${esc(chain)}" data-num="${r.id}" data-raw="${esc(r.raw_rule)}" data-spec="${esc(ruleSpec(r.raw_rule))}"`;
    const extra = [r.ct_state && "state: " + r.ct_state, r.dst_type && "dst type: " + r.dst_type, r.extra]
      .filter(Boolean).join(" · ");
    return `
      <tr class="${r.packets > 0 ? "" : "zero"}">
        <td class="mono">${r.id}</td>
        <td><div class="mono">${r.packets} pkts</div><div class="sub mono">${kb(r.bytes)}</div></td>
        <td class="mono">${ifaceText(r.in_iface)}<span class="arrow">→</span>${ifaceText(r.out_iface)}</td>
        <td class="mono">${r.proto && r.proto !== "all" ? esc(r.proto) : ANY}</td>
        <td class="mono">${addrText(r.source)}</td>
        <td class="mono">${addrText(r.destination)}</td>
        <td class="mono">${r.dst_port ? esc(r.dst_port) : ANY}</td>
        <td>${actionPill(r.target, r.to_dest)}</td>
        <td class="cmt">${esc(r.comment || "")}${extra ? `<div class="sub">${esc(extra)}</div>` : ""}</td>
        <td class="acts">
          ${locked ? `<span class="lock" title="${esc(tip)}" aria-label="${esc(tip)}">${ICON.lock}</span>` : ""}
          <button class="icon-ghost" data-act="edit" ${dis} ${attrs} aria-label="Edit rule #${r.id}" title="${locked ? esc(tip) : "Edit rule"}">${ICON.pencil}</button>
          <button class="icon-ghost icon-danger" data-act="del" ${dis} ${attrs} aria-label="Delete rule #${r.id}" title="${locked ? esc(tip) : "Delete rule"}">${ICON.trash}</button>
        </td>
      </tr>`;
  }

  function chainCard(ch, highlight) {
    const info = CHAIN_INFO[ch.name] || (ch.is_custom ? "User-defined chain, reached by a jump from another chain." : "");
    const tag = ch.is_custom
      ? `<span class="tag tag-custom">User-defined</span>`
      : ch.policy === "DROP"
        ? `<span class="tag tag-bad">Policy: drop</span>`
        : `<span class="tag tag-ok">Policy: accept</span>`;
    const rules = ch.rules || [];
    const rows = rules.length
      ? rules.map((r) => ruleRow(r, ch.name)).join("")
      : `<tr><td colspan="10" class="empty-cell">No rules in this chain. The chain policy applies.</td></tr>`;
    return `
      <section class="card${highlight ? " hl" : ""}" data-chain="${esc(ch.name)}">
        <header class="card-h">
          <div class="card-t">
            <span class="chain-name">${ICON.chain}${esc(ch.name)}</span>
            ${tag}
          </div>
          <span class="sp tert mono">${ch.packets} pkts</span>
        </header>
        ${info ? `<p class="card-sub">${esc(info)}</p>` : ""}
        <div class="scroll">
          <table>
            <thead><tr>
              <th>#</th><th>Traffic</th><th>Interfaces</th><th>Protocol</th><th>Source</th>
              <th>Destination</th><th>Port</th><th>Action</th><th>Comment</th><th><span class="sr-only">Actions</span></th>
            </tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </section>`;
  }

  function render() {
    const box = $("chains");
    $("table-desc").textContent = TABLE_INFO[activeTable] || "";
    const tbl = state && state.tables[activeTable];
    if (!tbl) {
      box.innerHTML = `<p class="empty">This table is not loaded on the server.</p>`;
      $("sys-count").textContent = "";
      return;
    }
    const names = tbl.chain_order && tbl.chain_order.length ? tbl.chain_order : Object.keys(tbl.chains || {});
    let hidden = 0;
    const cards = [];
    names.forEach((n) => {
      const ch = tbl.chains[n];
      if (!ch) return;
      if (!showSystem && isSystemChain(ch)) { hidden++; return; }
      const hl = !!focusChain && focusChain.table === activeTable && focusChain.chain === n;
      cards.push(chainCard(ch, hl));
    });
    $("sys-count").textContent = hidden && !showSystem ? `${hidden} system chain${hidden === 1 ? "" : "s"} hidden` : "";
    box.innerHTML = cards.length ? cards.join("") : `<p class="empty">No chains to show. Turn on "Show system chains" to see managed chains.</p>`;

    if (focusChain && !focusChain.scrolled) {
      const c = box.querySelector(".card.hl");
      if (c) {
        focusChain.scrolled = true;
        c.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }
  }

  function setTable(t) {
    activeTable = t;
    document.querySelectorAll(".seg-btn").forEach((b) => b.classList.toggle("active", b.dataset.table === t));
    lastSig = "";
    render();
  }

  /* ---------- simulator ---------- */
  function explain(s) {
    const a = s.action || "";
    let text = s.note || "";
    if (a === "ENTER_CHAIN") text = "The packet entered this chain.";
    else if (a === "RETURN") text = "End of chain; the packet returns to the calling chain.";
    else if (a.startsWith("DEFAULT_POLICY")) text = "No rule matched, so the chain policy applies.";
    else if (a.startsWith("MATCH -> JUMP")) text = "The rule sent the packet to another chain.";
    else if (a === "MATCH -> ACCEPT") text = "Rule matched: the packet is accepted.";
    else if (a === "MATCH -> DROP") text = "Rule matched: the packet is dropped.";
    else if (a === "MATCH -> REJECT") text = "Rule matched: the packet is rejected.";
    else if (a === "MATCH -> RETURN") text = "Rule matched: the packet returns to the calling chain.";
    else if (/DNAT|REDIRECT/.test(a)) text = "Rule matched: the destination is rewritten.";
    else if (/SNAT|MASQUERADE/.test(a)) text = "Rule matched: the source address is rewritten.";
    if (a !== "ENTER_CHAIN" && s.note && text !== s.note) text += " " + s.note;
    return text;
  }

  function shortAct(a) {
    if (a === "ENTER_CHAIN") return "enter";
    if (a === "RETURN" || a === "MATCH -> RETURN") return "return";
    if (a.startsWith("DEFAULT_POLICY")) return "policy";
    if (a.startsWith("MATCH -> JUMP")) return "jump";
    if (a === "MATCH -> ACCEPT") return "accept";
    if (a === "MATCH -> DROP") return "drop";
    if (a === "MATCH -> REJECT") return "reject";
    return a.replace(/^MATCH -> /, "");
  }

  function showSim(r) {
    const ok = r.final_verdict === "ACCEPT";
    let h = `<div class="verdict ${ok ? "v-ok" : "v-bad"}"><div>
      <b>${esc(VERDICT[r.final_verdict] || r.final_verdict)}</b>
      <div class="sub mono">${esc(r.final_verdict)}${r.final_dst ? " → " + esc(r.final_dst) : ""}</div>
    </div></div>`;
    if (r.uncertain) {
      h += `<div class="warn-note"><b>Approximate result.</b> Some rules use matches the simulator cannot evaluate and were assumed to match:<ul>${
        (r.warnings || []).map((w) => `<li>${esc(w)}</li>`).join("")}</ul></div>`;
    }
    h += `<ol class="timeline">`;
    (r.steps || []).forEach((s, i) => {
      if (s.action === "INFO") {
        h += `<li class="step info"><div class="note">${esc(s.note)}</div></li>`;
        return;
      }
      const hit = /^(MATCH|DEFAULT)/.test(s.action || "");
      h += `
        <li class="step ${hit ? "hit" : ""}">
          <div class="step-h">
            <span>${i + 1}. ${esc(s.table ? "[" + s.table + "] " : "")}${esc(s.chain)}${s.rule_id ? " #" + s.rule_id : ""}</span>
            <span class="act" title="${esc(s.action)}">${esc(shortAct(s.action))}</span>
          </div>
          ${s.raw_rule ? `<div class="raw">${esc(s.raw_rule)}</div>` : ""}
          <div class="note">${esc(explain(s))}</div>
        </li>`;
    });
    h += `</ol>`;
    const box = $("sim-result");
    box.innerHTML = h;
    box.hidden = false;
  }

  async function simulate() {
    const body = {
      src_ip: $("sim-src").value.trim(),
      dst_ip: $("sim-dst").value.trim(),
      in_iface: $("sim-in").value.trim(),
      out_iface: $("sim-out").value.trim(),
      proto: $("sim-proto").value,
      dst_port: $("sim-port").value.trim(),
      ct_state: $("sim-ct").value,
    };
    try {
      showSim(await api("/api/v1/simulate", { method: "POST", body: JSON.stringify(body) }));
    } catch (e) {
      toast(e.message, "error");
    }
  }

  /* ---------- add rule ---------- */
  function ruleFromForm() {
    const parts = [];
    const src = $("add-src").value.trim();
    const iface = $("add-iface").value.trim();
    const proto = $("add-proto").value;
    const port = $("add-port").value.trim();
    if (src) parts.push("-s", src);
    if (iface) parts.push("-i", iface);
    if (proto) parts.push("-p", proto);
    if (port) parts.push("--dport", port);
    parts.push("-j", $("add-action").value);
    return parts.join(" ");
  }

  function updatePreview() {
    const where = $("add-where").value;
    $("add-where-hint").textContent = WHERE_HINT[where] || "";
    const rule = ruleFromForm();
    const allow = $("add-action").value === "ACCEPT";
    const who = $("add-src").value.trim() || "any source";
    const ifc = $("add-iface").value.trim();
    const proto = $("add-proto").value;
    const port = $("add-port").value.trim();
    const what = port
      ? `${proto.toUpperCase()} port ${port}`
      : proto ? `all ${proto.toUpperCase()}` : "all traffic";
    const pv = $("add-preview");
    pv.innerHTML =
      `<div>From <b>${esc(who)}</b>${ifc ? ` on ${esc(ifc)}` : ""}, ${esc(what)} → ` +
      `<b class="${allow ? "ok" : "bad"}">${allow ? "allowed" : "blocked"}</b></div>` +
      `<div class="sub">Command: <code>-I ${esc(where)} 1 ${esc(rule)}</code></div>` +
      (!allow && where === "INPUT" ? `<div class="warn-note">Careful: this can cut off your own access to the server (SSH, this panel).</div>` : "");
  }

  function addRule() {
    const where = $("add-where").value;
    const action = $("add-action").value;
    const proto = $("add-proto").value;
    const port = $("add-port").value.trim();
    const iface = $("add-iface").value.trim();
    const src = $("add-src").value.trim();

    if (port && (!/^\d+$/.test(port) || +port < 1 || +port > 65535)) {
      toast("Port must be a number from 1 to 65535.", "error");
      return;
    }
    if (port && !proto) {
      toast("Choose TCP or UDP to filter by port.", "error");
      return;
    }
    if (action === "ACCEPT" && !port && !iface && !src) {
      toast("Set a port, interface or source. Without one, this rule would allow all traffic.", "error");
      return;
    }

    const rule = ruleFromForm();
    const go = () => doAction("/api/v1/apply", { table: "filter", chain: where, position: 1, rule }, PENDING_MSG, () => {
      focusChain = { table: "filter", chain: where, scrolled: false };
      setTable("filter");
      setTimeout(() => { focusChain = null; lastSig = ""; render(); }, 8000);
    });

    if (action === "DROP" && where === "INPUT") {
      confirmModal({
        title: "Add a block rule to INPUT?",
        text: "This rule can cut off your own access to the server (SSH, this panel). If it does, it is rolled back when the confirmation time runs out.",
        okLabel: "Add block rule",
        danger: true,
        onOk: go,
      });
      return;
    }
    go();
  }

  /* ---------- actions ---------- */
  async function doAction(path, body, okMsg = PENDING_MSG, onOk = null) {
    try {
      await api(path, { method: "POST", body: JSON.stringify(body) });
      if (onOk) onOk();
      toast(okMsg, "info");
    } catch (e) {
      toast(e.message, "error");
    }
    lastSig = "";
    refresh();
  }

  function reqBody(d) {
    return { table: activeTable, chain: d.chain, rule_id: parseInt(d.num, 10), expect: d.raw };
  }

  function openEdit(d) {
    const ta = el("textarea", "mono");
    ta.rows = 3;
    ta.spellcheck = false;
    ta.value = d.spec;
    openModal({
      title: "Edit rule",
      sub: `${d.chain} · rule #${d.num}`,
      body: [
        el("div", "field-label", "Current rule"),
        el("pre", "code-block mono", d.spec),
        el("div", "field-label", "New rule (iptables options)"),
        ta,
        el("p", "hint", "The edit is applied temporarily. If you do not confirm it in time, the old rule is restored."),
      ],
      actions: [
        { label: "Cancel", cls: "btn-ghost", onClick: dismissModal },
        { label: "Apply edit", cls: "btn-primary", onClick: () => {
          const nv = ta.value.trim();
          if (!nv) { toast("The rule cannot be empty.", "error"); return; }
          closeModal();
          doAction("/api/v1/rules/edit", { ...reqBody(d), rule: nv });
        } },
      ],
    });
  }

  function openDelete(d) {
    confirmModal({
      title: "Delete rule?",
      text: `Delete rule #${d.num} from ${d.chain}?`,
      okLabel: "Delete rule",
      danger: true,
      extra: [
        el("pre", "code-block mono", d.spec),
        el("p", "hint", "If you do not confirm the deletion in time, the rule is restored."),
      ],
      onOk: () => doAction("/api/v1/rules/delete", reqBody(d)),
    });
  }

  /* ---------- events ---------- */
  $("chains").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-act]");
    if (!b || b.disabled) return;
    const d = b.dataset;
    if (d.act === "edit") openEdit(d);
    else openDelete(d);
  });

  document.querySelectorAll(".seg-btn").forEach((btn) => {
    btn.addEventListener("click", () => setTable(btn.dataset.table));
  });

  $("show-sys").addEventListener("change", (e) => {
    showSystem = e.target.checked;
    lastSig = "";
    render();
  });

  ["add-where", "add-action", "add-proto", "add-port", "add-iface", "add-src"].forEach((id) => {
    $(id).addEventListener("input", updatePreview);
    $(id).addEventListener("change", updatePreview);
  });

  $("btn-sim").addEventListener("click", simulate);
  $("btn-add").addEventListener("click", addRule);
  $("btn-confirm").addEventListener("click", async () => {
    try {
      const r = await api("/api/v1/confirm", { method: "POST" });
      toast(r && r.persisted ? "Change confirmed and saved to disk." : "Change confirmed. It is active until reboot (no --persist-file set).", "ok");
    } catch (e) {
      toast(e.message, "error");
    }
    lastSig = "";
    refresh();
  });

  /* ---------- timers ---------- */
  setInterval(() => {
    if (bannerOn && remaining > 0) {
      remaining--;
      $("wd-timer").textContent = remaining;
    }
  }, 1000);
  setInterval(refresh, 2000);

  updatePreview();
  $("chains").innerHTML = `<div class="skel"></div><div class="skel"></div>`;
  refresh();
})();
