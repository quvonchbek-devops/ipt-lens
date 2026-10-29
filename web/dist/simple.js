// Simple view: who can reach which port. Edits a draft policy locally, then
// previews and applies it through /api/v1/access.
(() => {
  "use strict";

  const L = window.IPTLens;
  const $ = (id) => document.getElementById(id);
  const MODE_KEY = "iptlens_mode";
  const LEVELS = ["public", "vpn", "closed"];
  const LABEL = { public: "Everyone", vpn: "VPN only", closed: "Nobody" };
  // Pre-checked in "Lock the server": SSH, web, and VPN endpoints (which must
  // stay reachable from the internet, or the VPN itself goes down).
  // Shape as well as color tells the levels apart: open globe, shield, lock.
  const icon = (d) => `<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`;
  const LEVEL_ICON = {
    public: icon('<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>'),
    vpn: icon('<path d="M12 3 5 6v6c0 4.5 3 7.5 7 9 4-1.5 7-4.5 7-9V6Z"/>'),
    closed: icon('<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>'),
  };
  const VERDICT_ICON = {
    bad: icon('<path d="M12 3 2 20h20Z"/><path d="M12 10v4M12 17h.01"/>'),
    warn: LEVEL_ICON.public,
    ok: icon('<path d="M12 3 5 6v6c0 4.5 3 7.5 7 9 4-1.5 7-4.5 7-9V6Z"/><path d="m9 12 2 2 4-4"/>'),
  };
  const VPN_ENDPOINTS = new Set(["WireGuard", "Tailscale", "OpenVPN"]);
  const PUBLIC_BY_DEFAULT = new Set(["22/tcp", "80/tcp", "443/tcp", "51820/udp", "41641/udp", "1194/udp"]);

  let view = null; // last GET /api/v1/access
  let base = null; // the policy currently in force (normalized)
  let draft = null; // the policy being edited
  let vpnOpen = false; // the VPN picker stays folded once a VPN is chosen

  // A row or policy entry is a single port or a range ({port, port_end, proto}).
  const endOf = (x) => x.port_end || 0;
  const key = (x) => `${x.port}-${endOf(x)}/${x.proto}`;
  const portLabel = (x) => (endOf(x) ? `${x.port}–${x.port_end}` : String(x.port)) + (x.proto !== "tcp" ? "/" + x.proto : "");
  const clone = (o) => JSON.parse(JSON.stringify(o));

  function normalize(p, configured) {
    const n = clone(p || {});
    n.vpn = n.vpn || {};
    n.vpn.ifaces = n.vpn.ifaces || [];
    n.vpn.subnets = n.vpn.subnets || [];
    n.vpn.trusted = n.vpn.trusted || [];
    n.ports = n.ports || [];
    // Without a policy nothing is filtered: everything is open to everyone.
    if (!configured || !n.default) n.default = "public";
    return n;
  }

  const entryOf = (p, r) => p.ports.find((x) => x.port === r.port && endOf(x) === endOf(r) && x.proto === r.proto);

  // The level of a row: its own entry, else a range covering it, else "Any other port".
  function levelIn(p, r) {
    const e = entryOf(p, r);
    if (e) return { level: e.level, explicit: true };
    const range = !endOf(r) && p.ports.find((x) => endOf(x) && x.proto === r.proto && r.port >= x.port && r.port <= x.port_end);
    if (range) return { level: range.level, explicit: false, range };
    return { level: p.default, explicit: false };
  }

  // "VPN only" lets in the VPN and the trusted addresses.
  const hasVPN = (p) => p.vpn.ifaces.length + p.vpn.subnets.length + p.vpn.trusted.length > 0;
  const vpnText = (p) => [...p.vpn.ifaces, ...p.vpn.subnets, ...p.vpn.trusted].join(", ");

  // Every row to show: discovered ports plus ports only the draft mentions.
  function allRows() {
    const rows = view.rows.map((r) => ({ ...r }));
    const seen = new Set(rows.map(key));
    draft.ports.forEach((p) => {
      if (!seen.has(key(p))) {
        rows.push({ port: p.port, port_end: p.port_end, proto: p.proto, name: "", host: false, containers: [], locked: false, added: true });
      }
    });
    return rows.sort((a, b) => a.port - b.port || endOf(a) - endOf(b) || a.proto.localeCompare(b.proto));
  }

  function changeCount() {
    let n = 0;
    if (vpnText(base) !== vpnText(draft)) n++;
    if (base.default !== draft.default) n++;
    // A row that just follows "Any other port" is covered by the default's change.
    allRows().forEach((r) => {
      const a = levelIn(base, r);
      const b = levelIn(draft, r);
      if ((a.explicit || b.explicit) && a.level !== b.level) n++;
      else if (limitIn(base, r) !== limitIn(draft, r) || noteIn(base, r) !== noteIn(draft, r)) n++;
    });
    return n;
  }

  // entry returns the draft's own entry for a row, creating it at its current level.
  function entry(r) {
    let e = entryOf(draft, r);
    if (!e) {
      e = { port: r.port, proto: r.proto, level: levelIn(draft, r).level };
      if (endOf(r)) e.port_end = r.port_end;
      draft.ports.push(e);
    }
    return e;
  }

  function setLevel(r, level) {
    const e = entry(r);
    e.level = level;
    if (level !== "public") delete e.limit; // slowing down only applies to "Everyone"
  }

  const limitIn = (p, r) => !!(entryOf(p, r) || {}).limit;
  const noteIn = (p, r) => (entryOf(p, r) || {}).note || "";

  /* ---------- mode ---------- */
  function setMode(mode) {
    try { localStorage.setItem(MODE_KEY, mode); } catch { /* storage unavailable */ }
    const simple = mode === "simple";
    $("simple").hidden = !simple;
    $("advanced").hidden = simple;
    $("table-nav").hidden = simple;
    $("s-bar").hidden = !simple || !draft || changeCount() === 0;
    document.querySelectorAll(".mode-switch .seg-btn").forEach((b) => {
      b.classList.toggle("active", b.dataset.mode === mode);
      b.setAttribute("aria-pressed", String(b.dataset.mode === mode));
    });
    if (simple && !view) load();
  }

  /* ---------- data ---------- */
  async function load() {
    vpnOpen = false;
    try {
      view = await L.api("/api/v1/access");
      base = normalize(view.policy, view.configured);
      draft = clone(base);
      render();
    } catch (e) {
      $("s-rows").innerHTML = `<p class="empty">Could not load ports: ${L.esc(e.message)}</p>`;
    }
  }

  /* ---------- render ---------- */
  function levelButtons(port, proto, current, opts = {}) {
    const group = L.el("div", "s-levels");
    group.setAttribute("role", "group");
    group.setAttribute("aria-label", opts.label || `Who can reach port ${port}`);
    LEVELS.forEach((lvl) => {
      const b = L.el("button", `s-lvl s-lvl-${lvl}`);
      b.innerHTML = LEVEL_ICON[lvl];
      b.append(LABEL[lvl]);
      b.type = "button";
      b.setAttribute("aria-pressed", String(current === lvl));
      let why = "";
      if (lvl === "vpn" && !hasVPN(draft)) why = "Choose your VPN or add a trusted address first";
      if (lvl === "closed" && opts.locked) why = "IPT-Lens' own port stays reachable over the VPN, so you cannot lock yourself out";
      if (why) {
        b.disabled = true;
        b.title = why;
      }
      b.addEventListener("click", () => opts.onPick(lvl));
      group.append(b);
    });
    return group;
  }

  const titleOf = (r) => r.name || r.program || (r.containers.length ? r.containers[0] : r.host ? "Unknown service" : endOf(r) ? "Port range" : "Custom port");

  function describe(r, exposed = false) {
    const title = titleOf(r);
    const tags = [];
    // The program, when the name above is the service rather than the program.
    if (r.program && r.name) tags.push(`<span class="s-prog mono" title="The program listening on this port">${L.esc(r.program)}</span>`);
    if (exposed && r.risk) tags.push(`<span class="badge badge-risk">risky: ${L.esc(r.risk)}</span>`);
    r.containers.forEach((c) => tags.push(`<span class="badge badge-docker">container: ${L.esc(c)}</span>`));
    if (r.locked) tags.push(`<span class="badge badge-vpn">IPT-Lens</span>`);
    return `<span class="s-title"><b>${L.esc(title)}</b> ${tags.join(" ")}</span>`;
  }

  function renderVPN() {
    const list = $("s-vpn-list");
    list.innerHTML = "";
    const cands = view.vpn_candidates || [];
    cands.forEach((c) => {
      const on = draft.vpn.ifaces.includes(c.name);
      const b = L.el("button", "s-chip");
      b.type = "button";
      b.setAttribute("aria-pressed", String(on));
      b.innerHTML = `<span class="mono">${L.esc(c.name)}</span>${(c.subnets || []).length ? ` <span class="tert mono">${L.esc(c.subnets.join(", "))}</span>` : ""}`;
      b.addEventListener("click", () => {
        draft.vpn.ifaces = on ? draft.vpn.ifaces.filter((x) => x !== c.name) : [...draft.vpn.ifaces, c.name];
        render();
      });
      list.append(b);
    });
    draft.vpn.ifaces.filter((i) => !cands.some((c) => c.name === i)).concat(draft.vpn.subnets).forEach((v) => {
      const b = L.el("button", "s-chip");
      b.type = "button";
      b.setAttribute("aria-pressed", "true");
      b.title = "Remove";
      b.innerHTML = `<span class="mono">${L.esc(v)}</span> <span aria-hidden="true">×</span>`;
      b.setAttribute("aria-label", `Remove ${v}`);
      b.addEventListener("click", () => {
        draft.vpn.ifaces = draft.vpn.ifaces.filter((x) => x !== v);
        draft.vpn.subnets = draft.vpn.subnets.filter((x) => x !== v);
        render();
      });
      list.append(b);
    });
    if (!list.children.length) {
      list.append(L.el("p", "hint", "No VPN interface found (wg*, tailscale*, tun*, zt*). Add your VPN subnet below."));
    }
    const tl = $("s-trusted-list");
    tl.innerHTML = "";
    draft.vpn.trusted.forEach((v) => {
      const b = L.el("button", "s-chip");
      b.type = "button";
      b.setAttribute("aria-pressed", "true");
      b.setAttribute("aria-label", `Remove ${v}`);
      b.innerHTML = `<span class="mono">${L.esc(v)}</span> <span aria-hidden="true">×</span>`;
      b.addEventListener("click", () => {
        draft.vpn.trusted = draft.vpn.trusted.filter((x) => x !== v);
        render();
      });
      tl.append(b);
    });
    const folded = hasVPN(draft) && !vpnOpen;
    $("s-vpn-edit").hidden = folded;
    $("s-vpn-change").hidden = !folded;
    $("s-vpn-card").classList.toggle("folded", folded);
    $("s-vpn-status").innerHTML = hasVPN(draft)
      ? `<span class="mono">${L.esc(vpnText(draft))}</span>`
      : "Pick the VPN your devices connect through, or add a trusted address. “VPN only” needs one of them.";
  }

  // noteEditor shows a port's description, or an "Add description" link that
  // turns into a field (Enter or leaving the field keeps it, Escape cancels).
  function noteEditor(r) {
    const box = L.el("div", "s-note-line");
    const note = noteIn(draft, r);
    const open = L.el("button", note ? "s-note-text s-note-btn" : "s-note-add", note || "Add description");
    open.type = "button";
    open.title = note ? "Edit the description" : "Say what this port is for, e.g. “Grafana for the team”";
    open.addEventListener("click", () => {
      const input = L.el("input", "s-note-input");
      input.maxLength = 40;
      input.value = note;
      input.placeholder = "What is this port for?";
      input.setAttribute("aria-label", `Description of port ${portLabel(r)}`);
      let done = false;
      const finish = (keep) => {
        if (done) return;
        done = true;
        const v = input.value.trim();
        if (keep && v !== note) {
          const e = entry(r);
          if (v) e.note = v; else delete e.note;
        }
        render();
      };
      input.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter") finish(true);
        if (ev.key === "Escape") finish(false);
      });
      input.addEventListener("blur", () => finish(true));
      box.replaceChildren(input);
      input.focus();
    });
    box.append(open);
    return box;
  }

  function renderRows() {
    const box = $("s-rows");
    box.innerHTML = "";
    const rows = allRows();
    if (!rows.length) box.append(L.el("p", "empty", "No listening ports found."));
    rows.forEach((r) => {
      const cur = levelIn(draft, r);
      const was = levelIn(base, r).level;
      const changed = cur.level !== was || limitIn(base, r) !== limitIn(draft, r) || noteIn(base, r) !== noteIn(draft, r);
      const row = L.el("div", "s-row" + (changed ? " changed" : ""));
      const port = L.el("div", endOf(r) ? "s-port s-range mono" : "s-port mono", endOf(r) ? `${r.port}–${r.port_end}` : String(r.port));
      if (r.proto !== "tcp") port.append(L.el("span", "s-proto", "/" + r.proto));
      const what = L.el("div", "s-what");
      what.innerHTML = describe(r, cur.level === "public");
      // A port inside a range follows it; it is changed on the range's row, since
      // an entry of its own would overlap the range.
      if (cur.range) {
        what.append(L.el("div", "s-note-text", `Follows the range ${portLabel(cur.range)}. Change it on that row.`));
        const lvl = L.el("span", `s-lvl-static s-lvl-${cur.level}`);
        lvl.innerHTML = LEVEL_ICON[cur.level];
        lvl.append(LABEL[cur.level]);
        row.append(port, what, lvl);
        box.append(row);
        return;
      }
      what.append(noteEditor(r));
      // SSH open to everyone attracts password guessing; offer to slow it down.
      if (r.name === "SSH" && r.proto === "tcp" && cur.level === "public") {
        const l = L.el("label", "check s-limit");
        const c = L.el("input");
        c.type = "checkbox";
        c.checked = limitIn(draft, r);
        c.addEventListener("change", () => {
          setLevel(r, "public");
          entry(r).limit = c.checked || undefined;
          render();
        });
        const txt = L.el("span", "", "Slow down password guessing");
        txt.append(L.el("span", "tert", " · 6 new connections a minute per address"));
        l.append(c, txt);
        what.append(l);
      }
      row.append(port, what, levelButtons(r.port, r.proto, cur.level, {
        locked: r.locked,
        onPick: (lvl) => { setLevel(r, lvl); render(); },
      }));
      box.append(row);
    });

    const def = $("s-default");
    def.innerHTML = "";
    def.classList.toggle("changed", draft.default !== base.default);
    const label = L.el("div", "s-port", "*");
    label.setAttribute("aria-hidden", "true");
    const what = L.el("div", "s-what");
    what.innerHTML = "<b>Any other port</b>";
    what.append(L.el("div", "s-sentence", "Including ports that open later."));
    def.append(label, what, levelButtons(0, "", draft.default, {
      label: "Who can reach every other port",
      onPick: (lvl) => { draft.default = lvl; render(); },
    }));
  }

  // The answer to "is this server safe?" in one sentence, for the draft as it
  // stands, with one button that fixes the worst problem.
  function renderVerdict() {
    const box = $("s-verdict");
    const open = allRows().filter((r) => levelIn(draft, r).level === "public");
    const risky = open.filter((r) => r.risk);
    // A VPN endpoint must stay reachable from the internet, or the VPN goes down
    // and "VPN only" locks everyone out.
    const endpoints = draft.vpn.ifaces.length + draft.vpn.subnets.length > 0
      ? allRows().filter((r) => VPN_ENDPOINTS.has(r.name) && levelIn(draft, r).level !== "public")
      : [];
    const portList = (rows, withRisk) => {
      const ul = L.el("ul", "s-v-ports");
      rows.forEach((r) => {
        const li = L.el("li");
        li.innerHTML = `<b>${L.esc(titleOf(r))}</b> <span class="mono">${portLabel(r)}</span>`
          + (withRisk ? ` <span class="s-v-why">${L.esc(r.risk)}</span>` : "");
        ul.append(li);
      });
      return ul;
    };
    let tone, title, body = [], action = null;
    if (endpoints.length) {
      tone = "bad";
      title = "Your VPN would stop working";
      body.push(portList(endpoints, false));
      body.push(L.el("p", "s-v-text", "Devices connect to these from the internet before they are on the VPN, so they must stay open to everyone."));
      action = {
        label: endpoints.length === 1 ? `Keep ${endpoints[0].name} open` : "Keep them open",
        cls: "btn-danger",
        run: () => { endpoints.forEach((r) => setLevel(r, "public")); render(); },
      };
    } else if (risky.length) {
      tone = "bad";
      const n = risky.length;
      title = n === 1 ? "1 risky port is open to the whole internet" : `${n} risky ports are open to the whole internet`;
      body.push(portList(risky, true));
      const to = hasVPN(draft) ? "vpn" : "closed";
      body.push(L.el("p", "s-v-text", to === "vpn"
        ? `Make ${n === 1 ? "it" : "them"} VPN only: you keep access through ${vpnText(draft)}, nobody else gets in.`
        : `Close ${n === 1 ? "it" : "them"} to everyone. To keep access for yourself, choose your VPN below first.`));
      action = {
        label: to === "vpn" ? `Make ${n === 1 ? "it" : "them"} VPN only` : `Close ${n === 1 ? "it" : "them"}`,
        cls: "btn-danger",
        run: () => {
          risky.forEach((r) => setLevel(r, to));
          render();
          L.toast("Changed here, not on the server yet. Review and apply to make it real.", "info");
        },
      };
    } else if (draft.default === "public") {
      tone = "warn";
      title = "New services will be open to the whole internet";
      if (open.length) {
        body.push(L.el("p", "s-v-text", "Open to everyone right now:"), portList(open, false));
      }
      body.push(L.el("p", "s-v-text", "“Any other port” is set to Everyone."));
      action = { label: "Lock the server behind the VPN", cls: "btn-primary", run: taskLock };
    } else {
      tone = "ok";
      title = open.length ? "Only these are open to everyone" : "Nothing is open to everyone";
      if (open.length) body.push(portList(open, false));
      body.push(L.el("p", "s-v-text", draft.default === "vpn"
        ? "Every other port is VPN only."
        : "Every other port is closed."));
    }
    box.dataset.tone = tone;
    box.innerHTML = "";
    const mark = L.el("div", "s-v-icon");
    mark.innerHTML = VERDICT_ICON[tone];
    const main = L.el("div", "s-v-main");
    main.append(L.el("h2", "s-v-title", title), ...body);
    if (changeCount() > 0) main.append(L.el("p", "s-v-draft", "Includes changes you have not applied yet."));
    box.append(mark, main);
    if (action) {
      const b = L.el("button", `btn ${action.cls} s-v-action`, action.label);
      b.type = "button";
      b.addEventListener("click", action.run);
      box.append(b);
    }
    box.hidden = false;
  }

  // renderSummary is the one-line state under the title: how many ports, how
  // many open to everyone, and whether IPT-Lens protects the server yet.
  function renderSummary() {
    const rows = allRows();
    const open = rows.filter((r) => levelIn(base, r).level === "public").length;
    const box = $("s-summary");
    box.innerHTML = "";
    const badge = L.el("span", view.configured ? "pill pill-ok" : "pill pill-muted", view.configured ? "Protected" : "Not set up yet");
    badge.title = view.configured ? "IPT-Lens rules are active on this server" : "No IPT-Lens rules yet: every port is open";
    box.append(badge, L.el("span", "",
      `${rows.length} port${rows.length === 1 ? "" : "s"} · ${open} open to everyone · any other port: ${LABEL[base.default]}`));
  }

  function render() {
    if (!view) return;
    renderSummary();
    renderVerdict();
    renderVPN();
    renderRows();
    $("s-notes").textContent = (view.notes || []).join(" ");
    const n = changeCount();
    $("s-bar").hidden = n === 0 || $("simple").hidden;
    $("s-bar-text").textContent = `${n} change${n === 1 ? "" : "s"} not applied yet`;
  }

  /* ---------- review and apply ---------- */
  async function review() {
    let pv;
    try {
      pv = await L.api("/api/v1/access/preview", { method: "POST", body: JSON.stringify(draft) });
    } catch (e) {
      L.toast(e.message, "error");
      return;
    }
    const list = L.el("ul", "s-changes");
    pv.changes.forEach((c) => list.append(L.el("li", "", c)));
    const body = [list];
    // Warnings are about risk to this server; notes are context. Keep them apart
    // so a warning still stands out.
    pv.warnings.forEach((w) => body.push(L.el("div", "s-warn", w)));
    (pv.notes || []).forEach((n) => body.push(L.el("div", "s-note", n)));
    const det = L.el("details", "s-cmds");
    det.append(L.el("summary", "", "Show iptables commands"), L.el("pre", "code-block mono", pv.commands.join("\n")));
    body.push(det, L.el("p", "hint", "The change stays temporary until you press “Keep this change”. If you lose access, it is undone on its own."));
    L.openModal({
      title: "Review changes",
      body,
      actions: [
        { label: "Back", cls: "btn-ghost", onClick: L.dismissModal },
        { label: "Apply changes", cls: "btn-primary", onClick: () => { L.closeModal(); apply(); } },
      ],
    });
  }

  async function apply() {
    try {
      await L.api("/api/v1/access/apply", { method: "POST", body: JSON.stringify(draft) });
      L.toast("Applied for now. Press “Keep this change” in the yellow bar, or it is undone on its own.", "info");
      await load();
    } catch (e) {
      L.toast(e.message, "error");
    }
    L.refresh();
  }

  /* ---------- quick tasks ---------- */
  function check(labelHTML, checked) {
    const l = L.el("label", "check s-check");
    const c = L.el("input");
    c.type = "checkbox";
    c.checked = checked;
    const span = L.el("span");
    span.innerHTML = labelHTML;
    l.append(c, span);
    return { node: l, input: c };
  }

  function vpnPicker() {
    const box = L.el("div", "s-wiz-vpn");
    const radios = [];
    (view.vpn_candidates || []).forEach((c, i) => {
      const l = L.el("label", "check s-check");
      const r = L.el("input");
      r.type = "radio";
      r.name = "s-wiz-vpn";
      r.value = c.name;
      r.checked = i === 0;
      const span = L.el("span");
      span.innerHTML = `<span class="mono">${L.esc(c.name)}</span> <span class="tert mono">${L.esc((c.subnets || []).join(", "))}</span>`;
      l.append(r, span);
      radios.push(r);
      box.append(l);
    });
    const subnet = L.el("input", "mono");
    subnet.placeholder = radios.length ? "…or a VPN subnet, e.g. 100.64.0.0/10" : "VPN subnet, e.g. 100.64.0.0/10";
    subnet.setAttribute("aria-label", "VPN subnet");
    box.append(subnet);
    return {
      node: box,
      apply() {
        const s = subnet.value.trim();
        const r = radios.find((x) => x.checked);
        if (s) draft.vpn.subnets = [...new Set([...draft.vpn.subnets, s])];
        else if (r) draft.vpn.ifaces = [...new Set([...draft.vpn.ifaces, r.value])];
        return hasVPN(draft);
      },
    };
  }

  function taskLock() {
    const rows = allRows();
    const checks = rows.filter((r) => !r.locked).map((r) => {
      const label = `<span class="mono">${portLabel(r)}</span> ${describe(r)}`;
      return { r, ...check(label, PUBLIC_BY_DEFAULT.has(`${r.port}/${r.proto}`)) };
    });
    const body = [L.el("div", "field-label", "1. Which ports stay open to everyone?")];
    checks.forEach((c) => body.push(c.node));
    let picker = null;
    if (!hasVPN(draft)) {
      picker = vpnPicker();
      body.push(L.el("div", "field-label", "2. Which VPN do your devices use?"), picker.node);
    }
    body.push(L.el("p", "hint", "Every other port, Docker ones and ones that open later included, becomes VPN only."));
    L.openModal({
      title: "Lock the server behind the VPN",
      body,
      actions: [
        { label: "Cancel", cls: "btn-ghost", onClick: L.dismissModal },
        { label: "Continue to review", cls: "btn-primary", onClick: () => {
          if (picker && !picker.apply()) { L.toast("Choose a VPN interface or enter its subnet.", "error"); return; }
          draft.default = "vpn";
          checks.forEach(({ r, input }) => {
            const cur = levelIn(draft, r);
            if (input.checked) setLevel(r, "public");
            // Unchecked ports follow the new default, except ones already closed to everyone.
            else if (!(cur.explicit && cur.level === "closed")) {
              draft.ports = draft.ports.filter((p) => key(p) !== key(r));
            }
          });
          L.closeModal();
          render();
          review();
        } },
      ],
    });
  }

  // Common services, offered when adding a port so nobody has to remember numbers.
  const PRESETS = [
    { label: "SSH", port: 22 }, { label: "HTTP", port: 80 }, { label: "HTTPS", port: 443 },
    { label: "DNS", port: 53, proto: "udp" }, { label: "MySQL", port: 3306 }, { label: "PostgreSQL", port: 5432 },
    { label: "Redis", port: 6379 }, { label: "Grafana", port: 3000 }, { label: "Prometheus", port: 9090 },
    { label: "WireGuard", port: 51820, proto: "udp" },
    { label: "Kubernetes NodePorts", port: 30000, end: 32767 },
  ];

  function taskOpen() {
    const port = L.el("input", "mono");
    port.inputMode = "numeric";
    port.placeholder = "8080";
    port.setAttribute("aria-label", "Port");
    const end = L.el("input", "mono");
    end.inputMode = "numeric";
    end.placeholder = "optional";
    end.setAttribute("aria-label", "Last port of a range");
    const proto = L.el("select");
    ["tcp", "udp"].forEach((p) => proto.append(new Option(p.toUpperCase(), p)));
    proto.setAttribute("aria-label", "Protocol");
    const who = L.el("select");
    LEVELS.forEach((l) => who.append(new Option(LABEL[l], l)));
    if (hasVPN(draft)) who.value = "vpn";
    who.setAttribute("aria-label", "Who can connect");
    const note = L.el("input");
    note.maxLength = 40;
    note.placeholder = "e.g. Grafana for the team";
    note.setAttribute("aria-label", "Description");

    const presets = L.el("div", "s-presets");
    presets.setAttribute("role", "group");
    presets.setAttribute("aria-label", "Common services");
    PRESETS.forEach((p) => {
      const b = L.el("button", "s-chip");
      b.type = "button";
      b.innerHTML = `${L.esc(p.label)} <span class="tert mono">${p.port}${p.end ? "–" + p.end : ""}${p.proto === "udp" ? "/udp" : ""}</span>`;
      b.addEventListener("click", () => {
        port.value = String(p.port);
        end.value = p.end ? String(p.end) : "";
        proto.value = p.proto || "tcp";
        if (!note.value) note.value = p.label;
        presets.querySelectorAll(".s-chip").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
      });
      presets.append(b);
    });

    const grid = L.el("div", "s-wiz-grid s-wiz-port");
    const field = (label, input, cls = "") => { const l = L.el("label", cls, label); l.append(input); return l; };
    grid.append(field("Port", port), field("To (for a range)", end), field("Protocol", proto),
      field("Who can connect", who), field("Description", note, "span-all"));
    L.openModal({
      title: "Add a port",
      body: [L.el("div", "field-label", "Common services"), presets, grid],
      actions: [
        { label: "Cancel", cls: "btn-ghost", onClick: L.dismissModal },
        { label: "Continue to review", cls: "btn-primary", onClick: () => {
          const n = Number(port.value.trim());
          const last = end.value.trim() === "" ? 0 : Number(end.value.trim());
          if (!Number.isInteger(n) || n < 1 || n > 65535) { L.toast("Port must be a number from 1 to 65535.", "error"); return; }
          if (last && (!Number.isInteger(last) || last <= n || last > 65535)) {
            L.toast("The range must end above its first port, at most 65535.", "error");
            return;
          }
          if (who.value === "vpn" && !hasVPN(draft)) { L.toast("Choose your VPN or add a trusted address first, in the box above the ports.", "error"); return; }
          const r = { port: n, proto: proto.value };
          if (last) r.port_end = last;
          // Overlapping entries are refused by the server; say so here instead.
          const clash = draft.ports.find((x) => key(x) !== key(r) && x.proto === r.proto &&
            x.port <= (last || n) && n <= (endOf(x) || x.port));
          if (clash) {
            L.toast(`That overlaps port ${portLabel(clash)}. Change that row, or pick ports outside it.`, "error");
            return;
          }
          setLevel(r, who.value);
          const v = note.value.trim();
          if (v) entry(r).note = v;
          L.closeModal();
          render();
          review();
        } },
      ],
    });
  }

  /* ---------- history ---------- */
  // Color by outcome: failures red, rollbacks amber, confirmed green.
  const historyTone = (ev) => /failed/.test(ev) ? "bad" : /rolled back/.test(ev) ? "warn" : ev === "confirmed" ? "ok" : "edit";

  async function loadHistory() {
    const list = $("s-history-list");
    list.innerHTML = "";
    let res;
    try {
      res = await L.api("/api/v1/audit");
    } catch (e) {
      list.append(L.el("li", "hint", `Could not load the history: ${e.message}`));
      return;
    }
    if (!res.entries.length) {
      const li = L.el("li", "s-h-empty");
      li.innerHTML = icon('<path d="M12 8v4l3 2"/><circle cx="12" cy="12" r="9"/>');
      li.append(L.el("b", "", "No changes yet"), L.el("span", "", "Every change you apply, keep or undo shows up here."));
      list.append(li);
      return;
    }
    res.entries.forEach((e) => {
      const li = L.el("li", `s-h-item s-h-${historyTone(e.event)}`);
      const when = L.el("time", "s-h-time mono", new Date(e.time).toLocaleString());
      when.dateTime = e.time;
      const what = L.el("div", "s-h-what");
      what.append(L.el("b", "", e.event.charAt(0).toUpperCase() + e.event.slice(1)), document.createTextNode(e.desc ? ` · ${e.desc}` : ""));
      if (e.detail) what.append(L.el("div", "s-h-detail", e.detail));
      li.append(when, what);
      list.append(li);
    });
  }

  /* ---------- events ---------- */
  $("s-history").addEventListener("toggle", () => { if ($("s-history").open) loadHistory(); });
  document.querySelectorAll(".mode-switch .seg-btn").forEach((b) => b.addEventListener("click", () => setMode(b.dataset.mode)));
  $("s-add-port").addEventListener("click", () => { if (view) taskOpen(); });
  $("s-vpn-change").addEventListener("click", () => { vpnOpen = true; render(); $("s-vpn-list").querySelector("button")?.focus(); });
  $("s-vpn-add").addEventListener("click", () => {
    const v = $("s-vpn-subnet").value.trim();
    if (!/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(v)) { L.toast("Enter an IPv4 subnet such as 100.64.0.0/10.", "error"); return; }
    draft.vpn.subnets = [...new Set([...draft.vpn.subnets, v])];
    $("s-vpn-subnet").value = "";
    render();
  });
  $("s-trusted-add").addEventListener("click", () => {
    const v = $("s-trusted-addr").value.trim();
    // A rough shape check; the server validates for real.
    if (!/^(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:.]*)(\/\d{1,3})?$/.test(v)) {
      L.toast("Enter an IP address or range, such as 203.0.113.7 or 2001:db8::/48.", "error");
      return;
    }
    draft.vpn.trusted = [...new Set([...draft.vpn.trusted, v])];
    $("s-trusted-addr").value = "";
    render();
  });
  $("s-discard").addEventListener("click", () => { draft = clone(base); render(); });
  $("s-review").addEventListener("click", review);
  $("btn-confirm").addEventListener("click", () => setTimeout(load, 600));
  $("btn-undo").addEventListener("click", () => setTimeout(load, 600));

  let mode = "simple";
  try { mode = localStorage.getItem(MODE_KEY) || "simple"; } catch { /* storage unavailable */ }
  setMode(mode === "advanced" ? "advanced" : "simple");
})();
