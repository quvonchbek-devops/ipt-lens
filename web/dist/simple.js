// Simple view: who can reach which port. Edits a draft policy locally, then
// previews and applies it through /api/v1/access.
(() => {
  "use strict";

  const L = window.IPTLens;
  const $ = (id) => document.getElementById(id);
  const MODE_KEY = "iptlens_mode";
  const LEVELS = ["public", "vpn", "closed"];
  const LABEL = { public: "Everyone", vpn: "VPN only", closed: "Nobody" };
  const SENTENCE = {
    public: "Anyone on the internet can connect.",
    vpn: "Only devices on your VPN can connect.",
    closed: "Nobody can connect from outside.",
  };
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
  const PUBLIC_BY_DEFAULT = new Set(["22/tcp", "80/tcp", "443/tcp", "51820/udp", "41641/udp", "1194/udp"]);

  let view = null; // last GET /api/v1/access
  let base = null; // the policy currently in force (normalized)
  let draft = null; // the policy being edited

  const key = (port, proto) => `${port}/${proto}`;
  const clone = (o) => JSON.parse(JSON.stringify(o));

  function normalize(p, configured) {
    const n = clone(p || {});
    n.vpn = n.vpn || {};
    n.vpn.ifaces = n.vpn.ifaces || [];
    n.vpn.subnets = n.vpn.subnets || [];
    n.ports = n.ports || [];
    // Without a policy nothing is filtered: everything is open to everyone.
    if (!configured || !n.default) n.default = "public";
    return n;
  }

  function levelIn(p, port, proto) {
    const e = p.ports.find((x) => x.port === port && x.proto === proto);
    return e ? { level: e.level, explicit: true } : { level: p.default, explicit: false };
  }

  const hasVPN = (p) => p.vpn.ifaces.length + p.vpn.subnets.length > 0;
  const vpnText = (p) => [...p.vpn.ifaces, ...p.vpn.subnets].join(", ");

  // Every row to show: discovered ports plus ports only the draft mentions.
  function allRows() {
    const rows = view.rows.map((r) => ({ ...r }));
    const seen = new Set(rows.map((r) => key(r.port, r.proto)));
    draft.ports.forEach((p) => {
      if (!seen.has(key(p.port, p.proto))) {
        rows.push({ port: p.port, proto: p.proto, name: "", host: false, containers: [], locked: false, added: true });
      }
    });
    return rows.sort((a, b) => a.port - b.port || a.proto.localeCompare(b.proto));
  }

  function changeCount() {
    let n = 0;
    if (vpnText(base) !== vpnText(draft)) n++;
    if (base.default !== draft.default) n++;
    // A row that just follows "Everything else" is covered by the default's change.
    allRows().forEach((r) => {
      const a = levelIn(base, r.port, r.proto);
      const b = levelIn(draft, r.port, r.proto);
      if ((a.explicit || b.explicit) && a.level !== b.level) n++;
    });
    return n;
  }

  function setLevel(port, proto, level) {
    const e = draft.ports.find((x) => x.port === port && x.proto === proto);
    if (e) e.level = level;
    else draft.ports.push({ port, proto, level });
  }

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
      if (lvl === "vpn" && !hasVPN(draft)) why = "Choose your VPN first";
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

  const titleOf = (r) => r.name || (r.containers.length ? r.containers[0] : r.host ? "Unknown service" : "Custom port");

  function describe(r, exposed = false) {
    const title = titleOf(r);
    const tags = [];
    if (exposed && r.risk) tags.push(`<span class="badge badge-risk">risky: ${L.esc(r.risk)}</span>`);
    if (r.host) tags.push(`<span class="badge badge-iface">this server</span>`);
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
    $("s-vpn-status").textContent = hasVPN(draft)
      ? `Devices connecting through ${vpnText(draft)} count as your VPN.`
      : "Choose the VPN your devices connect through. “VPN only” needs it.";
  }

  function renderRows() {
    const box = $("s-rows");
    box.innerHTML = "";
    const rows = allRows();
    if (!rows.length) box.append(L.el("p", "empty", "No listening ports found."));
    rows.forEach((r) => {
      const cur = levelIn(draft, r.port, r.proto);
      const was = levelIn(base, r.port, r.proto).level;
      const row = L.el("div", "s-row" + (cur.level !== was ? " changed" : ""));
      const port = L.el("div", "s-port mono", String(r.port));
      if (r.proto !== "tcp") port.append(L.el("span", "s-proto", "/" + r.proto));
      const what = L.el("div", "s-what");
      what.innerHTML = describe(r, cur.level === "public");
      const sentence = L.el("div", "s-sentence", SENTENCE[cur.level]);
      if (!cur.explicit) sentence.append(L.el("span", "tert", " Follows “Everything else”."));
      what.append(sentence);
      row.append(port, what, levelButtons(r.port, r.proto, cur.level, {
        locked: r.locked,
        onPick: (lvl) => { setLevel(r.port, r.proto, lvl); render(); },
      }));
      box.append(row);
    });

    const def = $("s-default");
    def.innerHTML = "";
    def.classList.toggle("changed", draft.default !== base.default);
    const label = L.el("div", "s-port", "*");
    label.setAttribute("aria-hidden", "true");
    const what = L.el("div", "s-what");
    what.innerHTML = "<b>Everything else</b>";
    what.append(L.el("div", "s-sentence", `${SENTENCE[draft.default]} Applies to every port not listed above, including ones that start listening later.`));
    def.append(label, what, levelButtons(0, "", draft.default, {
      label: "Who can reach every other port",
      onPick: (lvl) => { draft.default = lvl; render(); },
    }));
  }

  // The answer to "is this server safe?" in one sentence, for the draft as it
  // stands, with one button that fixes the worst problem.
  function renderVerdict() {
    const box = $("s-verdict");
    const open = allRows().filter((r) => levelIn(draft, r.port, r.proto).level === "public");
    const risky = open.filter((r) => r.risk);
    const portList = (rows, withRisk) => {
      const ul = L.el("ul", "s-v-ports");
      rows.forEach((r) => {
        const li = L.el("li");
        li.innerHTML = `<b>${L.esc(titleOf(r))}</b> <span class="mono">${r.port}${r.proto !== "tcp" ? "/" + r.proto : ""}</span>`
          + (withRisk ? ` <span class="s-v-why">${L.esc(r.risk)}</span>` : "");
        ul.append(li);
      });
      return ul;
    };
    let tone, title, body = [], action = null;
    if (risky.length) {
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
          risky.forEach((r) => setLevel(r.port, r.proto, to));
          render();
          L.toast("Changed here, not on the server yet. Review and apply to make it real.", "info");
        },
      };
    } else if (draft.default === "public") {
      tone = "warn";
      title = "Every new service will be open to the whole internet";
      if (open.length) {
        body.push(L.el("p", "s-v-text", "Open to everyone right now:"), portList(open, false));
      }
      body.push(L.el("p", "s-v-text", "“Everything else” is set to Everyone, so any port that starts listening later is public too."));
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

  function render() {
    if (!view) return;
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
    body.push(det, L.el("p", "hint", "The change is temporary until you confirm it in the yellow bar. If you lose access, it rolls back on its own."));
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
      L.toast("Applied. Confirm it in the yellow bar, or it is rolled back automatically.", "info");
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
      const label = `<span class="mono">${r.port}${r.proto !== "tcp" ? "/" + r.proto : ""}</span> ${describe(r)}`;
      return { r, ...check(label, PUBLIC_BY_DEFAULT.has(key(r.port, r.proto))) };
    });
    const body = [L.el("div", "field-label", "1. Which ports stay open to everyone?")];
    checks.forEach((c) => body.push(c.node));
    let picker = null;
    if (!hasVPN(draft)) {
      picker = vpnPicker();
      body.push(L.el("div", "field-label", "2. Which VPN do your devices use?"), picker.node);
    }
    body.push(L.el("p", "hint", "Every other port, including Docker ports and ports that open later, becomes VPN only."));
    L.openModal({
      title: "Lock the server behind the VPN",
      body,
      actions: [
        { label: "Cancel", cls: "btn-ghost", onClick: L.dismissModal },
        { label: "Continue to review", cls: "btn-primary", onClick: () => {
          if (picker && !picker.apply()) { L.toast("Choose a VPN interface or enter its subnet.", "error"); return; }
          draft.default = "vpn";
          checks.forEach(({ r, input }) => {
            const cur = levelIn(draft, r.port, r.proto);
            if (input.checked) setLevel(r.port, r.proto, "public");
            // Unchecked ports follow the new default, except ones already closed to everyone.
            else if (!(cur.explicit && cur.level === "closed")) {
              draft.ports = draft.ports.filter((p) => !(p.port === r.port && p.proto === r.proto));
            }
          });
          L.closeModal();
          render();
          review();
        } },
      ],
    });
  }

  function taskOpen() {
    const port = L.el("input", "mono");
    port.inputMode = "numeric";
    port.placeholder = "8080";
    port.setAttribute("aria-label", "Port");
    const proto = L.el("select");
    ["tcp", "udp"].forEach((p) => proto.append(new Option(p.toUpperCase(), p)));
    proto.setAttribute("aria-label", "Protocol");
    const who = L.el("select");
    LEVELS.filter((l) => l !== "closed").forEach((l) => who.append(new Option(LABEL[l], l)));
    if (hasVPN(draft)) who.value = "vpn";
    who.setAttribute("aria-label", "Who can connect");
    const grid = L.el("div", "s-wiz-grid");
    const field = (label, input) => { const l = L.el("label", "", label); l.append(input); return l; };
    grid.append(field("Port", port), field("Protocol", proto), field("Who can connect", who));
    L.openModal({
      title: "Open a port",
      body: [grid],
      actions: [
        { label: "Cancel", cls: "btn-ghost", onClick: L.dismissModal },
        { label: "Continue to review", cls: "btn-primary", onClick: () => {
          const n = Number(port.value.trim());
          if (!Number.isInteger(n) || n < 1 || n > 65535) { L.toast("Port must be a number from 1 to 65535.", "error"); return; }
          if (who.value === "vpn" && !hasVPN(draft)) { L.toast("Choose your VPN first, in the “Your VPN” box.", "error"); return; }
          setLevel(n, proto.value, who.value);
          L.closeModal();
          render();
          review();
        } },
      ],
    });
  }

  function taskContainer() {
    const rows = allRows().filter((r) => r.containers.length);
    if (!rows.length) {
      L.toast("No published container ports found.", "info");
      return;
    }
    const checks = rows.map((r) => ({ r, ...check(`<span class="mono">${r.port}</span> ${describe(r)}`, false) }));
    const who = L.el("select");
    who.append(new Option("Nobody", "closed"));
    if (hasVPN(draft)) who.append(new Option("VPN only", "vpn"));
    who.setAttribute("aria-label", "Who can still connect");
    const pick = L.el("label", "", "Who can still connect");
    pick.append(who);
    L.openModal({
      title: "Close a container port",
      sub: "Docker publishes ports past the normal firewall rules. These rules reach them anyway.",
      body: [L.el("div", "field-label", "Ports to close"), ...checks.map((c) => c.node), pick],
      actions: [
        { label: "Cancel", cls: "btn-ghost", onClick: L.dismissModal },
        { label: "Continue to review", cls: "btn-primary", onClick: () => {
          const chosen = checks.filter((c) => c.input.checked);
          if (!chosen.length) { L.toast("Pick at least one port.", "error"); return; }
          chosen.forEach(({ r }) => setLevel(r.port, r.proto, who.value));
          L.closeModal();
          render();
          review();
        } },
      ],
    });
  }

  /* ---------- events ---------- */
  document.querySelectorAll(".mode-switch .seg-btn").forEach((b) => b.addEventListener("click", () => setMode(b.dataset.mode)));
  document.querySelectorAll(".s-task").forEach((b) => b.addEventListener("click", () => {
    if (!view) return;
    ({ lock: taskLock, open: taskOpen, container: taskContainer })[b.dataset.task]();
  }));
  $("s-vpn-add").addEventListener("click", () => {
    const v = $("s-vpn-subnet").value.trim();
    if (!/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(v)) { L.toast("Enter an IPv4 subnet such as 100.64.0.0/10.", "error"); return; }
    draft.vpn.subnets = [...new Set([...draft.vpn.subnets, v])];
    $("s-vpn-subnet").value = "";
    render();
  });
  $("s-discard").addEventListener("click", () => { draft = clone(base); render(); });
  $("s-review").addEventListener("click", review);
  $("btn-confirm").addEventListener("click", () => setTimeout(load, 600));

  let mode = "simple";
  try { mode = localStorage.getItem(MODE_KEY) || "simple"; } catch { /* storage unavailable */ }
  setMode(mode === "advanced" ? "advanced" : "simple");
})();
