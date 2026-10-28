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
  const BASE_KEY = "iptlens_base";
  const PENDING_MSG = "Qoida qo'llandi. 60 soniya ichida Tasdiqlang, aks holda avtomatik qaytariladi.";

  const svg = (d) => `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`;
  const ICON = {
    pencil: svg('<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>'),
    trash: svg('<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/>'),
    lock: svg('<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>'),
    chain: svg('<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/>'),
    x: svg('<path d="M18 6 6 18M6 6l12 12"/>'),
  };

  // Tushuntirishlar (faqat ko'rsatish uchun)
  const CHAIN_INFO = {
    INPUT: "Serverning o'ziga kiruvchi trafik (SSH, Web panel, servislar).",
    OUTPUT: "Serverdan chiquvchi trafik.",
    FORWARD: "Server orqali o'tuvchi trafik (konteynerlar, VPN).",
    "DOCKER-USER": "Docker konteynerlariga o'tuvchi trafik. Bu yerdagi qoidalar Docker qoidalaridan oldin ishlaydi.",
    PREROUTING: "Paket kelgan paytda, manzil o'zgartirishdan oldin.",
    POSTROUTING: "Paket chiqayotganda, manzil o'zgartirishdan keyin.",
  };
  const TABLE_INFO = {
    filter: "Ruxsat va taqiqlash qoidalari (asosiy firewall).",
    nat: "Manzil o'zgartirish qoidalari (NAT, port yo'naltirish).",
    mangle: "Paketlarni belgilash qoidalari.",
    raw: "Kuzatuvdan oldin ishlaydigan qoidalar.",
  };
  const WHERE_HINT = {
    INPUT: "Serverning o'ziga kiruvchi trafikka ta'sir qiladi. Masalan, SSH yoki Web panel uchun.",
    "DOCKER-USER": "Docker konteynerlariga o'tuvchi trafikka ta'sir qiladi. Serverning o'ziga ta'sir qilmaydi.",
  };
  const ACT_LABEL = { ACCEPT: "Ruxsat", DROP: "Taqiq", REJECT: "Rad etish", RETURN: "Qaytish" };
  const VERDICT = { ACCEPT: "RUXSAT BERILADI", DROP: "TAQIQLANADI", REJECT: "RAD ETILADI" };

  // Server (rules.go) bilan bir xil himoya ro'yxati
  const isProtectedName = (n) =>
    /^(KUBE-|cali-|LIBVIRT_|ufw-)/.test(n || "") || n === "DOCKER" || /^DOCKER-ISOLATION/.test(n || "");
  // Standart holatda yashiriladigan tizim zanjirlari
  const isSystemChain = (n) => isProtectedName(n) || /^(ts-|UFW-)/.test(n || "");

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

  const baseUrl = () => localStorage.getItem(BASE_KEY) || "";
  const kb = (bytes) => (bytes / 1024).toFixed(1) + " KB";
  const ruleSpec = (raw) => String(raw || "").replace(/^\[\d+:\d+\]\s*/, "").replace(/^-A\s+\S+\s*/, "");

  /* ---------- ulanish holati ---------- */
  function setConn(ok) {
    $("conn").className = "pill " + (ok ? "pill-ok" : "pill-err");
    $("conn-text").textContent = ok ? "Live" : "Ulanmagan";
  }

  /* ---------- xabarnomalar ---------- */
  function toast(msg, kind = "info") {
    const t = el("div", "toast " + kind);
    t.append(el("div", "toast-msg", msg));
    const x = el("button", "icon-ghost");
    x.innerHTML = ICON.x;
    x.setAttribute("aria-label", "Yopish");
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
        { label: "Bekor qilish", cls: "btn-ghost", onClick: dismissModal },
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
        sub: "Server tokenini kiriting. U faqat shu brauzer sessiyasida saqlanadi.",
        body: [inp],
        onCancel: () => done(null),
        actions: [
          { label: "Bekor qilish", cls: "btn-ghost", onClick: dismissModal },
          { label: "Saqlash", cls: "btn-primary", onClick: () => {
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
      res = await fetch(baseUrl() + path, { method: opts.method || "GET", headers, body: opts.body });
    } catch {
      throw new Error("Serverga ulanib bo'lmadi");
    }

    if (res.status === 401 && !retried) {
      const t = await askToken();
      if (!t) throw new Error("Token kiritilmadi");
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

  /* ---------- yordamchi renderlar ---------- */
  function badge(v) {
    if (!v || !state || !state.enrich_map) return "";
    const raw = String(v).replace(/^!/, "");
    const m = state.enrich_map[raw] || state.enrich_map[raw.replace(/\/32$/, "")];
    if (!m) return "";
    const t = ["docker", "vpn", "iface"].includes(m.type) ? m.type : "iface";
    return ` <span class="badge badge-${t}">${esc(m.type)}: ${esc(m.name)}</span>`;
  }

  const ifaceText = (v) => (v ? `${esc(v)}${badge(v)}` : `<span class="tert">istalgan</span>`);
  const addrText = (v) => (!v || v === "0.0.0.0/0" ? `<span class="tert">istalgan</span>` : `${esc(v)}${badge(v)}`);

  function actionPill(t, to) {
    const label = ACT_LABEL[t] || t;
    const cls = t === "ACCEPT" ? "tg-ok" : (t === "DROP" || t === "REJECT") ? "tg-bad" : "tg-warn";
    return `<span class="tg ${cls}" title="iptables: -j ${esc(t)}">${esc(label)}</span>${to ? `<div class="sub mono">${esc(to)}</div>` : ""}`;
  }

  function ruleRow(r, chain) {
    const locked = isProtectedName(chain) || isProtectedName(r.target);
    const dis = locked ? "disabled" : "";
    const tip = locked ? "Bu qoida Docker, Kubernetes yoki ufw tomonidan boshqariladi. O'zgartirib bo'lmaydi." : "";
    const attrs = `data-chain="${esc(chain)}" data-num="${r.id}" data-raw="${esc(r.raw_rule)}" data-spec="${esc(ruleSpec(r.raw_rule))}"`;
    const extra = [r.ct_state && "holat: " + r.ct_state, r.dst_type && "manzil turi: " + r.dst_type, r.extra]
      .filter(Boolean).join(" · ");
    return `
      <tr class="${r.packets > 0 ? "" : "zero"}">
        <td class="mono">${r.id}</td>
        <td><div class="mono">${r.packets} paket</div><div class="sub mono">${kb(r.bytes)}</div></td>
        <td class="mono">${ifaceText(r.in_iface)}<span class="arrow">→</span>${ifaceText(r.out_iface)}</td>
        <td class="mono">${r.proto && r.proto !== "all" ? esc(r.proto) : `<span class="tert">istalgan</span>`}</td>
        <td class="mono">${addrText(r.source)}</td>
        <td class="mono">${addrText(r.destination)}</td>
        <td class="mono">${r.dst_port ? esc(r.dst_port) : `<span class="tert">istalgan</span>`}</td>
        <td>${actionPill(r.target, r.to_dest)}</td>
        <td class="cmt">${esc(r.comment || "")}${extra ? `<div class="sub">${esc(extra)}</div>` : ""}</td>
        <td class="acts">
          ${locked ? `<span class="lock" title="${esc(tip)}" aria-label="${esc(tip)}">${ICON.lock}</span>` : ""}
          <button class="icon-ghost" data-act="edit" ${dis} ${attrs} aria-label="Tahrirlash" title="${locked ? esc(tip) : "Tahrirlash"}">${ICON.pencil}</button>
          <button class="icon-ghost icon-danger" data-act="del" ${dis} ${attrs} aria-label="O'chirish" title="${locked ? esc(tip) : "O'chirish"}">${ICON.trash}</button>
        </td>
      </tr>`;
  }

  function chainCard(ch, highlight) {
    const info = CHAIN_INFO[ch.name] || (ch.is_custom ? "Maxsus zanjir. Boshqa zanjirlardan chaqiriladi." : "");
    const tag = ch.is_custom
      ? `<span class="tag tag-custom">Maxsus</span>`
      : ch.policy === "DROP"
        ? `<span class="tag tag-bad">Standart: taqiq</span>`
        : `<span class="tag tag-ok">Standart: ruxsat</span>`;
    const rules = ch.rules || [];
    const rows = rules.length
      ? rules.map((r) => ruleRow(r, ch.name)).join("")
      : `<tr><td colspan="10" class="empty-cell">Bu zanjirda hali qoida yo'q. Standart siyosat ishlaydi.</td></tr>`;
    return `
      <section class="card${highlight ? " hl" : ""}" data-chain="${esc(ch.name)}">
        <header class="card-h">
          <div class="card-t">
            <span class="chain-name">${ICON.chain}${esc(ch.name)}</span>
            ${tag}
          </div>
          <span class="sp tert mono">${ch.packets} paket</span>
        </header>
        ${info ? `<p class="card-sub">${esc(info)}</p>` : ""}
        <div class="scroll">
          <table>
            <thead><tr>
              <th>#</th><th>Trafik</th><th>Yo'nalish</th><th>Protokol</th><th>Kimdan</th>
              <th>Kimga</th><th>Port</th><th>Harakat</th><th>Izoh</th><th></th>
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
      box.innerHTML = `<p class="empty">Bu jadval topilmadi</p>`;
      $("sys-count").textContent = "";
      return;
    }
    const names = tbl.chain_order && tbl.chain_order.length ? tbl.chain_order : Object.keys(tbl.chains || {});
    let hidden = 0;
    const cards = [];
    names.forEach((n) => {
      const ch = tbl.chains[n];
      if (!ch) return;
      if (!showSystem && isSystemChain(n)) { hidden++; return; }
      const hl = !!focusChain && focusChain.table === activeTable && focusChain.chain === n;
      cards.push(chainCard(ch, hl));
    });
    $("sys-count").textContent = hidden && !showSystem ? `${hidden} ta tizim zanjiri yashirin` : "";
    box.innerHTML = cards.length ? cards.join("") : `<p class="empty">Ko'rsatiladigan zanjir yo'q</p>`;

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

  /* ---------- simulyator ---------- */
  function explain(s) {
    const a = s.action || "";
    if (a === "ENTER_CHAIN") return "Paket shu zanjirga kirdi.";
    if (a === "RETURN") return "Zanjir oxiriga yetdi, paket asosiy zanjirga qaytdi.";
    if (a.startsWith("DEFAULT_POLICY")) return "Hech bir qoida mos kelmadi, standart siyosat qo'llandi.";
    if (a.startsWith("MATCH -> JUMP")) return "Qoida paketni boshqa zanjirga yo'naltirdi.";
    if (a === "MATCH -> ACCEPT") return "Qoida mos keldi: paketga ruxsat berildi.";
    if (a === "MATCH -> DROP") return "Qoida mos keldi: paket taqiqlandi.";
    if (a === "MATCH -> REJECT") return "Qoida mos keldi: paket rad etildi.";
    if (a === "MATCH -> RETURN") return "Qoida mos keldi: paket qaytarildi.";
    if (/DNAT|REDIRECT/.test(a)) return "Qoida mos keldi: manzil o'zgartirildi.";
    if (/SNAT|MASQUERADE/.test(a)) return "Qoida mos keldi: manba manzili almashtirildi.";
    return s.note || "";
  }

  function shortAct(a) {
    if (a === "ENTER_CHAIN") return "kirish";
    if (a === "RETURN" || a === "MATCH -> RETURN") return "qaytish";
    if (a.startsWith("DEFAULT_POLICY")) return "standart";
    if (a.startsWith("MATCH -> JUMP")) return "o'tish";
    if (a === "MATCH -> ACCEPT") return "ruxsat";
    if (a === "MATCH -> DROP") return "taqiq";
    if (a === "MATCH -> REJECT") return "rad";
    return a.replace(/^MATCH -> /, "");
  }

  function showSim(r) {
    const ok = r.final_verdict === "ACCEPT";
    let h = `<div class="verdict ${ok ? "v-ok" : "v-bad"}"><div>
      <b>${esc(VERDICT[r.final_verdict] || r.final_verdict)}</b>
      <div class="sub mono">${esc(r.final_verdict)}${r.final_dst ? " → " + esc(r.final_dst) : ""}</div>
    </div></div>`;
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

  /* ---------- yangi qoida qo'shish ---------- */
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
    const who = $("add-src").value.trim() || "istalgan manba";
    const ifc = $("add-iface").value.trim();
    const proto = $("add-proto").value;
    const port = $("add-port").value.trim();
    const what = port
      ? `${proto.toUpperCase()} ${port}-port`
      : proto ? `${proto.toUpperCase()} protokoli` : "istalgan trafik";
    const pv = $("add-preview");
    pv.innerHTML =
      `<div>Manba: <b>${esc(who)}</b>${ifc ? ` (${esc(ifc)} interfeysi)` : ""}, ${esc(what)} → ` +
      `<b class="${allow ? "ok" : "bad"}">${allow ? "ruxsat beriladi" : "taqiqlanadi"}</b></div>` +
      `<div class="sub">Qo'llanadigan buyruq: <code>-I ${esc(where)} 1 ${esc(rule)}</code></div>` +
      (!allow && where === "INPUT" ? `<div class="warn-note">Diqqat: bu serverga kirishni (SSH, panel) uzishi mumkin.</div>` : "");
  }

  function addRule() {
    const where = $("add-where").value;
    const action = $("add-action").value;
    const proto = $("add-proto").value;
    const port = $("add-port").value.trim();
    const iface = $("add-iface").value.trim();
    const src = $("add-src").value.trim();

    if (port && (!/^\d+$/.test(port) || +port < 1 || +port > 65535)) {
      toast("Port 1 dan 65535 gacha raqam bo'lishi kerak", "error");
      return;
    }
    if (port && !proto) {
      toast("Port uchun protokol tanlang (TCP yoki UDP)", "error");
      return;
    }
    if (action === "ACCEPT" && !port && !iface && !src) {
      toast("Port, interfeys yoki manbadan kamida bittasini kiriting. Aks holda hamma trafikka ruxsat beriladi.", "error");
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
        title: "Taqiqlash qoidasi",
        text: "Bu qoida serverning o'ziga kirishni (SSH, panel) uzishi mumkin. Davom etasizmi?",
        okLabel: "Ha, qo'shish",
        danger: true,
        onOk: go,
      });
      return;
    }
    go();
  }

  /* ---------- amallar ---------- */
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
      title: "Qoidani o'zgartirish",
      sub: `${d.chain} · qoida #${d.num}`,
      body: [
        el("div", "field-label", "Hozirgi qoida"),
        el("pre", "code-block mono", d.spec),
        el("div", "field-label", "Yangi qoida (iptables flaglari)"),
        ta,
        el("p", "hint", "Saqlangach o'zgarish vaqtinchalik qo'llanadi. 60 soniya ichida tasdiqlanmasa, eski holatiga qaytadi."),
      ],
      actions: [
        { label: "Bekor qilish", cls: "btn-ghost", onClick: dismissModal },
        { label: "Saqlash", cls: "btn-primary", onClick: () => {
          const nv = ta.value.trim();
          if (!nv) { toast("Qoida bo'sh bo'lishi mumkin emas", "error"); return; }
          closeModal();
          doAction("/api/v1/rules/edit", { ...reqBody(d), rule: nv });
        } },
      ],
    });
  }

  function openDelete(d) {
    confirmModal({
      title: "Qoidani o'chirish",
      text: `${d.chain} · #${d.num} qoidasini o'chirasizmi?`,
      okLabel: "O'chirish",
      danger: true,
      extra: [
        el("pre", "code-block mono", d.spec),
        el("p", "hint", "O'chirilgan qoida 60 soniya ichida tasdiqlanmasa, qaytariladi."),
      ],
      onOk: () => doAction("/api/v1/rules/delete", reqBody(d)),
    });
  }

  function openSettings() {
    const inp = el("input", "mono");
    inp.value = localStorage.getItem(BASE_KEY) || "";
    inp.placeholder = "bo'sh = joriy server";
    openModal({
      title: "Sozlamalar",
      sub: "Server manzili",
      body: [
        el("div", "field-label", "Server manzili (ixtiyoriy)"),
        inp,
        el("p", "hint", "Bo'sh qoldirsangiz, UI joylashgan server ishlatiladi."),
      ],
      actions: [
        { label: "Bekor qilish", cls: "btn-ghost", onClick: dismissModal },
        { label: "Saqlash", cls: "btn-primary", onClick: () => {
          const v = inp.value.trim().replace(/\/+$/, "");
          if (v) localStorage.setItem(BASE_KEY, v);
          else localStorage.removeItem(BASE_KEY);
          closeModal();
          lastSig = "";
          refresh();
        } },
      ],
    });
  }

  /* ---------- hodisalar ---------- */
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
  $("btn-settings").addEventListener("click", openSettings);
  $("btn-confirm").addEventListener("click", async () => {
    try {
      await api("/api/v1/confirm", { method: "POST" });
      toast("Tasdiqlandi. Qoida doimiy saqlandi.", "ok");
    } catch (e) {
      toast(e.message, "error");
    }
    lastSig = "";
    refresh();
  });

  /* ---------- taymerlar ---------- */
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
