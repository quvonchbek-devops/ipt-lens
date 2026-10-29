// Applies the saved theme before the first paint (no flash); app.js wires the toggle.
(() => {
  try {
    const t = localStorage.getItem("iptlens_theme");
    if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
  } catch { /* storage unavailable: follow the system */ }
})();
