/* ==========================================================================
   UniGuard AI - Navigation / router (hash-based, no build system needed)
   ========================================================================== */

const UGRoutes = [
  { id: "dashboard", num: "01", label: "Dashboard" },
  { id: "traffic", num: "02", label: "Live Traffic" },
  { id: "threats", num: "03", label: "Threats" },
  { id: "alerts", num: "04", label: "Alerts" },
  { id: "investigation", num: "05", label: "Investigation" },
  { id: "ip", num: "06", label: "IP Intelligence" },
  { id: "network", num: "07", label: "Network Graph" },
  { id: "ai", num: "08", label: "AI Models" },
  { id: "health", num: "09", label: "System Health" },
  { id: "settings", num: "10", label: "Settings" },
  { id: "reports", num: "11", label: "Reports" },
];

// Routes that exist and are hash-navigable, but are deliberately NOT shown
// in the main sidebar (reached only via Settings > System Diagnostics).
const UGHiddenRoutes = [
  { id: "mobile-demo", label: "System Diagnostics" },
];

const UGNav = (() => {
  let currentId = "dashboard";

  function buildSidebar() {
    const nav = document.getElementById("sidebarNav");
    nav.innerHTML = "";
    UGRoutes.forEach((r) => {
      const el = document.createElement("div");
      el.className = "nav-item";
      el.dataset.route = r.id;
      el.innerHTML = `<span class="num">${r.num}</span><span>${r.label}</span>`;
      el.addEventListener("click", () => { location.hash = "#/" + r.id; });
      nav.appendChild(el);
    });
  }

  function routeFromHash() {
    const h = location.hash.replace(/^#\/?/, "");
    if (UGRoutes.some((r) => r.id === h)) return h;
    if (UGHiddenRoutes.some((r) => r.id === h)) return h;
    return "dashboard";
  }

  function showPage(id) {
    const prev = currentId;
    currentId = id;

    document.querySelectorAll(".page-section").forEach((el) => {
      el.classList.toggle("page-hidden", el.id !== "page-" + id);
    });
    document.querySelectorAll(".nav-item").forEach((el) => {
      el.classList.toggle("active", el.dataset.route === id);
    });
    const route = UGRoutes.find((r) => r.id === id) || UGHiddenRoutes.find((r) => r.id === id);
    document.getElementById("pageTitle").textContent = route ? route.label : id;

    document.getElementById("sidebar").classList.remove("open");

    if (prev !== id && window.UGPages && UGPages[prev] && typeof UGPages[prev].onHide === "function") {
      UGPages[prev].onHide();
    }
    if (window.UGPages && UGPages[id] && typeof UGPages[id].onShow === "function") {
      UGPages[id].onShow(window.UGState);
    }
  }

  function init() {
    buildSidebar();
    window.addEventListener("hashchange", () => showPage(routeFromHash()));
    showPage(routeFromHash());

    const menuBtn = document.getElementById("mobileMenuBtn");
    if (menuBtn) menuBtn.addEventListener("click", () => document.getElementById("sidebar").classList.toggle("open"));
  }

  return { init, get currentId() { return currentId; } };
})();
