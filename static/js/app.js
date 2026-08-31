/* ==========================================================================
   UniGuard AI - App bootstrap

   Central 1s tick loop: in LIVE mode, polls the real backend
   (/api/metrics) exactly like the previous single-page dashboard did.
   In DEMO mode, advances the client-side simulation engine instead.
   Either way, the result is handed to the currently visible page module
   through the SAME shape, so page code never needs to know which mode
   produced it except for the explicit source/REAL/SIMULATED labels.
   ========================================================================== */

window.UGPages = window.UGPages || {};
window.UGState = {
  mode: "demo",            // 'live' | 'demo' - DEMO is the default so the SOC opens populated
  lastSnapshot: null,     // last /api/metrics (live) or UGDemo.getSnapshot() (demo)
  lastHealth: null,
  lastSystem: null,
  connectionOk: true,
  selectedIncidentId: null,
  settings: {
    mitigationTtl: 120,       // real - used as the ttl sent to /api/mitigate
    mitigationLimit: 1,       // real - used as the rate limit sent to /api/mitigate
    refreshIntervalMs: 1000,  // real - controls the actual poll/tick interval
    autoRefresh: true,        // real - pauses/resumes the tick loop
    compactMode: false,       // real - toggles a CSS class
    detectionThresholdDisplay: 25,  // DISPLAY ONLY - backend risk.py has fixed thresholds
    riskThresholdDisplay: 50,       // DISPLAY ONLY - backend risk.py has fixed thresholds
  },
};

const UGApp = (() => {
  let tickHandle = null;

  function setMode(mode) {
    UGState.mode = mode;
    document.querySelectorAll(".mode-toggle button").forEach((b) => {
      b.classList.toggle("active", b.dataset.mode === mode);
    });
    if (mode === "demo" && !UGDemo.isRunning) UGDemo.start();
  }

  function updateHeaderFromSnapshot(snap) {
    if (!snap) return;
    const chip = document.getElementById("statusChip");
    chip.className = "status-chip " + snap.system_status;
    chip.textContent = snap.system_status === "ATTACK" ? "🔴 ATTACK DETECTED"
      : snap.system_status === "SUSPICIOUS" ? "🟡 SUSPICIOUS" : "🟢 PROTECTED";

    const bell = document.getElementById("bellIcon");
    const badge = document.getElementById("bellBadge");
    const hasIncident = !!snap.active_incident;
    bell.classList.toggle("active", hasIncident);
    badge.style.display = hasIncident ? "inline-block" : "none";
  }

  function showConnBanner(show) {
    document.getElementById("connBanner").classList.toggle("show", show);
  }

  async function tick() {
    try {
      if (UGState.mode === "live") {
        const snap = await UGApi.getMetrics();
        UGState.lastSnapshot = { ...snap, source: "REAL" };
        UGState.connectionOk = true;
        showConnBanner(false);
      } else {
        UGDemo.tick(1);
        UGState.lastSnapshot = UGDemo.getSnapshot();
        UGState.connectionOk = true;
        showConnBanner(false);
      }
    } catch (e) {
      UGState.connectionOk = false;
      showConnBanner(true);
    }

    // "This device" phone simulation runs independently of live/demo mode
    // and never replaces the snapshot above - only pages read it separately.
    if (window.UGPhone) UGPhone.tick(1);

    updateHeaderFromSnapshot(UGState.lastSnapshot);

    const footer = document.getElementById("sidebarFooter");
    if (footer) {
      footer.classList.toggle("offline", !UGState.connectionOk && UGState.mode === "live");
      footer.lastChild.textContent = " " + (UGState.mode === "demo" ? "Demo mode active"
        : UGState.connectionOk ? "System Operational" : "Connection lost");
    }

    const page = UGPages[UGNav.currentId];
    if (page && typeof page.render === "function") {
      try { page.render(UGState); } catch (e) { console.error("Page render error:", UGNav.currentId, e); }
    }
  }

  function initHeader() {
    document.querySelectorAll(".mode-toggle button").forEach((b) => {
      b.addEventListener("click", () => setMode(b.dataset.mode));
    });
    setInterval(() => {
      document.getElementById("headerClock").textContent = new Date().toLocaleTimeString();
    }, 1000);
    document.getElementById("retryConnBtn")?.addEventListener("click", tick);
  }

  function renderPhoneIncidentModal(inc) {
    if (!inc) return;
    const kv = document.getElementById("phoneIncidentKv");
    if (kv) {
      kv.innerHTML = `
        <div><span>Device</span><span>📱 ${inc.device}</span></div>
        <div><span>Source IP</span><span>${inc.source_ip}</span></div>
        <div><span>Threat</span><span>${inc.threat_type}</span></div>
        <div><span>Severity</span><span class="badge b-${inc.severity}">${inc.severity}</span></div>
        <div><span>Traffic Rate</span><span>${inc.traffic_rate} req/s</span></div>
        <div><span>Risk Score</span><span>${inc.threat_score}/100</span></div>
        <div><span>Confidence</span><span>${inc.confidence != null ? inc.confidence + "%" : "-"}</span></div>
        <div><span>Mode</span><span class="src-badge src-SIMULATED">🟣 SIMULATED</span></div>
      `;
    }
    const ev = document.getElementById("phoneIncidentEvidence");
    if (ev) ev.innerHTML = (inc.evidence || []).map(e => `<li>✓ ${e}</li>`).join("");
  }

  function initPhoneIncidentPopup() {
    if (!window.UGPhone) return;
    UGPhone.on("incident_start", (inc) => {
      renderPhoneIncidentModal(inc || UGPhone.getIncident());
      document.getElementById("phoneIncidentModal")?.classList.add("show");
    });
    document.getElementById("phoneIncidentDismiss")?.addEventListener("click", () => {
      document.getElementById("phoneIncidentModal").classList.remove("show");
    });
    document.getElementById("phoneIncidentView")?.addEventListener("click", () => {
      document.getElementById("phoneIncidentModal").classList.remove("show");
      UGState.selectedIncidentId = UGPhone.INCIDENT_ID;
      location.hash = "#/investigation";
    });
  }

  function init() {
    initHeader();
    initPhoneIncidentPopup();
    UGNav.init();
    // DEMO is the default mode - make sure the background simulation is
    // actually running the moment the page opens/refreshes.
    if (UGState.mode === "demo") UGDemo.start();
    tick();
    tickHandle = setInterval(tick, 1000);
  }

  function setRefreshInterval(ms) {
    clearInterval(tickHandle);
    tickHandle = setInterval(tick, Math.max(250, ms));
  }

  function setAutoRefresh(on) {
    if (on) {
      if (!tickHandle) tickHandle = setInterval(tick, UGState.settings?.refreshIntervalMs || 1000);
    } else {
      clearInterval(tickHandle);
      tickHandle = null;
    }
  }

  return { init, setMode, setRefreshInterval, setAutoRefresh, tick };
})();

document.addEventListener("DOMContentLoaded", () => UGApp.init());
