/* ==========================================================================
   UniGuard AI - IP Intelligence page (06)
   ========================================================================== */

UGPages.ip = (() => {
  function onShow() {
    document.getElementById("ipLookupBtn").onclick = doLookup;
    document.getElementById("ipInput").onkeydown = (e) => { if (e.key === "Enter") doLookup(); };
  }

  function demoLookup(ip) {
    const known = UGDemo.DEMO_SOURCE_IPS.includes(ip);
    return {
      ip, request_count: known ? 340 : 0, unique_user_agents: known ? 1 : 0,
      dominant_user_agent: known ? "UniGuard-Demo-Simulator/1.0" : null,
      timing_regularity: known ? 0.92 : null, endpoint_spread: known ? 1 : 0,
      authenticity_note: known ? "[SIMULATED] Highly regular request timing, consistent with scripted traffic" : "[SIMULATED] No requests observed from this address",
      concern_level: known ? "ELEVATED" : "NONE",
      first_seen: known ? Date.now() / 1000 - 300 : null, last_seen: known ? Date.now() / 1000 : null,
      ip_type: ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.16.") ? "Private" : "Public",
    };
  }

  async function doLookup() {
    const ip = document.getElementById("ipInput").value.trim();
    if (!ip) return;
    const resultEl = document.getElementById("ipResult");
    resultEl.innerHTML = '<div class="loading-state"><div class="spin"></div>Looking up...</div>';
    let intel;
    try {
      intel = window.UGState.mode === "live" ? await UGApi.ipLookup(ip) : demoLookup(ip);
    } catch (e) {
      resultEl.innerHTML = '<div class="error-state">Lookup failed - backend unreachable.</div>';
      return;
    }
    renderResult(intel, window.UGState.mode === "live");
  }

  function renderResult(intel, isLive) {
    const resultEl = document.getElementById("ipResult");
    if (!intel.request_count) {
      resultEl.innerHTML = `<div class="empty-state">No traffic observed from ${intel.ip} yet.</div>`;
      return;
    }
    const risk = intel.concern_level === "ELEVATED" ? "HIGH RISK" : "LOW RISK";
    const riskColor = intel.concern_level === "ELEVATED" ? "var(--critical)" : "var(--low)";
    resultEl.innerHTML = `
      <div class="risk-hero" style="color:${riskColor}">${risk}</div>
      <div class="kv" style="margin-bottom:14px;">
        <div><span>IP Type</span><span>${intel.ip_type || "N/A"}</span></div>
        <div><span>First Seen</span><span>${intel.first_seen ? new Date(intel.first_seen * 1000).toLocaleTimeString() : "N/A"}</span></div>
        <div><span>Last Seen</span><span>${intel.last_seen ? new Date(intel.last_seen * 1000).toLocaleTimeString() : "N/A"}</span></div>
        <div><span>Total Requests</span><span>${intel.request_count}</span></div>
        <div><span>Unique User Agents</span><span>${intel.unique_user_agents}</span></div>
        <div><span>Endpoint Spread</span><span>${intel.endpoint_spread}</span></div>
        <div><span>Timing Regularity</span><span>${intel.timing_regularity ?? "N/A"}</span></div>
        <div><span>Concern Level</span><span class="badge b-${intel.concern_level}">${intel.concern_level}</span></div>
      </div>
      <div class="card-title" style="margin-top:6px;">BEHAVIOR SUMMARY</div>
      <p style="font-size:12px;color:#c9d3e0;">${intel.authenticity_note}</p>
      <div class="notice">
        UniGuard AI does not claim to recover the attacker's real IP. It analyzes observed traffic and
        behavioral authenticity indicators only (${isLive ? "real, application-layer heuristics" : "simulated demo data"}).
      </div>
    `;
  }

  function render(state) {
    document.getElementById("ipModeNotice").textContent = state.mode === "live"
      ? "Live mode - real lookups against actual observed traffic (try an IP from the Recent Requests / Live Traffic page)"
      : "Demo mode - try one of: " + UGDemo.DEMO_SOURCE_IPS.slice(0, 3).join(", ");
  }

  return { onShow, render };
})();
