/* ==========================================================================
   UniGuard AI - Mobile Demo / System Diagnostics page (hidden route)
   ========================================================================== */

UGPages["mobile-demo"] = (() => {
  let selectedIntensity = "MEDIUM";

  function onShow() {
    document.querySelectorAll(".md-intensity-btn").forEach((b) => {
      b.onclick = () => {
        if (UGPhone.isActive) return;
        selectedIntensity = b.dataset.intensity;
        document.querySelectorAll(".md-intensity-btn").forEach((x) => x.classList.toggle("active", x === b));
      };
    });

    document.getElementById("mdStartBtn").onclick = () => {
      if (UGPhone.isActive) return;
      UGPhone.start(selectedIntensity);
      render(window.UGState);
    };

    document.getElementById("mdStopBtn").onclick = () => {
      UGPhone.stop();
      render(window.UGState);
    };
  }

  function fmtTime(t) { return t ? new Date(t * 1000).toLocaleTimeString() : "-"; }

  function render() {
    const startBtn = document.getElementById("mdStartBtn");
    const stopBtn = document.getElementById("mdStopBtn");
    startBtn.disabled = UGPhone.isActive;
    stopBtn.disabled = !UGPhone.isVisible;
    document.querySelectorAll(".md-intensity-btn").forEach((b) => { b.disabled = UGPhone.isActive; });

    const inc = UGPhone.getIncident();
    const body = document.getElementById("mdDeviceBody");

    if (!inc) {
      body.innerHTML = '<div class="empty-state">Not running. Press START to begin the controlled simulation.</div>';
      return;
    }

    const mitigateDisabled = inc.status !== "INVESTIGATING";
    body.innerHTML = `
      <div class="kv">
        <div><span>Device</span><span>📱 ${inc.device}</span></div>
        <div><span>Source</span><span>${inc.source_ip}</span></div>
        <div><span>Threat</span><span>${inc.threat_type}</span></div>
        <div><span>Severity</span><span class="badge b-${inc.severity}">${inc.severity}</span></div>
        <div><span>Risk Score</span><span>${inc.threat_score}/100</span></div>
        <div><span>Confidence</span><span>${inc.confidence != null ? inc.confidence + "%" : "-"}</span></div>
        <div><span>Status</span><span class="badge b-${inc.status}">${inc.status}</span></div>
        <div><span>Traffic Rate</span><span>${inc.traffic_rate} req/s</span></div>
        <div><span>Connection Rate</span><span>${inc.connection_rate} conn/s</span></div>
        <div><span>First Seen</span><span>${fmtTime(inc.first_detected)}</span></div>
        <div><span>Last Seen</span><span>${fmtTime(inc.last_detected)}</span></div>
      </div>
      <div class="card-title" style="margin-top:14px;">WHY WAS THIS DEVICE FLAGGED?</div>
      <ul class="evidence-list">${inc.evidence.map(e => `<li>✓ ${e}</li>`).join("")}</ul>
      <button class="btn primary" id="mdMitigateBtn" style="margin-top:6px;width:100%;" ${mitigateDisabled ? "disabled" : ""}>🛡️ MITIGATE DEVICE</button>
      <div style="font-size:10.5px;color:var(--muted);margin-top:8px;">🟣 SIMULATED — no real device was contacted or blocked.</div>
    `;

    document.getElementById("mdMitigateBtn")?.addEventListener("click", () => {
      UGPhone.mitigate();
      render(window.UGState);
    });
  }

  UGPhone.on("mitigated", () => render(window.UGState));
  UGPhone.on("recovered", () => render(window.UGState));

  return { onShow, render };
})();
