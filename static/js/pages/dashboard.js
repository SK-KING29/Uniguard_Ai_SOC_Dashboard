/* ==========================================================================
   UniGuard AI - Dashboard page (01)
   ========================================================================== */

UGPages.dashboard = (() => {
  let trafficChart = null;
  let donutChart = null;

  function onShow() {
    if (!trafficChart) {
      trafficChart = UGCharts.lineChart(document.getElementById("dashTrafficChart"), [
        { label: "Traffic", color: "#3ba7d1" },
        { label: "Baseline", color: "#5f6878", dash: [4, 4] },
      ]);
    }
    if (!donutChart) {
      donutChart = UGCharts.donutChart(document.getElementById("dashDonut"),
        ["Critical", "High", "Medium", "Low"], ["#d6484a", "#e0913c", "#d6b83c", "#3cb371"]);
    }
  }

  function severityDistribution(incidents) {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    incidents.forEach((i) => { if (counts[i.severity] !== undefined) counts[i.severity]++; });
    return counts;
  }

  function demoCategoryDistribution() {
    // Only shown in DEMO mode - the real backend does not classify traffic
    // into these categories (no port-scan/brute-force/C2 classifier exists;
    // it detects DoS-like traffic patterns via rate/burst/concentration only)
    return { "DDoS-like": 42, "Port Scan": 18, "Brute Force": 12, "C2 Activity": 6, "Other": 22 };
  }

  function render(state) {
    const snap = state.lastSnapshot;
    const isLive = state.mode === "live";
    document.getElementById("dashModeNotice").textContent = isLive
      ? "Live mode — all values from real backend telemetry"
      : "Demo mode — all values are simulated (client-side only)";
    document.getElementById("dashModeNotice").className = "notice";

    const phoneInc = window.UGPhone ? UGPhone.getIncident() : null;
    const bannerEl = document.getElementById("dashPhoneBanner");
    if (phoneInc && phoneInc.status !== "RESOLVED") {
      bannerEl.innerHTML = `
        <div class="card phone-incident-banner" style="margin-bottom:12px;">
          <div class="card-title">🚨 ACTIVE SECURITY INCIDENT <span class="src-badge src-SIMULATED">🟣 SIMULATED</span></div>
          <div class="kv">
            <div><span>Source</span><span>📱 ${phoneInc.device}</span></div>
            <div><span>Threat</span><span>${phoneInc.threat_type}</span></div>
            <div><span>Risk</span><span class="badge b-${phoneInc.severity}">${phoneInc.threat_score}/100</span></div>
            <div><span>Status</span><span class="badge b-${phoneInc.status}">${phoneInc.status}</span></div>
          </div>
        </div>`;
    } else {
      bannerEl.innerHTML = "";
    }

    if (!snap) {
      document.getElementById("dashMetrics").innerHTML = '<div class="loading-state"><div class="spin"></div><div>Loading...</div></div>';
      return;
    }
    const c = snap.current || {};

    const cards = [
      { label: "Traffic Rate", value: (c.req_per_sec ?? 0).toFixed(0), sub: "req/s" },
      { label: "Active Threats", value: snap.incidents.filter(i => i.status !== "RESOLVED").length, sub: "open incidents" },
      { label: "Critical Threats", value: snap.incidents.filter(i => i.severity === "CRITICAL" && i.status !== "RESOLVED").length, sub: "critical severity" },
      { label: "Threat Score", value: (c.risk_score ?? 0).toFixed(0) + "/100", sub: c.severity || "LOW" },
    ];
    document.getElementById("dashMetrics").innerHTML = cards.map(m => `
      <div class="card metric"><div class="label">${m.label}</div><div class="value">${m.value}</div><div class="sub">${m.sub}</div></div>
    `).join("");

    const cards2 = [
      { label: "AI Confidence", value: c.model_ready ? ((100 - (c.anomaly_score ?? 0) * 0.1)).toFixed(1) + "%" : "warming up", sub: "Isolation Forest" },
      { label: "Total Requests", value: snap.total_requests ?? 0, sub: "since reset" },
      { label: "Unique Sources", value: c.unique_ips ?? 0, sub: "observed IPs" },
      { label: "Active Connections", value: snap.active_connections ?? "N/A", sub: isLive ? "real in-flight" : "simulated" },
    ];
    document.getElementById("dashMetrics2").innerHTML = cards2.map(m => `
      <div class="card metric"><div class="label">${m.label}</div><div class="value">${m.value}</div><div class="sub">${m.sub}</div></div>
    `).join("");

    if (trafficChart) {
      const hist = snap.history || [];
      UGCharts.updateLineChart(trafficChart,
        hist.map(w => new Date(w.t * 1000).toLocaleTimeString()),
        [hist.map(w => w.req_per_sec), hist.map(w => w.baseline_rate)]);
    }

    if (donutChart) {
      if (isLive) {
        const dist = severityDistribution(snap.incidents || []);
        document.getElementById("dashDonutLabel").textContent = "Open incidents by severity (real)";
        donutChart.data.labels = ["Critical", "High", "Medium", "Low"];
        UGCharts.updateDonutChart(donutChart, [dist.CRITICAL, dist.HIGH, dist.MEDIUM, dist.LOW]);
      } else {
        const dist = demoCategoryDistribution();
        document.getElementById("dashDonutLabel").textContent = "Threat distribution (simulated example)";
        donutChart.data.labels = Object.keys(dist);
        donutChart.data.datasets[0].backgroundColor = ["#d6484a", "#e0913c", "#d6b83c", "#9b6fd6", "#5f6878"];
        UGCharts.updateDonutChart(donutChart, Object.values(dist));
      }
    }

    const recentIncidents = (snap.incidents || []).slice(0, 5);
    const phoneRow = (phoneInc && phoneInc.status !== "RESOLVED")
      ? `<tr class="row-phone-highlight"><td>${new Date(phoneInc.first_detected * 1000).toLocaleTimeString()}</td>
         <td>📱 ${phoneInc.device}</td><td><span class="badge b-${phoneInc.severity}">${phoneInc.severity}</span></td>
         <td><span class="badge b-${phoneInc.status}">${phoneInc.status}</span></td></tr>`
      : "";
    document.getElementById("dashRecentThreats").innerHTML = phoneRow + (recentIncidents.length
      ? recentIncidents.map(i => `
        <tr><td>${new Date(i.first_detected * 1000).toLocaleTimeString()}</td>
        <td>${i.source_ip || "-"}</td><td><span class="badge b-${i.severity}">${i.severity}</span></td>
        <td><span class="badge b-${i.status}">${i.status}</span></td></tr>
      `).join("")
      : (phoneRow ? "" : '<tr><td colspan="4" style="color:var(--muted);text-align:center;padding:16px;">No threats recorded yet</td></tr>'));

    const active = phoneInc && phoneInc.status !== "RESOLVED" ? null : snap.active_incident;
    document.getElementById("dashActiveIncident").innerHTML = (phoneInc && phoneInc.status !== "RESOLVED")
      ? `<div class="kv"><div><span>ID</span><span>${phoneInc.id}</span></div><div><span>Severity</span><span class="badge b-${phoneInc.severity}">${phoneInc.severity}</span></div>
         <div><span>Source</span><span>📱 ${phoneInc.device}</span></div><div><span>Status</span><span class="badge b-${phoneInc.status}">${phoneInc.status}</span></div></div>`
      : active
      ? `<div class="kv"><div><span>ID</span><span>${active.id}</span></div><div><span>Severity</span><span class="badge b-${active.severity}">${active.severity}</span></div>
         <div><span>Source</span><span>${active.source_ip}</span></div><div><span>Status</span><span class="badge b-${active.status}">${active.status}</span></div></div>`
      : '<div class="empty-state">No active incident. System nominal.</div>';
  }

  return { onShow, render };
})();
