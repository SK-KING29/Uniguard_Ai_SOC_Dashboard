/* ==========================================================================
   UniGuard AI - Live Traffic page (02)
   ========================================================================== */

UGPages.traffic = (() => {
  let chart = null;
  let paused = false;
  let filter = "all";

  function onShow() {
    if (!chart) {
      chart = UGCharts.lineChart(document.getElementById("trafficPageChart"), [
        { label: "Requests/sec", color: "#3ba7d1" },
        { label: "Bytes/sec (÷10)", color: "#e0913c" },
      ]);
    }
    document.getElementById("trafficPauseBtn").onclick = () => {
      paused = !paused;
      document.getElementById("trafficPauseBtn").textContent = paused ? "▶ Resume" : "⏸ Pause";
    };
    document.getElementById("trafficClearBtn").onclick = () => {
      document.getElementById("trafficLogBody").innerHTML = "";
    };
    document.getElementById("trafficFilter").onchange = (e) => { filter = e.target.value; };
  }

  async function render(state) {
    const snap = state.lastSnapshot;
    const isLive = state.mode === "live";
    document.getElementById("trafficScopeNotice").textContent = isLive
      ? "Application-layer HTTP monitoring (real) — no raw packet/port-level data available on hosted PaaS"
      : "Simulated flow-level data for demonstration";

    if (!snap) return;
    const c = snap.current || {};

    document.getElementById("trafficMetrics").innerHTML = [
      { label: "Requests/sec", value: (c.req_per_sec ?? 0).toFixed(1) },
      { label: "Bytes/sec", value: Math.round(c.bytes_per_sec ?? 0) },
      { label: "Active IPs", value: c.unique_ips ?? 0 },
      { label: "Active Connections", value: snap.active_connections ?? "N/A" },
    ].map(m => `<div class="card metric"><div class="label">${m.label}</div><div class="value">${m.value}</div></div>`).join("");

    if (chart) {
      const hist = snap.history || [];
      UGCharts.updateLineChart(chart,
        hist.map(w => new Date(w.t * 1000).toLocaleTimeString()),
        [hist.map(w => w.req_per_sec), hist.map(w => (w.bytes_per_sec || 0) / 10)]);
    }

    if (paused) return;

    let rows = [];
    if (isLive) {
      try {
        const recent = await UGApi.getRecentTraffic(30);
        rows = (recent.events || []).map(e => ({
          time: e.time, source_ip: e.ip, dest: "this server", protocol: "HTTP",
          src_port: "N/A", dst_port: "N/A", packets: "N/A", bytes: e.bytes,
          status: e.mitigated ? ("blocked: " + e.reason) : e.status, source: "REAL",
        }));
      } catch (err) { /* connection issue already surfaced by app.js */ }
    } else {
      rows = (snap.history || []).slice(-15).flatMap(w =>
        Object.entries(w.per_endpoint || {}).slice(0, 2).map(([path, count]) => {
          const dest = UGDemo.DEMO_TARGET_DEVICES[Math.floor(Math.random() * UGDemo.DEMO_TARGET_DEVICES.length)];
          return {
            time: w.t, source_ip: UGDemo.DEMO_SOURCE_IPS[Math.floor(Math.random() * UGDemo.DEMO_SOURCE_IPS.length)],
            dest: dest.label, protocol: UGDemo.PROTOCOLS[Math.floor(Math.random() * UGDemo.PROTOCOLS.length)],
            src_port: Math.floor(30000 + Math.random() * 20000),
            dst_port: 443, packets: count, bytes: count * 512, status: "200", source: "SIMULATED", isPhone: false,
          };
        })
      );
    }

    // Overlay THIS DEVICE traffic on top of the background rows without
    // ever replacing or pausing them.
    const phoneInc = window.UGPhone ? UGPhone.getIncident() : null;
    if (phoneInc && phoneInc.status !== "RESOLVED") {
      rows.push({
        time: Date.now() / 1000, source_ip: "📱 " + phoneInc.device, dest: "Web Server", protocol: "HTTP",
        src_port: "N/A", dst_port: 80, packets: Math.round(phoneInc.traffic_rate / 2), bytes: phoneInc.traffic_rate * 480,
        status: "SUSPICIOUS", source: "SIMULATED", isPhone: true,
      });
    }
    if (filter !== "all") {
      rows = rows.filter(r => filter === "blocked" ? String(r.status).includes("block") : filter === "suspicious" ? false : true);
    }

    const tbody = document.getElementById("trafficLogBody");
    tbody.innerHTML = rows.slice(-25).reverse().map(r => `
      <tr class="${r.isPhone ? "row-phone-highlight" : ""}"><td>${new Date(r.time * 1000).toLocaleTimeString()}</td><td>${r.source_ip}</td><td>${r.dest}</td>
      <td>${r.protocol}</td><td>${r.src_port}</td><td>${r.dst_port}</td><td>${r.packets}</td><td>${r.bytes}</td>
      <td>${r.status}</td><td><span class="src-badge src-${r.source}">${r.source === "REAL" ? "🟢 REAL" : "🟣 SIMULATED"}</span></td></tr>
    `).join("") || '<tr><td colspan="10" style="text-align:center;color:var(--muted);padding:16px;">No traffic yet</td></tr>';
  }

  return { onShow, render };
})();
