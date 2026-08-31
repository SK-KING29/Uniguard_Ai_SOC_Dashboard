/* ==========================================================================
   UniGuard AI - System Health page (09)
   ========================================================================== */

UGPages.health = (() => {
  let lastFetch = 0;
  let cachedSystem = null;
  let lastBenchFetch = 0;
  let cachedBench = null;

  function onShow() {}

  function bar(label, pct) {
    const p = pct == null ? 0 : pct;
    return `<div class="resource-bar"><div class="top"><span>${label}</span><span>${pct == null ? "N/A" : p.toFixed(1) + "%"}</span></div>
      <div class="bar-track"><div class="bar-fill" style="width:${p}%"></div></div></div>`;
  }

  async function render(state) {
    const snap = state.lastSnapshot;
    if (!snap) return;
    const isLive = state.mode === "live";
    document.getElementById("healthModeNotice").textContent = isLive
      ? "Live mode - real resource usage via psutil"
      : "Demo mode - simulated resource figures";

    let sys;
    if (isLive) {
      const now = Date.now();
      if (now - lastFetch > 2000) {
        try { cachedSystem = await UGApi.getSystem(); lastFetch = now; } catch (e) { /* keep last known */ }
      }
      sys = cachedSystem;
    } else {
      sys = {
        resource_data_available: true,
        cpu_percent: 18 + Math.sin(Date.now() / 5000) * 6,
        memory_percent: 34 + Math.sin(Date.now() / 7000) * 4,
        disk_percent: 46,
        components: { traffic_middleware: "running", detection_engine: "running", incident_manager: "running", mitigation_engine: "running", dashboard_api: "running" },
        uptime_seconds: snap.uptime_seconds,
        total_requests_processed: snap.total_requests,
      };
    }

    if (!sys) {
      document.getElementById("healthResources").innerHTML = '<div class="loading-state"><div class="spin"></div>Loading...</div>';
      return;
    }

    document.getElementById("healthResources").innerHTML = sys.resource_data_available
      ? bar("CPU", sys.cpu_percent) + bar("Memory", sys.memory_percent) + bar("Disk", sys.disk_percent)
      : '<div class="empty-state">Resource data not available (psutil not installed on this host)</div>';

    const comps = sys.components || {};
    const statusDot = (s) => s === "running" ? "🟢" : s === "warming_up" ? "🟡" : "🔴";
    document.getElementById("healthComponents").innerHTML = Object.entries(comps).map(([name, s]) => `
      <div class="component-row"><span>${name.replace(/_/g, " ")}</span><span>${statusDot(s)} ${s.replace(/_/g, " ")}</span></div>
    `).join("");

    document.getElementById("healthInfo").innerHTML = `
      <div class="kv">
        <div><span>Uptime</span><span>${sys.uptime_seconds}s</span></div>
        <div><span>Total requests processed</span><span>${sys.total_requests_processed ?? "N/A"}</span></div>
        <div><span>Environment</span><span>${location.hostname === "127.0.0.1" || location.hostname === "localhost" ? "Local" : "Production"}</span></div>
        <div><span>Monitoring scope</span><span>Application-layer HTTP</span></div>
      </div>`;

    // Real benchmark (perf_counter-measured) - independent of live/demo
    // dashboard mode, since the analysis loop always runs against real
    // traffic windows on the backend.
    const bnow = Date.now();
    if (bnow - lastBenchFetch > 2000) {
      lastBenchFetch = bnow;
      try { cachedBench = await UGApi.getBenchmark(); window.UGState.lastBenchmark = cachedBench; } catch (e) { /* keep last known */ }
    }
    const b = cachedBench;
    document.getElementById("healthBenchmark").innerHTML = (b && b.benchmarked) ? `
        <div><span>Avg Detection Latency</span><span>${b.avg_detection_latency_ms} ms</span></div>
        <div><span>P95 Detection Latency</span><span>${b.p95_detection_latency_ms} ms</span></div>
        <div><span>Throughput</span><span>${b.throughput_requests_per_sec} req/s</span></div>
        <div><span>Alerts/sec</span><span>${b.alerts_per_sec}</span></div>
        <div><span>Windows processed</span><span>${b.windows_processed}</span></div>
        <div><span>Measurement scope</span><span style="font-size:10.5px;">${b.measurement_scope}</span></div>
      ` : `
        <div><span>Status</span><span class="badge b-NOT_BENCHMARKED">NOT BENCHMARKED</span></div>
        <div><span>Samples collected</span><span>${b ? b.samples_collected : 0} / ${b ? b.samples_required : "-"}</span></div>
      `;
  }

  return { onShow, render };
})();
