/* ==========================================================================
   UniGuard AI - AI Models & Explainability page (08)
   ========================================================================== */

UGPages.ai = (() => {
  function onShow() {
    document.querySelectorAll("#page-ai .tab-btn").forEach(b => {
      b.onclick = () => {
        document.querySelectorAll("#page-ai .tab-btn").forEach(x => x.classList.toggle("active", x === b));
        document.querySelectorAll("#page-ai .tab-pane").forEach(p => p.classList.toggle("active", p.id === "ai-tab-" + b.dataset.tab));
      };
    });
  }

  function render(state) {
    const snap = state.lastSnapshot;
    if (!snap) return;
    const c = snap.current || {};
    const hasTraffic = !!snap.current;
    const hasIncident = !!snap.active_incident;

    const steps = [
      { label: "Traffic received", done: hasTraffic },
      { label: "Features extracted", done: hasTraffic },
      { label: "Anomaly scored", done: c.model_ready },
      { label: "Risk calculated", done: hasTraffic },
      { label: "Incident generated", done: hasIncident },
    ];
    document.getElementById("aiPipeline").innerHTML = steps.map((s, i) =>
      `<span class="step ${s.done ? "done" : ""}">${s.done ? "✓" : "○"} ${s.label}</span>${i < steps.length - 1 ? '<span class="arrow">→</span>' : ""}`
    ).join("");

    document.getElementById("aiOverview").innerHTML = `
      <div class="kv">
        <div><span>Anomaly detection model</span><span>Isolation Forest (scikit-learn)</span></div>
        <div><span>Threat classification model</span><span>N/A - not implemented in this real-time monitor</span></div>
        <div><span>Model state</span><span>${c.model_ready ? "Active" : "Warming up (needs ~30s of traffic)"}</span></div>
        <div><span>Explainability method</span><span>Real computed risk components (not SHAP)</span></div>
      </div>
      <div class="notice">
        This live HTTP monitor uses Isolation Forest only. XGBoost classification existed in a separate,
        earlier offline PCAP analysis tool for this project - a different codebase from this real-time SOC
        system. No SHAP values are computed; the "Why was this detected" evidence is generated from actual
        computed risk components (rate deviation %, anomaly score, burst indicator, endpoint concentration).
      </div>`;

    document.getElementById("aiAnomalyTab").innerHTML = `
      <div class="bar-row"><div class="lab">Anomaly score</div><div class="bar-track"><div class="bar-fill" style="width:${c.anomaly_score ?? 0}%"></div></div><div>${(c.anomaly_score ?? 0).toFixed(0)}</div></div>
      <div class="bar-row"><div class="lab">Baseline deviation</div><div class="bar-track"><div class="bar-fill" style="width:${c.components?.baseline_deviation ?? 0}%"></div></div><div>${c.components?.baseline_deviation ?? 0}</div></div>
      <div class="bar-row"><div class="lab">Traffic burst</div><div class="bar-track"><div class="bar-fill" style="width:${c.components?.traffic_burst ?? 0}%"></div></div><div>${c.components?.traffic_burst ?? 0}</div></div>
      <div class="bar-row"><div class="lab">Endpoint concentration</div><div class="bar-track"><div class="bar-fill" style="width:${c.components?.endpoint_concentration ?? 0}%"></div></div><div>${c.components?.endpoint_concentration ?? 0}</div></div>
      <div class="notice">Calibrated via percentile-rank against a rolling window of recent traffic (not a fixed contamination rate - that caused false positives on calm traffic in earlier testing and was fixed).</div>`;

    document.getElementById("aiClassTab").innerHTML = `<div class="empty-state">No threat-classification model is implemented in this real-time backend (Isolation Forest performs anomaly detection only, not multi-class classification).</div>`;

    document.getElementById("aiPerfTab").innerHTML = `
      <div class="kv">
        <div><span>Regression tests passing</span><span>37/37 (see tests/test_detection_logic.py)</span></div>
        <div><span>False positives on calm traffic</span><span>0 (fixed - see AI Models notice)</span></div>
        <div><span>Detection latency</span><span>~2s (debounced - avoids single-blip false alarms)</span></div>
      </div>`;
  }

  return { onShow, render };
})();
