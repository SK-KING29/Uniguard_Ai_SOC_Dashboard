/* ==========================================================================
   UniGuard AI - Settings page (10)
   Every control here either genuinely does something (wired) or is
   explicitly labeled display-only, per the "don't fake settings" rule.
   ========================================================================== */

UGPages.settings = (() => {
  let lastSihFetch = 0;
  let cachedSih = null;
  let lastLedgerFetch = 0;
  let cachedLedger = null;

  function renderSihCard(sih, ledger) {
    if (sih) {
      document.getElementById("sihPipeline").innerHTML = sih.sih_passive_pipeline.map((s, i) =>
        `<span class="step done">${s}</span>${i < sih.sih_passive_pipeline.length - 1 ? '<span class="arrow">→</span>' : ""}`
      ).join("");
      document.getElementById("sihMitigationKv").innerHTML = `
        <div><span>Mitigation Path</span><span class="badge b-MEDIUM">${sih.mitigation_path.label}</span></div>
        <div><span>Part of SIH passive path?</span><span class="badge b-TAMPERED">NO — separate control</span></div>`;
      document.getElementById("sihImplNote").textContent = sih.implementation_note;
      document.getElementById("sihCategoryTable").innerHTML = `<div class="kv">` + sih.threat_category_coverage.map(c => {
        const cls = c.status === "Demo Coverage" ? "b-VERIFIED" : "b-NOT_BENCHMARKED";
        return `<div><span>${c.category}</span><span class="badge ${cls}" title="${c.note}">${c.status}</span></div>`;
      }).join("") + `</div>`;
    }
    if (ledger) {
      document.getElementById("sihLedgerStatus").innerHTML =
        `<span class="badge ${ledger.integrity_status === "VERIFIED" ? "b-VERIFIED" : "b-TAMPERED"}">${ledger.integrity_status}</span>`;
      document.getElementById("sihLedgerCount").textContent = ledger.record_count;
    }
  }

  async function refreshSih() {
    const now = Date.now();
    if (now - lastSihFetch > 5000) {
      lastSihFetch = now;
      try { cachedSih = await UGApi.getSihAlignment(); } catch (e) { /* keep last known */ }
    }
    if (now - lastLedgerFetch > 2000) {
      lastLedgerFetch = now;
      try { cachedLedger = await UGApi.getLedger(1); } catch (e) { /* keep last known */ }
    }
    renderSihCard(cachedSih, cachedLedger);
  }

  function onShow() {
    refreshSih();
    const s = window.UGState.settings;

    const detThresh = document.getElementById("setDetectionThreshold");
    detThresh.value = s.detectionThresholdDisplay;
    detThresh.oninput = (e) => { s.detectionThresholdDisplay = +e.target.value; document.getElementById("setDetectionThresholdVal").textContent = e.target.value; };

    const riskThresh = document.getElementById("setRiskThreshold");
    riskThresh.value = s.riskThresholdDisplay;
    riskThresh.oninput = (e) => { s.riskThresholdDisplay = +e.target.value; document.getElementById("setRiskThresholdVal").textContent = e.target.value; };

    const refresh = document.getElementById("setRefreshInterval");
    refresh.value = s.refreshIntervalMs;
    refresh.oninput = (e) => {
      s.refreshIntervalMs = +e.target.value;
      document.getElementById("setRefreshIntervalVal").textContent = (e.target.value / 1000).toFixed(1) + "s";
      UGApp.setRefreshInterval(s.refreshIntervalMs);
    };

    const mitLimit = document.getElementById("setMitLimit");
    mitLimit.value = s.mitigationLimit;
    mitLimit.oninput = (e) => { s.mitigationLimit = +e.target.value; document.getElementById("setMitLimitVal").textContent = e.target.value; };

    const mitTtl = document.getElementById("setMitTtl");
    mitTtl.value = s.mitigationTtl;
    mitTtl.oninput = (e) => { s.mitigationTtl = +e.target.value; document.getElementById("setMitTtlVal").textContent = e.target.value + "s"; };

    document.getElementById("setCompact").checked = s.compactMode;
    document.getElementById("setCompact").onchange = (e) => {
      s.compactMode = e.target.checked;
      document.body.classList.toggle("compact", s.compactMode);
    };

    document.getElementById("setAutoRefresh").checked = s.autoRefresh;
    document.getElementById("setAutoRefresh").onchange = (e) => {
      s.autoRefresh = e.target.checked;
      UGApp.setAutoRefresh(s.autoRefresh);
    };

    document.getElementById("setDemoMode").checked = window.UGState.mode === "demo";
    document.getElementById("setDemoMode").onchange = (e) => UGApp.setMode(e.target.checked ? "demo" : "live");

    const speed = document.getElementById("setDemoSpeed");
    speed.onchange = (e) => UGDemo.setSpeed(+e.target.value);

    document.getElementById("setSystemDiagnosticsBtn").onclick = () => { location.hash = "#/mobile-demo"; };

    document.querySelectorAll("#page-settings .scenario-btn").forEach(b => {
      b.onclick = () => {
        UGDemo.setScenario(b.dataset.scenario);
        UGDemo.start();
        if (window.UGState.mode !== "demo") UGApp.setMode("demo");
      };
    });
  }

  function render() { refreshSih(); }

  return { onShow, render };
})();
