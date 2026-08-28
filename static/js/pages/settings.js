/* ==========================================================================
   UniGuard AI - Settings page (10)
   Every control here either genuinely does something (wired) or is
   explicitly labeled display-only, per the "don't fake settings" rule.
   ========================================================================== */

UGPages.settings = (() => {
  function onShow() {
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

  function render() {}

  return { onShow, render };
})();
