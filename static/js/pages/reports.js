/* ==========================================================================
   UniGuard AI - Reports page (11)
   Generate/Print/Export are all genuinely functional (client-side
   rendering + Blob download + window.print()) - no dead buttons.
   ========================================================================== */

UGPages.reports = (() => {
  let currentReportText = "";

  function onShow() {
    document.getElementById("repGenerateBtn").onclick = generate;
    document.getElementById("repPrintBtn").onclick = () => window.print();
    document.getElementById("repExportBtn").onclick = doExport;
  }

  function buildReportText(inc, snap, isLive) {
    const dur = inc.last_detected - inc.first_detected;
    return [
      "UNIGUARD AI - INCIDENT REPORT",
      "=".repeat(40),
      `Data source: ${isLive ? "REAL (live backend telemetry)" : "SIMULATED (demo mode)"}`,
      `Generated: ${new Date().toLocaleString()}`,
      "",
      `Incident ID:       ${inc.id}`,
      `Threat Type:       DoS-like Behavior`,
      `Severity:          ${inc.severity}`,
      `Source IP:         ${inc.source_ip || "-"}`,
      `Target Endpoint:   ${inc.affected_endpoint || "-"}`,
      `First Seen:        ${new Date(inc.first_detected * 1000).toLocaleString()}`,
      `Last Seen:         ${new Date(inc.last_detected * 1000).toLocaleString()}`,
      `Duration:          ${Math.round(dur)}s`,
      `Risk Score:        ${inc.threat_score}/100`,
      `Status:            ${inc.status}`,
      "",
      "DETECTION EVIDENCE",
      "-".repeat(40),
      ...(inc.evidence || []).map(e => "  - " + e),
      "",
      "MITIGATION",
      "-".repeat(40),
      `  Action taken:    ${inc.mitigation_applied || "none"}`,
      `  Applied at:      ${inc.mitigation_applied_at ? new Date(inc.mitigation_applied_at * 1000).toLocaleString() : "N/A"}`,
      `  Resolved at:     ${inc.resolved_at ? new Date(inc.resolved_at * 1000).toLocaleString() : "N/A (still active)"}`,
      `  Recovery time:   ${inc.resolved_at && inc.mitigation_applied_at ? Math.round(inc.resolved_at - inc.mitigation_applied_at) + "s" : "N/A"}`,
      "",
      "FINAL STATUS",
      "-".repeat(40),
      `  ${inc.status === "RESOLVED" ? "SYSTEM RECOVERED" : inc.status}`,
      "",
      !isLive ? "NOTE: This report was generated from SIMULATED demo data, not a real security event." : "",
    ].filter(Boolean).join("\n");
  }

  function generate() {
    const snap = window.UGState.lastSnapshot;
    const isLive = window.UGState.mode === "live";
    if (!snap || !snap.incidents || !snap.incidents.length) {
      document.getElementById("repPreview").textContent = "No incidents available to report on yet.";
      currentReportText = "";
      return;
    }
    const inc = window.UGState.selectedIncidentId
      ? snap.incidents.find(i => i.id === window.UGState.selectedIncidentId) || snap.incidents[0]
      : snap.incidents[0];
    currentReportText = buildReportText(inc, snap, isLive);
    document.getElementById("repPreview").textContent = currentReportText;
  }

  function doExport() {
    if (!currentReportText) { generate(); }
    if (!currentReportText) return;
    const blob = new Blob([currentReportText], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "uniguard-incident-report.txt";
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function render() {}

  return { onShow, render };
})();
